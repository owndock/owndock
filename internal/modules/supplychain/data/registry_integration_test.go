package data

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	buildbiz "github.com/owndock/owndock/internal/modules/build/biz"
	"github.com/owndock/owndock/internal/modules/supplychain/biz"
	"github.com/owndock/owndock/internal/shared/registryauth"
	"golang.org/x/crypto/bcrypt"
)

const pinnedRegistryImage = "registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"
const pinnedSyftImage = "anchore/syft:v1.50.0@sha256:1288ea4c8b38767b4e620c1e312c8cb26b6e887a99b4f07ab6cd19fc6f225026"
const pinnedCosignImage = "ghcr.io/sigstore/cosign/cosign:v3.0.6@sha256:de9c65609e6bde17e6b48de485ee788407c9502fa08b8f4459f595b21f56cd00"
const pinnedVaultImage = "hashicorp/vault:1.20.4@sha256:268bb80aa9c6d13d65fcfa05c0c268caca068952240a8087291a6ce0b66e3a10"
const pinnedTrivyImage = "aquasec/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969"

type credentialCaptureProvider struct {
	username string
	password string
	issued   []byte
}

func (p *credentialCaptureProvider) ResolveRegistryCredential(
	context.Context, string, string, string,
) (biz.RegistryCredential, error) {
	p.issued = []byte(p.password)
	return biz.RegistryCredential{AuthenticationMode: registryauth.ModeBasic, Username: p.username, Password: p.issued}, nil
}

func (p *credentialCaptureProvider) cleared() bool {
	if len(p.issued) == 0 {
		return false
	}
	for _, value := range p.issued {
		if value != 0 {
			return false
		}
	}
	return true
}

func TestOCIReferrerClientWithRealRegistry(t *testing.T) {
	if os.Getenv("OWNDOCK_RUN_SUPPLY_CHAIN_INTEGRATION") != "1" {
		t.Skip("set OWNDOCK_RUN_SUPPLY_CHAIN_INTEGRATION=1 to run the OCI Registry integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	name := fmt.Sprintf("owndock-evidence-registry-%d", time.Now().UnixNano())
	networkName := fmt.Sprintf("owndock-evidence-%d", time.Now().UnixNano())
	runDockerCommand(t, ctx, "network", "create", networkName)
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()
		_ = exec.CommandContext(cleanupContext, "docker", "network", "rm", networkName).Run()
	})
	runDockerCommand(t, ctx, "run", "--detach", "--name", name,
		"--network", networkName, "--publish", "127.0.0.1::5000", pinnedRegistryImage)
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()
		_ = exec.CommandContext(cleanupContext, "docker", "rm", "--force", name).Run()
	})
	port := strings.TrimSpace(runDockerCommand(t, ctx, "port", name, "5000/tcp"))
	base := "http://" + port
	waitForRegistry(t, ctx, base, nil)

	config := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"config":{}}`)
	configDigest := digestBytes(config)
	uploadRegistryBlob(t, ctx, base, "team/api", configDigest, config, nil)
	subjectManifest := []byte(fmt.Sprintf(
		`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.empty.v1+json","digest":%q,"size":%d},"layers":[]}`,
		configDigest, len(config),
	))
	subjectDigest := putRegistryManifest(t, ctx, base, "team/api", "subject", ociManifestMediaType, subjectManifest, nil)
	syftOutput := runDockerStdout(t, ctx,
		"run", "--rm", "--network", networkName,
		"--user", "65532:65532", "--read-only",
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=536870912,mode=1777",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
		"--pids-limit", "128", "--memory", "1g", "--cpus", "1",
		"--env", "SYFT_REGISTRY_INSECURE_USE_HTTP=true",
		"--env", "SYFT_CHECK_FOR_APP_UPDATE=false",
		pinnedSyftImage, "scan", "registry:"+name+":5000/team/api@"+subjectDigest,
		"-o", "cyclonedx-json@1.6",
	)
	if _, err := biz.NewCycloneDX16Document(syftOutput, 16*1024*1024); err != nil {
		t.Fatalf("real pinned Syft returned an invalid CycloneDX 1.6 document: %v", err)
	}
	oversizedSubjectDigest := createRegistrySubjectWithLayer(
		t, ctx, base, "team/oversized", "subject", 2*1024*1024,
	)
	imageGuard, err := NewOCIImageGuard(OCIImageGuardOptions{
		AllowPlainHTTP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := imageGuard.ValidateSBOMImage(ctx, biz.SBOMRequest{
		ProjectID: "project-1", RegistryCredentialID: "registry-1",
		RegistryRepository: strings.TrimPrefix(base, "http://") + "/team/api",
		SubjectDigest:      subjectDigest, FormatVersion: biz.CycloneDXVersion16,
	}, 1024*1024, biz.RegistryCredential{AuthenticationMode: registryauth.ModeAnonymous}); err != nil {
		t.Fatalf("valid Registry image guard error = %v", err)
	}
	if err := imageGuard.ValidateSBOMImage(ctx, biz.SBOMRequest{
		ProjectID: "project-1", RegistryCredentialID: "registry-1",
		RegistryRepository: strings.TrimPrefix(base, "http://") + "/team/oversized",
		SubjectDigest:      oversizedSubjectDigest, FormatVersion: biz.CycloneDXVersion16,
	}, 1024*1024, biz.RegistryCredential{AuthenticationMode: registryauth.ModeAnonymous}); !errors.Is(err, biz.ErrSBOMImageTooLarge) {
		t.Fatalf("oversized Registry image guard error = %v", err)
	}
	document, err := biz.NewCycloneDX16Document(
		[]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"operating-system","name":"fixture"}]}`), 4096,
	)
	if err != nil {
		t.Fatalf("create CycloneDX fixture: %v", err)
	}
	publisher, err := NewORASPublisher(ORASPublisherOptions{AllowPlainHTTP: true, MaxDocumentBytes: 4096})
	if err != nil {
		t.Fatalf("create ORAS publisher: %v", err)
	}
	published, err := publisher.PublishSBOM(ctx, biz.SBOMPublication{
		ProjectID: "project-1", RegistryCredentialID: "registry-1",
		RegistryRepository: strings.TrimPrefix(base, "http://") + "/team/api",
		SubjectDigest:      subjectDigest, Document: document, CreatedAt: time.Unix(100, 0),
	})
	if err != nil || published.MediaType != ociManifestMediaType || !strings.HasPrefix(published.Digest, "sha256:") {
		t.Fatalf("PublishSBOM() = %+v, %v", published, err)
	}
	repositoryName := strings.TrimPrefix(base, "http://") + "/team/api"
	provenancePublication := provenancePublicationFixture(t, repositoryName, subjectDigest)
	publishedProvenance, err := publisher.PublishProvenance(ctx, provenancePublication)
	if err != nil || publishedProvenance.MediaType != ociManifestMediaType {
		t.Fatalf("PublishProvenance() = %+v, %v", publishedProvenance, err)
	}

	client, err := NewOCIReferrerClient(OCIReferrerClientOptions{AllowPlainHTTP: true})
	if err != nil {
		t.Fatalf("create OCI Referrer client: %v", err)
	}
	capability, err := client.Probe(ctx, strings.TrimPrefix(base, "http://")+"/team/api", subjectDigest)
	if err != nil || !capability.Supported || capability.Count != 2 ||
		capability.Mode != ReferrerDiscoveryTagSchema {
		t.Fatalf("real Registry Probe() = %+v, %v", capability, err)
	}
	reader, err := NewOCIContentReader(OCIContentReaderOptions{
		AllowPlainHTTP: true, MaxDocumentBytes: 16 * 1024 * 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	subject := biz.ArtifactSubject{
		ID: "artifact-1", OrganizationID: "organization-1", ProjectID: "project-1",
		SubjectDigest: subjectDigest, RegistryRepository: repositoryName,
		RegistryCredentialID: "registry-1",
	}
	sbomEvidence, err := biz.NewEvidence(biz.EvidenceInput{
		ID: "sbom-1", OrganizationID: subject.OrganizationID, ProjectID: subject.ProjectID,
		ArtifactID: subject.ID, SubjectDigest: subjectDigest, Kind: biz.EvidenceKindSBOM,
		MediaType: biz.CycloneDXJSONMediaType, FormatVersion: biz.CycloneDXVersion16,
		Producer: "syft/1.50.0", RegistryRepository: repositoryName,
		DescriptorDigest: published.Digest, VerificationStatus: biz.VerificationUnverified,
		CreatedAt: time.Unix(100, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	downloadedSBOM, err := reader.ReadEvidence(ctx, subject, sbomEvidence)
	if err != nil || !bytes.Equal(downloadedSBOM.Content, document.Content) ||
		downloadedSBOM.Digest != document.ContentDigest {
		t.Fatalf("ReadEvidence(SBOM) = %+v, %v", downloadedSBOM, err)
	}
	provenanceEvidence, err := biz.NewEvidence(biz.EvidenceInput{
		ID: "provenance-1", OrganizationID: subject.OrganizationID, ProjectID: subject.ProjectID,
		ArtifactID: subject.ID, SubjectDigest: subjectDigest, Kind: biz.EvidenceKindProvenance,
		MediaType: biz.SLSAProvenanceMediaType, FormatVersion: biz.SLSAProvenanceFormatVersion,
		PredicateType: biz.SLSAProvenancePredicateV1, Producer: "owndock-build-worker/0.1.0",
		RegistryRepository: repositoryName, DescriptorDigest: publishedProvenance.Digest,
		VerificationStatus: biz.VerificationUnverified, CreatedAt: time.Unix(200, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	downloaded, err := reader.ReadEvidence(ctx, subject, provenanceEvidence)
	if err != nil || !bytes.Equal(downloaded.Content, provenancePublication.Document.Content) ||
		downloaded.Digest != provenancePublication.Document.ContentDigest {
		t.Fatalf("ReadEvidence() = %+v, %v", downloaded, err)
	}
}

func TestCosignSignatureVerificationWithRealRegistry(t *testing.T) {
	if os.Getenv("OWNDOCK_RUN_SUPPLY_CHAIN_INTEGRATION") != "1" {
		t.Skip("set OWNDOCK_RUN_SUPPLY_CHAIN_INTEGRATION=1 to run the Cosign Registry integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cosign := extractCosignExecutable(t, ctx)
	name := fmt.Sprintf("owndock-cosign-registry-%d", time.Now().UnixNano())
	runDockerCommand(t, ctx, "run", "--detach", "--name", name,
		"--publish", "127.0.0.1::5000", pinnedRegistryImage)
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()
		_ = exec.CommandContext(cleanupContext, "docker", "rm", "--force", name).Run()
	})
	port := strings.TrimSpace(runDockerCommand(t, ctx, "port", name, "5000/tcp"))
	base := "http://" + port
	waitForRegistry(t, ctx, base, nil)
	config := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"config":{}}`)
	configDigest := digestBytes(config)
	uploadRegistryBlob(t, ctx, base, "signed/api", configDigest, config, nil)
	manifest := []byte(fmt.Sprintf(
		`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":%q,"size":%d},"layers":[]}`,
		configDigest, len(config)))
	subjectDigest := putRegistryManifest(t, ctx, base, "signed/api", "subject", ociManifestMediaType, manifest, nil)
	repository := strings.TrimPrefix(base, "http://") + "/signed/api"
	subject := repository + "@" + subjectDigest
	keyDirectory := filepath.Join(t.TempDir(), "keys")
	if err := os.Mkdir(keyDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	generateCosignKeyPair(t, ctx, cosign, keyDirectory)
	signingConfig := filepath.Join(keyDirectory, "signing-config.json")
	if err := os.WriteFile(signingConfig, []byte(offlineCosignSigningConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, cosign, "sign", "--key", filepath.Join(keyDirectory, "cosign.key"),
		"--signing-config", signingConfig, "--new-bundle-format=true", "--yes", "--allow-http-registry", subject)
	command.Env = []string{"HOME=" + keyDirectory, "COSIGN_PASSWORD=integration-password"}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("Cosign sign failed: %v: %s", err, string(output))
	}
	publicKey, err := os.ReadFile(filepath.Join(keyDirectory, "cosign.pub"))
	if err != nil {
		t.Fatal(err)
	}
	credentials := &credentialCaptureProvider{username: "anonymous", password: "unused-password"}
	verifier, err := NewCosignVerifier(CosignVerifierOptions{Executable: cosign,
		ExpectedVersion: PinnedCosignVersion, Credentials: credentials,
		TemporaryRoot: t.TempDir(), AllowPlainHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(ctx); err != nil {
		t.Fatalf("Cosign version verification: %v", err)
	}
	request := biz.SignatureVerificationRequest{ProjectID: "project-1", RegistryCredentialID: "registry-1",
		RegistryRepository: repository, SubjectDigest: subjectDigest,
		Trust: biz.SignatureTrustMaterial{Mode: biz.SignatureTrustPublicKey, PublicKeyPEM: publicKey}}
	result, err := verifier.VerifySignature(ctx, request)
	if err != nil || result.TrustMode != biz.SignatureTrustPublicKey ||
		!strings.HasPrefix(result.BundleSetDigest, "sha256:") || result.VerifierVersion != PinnedCosignVersion {
		diagnostic := exec.CommandContext(ctx, cosign, "verify", "--output=json", "--max-workers=1",
			"--new-bundle-format=true", "--allow-http-registry", "--key",
			filepath.Join(keyDirectory, "cosign.pub"), "--insecure-ignore-tlog", subject)
		diagnostic.Env = []string{"HOME=" + keyDirectory}
		output, diagnosticErr := diagnostic.CombinedOutput()
		t.Fatalf("Cosign VerifySignature() = %+v, %v; direct verification: %v: %s", result, err, diagnosticErr, output)
	}
	if !credentials.cleared() {
		t.Fatal("Cosign verifier did not clear Registry credential")
	}
	otherConfig := []byte(`{"architecture":"arm64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"config":{}}`)
	otherConfigDigest := digestBytes(otherConfig)
	uploadRegistryBlob(t, ctx, base, "signed/api", otherConfigDigest, otherConfig, nil)
	otherManifest := []byte(fmt.Sprintf(
		`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.empty.v1+json","digest":%q,"size":%d},"layers":[]}`,
		otherConfigDigest, len(otherConfig)))
	otherSubjectDigest := putRegistryManifest(t, ctx, base, "signed/api", "unsigned-subject", ociManifestMediaType, otherManifest, nil)
	request.SubjectDigest = otherSubjectDigest
	if _, err := verifier.VerifySignature(ctx, request); !errors.Is(err, biz.ErrSignatureVerification) {
		t.Fatalf("signature replay onto a different digest error = %v", err)
	}
	request.SubjectDigest = subjectDigest
	rotatedDirectory := filepath.Join(t.TempDir(), "rotated")
	if err := os.Mkdir(rotatedDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	generateCosignKeyPair(t, ctx, cosign, rotatedDirectory)
	rotatedKey, err := os.ReadFile(filepath.Join(rotatedDirectory, "cosign.pub"))
	if err != nil {
		t.Fatal(err)
	}
	request.Trust.PublicKeyPEM = rotatedKey
	if _, err := verifier.VerifySignature(ctx, request); !errors.Is(err, biz.ErrSignatureVerification) {
		t.Fatalf("rotated untrusted key error = %v", err)
	}
	runDockerCommand(t, ctx, "stop", name)
	request.Trust.PublicKeyPEM = publicKey
	if _, err := verifier.VerifySignature(ctx, request); !errors.Is(err, biz.ErrSignatureVerification) {
		t.Fatalf("Registry outage error = %v", err)
	}
}

func TestCosignVaultKMSSignAndVerifyWithRealRegistry(t *testing.T) {
	if os.Getenv("OWNDOCK_RUN_SUPPLY_CHAIN_INTEGRATION") != "1" {
		t.Skip("set OWNDOCK_RUN_SUPPLY_CHAIN_INTEGRATION=1 to run the Vault KMS integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cosign := extractCosignExecutable(t, ctx)

	registryName := fmt.Sprintf("owndock-kms-registry-%d", time.Now().UnixNano())
	runDockerCommand(t, ctx, "run", "--detach", "--name", registryName,
		"--publish", "127.0.0.1::5000", pinnedRegistryImage)
	t.Cleanup(func() { removeDockerContainer(registryName) })
	registryPort := strings.TrimSpace(runDockerCommand(t, ctx, "port", registryName, "5000/tcp"))
	registryBase := "http://" + registryPort
	waitForRegistry(t, ctx, registryBase, nil)
	repository := strings.TrimPrefix(registryBase, "http://") + "/kms/api"

	vaultDirectory := t.TempDir()
	if err := os.Chmod(vaultDirectory, 0o777); err != nil {
		t.Fatal(err)
	}
	vaultName := fmt.Sprintf("owndock-vault-kms-%d", time.Now().UnixNano())
	runDockerCommand(t, ctx, "run", "--detach", "--name", vaultName, "--cap-add", "IPC_LOCK",
		"--publish", "127.0.0.1::8200", "--volume", vaultDirectory+":/tls", pinnedVaultImage,
		"server", "-dev", "-dev-tls", "-dev-tls-cert-dir=/tls", "-dev-tls-san=host.docker.internal",
		"-dev-listen-address=0.0.0.0:8200", "-dev-root-token-id=integration-root-token")
	t.Cleanup(func() { removeDockerContainer(vaultName) })
	vaultPort := strings.TrimSpace(runDockerCommand(t, ctx, "port", vaultName, "8200/tcp"))
	vaultAddress := "https://" + vaultPort
	vaultCA := filepath.Join(vaultDirectory, "vault-ca.pem")
	vaultClient := waitForVault(t, ctx, vaultAddress, vaultCA)
	vaultRequest(t, ctx, vaultClient, http.MethodPost, vaultAddress+"/v1/sys/mounts/transit",
		`{"type":"transit"}`, http.StatusNoContent)
	vaultRequest(t, ctx, vaultClient, http.MethodPost, vaultAddress+"/v1/transit/keys/release-signing-key",
		`{"type":"ecdsa-p256"}`, http.StatusOK)
	firstPublicKey := readVaultTransitPublicKey(t, ctx, vaultClient, vaultAddress, "1")

	firstDigest := createUnsignedRegistrySubject(t, ctx, registryBase, "kms/api", "kms-first", "amd64")
	firstRequest := biz.SignatureSigningRequest{ProjectID: "project-1", ProfileID: "profile-1",
		RegistryCredentialID: "registry-1", RegistryRepository: repository, SubjectDigest: firstDigest,
		KeyReference: "hashivault://release-signing-key"}
	signer, signingEnvironment, signingCredentials := newVaultCosignSigner(t, cosign, vaultAddress, vaultCA)
	result, err := signer.SignSignature(ctx, firstRequest)
	if err != nil || result.Provider != biz.SigningKeyVault ||
		result.KeyReferenceFingerprint != biz.SigningKeyReferenceFingerprint(firstRequest.KeyReference) {
		t.Fatalf("Vault SignSignature() = %+v, %v", result, err)
	}
	if len(signingEnvironment.values) != 0 || !signingCredentials.cleared() {
		t.Fatal("Vault or Registry credential remained after signing")
	}
	verifyRegistrySignature(t, ctx, cosign, repository, firstDigest, firstPublicKey)

	vaultRequest(t, ctx, vaultClient, http.MethodPost,
		vaultAddress+"/v1/transit/keys/release-signing-key/rotate", `{}`, http.StatusOK)
	secondPublicKey := readVaultTransitPublicKey(t, ctx, vaultClient, vaultAddress, "2")
	secondDigest := createUnsignedRegistrySubject(t, ctx, registryBase, "kms/api", "kms-second", "arm64")
	secondRequest := firstRequest
	secondRequest.SubjectDigest = secondDigest
	signer, _, _ = newVaultCosignSigner(t, cosign, vaultAddress, vaultCA)
	if _, err := signer.SignSignature(ctx, secondRequest); err != nil {
		t.Fatalf("Vault SignSignature() after rotation = %v", err)
	}
	if err := verifyRegistrySignatureError(ctx, cosign, repository, secondDigest, firstPublicKey); !errors.Is(err, biz.ErrSignatureVerification) {
		t.Fatalf("old Vault public key after rotation error = %v", err)
	}
	verifyRegistrySignature(t, ctx, cosign, repository, secondDigest, secondPublicKey)

	runDockerCommand(t, ctx, "stop", vaultName)
	thirdDigest := createUnsignedRegistrySubject(t, ctx, registryBase, "kms/api", "kms-outage", "amd64")
	thirdRequest := firstRequest
	thirdRequest.SubjectDigest = thirdDigest
	signer, _, _ = newVaultCosignSigner(t, cosign, vaultAddress, vaultCA)
	if _, err := signer.SignSignature(ctx, thirdRequest); !errors.Is(err, biz.ErrSignatureSigning) {
		t.Fatalf("Vault outage signing error = %v", err)
	}
}

func TestCosignKeylessVerificationWithPrivateSigstore(t *testing.T) {
	if os.Getenv("OWNDOCK_RUN_PRIVATE_SIGSTORE_INTEGRATION") != "1" {
		t.Skip("set OWNDOCK_RUN_PRIVATE_SIGSTORE_INTEGRATION=1 with a private Sigstore stack")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cosign := extractCosignExecutable(t, ctx)
	signingConfig := strings.TrimSpace(os.Getenv("OWNDOCK_SIGSTORE_SIGNING_CONFIG"))
	trustedRootPath := strings.TrimSpace(os.Getenv("OWNDOCK_SIGSTORE_TRUSTED_ROOT"))
	identity := strings.TrimSpace(os.Getenv("OWNDOCK_SIGSTORE_IDENTITY"))
	issuer := strings.TrimSpace(os.Getenv("OWNDOCK_SIGSTORE_ISSUER"))
	offlineContainer := strings.TrimSpace(os.Getenv("OWNDOCK_SIGSTORE_OFFLINE_CONTAINER"))
	identityToken := []byte(os.Getenv("OWNDOCK_SIGSTORE_IDENTITY_TOKEN"))
	defer clear(identityToken)
	if !filepath.IsAbs(signingConfig) || !filepath.IsAbs(trustedRootPath) || identity == "" || issuer == "" ||
		offlineContainer == "" || len(identityToken) < 32 || len(identityToken) > 64*1024 {
		t.Fatal("private Sigstore fixture configuration is incomplete")
	}
	trustedRoot, err := os.ReadFile(trustedRootPath)
	if err != nil || len(trustedRoot) < 64 || len(trustedRoot) > 4*1024*1024 || !json.Valid(trustedRoot) {
		t.Fatalf("read private Sigstore trusted root: %v", err)
	}
	kindCluster := strings.TrimSpace(runDockerCommand(t, ctx, "inspect", "--format",
		"{{ index .Config.Labels \"io.x-k8s.kind.cluster\" }}", offlineContainer))
	if kindCluster == "" || strings.ContainsAny(offlineContainer, "\r\n\x00") {
		t.Fatal("offline target is not a KinD node container")
	}

	registryName := fmt.Sprintf("owndock-keyless-registry-%d", time.Now().UnixNano())
	runDockerCommand(t, ctx, "run", "--detach", "--name", registryName,
		"--publish", "127.0.0.1::5000", pinnedRegistryImage)
	t.Cleanup(func() { removeDockerContainer(registryName) })
	registryPort := strings.TrimSpace(runDockerCommand(t, ctx, "port", registryName, "5000/tcp"))
	registryBase := "http://" + registryPort
	waitForRegistry(t, ctx, registryBase, nil)
	repository := strings.TrimPrefix(registryBase, "http://") + "/keyless/api"
	subjectDigest := createUnsignedRegistrySubject(t, ctx, registryBase, "keyless/api", "signed", "amd64")
	subject := repository + "@" + subjectDigest
	home := t.TempDir()
	command := exec.CommandContext(ctx, cosign, "sign", "--yes", "--allow-http-registry",
		"--new-bundle-format=true", "--signing-config", signingConfig, "--trusted-root", trustedRootPath, subject)
	command.Env = []string{"HOME=" + home, "SIGSTORE_NO_CACHE=true", "SIGSTORE_ID_TOKEN=" + string(identityToken)}
	output, err := command.CombinedOutput()
	command.Env = nil
	if err != nil {
		t.Fatalf("private keyless Cosign sign failed: %v: %s", err, output)
	}
	clear(output)

	runDockerCommand(t, ctx, "stop", offlineContainer)
	t.Cleanup(func() {
		restartContext, restartCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer restartCancel()
		_ = exec.CommandContext(restartContext, "docker", "start", offlineContainer).Run()
	})
	verifier, err := NewCosignVerifier(CosignVerifierOptions{Executable: cosign,
		ExpectedVersion: PinnedCosignVersion,
		Credentials:     &credentialCaptureProvider{username: "anonymous", password: "unused-password"},
		TemporaryRoot:   t.TempDir(), AllowPlainHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	request := biz.SignatureVerificationRequest{ProjectID: "project-1", RegistryCredentialID: "registry-1",
		RegistryRepository: repository, SubjectDigest: subjectDigest,
		Trust: biz.SignatureTrustMaterial{Mode: biz.SignatureTrustKeyless, TrustedRootJSON: trustedRoot,
			CertificateIdentity: identity, OIDCIssuer: issuer}}
	verify := func(request biz.SignatureVerificationRequest) (biz.SignatureVerificationResult, error) {
		verifyContext, verifyCancel := context.WithTimeout(ctx, 30*time.Second)
		defer verifyCancel()
		return verifier.VerifySignature(verifyContext, request)
	}
	result, err := verify(request)
	if err != nil || result.TrustMode != biz.SignatureTrustKeyless || result.SignerIdentity != identity ||
		result.OIDCIssuer != issuer || result.TrustRootHash != request.Trust.Fingerprint() {
		t.Fatalf("offline private keyless verification = %+v, %v", result, err)
	}

	wrongIdentity := request
	wrongIdentity.Trust.CertificateIdentity = identity + "/unexpected"
	if _, err := verify(wrongIdentity); !errors.Is(err, biz.ErrSignatureVerification) {
		t.Fatalf("wrong keyless identity error = %v", err)
	}
	wrongIssuer := request
	wrongIssuer.Trust.OIDCIssuer = "https://issuer.invalid.example"
	if _, err := verify(wrongIssuer); !errors.Is(err, biz.ErrSignatureVerification) {
		t.Fatalf("wrong keyless issuer error = %v", err)
	}
	unsignedDigest := createUnsignedRegistrySubject(t, ctx, registryBase, "keyless/api", "unsigned", "arm64")
	wrongSubject := request
	wrongSubject.SubjectDigest = unsignedDigest
	if _, err := verify(wrongSubject); !errors.Is(err, biz.ErrSignatureVerification) {
		t.Fatalf("keyless signature replay error = %v", err)
	}
	var rootObject map[string]any
	if err := json.Unmarshal(trustedRoot, &rootObject); err != nil {
		t.Fatal(err)
	}
	delete(rootObject, "tlogs")
	rootWithoutTransparencyLog, err := json.Marshal(rootObject)
	if err != nil {
		t.Fatal(err)
	}
	wrongRoot := request
	wrongRoot.Trust.TrustedRootJSON = rootWithoutTransparencyLog
	if _, err := verify(wrongRoot); !errors.Is(err, biz.ErrSignatureVerification) {
		t.Fatalf("trusted root without transparency log error = %v", err)
	}
}

func TestTrivyVulnerabilityScanWithPinnedDatabaseAndRegistry(t *testing.T) {
	if os.Getenv("OWNDOCK_RUN_VULNERABILITY_INTEGRATION") != "1" {
		t.Skip("set OWNDOCK_RUN_VULNERABILITY_INTEGRATION=1 to run the pinned Trivy integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	trivy := extractTrivyExecutable(t, ctx)
	databaseRoot := filepath.Join(t.TempDir(), "trivy-db")
	databaseManager, err := NewTrivyDatabaseSnapshotManager(TrivyDatabaseSnapshotOptions{
		Executable: trivy, ExpectedVersion: PinnedTrivyVersion, RootDirectory: databaseRoot,
		RetainSnapshots: 3, MinimumRetention: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	databaseSnapshot, err := databaseManager.Update(ctx)
	if err != nil {
		t.Fatalf("publish pinned Trivy database snapshot: %v", err)
	}
	cache := databaseSnapshot.CurrentPath
	if target, linkErr := os.Readlink(cache); linkErr != nil ||
		target != filepath.Join("snapshots", databaseSnapshot.Name) {
		t.Fatalf("atomic Trivy database link = %q, %v", target, linkErr)
	}
	if err := filepath.Walk(databaseRoot, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		if info.IsDir() {
			return os.Chmod(path, 0o755)
		}
		return os.Chmod(path, 0o644)
	}); err != nil {
		t.Fatalf("prepare non-secret DB fixture permissions: %v", err)
	}

	registryName := fmt.Sprintf("owndock-trivy-registry-%d", time.Now().UnixNano())
	networkName := fmt.Sprintf("owndock-trivy-%d", time.Now().UnixNano())
	runDockerCommand(t, ctx, "network", "create", networkName)
	t.Cleanup(func() { _ = exec.Command("docker", "network", "rm", networkName).Run() })
	runDockerCommand(t, ctx, "run", "--detach", "--name", registryName,
		"--network", networkName, "--publish", "127.0.0.1::5000", pinnedRegistryImage)
	t.Cleanup(func() { removeDockerContainer(registryName) })
	registryPort := strings.TrimSpace(runDockerCommand(t, ctx, "port", registryName, "5000/tcp"))
	registryBase := "http://" + registryPort
	waitForRegistry(t, ctx, registryBase, nil)
	repository := strings.TrimPrefix(registryBase, "http://") + "/vulnerability/api"
	subjectDigest := createUnsignedRegistrySubject(t, ctx, registryBase,
		"vulnerability/api", "scan", "amd64")
	isolatedSubject := registryName + ":5000/vulnerability/api@" + subjectDigest
	isolatedOutput, isolatedError, isolatedErr := runDockerCapture(ctx, map[string]string{"HOME": "/tmp"},
		"run", "--rm", "--network", networkName, "--user", "65532:65532", "--read-only",
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=536870912,mode=1777",
		"--volume", databaseRoot+":/var/lib/owndock/trivy-db:ro",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
		"--pids-limit", "128", "--memory", "1g", "--cpus", "1", "--env", "HOME",
		"--entrypoint", "/usr/local/bin/trivy", pinnedTrivyImage,
		"image", "--format", "json", "--scanners", "vuln", "--skip-db-update", "--offline-scan",
		"--no-progress", "--cache-backend", "memory", "--cache-dir", "/var/lib/owndock/trivy-db/current",
		"--insecure", isolatedSubject)
	if isolatedErr != nil {
		t.Fatalf("resource-isolated Trivy scan: %v: %s", isolatedErr, isolatedError)
	}
	if _, err := newTrivyV2Report(isolatedOutput, biz.MaximumVulnerabilityReportSize,
		isolatedSubject, PinnedTrivyVersion, databaseSnapshot.Database); err != nil {
		t.Fatalf("resource-isolated Trivy report: %v", err)
	}
	credentials := &credentialCaptureProvider{username: "anonymous", password: "unused-password"}
	scanner, err := NewTrivyScanner(TrivyOptions{Executable: trivy,
		ExpectedVersion: PinnedTrivyVersion, CacheDirectory: cache,
		MaxOutputBytes: biz.MaximumVulnerabilityReportSize, Credentials: credentials, AllowPlainHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := scanner.Verify(ctx); err != nil {
		t.Fatalf("verify real Trivy database = %v", err)
	}
	report, err := scanner.ScanVulnerabilities(ctx, biz.VulnerabilityScanRequest{
		ProjectID: "project-1", RegistryCredentialID: "registry-1", RegistryRepository: repository,
		SubjectDigest: subjectDigest, FormatVersion: biz.TrivyReportFormatVersion})
	if err != nil {
		diagnostic := exec.CommandContext(ctx, trivy, "image", "--format", "json", "--scanners", "vuln",
			"--skip-db-update", "--offline-scan", "--no-progress", "--cache-backend", "memory",
			"--cache-dir", cache, "--insecure", repository+"@"+subjectDigest)
		diagnostic.Env = []string{"HOME=" + t.TempDir(), "TRIVY_CACHE_DIR=" + cache,
			"TRIVY_USERNAME=anonymous", "TRIVY_PASSWORD=unused-password"}
		if output, diagnosticErr := diagnostic.CombinedOutput(); diagnosticErr != nil {
			t.Fatalf("real Trivy scan = %v; diagnostic = %v: %s", err, diagnosticErr, output)
		}
	}
	if err != nil || report.ScannerVersion != PinnedTrivyVersion || report.Database.SchemaVersion == 0 ||
		report.Database.UpdatedAt.IsZero() || report.ScannedAt.IsZero() || !credentials.cleared() {
		t.Fatalf("real Trivy report = %+v, %v, credential cleared=%t", report, err, credentials.cleared())
	}
	oversizedFixture := filepath.Join(t.TempDir(), "oversized-trivy-report.json")
	fixture, err := os.OpenFile(oversizedFixture, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.Truncate(biz.MaximumVulnerabilityReportSize + 1); err != nil {
		_ = fixture.Close()
		t.Fatal(err)
	}
	_ = fixture.Close()
	oversizedExecutable := writeFakeTrivy(t, fmt.Sprintf(`
if [ "$1" = "version" ]; then exec %q "$@"; fi
exec /bin/cat %q
`, trivy, oversizedFixture))
	oversizedCredentials := &credentialCaptureProvider{username: "anonymous", password: "unused-password"}
	oversizedScanner, err := NewTrivyScanner(TrivyOptions{Executable: oversizedExecutable,
		ExpectedVersion: PinnedTrivyVersion, CacheDirectory: cache,
		MaxOutputBytes: biz.MaximumVulnerabilityReportSize, Credentials: oversizedCredentials,
		AllowPlainHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := oversizedScanner.ScanVulnerabilities(ctx, biz.VulnerabilityScanRequest{
		ProjectID: "project-1", RegistryCredentialID: "registry-1", RegistryRepository: repository,
		SubjectDigest: subjectDigest, FormatVersion: biz.TrivyReportFormatVersion}); !errors.Is(err, biz.ErrVulnerabilityReportSize) || !oversizedCredentials.cleared() {
		t.Fatalf("oversized Trivy report error = %v, credential cleared=%t", err, oversizedCredentials.cleared())
	}
	publisher, err := NewORASPublisher(ORASPublisherOptions{Credentials: credentials,
		AllowPlainHTTP: true, MaxDocumentBytes: biz.MaximumVulnerabilityReportSize})
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := publisher.PublishVulnerabilityReport(ctx, biz.VulnerabilityPublication{
		ProjectID: "project-1", RegistryCredentialID: "registry-1", RegistryRepository: repository,
		SubjectDigest: subjectDigest, Report: report, CreatedAt: report.ScannedAt})
	if err != nil {
		t.Fatalf("publish real Trivy report = %v", err)
	}
	evidence, err := biz.NewEvidence(biz.EvidenceInput{ID: "vulnerability-evidence-1",
		OrganizationID: "organization-1", ProjectID: "project-1", ArtifactID: "artifact-1",
		SubjectDigest: subjectDigest, Kind: biz.EvidenceKindVulnerabilityReport,
		MediaType: report.MediaType, FormatVersion: report.FormatVersion, Producer: "trivy/" + PinnedTrivyVersion,
		RegistryRepository: repository, DescriptorDigest: descriptor.Digest,
		VerificationStatus: biz.VerificationUnverified, CreatedAt: report.ScannedAt})
	if err != nil {
		t.Fatal(err)
	}
	reader, _ := NewOCIContentReader(OCIContentReaderOptions{Credentials: credentials,
		AllowPlainHTTP: true, MaxDocumentBytes: biz.MaximumVulnerabilityReportSize})
	content, err := reader.ReadEvidence(ctx, biz.ArtifactSubject{ID: evidence.ArtifactID,
		ProjectID: evidence.ProjectID, SubjectDigest: subjectDigest, RegistryRepository: repository,
		RegistryCredentialID: "registry-1"}, evidence)
	if err != nil || !bytes.Equal(content.Content, report.Content) || content.MediaType != biz.TrivyReportMediaType {
		t.Fatalf("read real Trivy evidence = %+v/%v", content, err)
	}
}

func newVaultCosignSigner(t *testing.T, executable, vaultAddress, vaultCA string) (
	*CosignSigner, *signingEnvironmentProbe, *credentialCaptureProvider) {
	t.Helper()
	environment := &signingEnvironmentProbe{values: map[string][]byte{
		"VAULT_ADDR": []byte(vaultAddress), "VAULT_TOKEN": []byte("integration-root-token"),
		"VAULT_CACERT": []byte(vaultCA),
	}}
	credentials := &credentialCaptureProvider{username: "anonymous", password: "unused-password"}
	signer, err := NewCosignSigner(CosignSignerOptions{Executable: executable,
		ExpectedVersion: PinnedCosignVersion, Credentials: credentials, SigningEnvironment: environment,
		TemporaryRoot: t.TempDir(), AllowPlainHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	return signer, environment, credentials
}

func verifyRegistrySignature(t *testing.T, ctx context.Context, executable, repository, subjectDigest string,
	publicKey []byte) {
	t.Helper()
	if err := verifyRegistrySignatureError(ctx, executable, repository, subjectDigest, publicKey); err != nil {
		t.Fatalf("verify Registry signature %s: %v", subjectDigest, err)
	}
}

func verifyRegistrySignatureError(ctx context.Context, executable, repository, subjectDigest string,
	publicKey []byte) error {
	verifier, err := NewCosignVerifier(CosignVerifierOptions{Executable: executable,
		ExpectedVersion: PinnedCosignVersion,
		Credentials:     &credentialCaptureProvider{username: "anonymous", password: "unused-password"},
		TemporaryRoot:   os.TempDir(), AllowPlainHTTP: true})
	if err != nil {
		return err
	}
	_, err = verifier.VerifySignature(ctx, biz.SignatureVerificationRequest{
		ProjectID: "project-1", RegistryCredentialID: "registry-1", RegistryRepository: repository,
		SubjectDigest: subjectDigest,
		Trust:         biz.SignatureTrustMaterial{Mode: biz.SignatureTrustPublicKey, PublicKeyPEM: publicKey},
	})
	return err
}

func createUnsignedRegistrySubject(t *testing.T, ctx context.Context, base, repository, tag, architecture string) string {
	t.Helper()
	config := []byte(fmt.Sprintf(
		`{"architecture":%q,"os":"linux","rootfs":{"type":"layers","diff_ids":[]},"config":{}}`, architecture))
	configDigest := digestBytes(config)
	uploadRegistryBlob(t, ctx, base, repository, configDigest, config, nil)
	manifest := []byte(fmt.Sprintf(
		`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":%q,"size":%d},"layers":[]}`,
		configDigest, len(config)))
	return putRegistryManifest(t, ctx, base, repository, tag, ociManifestMediaType, manifest, nil)
}

func createRegistrySubjectWithLayer(t *testing.T, ctx context.Context, base, repository, tag string,
	payloadBytes int64) string {
	t.Helper()
	var layer bytes.Buffer
	writer := tar.NewWriter(&layer)
	if err := writer.WriteHeader(&tar.Header{
		Name: "usr/share/owndock/oversized-fixture.bin", Mode: 0o644, Size: payloadBytes,
	}); err != nil {
		t.Fatal(err)
	}
	block := bytes.Repeat([]byte("0123456789abcdef"), 4096)
	for remaining := payloadBytes; remaining > 0; {
		chunk := int64(len(block))
		if chunk > remaining {
			chunk = remaining
		}
		if _, err := writer.Write(block[:chunk]); err != nil {
			t.Fatal(err)
		}
		remaining -= chunk
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	diffID := digestBytes(layer.Bytes())
	var compressed bytes.Buffer
	compressor, err := gzip.NewWriterLevel(&compressed, gzip.NoCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := compressor.Write(layer.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := compressor.Close(); err != nil {
		t.Fatal(err)
	}
	layerDigest := digestBytes(compressed.Bytes())
	uploadRegistryBlob(t, ctx, base, repository, layerDigest, compressed.Bytes(), nil)
	config := []byte(fmt.Sprintf(
		`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[%q]},"config":{}}`,
		diffID,
	))
	configDigest := digestBytes(config)
	uploadRegistryBlob(t, ctx, base, repository, configDigest, config, nil)
	manifest := []byte(fmt.Sprintf(
		`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":%q,"size":%d},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":%q,"size":%d}]}`,
		configDigest, len(config), layerDigest, compressed.Len(),
	))
	return putRegistryManifest(t, ctx, base, repository, tag, ociManifestMediaType, manifest, nil)
}

func waitForVault(t *testing.T, ctx context.Context, address, caPath string) *http.Client {
	t.Helper()
	var client *http.Client
	for attempt := 0; attempt < 80; attempt++ {
		ca, err := os.ReadFile(caPath)
		pool := x509.NewCertPool()
		if err == nil && pool.AppendCertsFromPEM(ca) {
			client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12, RootCAs: pool,
			}}, Timeout: 2 * time.Second}
			request, _ := http.NewRequestWithContext(ctx, http.MethodGet, address+"/v1/sys/health", nil)
			if response, requestErr := client.Do(request); requestErr == nil {
				_ = response.Body.Close()
				if response.StatusCode == http.StatusOK {
					return client
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("Vault TLS fixture did not become ready")
	return nil
}

func vaultRequest(t *testing.T, ctx context.Context, client *http.Client, method, target, body string, want int) []byte {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, method, target, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Vault-Token", "integration-root-token")
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	content, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024))
	if err != nil || response.StatusCode != want {
		t.Fatalf("Vault %s %s = %d, %v: %s", method, target, response.StatusCode, err, content)
	}
	return content
}

func readVaultTransitPublicKey(t *testing.T, ctx context.Context, client *http.Client,
	address, version string) []byte {
	t.Helper()
	content := vaultRequest(t, ctx, client, http.MethodGet,
		address+"/v1/transit/keys/release-signing-key", "", http.StatusOK)
	var response struct {
		Data struct {
			Keys map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(content, &response); err != nil ||
		!strings.HasPrefix(response.Data.Keys[version].PublicKey, "-----BEGIN PUBLIC KEY-----") {
		t.Fatalf("invalid Vault Transit public key response: %v", err)
	}
	return []byte(response.Data.Keys[version].PublicKey)
}

func removeDockerContainer(name string) {
	cleanupContext, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_ = exec.CommandContext(cleanupContext, "docker", "rm", "--force", name).Run()
}

func extractCosignExecutable(t *testing.T, ctx context.Context) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		return writeContainerizedCosignWrapper(t)
	}
	name := fmt.Sprintf("owndock-cosign-extract-%d", time.Now().UnixNano())
	runDockerCommand(t, ctx, "create", "--name", name, "--entrypoint", "/ko-app/cosign", pinnedCosignImage, "version")
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "--force", name).Run() })
	path := filepath.Join(t.TempDir(), "cosign")
	runDockerCommand(t, ctx, "cp", name+":/ko-app/cosign", path)
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func extractTrivyExecutable(t *testing.T, ctx context.Context) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		return writeContainerizedTrivyWrapper(t)
	}
	name := fmt.Sprintf("owndock-trivy-extract-%d", time.Now().UnixNano())
	runDockerCommand(t, ctx, "create", "--name", name, "--entrypoint", "/usr/local/bin/trivy",
		pinnedTrivyImage, "version")
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "--force", name).Run() })
	path := filepath.Join(t.TempDir(), "trivy")
	runDockerCommand(t, ctx, "cp", name+":/usr/local/bin/trivy", path)
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeContainerizedTrivyWrapper(t *testing.T) string {
	t.Helper()
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "trivy")
	script := fmt.Sprintf(`#!/bin/sh
remaining=$#
while [ "$remaining" -gt 0 ]; do
  argument=$1
  shift
  case "$argument" in
    127.0.0.1:*) argument="host.docker.internal:${argument#127.0.0.1:}" ;;
  esac
  set -- "$@" "$argument"
  remaining=$((remaining - 1))
done
cache_mount=''
if [ -n "${TRIVY_CACHE_DIR:-}" ]; then
  cache_mount="--volume=$TRIVY_CACHE_DIR:$TRIVY_CACHE_DIR"
fi
output=$(mktemp)
%q run --rm --add-host host.docker.internal:host-gateway \
  --volume "$HOME:$HOME" --workdir "$HOME" $cache_mount \
  --env HOME --env TRIVY_CACHE_DIR --env TRIVY_USERNAME --env TRIVY_PASSWORD \
  --entrypoint /usr/local/bin/trivy %q "$@" >"$output"
status=$?
sed 's/host\.docker\.internal:/127.0.0.1:/g' "$output"
rm -f "$output"
exit "$status"
`, docker, pinnedTrivyImage)
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeContainerizedCosignWrapper(t *testing.T) string {
	t.Helper()
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "cosign")
	script := fmt.Sprintf(`#!/bin/sh
remaining=$#
while [ "$remaining" -gt 0 ]; do
  argument=$1
  shift
  case "$argument" in
    127.0.0.1:*) argument="host.docker.internal:${argument#127.0.0.1:}" ;;
  esac
  set -- "$@" "$argument"
  remaining=$((remaining - 1))
done
case "${VAULT_ADDR:-}" in
  https://127.0.0.1:*) VAULT_ADDR="https://host.docker.internal:${VAULT_ADDR#https://127.0.0.1:}"; export VAULT_ADDR ;;
esac
vault_cacert_mount=''
if [ -n "${VAULT_CACERT:-}" ]; then
  vault_cacert_mount="--volume=$VAULT_CACERT:$VAULT_CACERT:ro"
fi
exec %q run --rm --add-host host.docker.internal:host-gateway \
  --volume "$HOME:$HOME" --volume "$PWD:$PWD" --workdir "$PWD" \
  --env HOME --env DOCKER_CONFIG --env COSIGN_PASSWORD \
  --env VAULT_ADDR --env VAULT_TOKEN --env VAULT_NAMESPACE --env VAULT_CACERT \
  $vault_cacert_mount \
  --entrypoint /ko-app/cosign %q "$@"
`, docker, pinnedCosignImage)
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func generateCosignKeyPair(t *testing.T, ctx context.Context, executable, directory string) {
	t.Helper()
	command := exec.CommandContext(ctx, executable, "generate-key-pair")
	command.Dir = directory
	command.Env = []string{"HOME=" + directory, "COSIGN_PASSWORD=integration-password"}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generate Cosign key pair: %v: %s", err, string(output))
	}
}

func TestAuthenticatedSBOMPipelineWithRealRegistry(t *testing.T) {
	if os.Getenv("OWNDOCK_RUN_SUPPLY_CHAIN_INTEGRATION") != "1" {
		t.Skip("set OWNDOCK_RUN_SUPPLY_CHAIN_INTEGRATION=1 to run the authenticated Registry integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	username := "evidence-worker"
	password := "owndock-registry-secret-sentinel"
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	authDirectory := filepath.Join(t.TempDir(), "auth")
	if err := os.Mkdir(authDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(authDirectory, "htpasswd"),
		[]byte(username+":"+string(passwordHash)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	name := "owndock-auth-evidence-registry-" + suffix
	networkName := "owndock-auth-evidence-" + suffix
	runDockerCommand(t, ctx, "network", "create", networkName)
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()
		_ = exec.CommandContext(cleanupContext, "docker", "network", "rm", networkName).Run()
	})
	runDockerCommand(t, ctx, "run", "--detach", "--name", name,
		"--network", networkName, "--publish", "127.0.0.1::5000",
		"--env", "REGISTRY_AUTH=htpasswd", "--env", "REGISTRY_AUTH_HTPASSWD_REALM=OwnDock Evidence Test",
		"--env", "REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd",
		"--volume", authDirectory+":/auth:ro", pinnedRegistryImage)
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()
		_ = exec.CommandContext(cleanupContext, "docker", "rm", "--force", name).Run()
	})
	port := strings.TrimSpace(runDockerCommand(t, ctx, "port", name, "5000/tcp"))
	base := "http://" + port
	auth := &registryTestAuth{username: username, password: password}
	waitForRegistry(t, ctx, base, auth)

	config := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"config":{}}`)
	configDigest := digestBytes(config)
	uploadRegistryBlob(t, ctx, base, "private/api", configDigest, config, auth)
	subjectManifest := []byte(fmt.Sprintf(
		`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.empty.v1+json","digest":%q,"size":%d},"layers":[]}`,
		configDigest, len(config),
	))
	subjectDigest := putRegistryManifest(
		t, ctx, base, "private/api", "subject", ociManifestMediaType, subjectManifest, auth,
	)
	syftEnvironment := map[string]string{
		"HOME":                            "/tmp",
		"SYFT_CHECK_FOR_APP_UPDATE":       "false",
		"SYFT_LOG_QUIET":                  "true",
		"SYFT_REGISTRY_INSECURE_USE_HTTP": "true",
		"SYFT_REGISTRY_AUTH_AUTHORITY":    name + ":5000",
		"SYFT_REGISTRY_AUTH_USERNAME":     username,
		"SYFT_REGISTRY_AUTH_PASSWORD":     password,
	}
	syftArguments := []string{
		"run", "--rm", "--network", networkName, "--user", "65532:65532", "--read-only",
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=536870912,mode=1777",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
		"--pids-limit", "128", "--memory", "1g", "--cpus", "1",
	}
	for _, name := range []string{
		"HOME", "SYFT_CHECK_FOR_APP_UPDATE", "SYFT_LOG_QUIET",
		"SYFT_REGISTRY_INSECURE_USE_HTTP", "SYFT_REGISTRY_AUTH_AUTHORITY",
		"SYFT_REGISTRY_AUTH_USERNAME", "SYFT_REGISTRY_AUTH_PASSWORD",
	} {
		syftArguments = append(syftArguments, "--env", name)
	}
	syftArguments = append(syftArguments, pinnedSyftImage, "scan",
		"registry:"+name+":5000/private/api@"+subjectDigest, "-o", "cyclonedx-json@1.6")
	syftOutput, syftError, err := runDockerCapture(ctx, syftEnvironment, syftArguments...)
	if err != nil {
		t.Fatalf("authenticated Syft failed: %v: %s", err, redactTestSecret(syftError, password))
	}
	document, err := biz.NewCycloneDX16Document(syftOutput, 16*1024*1024)
	if err != nil {
		t.Fatalf("authenticated Syft document: %v", err)
	}
	assertSecretAbsent(t, password, syftOutput, syftError)

	publisherCredentials := &credentialCaptureProvider{username: username, password: password}
	publisher, err := NewORASPublisher(ORASPublisherOptions{
		AllowPlainHTTP: true, MaxDocumentBytes: 16 * 1024 * 1024,
		Credentials: publisherCredentials,
	})
	if err != nil {
		t.Fatal(err)
	}
	published, err := publisher.PublishSBOM(ctx, biz.SBOMPublication{
		ProjectID: "project-1", RegistryCredentialID: "registry-1",
		RegistryRepository: strings.TrimPrefix(base, "http://") + "/private/api",
		SubjectDigest:      subjectDigest, Document: document, CreatedAt: time.Unix(100, 0),
	})
	if err != nil {
		t.Fatalf("authenticated ORAS publication failed: %v", err)
	}
	if !publisherCredentials.cleared() {
		t.Fatal("ORAS publisher did not clear its mutable Registry password")
	}
	privateRepository := strings.TrimPrefix(base, "http://") + "/private/api"
	probeCredentials := &credentialCaptureProvider{username: username, password: password}
	artifactProber := mustNewOCIArtifactProber(t, OCIArtifactProberOptions{
		Credentials: probeCredentials, AllowPlainHTTP: true,
	})
	if err := artifactProber.ProbeArtifact(
		ctx, "project-1", "registry-1", privateRepository, subjectDigest,
	); err != nil {
		t.Fatalf("authenticated external Artifact probe failed: %v", err)
	}
	if !probeCredentials.cleared() {
		t.Fatal("external Artifact prober did not clear its mutable Registry password")
	}
	badProbeCredentials := &credentialCaptureProvider{username: username, password: "incorrect-secret-sentinel"}
	badArtifactProber := mustNewOCIArtifactProber(t, OCIArtifactProberOptions{
		Credentials: badProbeCredentials, AllowPlainHTTP: true,
	})
	if err := badArtifactProber.ProbeArtifact(
		ctx, "project-1", "registry-1", privateRepository, subjectDigest,
	); !errors.Is(err, buildbiz.ErrArtifactRegistryAuthentication) ||
		strings.Contains(err.Error(), badProbeCredentials.password) {
		t.Fatalf("wrong external Artifact Registry credential error = %v", err)
	}
	if !badProbeCredentials.cleared() {
		t.Fatal("external Artifact prober did not clear rejected Registry password")
	}
	provenancePublication := provenancePublicationFixture(t, privateRepository, subjectDigest)
	publishedProvenance, err := publisher.PublishProvenance(ctx, provenancePublication)
	if err != nil {
		t.Fatalf("authenticated provenance publication failed: %v", err)
	}
	if !publisherCredentials.cleared() {
		t.Fatal("ORAS publisher did not clear its mutable Registry password after provenance")
	}
	readerCredentials := &credentialCaptureProvider{username: username, password: password}
	reader, err := NewOCIContentReader(OCIContentReaderOptions{
		AllowPlainHTTP: true, MaxDocumentBytes: 16 * 1024 * 1024,
		Credentials: readerCredentials,
	})
	if err != nil {
		t.Fatal(err)
	}
	subject := biz.ArtifactSubject{
		ID: "artifact-1", OrganizationID: "organization-1", ProjectID: "project-1",
		SubjectDigest: subjectDigest, RegistryRepository: privateRepository,
		RegistryCredentialID: "registry-1",
	}
	provenanceEvidence, err := biz.NewEvidence(biz.EvidenceInput{
		ID: "provenance-1", OrganizationID: subject.OrganizationID, ProjectID: subject.ProjectID,
		ArtifactID: subject.ID, SubjectDigest: subjectDigest, Kind: biz.EvidenceKindProvenance,
		MediaType: biz.SLSAProvenanceMediaType, FormatVersion: biz.SLSAProvenanceFormatVersion,
		PredicateType: biz.SLSAProvenancePredicateV1, Producer: "owndock-build-worker/0.1.0",
		RegistryRepository: privateRepository, DescriptorDigest: publishedProvenance.Digest,
		VerificationStatus: biz.VerificationUnverified, CreatedAt: time.Unix(200, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	downloaded, err := reader.ReadEvidence(ctx, subject, provenanceEvidence)
	if err != nil || !bytes.Equal(downloaded.Content, provenancePublication.Document.Content) {
		t.Fatalf("authenticated provenance download = %+v, %v", downloaded, err)
	}
	if !readerCredentials.cleared() {
		t.Fatal("OCI content reader did not clear its mutable Registry password")
	}
	badReaderCredentials := &credentialCaptureProvider{username: username, password: "incorrect-secret-sentinel"}
	badReader, _ := NewOCIContentReader(OCIContentReaderOptions{
		AllowPlainHTTP: true, MaxDocumentBytes: 16 * 1024 * 1024,
		Credentials: badReaderCredentials,
	})
	if _, err := badReader.ReadEvidence(ctx, subject, provenanceEvidence); !errors.Is(err, biz.ErrRegistryAuthentication) || strings.Contains(err.Error(), badReaderCredentials.password) {
		t.Fatalf("wrong download credential error = %v", err)
	}
	if !badReaderCredentials.cleared() {
		t.Fatal("OCI content reader did not clear rejected Registry password")
	}
	client, err := NewOCIReferrerClient(OCIReferrerClientOptions{
		AllowPlainHTTP: true,
		Transport: basicAuthRoundTripper{
			base: http.DefaultTransport, username: username, password: password,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	capability, err := client.Probe(
		ctx, strings.TrimPrefix(base, "http://")+"/private/api", subjectDigest,
	)
	if err != nil || !capability.Supported || capability.Count != 2 {
		t.Fatalf("authenticated Referrer Probe() = %+v, %v", capability, err)
	}
	assertRegistryEvidenceSecretFree(t, ctx, base, "private/api", published.Digest, auth, password)
	assertRegistryEvidenceSecretFree(t, ctx, base, "private/api", publishedProvenance.Digest, auth, password)
	badSyftEnvironment := make(map[string]string, len(syftEnvironment))
	for key, value := range syftEnvironment {
		badSyftEnvironment[key] = value
	}
	badPassword := "incorrect-secret-sentinel"
	badSyftEnvironment["SYFT_REGISTRY_AUTH_PASSWORD"] = badPassword
	badOutput, badError, badSyftErr := runDockerCapture(ctx, badSyftEnvironment, syftArguments...)
	if badSyftErr == nil {
		t.Fatal("Syft accepted an incorrect Registry password")
	}
	assertSecretAbsent(t, password, badOutput, badError)
	assertSecretAbsent(t, badPassword, badOutput, badError)

	badPublisher, _ := NewORASPublisher(ORASPublisherOptions{
		AllowPlainHTTP: true, MaxDocumentBytes: 16 * 1024 * 1024,
		Credentials: registryCredentialProviderProbe{credential: biz.RegistryCredential{
			AuthenticationMode: registryauth.ModeBasic,
			Username:           username, Password: []byte("incorrect-secret-sentinel"),
		}},
	})
	if _, err := badPublisher.PublishSBOM(ctx, biz.SBOMPublication{
		ProjectID: "project-1", RegistryCredentialID: "registry-1",
		RegistryRepository: strings.TrimPrefix(base, "http://") + "/private/api",
		SubjectDigest:      subjectDigest, Document: document, CreatedAt: time.Unix(101, 0),
	}); !errors.Is(err, biz.ErrRegistryAuthentication) {
		t.Fatalf("wrong Registry credential error = %v", err)
	}

	registryLogs := []byte(runDockerCommand(t, ctx, "logs", name))
	assertSecretAbsent(t, password, registryLogs)
}

func runDockerCommand(t *testing.T, ctx context.Context, arguments ...string) string {
	t.Helper()
	command := exec.CommandContext(ctx, "docker", arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v: %s", strings.Join(arguments, " "), err, output)
	}
	return string(output)
}

func runDockerStdout(t *testing.T, ctx context.Context, arguments ...string) []byte {
	t.Helper()
	command := exec.CommandContext(ctx, "docker", arguments...)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		detail := stderr.String()
		if len(detail) > 4096 {
			detail = detail[:4096]
		}
		t.Fatalf("docker %s: %v: %s", strings.Join(arguments, " "), err, detail)
	}
	return stdout.Bytes()
}

func runDockerCapture(
	ctx context.Context,
	environment map[string]string,
	arguments ...string,
) ([]byte, []byte, error) {
	command := exec.CommandContext(ctx, "docker", arguments...)
	values := os.Environ()
	for key, value := range environment {
		filtered := values[:0]
		prefix := key + "="
		for _, current := range values {
			if !strings.HasPrefix(current, prefix) {
				filtered = append(filtered, current)
			}
		}
		values = append(filtered, key+"="+value)
	}
	command.Env = values
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

type registryTestAuth struct {
	username string
	password string
}

func (a *registryTestAuth) apply(request *http.Request) {
	if a != nil {
		request.SetBasicAuth(a.username, a.password)
	}
}

type basicAuthRoundTripper struct {
	base               http.RoundTripper
	username, password string
}

func (t basicAuthRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.Header = request.Header.Clone()
	clone.SetBasicAuth(t.username, t.password)
	return t.base.RoundTrip(clone)
}

func waitForRegistry(t *testing.T, ctx context.Context, base string, auth *registryTestAuth) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v2/", nil)
		auth.apply(request)
		response, err := http.DefaultClient.Do(request)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("OCI Registry did not become ready")
}

func uploadRegistryBlob(
	t *testing.T,
	ctx context.Context,
	base, repository, blobDigest string,
	body []byte,
	auth *registryTestAuth,
) {
	t.Helper()
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		base+"/v2/"+repository+"/blobs/uploads/", nil)
	auth.apply(request)
	response, err := http.DefaultClient.Do(request)
	if err != nil || response.StatusCode != http.StatusAccepted {
		if response != nil {
			_ = response.Body.Close()
		}
		t.Fatalf("start Registry blob upload: status=%v error=%v", responseStatus(response), err)
	}
	location := response.Header.Get("Location")
	_ = response.Body.Close()
	parsedLocation, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse Registry upload location: %v", err)
	}
	if !parsedLocation.IsAbs() {
		parsedBase, _ := url.Parse(base)
		parsedLocation = parsedBase.ResolveReference(parsedLocation)
	}
	query := parsedLocation.Query()
	query.Set("digest", blobDigest)
	parsedLocation.RawQuery = query.Encode()
	request, _ = http.NewRequestWithContext(ctx, http.MethodPut, parsedLocation.String(), bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/octet-stream")
	auth.apply(request)
	response, err = http.DefaultClient.Do(request)
	if err != nil || response.StatusCode != http.StatusCreated {
		if response != nil {
			_ = response.Body.Close()
		}
		t.Fatalf("complete Registry blob upload: status=%v error=%v", responseStatus(response), err)
	}
	_ = response.Body.Close()
}

const ociManifestMediaType = "application/vnd.oci.image.manifest.v1+json"

func putRegistryManifest(
	t *testing.T,
	ctx context.Context,
	base, repository, manifestReference, mediaType string,
	body []byte,
	auth *registryTestAuth,
) string {
	t.Helper()
	request, _ := http.NewRequestWithContext(ctx, http.MethodPut,
		base+"/v2/"+repository+"/manifests/"+manifestReference, bytes.NewReader(body))
	request.Header.Set("Content-Type", mediaType)
	auth.apply(request)
	response, err := http.DefaultClient.Do(request)
	if err != nil || response.StatusCode != http.StatusCreated {
		var detail []byte
		if response != nil {
			detail, _ = io.ReadAll(io.LimitReader(response.Body, 4096))
			_ = response.Body.Close()
		}
		t.Fatalf("put Registry manifest: status=%v error=%v detail=%s", responseStatus(response), err, detail)
	}
	defer response.Body.Close()
	digest := response.Header.Get("Docker-Content-Digest")
	if digest == "" {
		t.Fatal("Registry manifest response omitted Docker-Content-Digest")
	}
	return digest
}

func assertRegistryEvidenceSecretFree(
	t *testing.T,
	ctx context.Context,
	base, repository, manifestDigest string,
	auth *registryTestAuth,
	secret string,
) {
	t.Helper()
	manifest := getRegistryBody(t, ctx,
		base+"/v2/"+repository+"/manifests/"+manifestDigest, ociManifestMediaType, auth)
	assertSecretAbsent(t, secret, manifest)
	var document struct {
		Layers []struct {
			Digest string `json:"digest"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(manifest, &document); err != nil || len(document.Layers) != 1 {
		t.Fatalf("decode published Evidence manifest: %v", err)
	}
	blob := getRegistryBody(t, ctx,
		base+"/v2/"+repository+"/blobs/"+document.Layers[0].Digest,
		"application/octet-stream", auth)
	assertSecretAbsent(t, secret, blob)
}

func getRegistryBody(
	t *testing.T,
	ctx context.Context,
	endpoint, accept string,
	auth *registryTestAuth,
) []byte {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Accept", accept)
	auth.apply(request)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 16*1024*1024+1))
	if readErr != nil || response.StatusCode != http.StatusOK || len(body) > 16*1024*1024 {
		t.Fatalf("read Registry evidence: status=%d bytes=%d error=%v", response.StatusCode, len(body), readErr)
	}
	return body
}

func assertSecretAbsent(t *testing.T, secret string, values ...[]byte) {
	t.Helper()
	for _, value := range values {
		if bytes.Contains(value, []byte(secret)) {
			t.Fatal("secret sentinel leaked into an Evidence pipeline output")
		}
	}
}

func redactTestSecret(value []byte, secret string) string {
	redacted := strings.ReplaceAll(string(value), secret, "[REDACTED]")
	if len(redacted) > 4096 {
		return redacted[:4096]
	}
	return redacted
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func responseStatus(response *http.Response) any {
	if response == nil {
		return nil
	}
	return response.StatusCode
}
