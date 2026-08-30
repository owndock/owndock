package data

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/owndock/owndock/internal/modules/supplychain/biz"
	"github.com/owndock/owndock/internal/shared/registryauth"
)

func TestCosignVerifierUsesPinnedBinaryExactDigestAndTemporaryDockerCredential(t *testing.T) {
	directory := t.TempDir()
	capture := filepath.Join(directory, "arguments")
	executable := writeCosignFixture(t, directory, capture, "v3.0.6", true)
	credentials := &credentialCaptureProvider{username: "signer", password: "registry-secret-sentinel"}
	verifier, err := NewCosignVerifier(CosignVerifierOptions{
		Executable: executable, ExpectedVersion: "3.0.6",
		Credentials: credentials, TemporaryRoot: directory,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(t.Context()); err != nil {
		t.Fatalf("Verify() = %v", err)
	}
	request := signatureVerificationFixture(t)
	result, err := verifier.VerifySignature(t.Context(), request)
	if err != nil || result.TrustMode != biz.SignatureTrustPublicKey ||
		!strings.HasPrefix(result.TrustRootHash, "sha256:") || result.SignerIdentity != "" {
		t.Fatalf("VerifySignature() = %+v, %v", result, err)
	}
	arguments, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	argumentText := string(arguments)
	for _, expected := range []string{
		"verify", "--output=json", "--max-workers=1", "--new-bundle-format=true", "--key", "--insecure-ignore-tlog",
		request.RegistryRepository + "@" + request.SubjectDigest,
	} {
		if !strings.Contains(argumentText, expected) {
			t.Fatalf("cosign arguments are missing %q:\n%s", expected, argumentText)
		}
	}
	if strings.Contains(argumentText, credentials.password) || !credentials.cleared() {
		t.Fatal("Registry password leaked in arguments or remained in the provider buffer")
	}
	dockerConfig, err := os.ReadFile(capture + ".docker-config")
	if err != nil || !strings.Contains(string(dockerConfig), "auth") ||
		strings.Contains(string(dockerConfig), credentials.password) {
		t.Fatalf("temporary Docker auth config is invalid: %v %s", err, dockerConfig)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".owndock-cosign-") {
			t.Fatalf("temporary trust/credential directory was retained: %s", entry.Name())
		}
	}
}

func TestAnonymousRegistryCredentialCreatesNoDockerAuthentication(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	credential := biz.RegistryCredential{AuthenticationMode: registryauth.ModeAnonymous}
	if !validCosignCredential(credential) {
		t.Fatal("anonymous Registry credential was rejected")
	}
	if err := writeDockerCredential(path, "registry.example.com", credential); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != `{"auths":{}}` {
		t.Fatalf("anonymous Docker config = %s", content)
	}
}

func TestCosignVerifierRequiresExactKeylessIdentityAndOfflineRoot(t *testing.T) {
	directory := t.TempDir()
	capture := filepath.Join(directory, "arguments")
	executable := writeCosignFixture(t, directory, capture, "v3.0.6", true)
	verifier, err := NewCosignVerifier(CosignVerifierOptions{
		Executable: executable, ExpectedVersion: "v3.0.6",
		Credentials:   &credentialCaptureProvider{username: "signer", password: "password"},
		TemporaryRoot: directory,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := signatureVerificationFixture(t)
	request.Trust = biz.SignatureTrustMaterial{
		Mode:                biz.SignatureTrustKeyless,
		TrustedRootJSON:     []byte(`{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1","certificateAuthorities":[]}`),
		CertificateIdentity: "https://github.com/owndock/owndock/.github/workflows/release.yml@refs/tags/v1.0.0",
		OIDCIssuer:          "https://token.actions.githubusercontent.com",
	}
	result, err := verifier.VerifySignature(t.Context(), request)
	if err != nil || result.SignerIdentity != request.Trust.CertificateIdentity ||
		result.OIDCIssuer != request.Trust.OIDCIssuer {
		t.Fatalf("keyless VerifySignature() = %+v, %v", result, err)
	}
	arguments, _ := os.ReadFile(capture)
	for _, expected := range []string{
		"--trusted-root", "--certificate-identity", request.Trust.CertificateIdentity,
		"--certificate-oidc-issuer", request.Trust.OIDCIssuer,
	} {
		if !strings.Contains(string(arguments), expected) {
			t.Fatalf("keyless arguments are missing %q:\n%s", expected, arguments)
		}
	}
	if strings.Contains(string(arguments), "--insecure-ignore-tlog") {
		t.Fatalf("keyless verification must validate transparency material: %s", arguments)
	}
}

func TestCosignVerifierFailsClosed(t *testing.T) {
	directory := t.TempDir()
	for name, testCase := range map[string]struct {
		version string
		succeed bool
		want    error
	}{
		"version mismatch":   {version: "v3.0.5", succeed: true, want: biz.ErrSignatureToolVersion},
		"signature rejected": {version: "v3.0.6", succeed: false, want: biz.ErrSignatureVerification},
	} {
		t.Run(name, func(t *testing.T) {
			executable := writeCosignFixture(t, directory, filepath.Join(directory, name+"-arguments"),
				testCase.version, testCase.succeed)
			verifier, err := NewCosignVerifier(CosignVerifierOptions{
				Executable: executable, ExpectedVersion: "3.0.6",
				Credentials:   &credentialCaptureProvider{username: "signer", password: "password"},
				TemporaryRoot: directory,
			})
			if err != nil {
				t.Fatal(err)
			}
			if testCase.want == biz.ErrSignatureToolVersion {
				err = verifier.Verify(t.Context())
			} else {
				_, err = verifier.VerifySignature(t.Context(), signatureVerificationFixture(t))
			}
			if !errors.Is(err, testCase.want) {
				t.Fatalf("error = %v, want %v", err, testCase.want)
			}
		})
	}
}

func TestVerifiedBundleSetDigestIsCanonicalAndBounded(t *testing.T) {
	first, err := verifiedBundleSetDigest([]byte(`[
		{"optional":{"z":2,"a":1},"critical":{"identity":{"docker-reference":"registry.example.com/team/api"}}}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	second, err := verifiedBundleSetDigest([]byte(
		`[{"critical":{"identity":{"docker-reference":"registry.example.com/team/api"}},"optional":{"a":1,"z":2}}]`))
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("semantically identical Cosign results produced different digests: %s != %s", first, second)
	}
	if _, err := verifiedBundleSetDigest([]byte(`[]`)); !errors.Is(err, biz.ErrSignatureVerification) {
		t.Fatalf("empty result error = %v", err)
	}
}

func signatureVerificationFixture(t *testing.T) biz.SignatureVerificationRequest {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return biz.SignatureVerificationRequest{
		ProjectID: "project-1", RegistryCredentialID: "registry-1",
		RegistryRepository: "registry.example.com/team/api",
		SubjectDigest:      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Trust: biz.SignatureTrustMaterial{Mode: biz.SignatureTrustPublicKey,
			PublicKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})},
	}
}

func writeCosignFixture(t *testing.T, directory, capture, version string, succeed bool) string {
	t.Helper()
	executable := filepath.Join(directory, "cosign-"+strings.ReplaceAll(strings.TrimPrefix(version, "v"), ".", "-")+
		"-"+strings.ReplaceAll(filepath.Base(capture), " ", "-"))
	exit := "0"
	output := `[{"critical":{"image":{"docker-manifest-digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}]`
	if !succeed {
		exit, output = "7", ""
	}
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = version ]; then printf '%s\\n' '{\"gitVersion\":\"" + version + "\"}'; exit 0; fi\n" +
		"printf '%s\\n' \"$@\" > '" + capture + "'\n" +
		"cp \"$DOCKER_CONFIG/config.json\" '" + capture + ".docker-config'\n" +
		"printf '%s\\n' '" + output + "'\nexit " + exit + "\n"
	if err := os.WriteFile(executable, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return executable
}
