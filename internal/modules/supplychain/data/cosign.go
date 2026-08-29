package data

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/distribution/reference"
	"github.com/owndock/owndock/internal/modules/supplychain/biz"
)

const PinnedCosignVersion = "3.0.6"

type CosignVerifierOptions struct {
	Executable      string
	ExpectedVersion string
	Credentials     biz.RegistryCredentialProvider
	TemporaryRoot   string
	AllowPlainHTTP  bool
}

type CosignVerifier struct {
	executable      string
	expectedVersion string
	credentials     biz.RegistryCredentialProvider
	temporaryRoot   string
	allowPlainHTTP  bool
}

func NewCosignVerifier(options CosignVerifierOptions) (*CosignVerifier, error) {
	executable := strings.TrimSpace(options.Executable)
	version := strings.TrimPrefix(strings.TrimSpace(options.ExpectedVersion), "v")
	temporaryRoot := strings.TrimSpace(options.TemporaryRoot)
	if !filepath.IsAbs(executable) || version != PinnedCosignVersion ||
		options.Credentials == nil || !filepath.IsAbs(temporaryRoot) {
		return nil, biz.ErrSignatureToolVersion
	}
	return &CosignVerifier{
		executable: executable, expectedVersion: version,
		credentials: options.Credentials, temporaryRoot: temporaryRoot,
		allowPlainHTTP: options.AllowPlainHTTP,
	}, nil
}

func (v *CosignVerifier) Verify(ctx context.Context) error {
	command := exec.CommandContext(ctx, v.executable, "version", "--json")
	command.Env = cosignEnvironment(v.temporaryRoot, "")
	output := &boundedBuffer{maximum: 64 * 1024}
	command.Stdout, command.Stderr = output, &boundedBuffer{maximum: 4096}
	if err := command.Run(); err != nil {
		return biz.ErrSignatureToolVersion
	}
	var result struct {
		GitVersion string `json:"gitVersion"`
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil ||
		strings.TrimPrefix(strings.TrimSpace(result.GitVersion), "v") != v.expectedVersion {
		return biz.ErrSignatureToolVersion
	}
	return nil
}

func (v *CosignVerifier) VerifySignature(ctx context.Context,
	request biz.SignatureVerificationRequest) (biz.SignatureVerificationResult, error) {
	if err := request.Validate(); err != nil {
		return biz.SignatureVerificationResult{}, err
	}
	named, _ := reference.ParseNormalizedNamed(request.RegistryRepository)
	registry := reference.Domain(named)
	if v.allowPlainHTTP {
		if !loopbackRegistry(registry) {
			return biz.SignatureVerificationResult{}, biz.ErrInvalidSignatureTrust
		}
	}
	credential, err := v.credentials.ResolveRegistryCredential(
		ctx, request.ProjectID, request.RegistryCredentialID, registry,
	)
	if err != nil || !validCosignCredential(credential) {
		clear(credential.Password)
		return biz.SignatureVerificationResult{}, biz.ErrRegistryAuthentication
	}
	defer clear(credential.Password)

	directory, err := os.MkdirTemp(v.temporaryRoot, ".owndock-cosign-")
	if err != nil {
		return biz.SignatureVerificationResult{}, biz.ErrSignatureVerification
	}
	defer os.RemoveAll(directory)
	if err := os.Chmod(directory, 0o700); err != nil {
		return biz.SignatureVerificationResult{}, biz.ErrSignatureVerification
	}
	dockerDirectory := filepath.Join(directory, "docker")
	if err := os.Mkdir(dockerDirectory, 0o700); err != nil {
		return biz.SignatureVerificationResult{}, biz.ErrSignatureVerification
	}
	if err := writeDockerCredential(filepath.Join(dockerDirectory, "config.json"), registry, credential); err != nil {
		return biz.SignatureVerificationResult{}, biz.ErrSignatureVerification
	}

	arguments := []string{"verify", "--output=json", "--max-workers=1", "--new-bundle-format=true"}
	if v.allowPlainHTTP {
		arguments = append(arguments, "--allow-http-registry")
	}
	result := biz.SignatureVerificationResult{
		TrustMode: request.Trust.Mode, SignerIdentity: request.Trust.CertificateIdentity,
		OIDCIssuer: request.Trust.OIDCIssuer, VerifierVersion: v.expectedVersion,
	}
	switch request.Trust.Mode {
	case biz.SignatureTrustPublicKey:
		canonicalKey, fingerprint, parseErr := biz.NormalizeSignaturePublicKey(request.Trust.PublicKeyPEM)
		if parseErr != nil {
			return biz.SignatureVerificationResult{}, biz.ErrInvalidSignatureTrust
		}
		trustFile := filepath.Join(directory, "cosign.pub")
		if err := os.WriteFile(trustFile, canonicalKey, 0o600); err != nil {
			return biz.SignatureVerificationResult{}, biz.ErrSignatureVerification
		}
		arguments = append(arguments, "--key", trustFile, "--insecure-ignore-tlog")
		result.TrustRootHash = fingerprint
	case biz.SignatureTrustKeyless:
		trustFile := filepath.Join(directory, "trusted-root.json")
		if err := os.WriteFile(trustFile, request.Trust.TrustedRootJSON, 0o600); err != nil {
			return biz.SignatureVerificationResult{}, biz.ErrSignatureVerification
		}
		arguments = append(arguments,
			"--trusted-root", trustFile,
			"--certificate-identity", request.Trust.CertificateIdentity,
			"--certificate-oidc-issuer", request.Trust.OIDCIssuer,
		)
		result.TrustRootHash = request.Trust.Fingerprint()
	default:
		return biz.SignatureVerificationResult{}, biz.ErrInvalidSignatureTrust
	}
	arguments = append(arguments, request.CanonicalSubject())
	command := exec.CommandContext(ctx, v.executable, arguments...)
	command.Env = cosignEnvironment(directory, dockerDirectory)
	output := &boundedBuffer{maximum: 1024 * 1024}
	command.Stdout, command.Stderr = output, &boundedBuffer{maximum: 16 * 1024}
	if err := command.Run(); err != nil {
		command.Env = nil
		if ctx.Err() != nil {
			return biz.SignatureVerificationResult{}, ctx.Err()
		}
		return biz.SignatureVerificationResult{}, biz.ErrSignatureVerification
	}
	command.Env = nil
	bundleSetDigest, err := verifiedBundleSetDigest(output.Bytes())
	if err != nil {
		return biz.SignatureVerificationResult{}, biz.ErrSignatureVerification
	}
	result.BundleSetDigest = bundleSetDigest
	return result, nil
}

func verifiedBundleSetDigest(output []byte) (string, error) {
	var verified []any
	if err := json.Unmarshal(output, &verified); err != nil || len(verified) == 0 || len(verified) > 256 {
		return "", biz.ErrSignatureVerification
	}
	canonical, err := json.Marshal(verified)
	if err != nil {
		return "", biz.ErrSignatureVerification
	}
	digest := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func validCosignCredential(value biz.RegistryCredential) bool {
	username := strings.TrimSpace(value.Username)
	return username != "" && username == value.Username && len(username) <= 255 &&
		!strings.ContainsAny(username, ":\r\n\x00") && len(value.Password) > 0 && len(value.Password) <= 64*1024
}

func writeDockerCredential(path, registry string, credential biz.RegistryCredential) error {
	auth := base64.StdEncoding.EncodeToString(append([]byte(credential.Username+":"), credential.Password...))
	defer func() { auth = "" }()
	content, err := json.Marshal(struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
	}{Auths: map[string]struct {
		Auth string `json:"auth"`
	}{registry: {Auth: auth}}})
	if err != nil {
		return err
	}
	defer clear(content)
	return os.WriteFile(path, content, 0o600)
}

func cosignEnvironment(home, dockerConfig string) []string {
	result := []string{
		"HOME=" + home,
		"COSIGN_YES=false",
		"COSIGN_EXPERIMENTAL=0",
		"SIGSTORE_NO_CACHE=true",
	}
	if dockerConfig != "" {
		result = append(result, "DOCKER_CONFIG="+dockerConfig)
	}
	return result
}

var _ biz.SignatureVerifier = (*CosignVerifier)(nil)
