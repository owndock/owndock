package data

import (
	"context"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/distribution/reference"
	"github.com/owndock/owndock/internal/modules/supplychain/biz"
)

const offlineCosignSigningConfig = `{"mediaType":"application/vnd.dev.sigstore.signingconfig.v0.2+json","rekorTlogConfig":{},"tsaConfig":{}}`

type CosignSignerOptions struct {
	Executable         string
	ExpectedVersion    string
	Credentials        biz.RegistryCredentialProvider
	SigningEnvironment biz.SigningEnvironmentResolver
	TemporaryRoot      string
	AllowPlainHTTP     bool
}

type CosignSigner struct {
	executable      string
	expectedVersion string
	credentials     biz.RegistryCredentialProvider
	environment     biz.SigningEnvironmentResolver
	temporaryRoot   string
	allowPlainHTTP  bool
}

func NewCosignSigner(options CosignSignerOptions) (*CosignSigner, error) {
	executable, version := strings.TrimSpace(options.Executable), strings.TrimPrefix(strings.TrimSpace(options.ExpectedVersion), "v")
	root := strings.TrimSpace(options.TemporaryRoot)
	if !filepath.IsAbs(executable) || version != PinnedCosignVersion || options.Credentials == nil ||
		options.SigningEnvironment == nil || !filepath.IsAbs(root) {
		return nil, biz.ErrSignatureToolVersion
	}
	return &CosignSigner{executable: executable, expectedVersion: version,
		credentials: options.Credentials, environment: options.SigningEnvironment, temporaryRoot: root,
		allowPlainHTTP: options.AllowPlainHTTP}, nil
}

func (s *CosignSigner) SignSignature(ctx context.Context,
	request biz.SignatureSigningRequest) (biz.SignatureSigningResult, error) {
	provider, err := request.Validate()
	if err != nil {
		return biz.SignatureSigningResult{}, err
	}
	named, _ := reference.ParseNormalizedNamed(request.RegistryRepository)
	registry := reference.Domain(named)
	if s.allowPlainHTTP && !loopbackRegistry(registry) {
		return biz.SignatureSigningResult{}, biz.ErrInvalidSigningKey
	}
	credential, err := s.credentials.ResolveRegistryCredential(ctx, request.ProjectID,
		request.RegistryCredentialID, registry)
	if err != nil || !validCosignCredential(credential) {
		clear(credential.Password)
		return biz.SignatureSigningResult{}, biz.ErrRegistryAuthentication
	}
	defer clear(credential.Password)
	providerEnvironment, err := s.environment.ResolveSigningEnvironment(ctx, request.ProjectID, request.ProfileID, provider)
	if err != nil || !validSigningEnvironment(provider, providerEnvironment) {
		clearSigningEnvironment(providerEnvironment)
		return biz.SignatureSigningResult{}, biz.ErrSignatureSigning
	}
	defer clearSigningEnvironment(providerEnvironment)
	directory, err := os.MkdirTemp(s.temporaryRoot, ".owndock-cosign-sign-")
	if err != nil {
		return biz.SignatureSigningResult{}, biz.ErrSignatureSigning
	}
	defer os.RemoveAll(directory)
	dockerDirectory := filepath.Join(directory, "docker")
	if err := os.Mkdir(dockerDirectory, 0o700); err != nil {
		return biz.SignatureSigningResult{}, biz.ErrSignatureSigning
	}
	if err := writeDockerCredential(filepath.Join(dockerDirectory, "config.json"), registry, credential); err != nil {
		return biz.SignatureSigningResult{}, biz.ErrSignatureSigning
	}
	signingConfig := filepath.Join(directory, "signing-config.json")
	if err := os.WriteFile(signingConfig, []byte(offlineCosignSigningConfig), 0o600); err != nil {
		return biz.SignatureSigningResult{}, biz.ErrSignatureSigning
	}
	environment := cosignEnvironment(directory, dockerDirectory)
	keys := make([]string, 0, len(providerEnvironment))
	for key := range providerEnvironment {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		environment = append(environment, key+"="+string(providerEnvironment[key]))
	}
	arguments := []string{"sign", "--yes", "--new-bundle-format=true", "--signing-config", signingConfig,
		"--key", strings.TrimSpace(request.KeyReference)}
	if s.allowPlainHTTP {
		arguments = append(arguments, "--allow-http-registry")
	}
	arguments = append(arguments, request.CanonicalSubject())
	command := exec.CommandContext(ctx, s.executable, arguments...)
	command.Env = environment
	command.Stdout, command.Stderr = &boundedBuffer{maximum: 64 * 1024}, &boundedBuffer{maximum: 16 * 1024}
	if err := command.Run(); err != nil {
		command.Env = nil
		if ctx.Err() != nil {
			return biz.SignatureSigningResult{}, ctx.Err()
		}
		return biz.SignatureSigningResult{}, biz.ErrSignatureSigning
	}
	command.Env = nil
	return biz.SignatureSigningResult{Provider: provider,
		KeyReferenceFingerprint: biz.SigningKeyReferenceFingerprint(request.KeyReference)}, nil
}

func validSigningEnvironment(provider biz.SigningKeyProvider, values map[string][]byte) bool {
	allowed := map[biz.SigningKeyProvider]map[string]bool{
		biz.SigningKeyAWSKMS: {"AWS_ACCESS_KEY_ID": true, "AWS_SECRET_ACCESS_KEY": true, "AWS_SESSION_TOKEN": true,
			"AWS_REGION": true, "AWS_DEFAULT_REGION": true, "AWS_ROLE_ARN": true, "AWS_WEB_IDENTITY_TOKEN_FILE": true},
		biz.SigningKeyGCPKMS: {"GOOGLE_APPLICATION_CREDENTIALS": true},
		biz.SigningKeyAzureKMS: {"AZURE_TENANT_ID": true, "AZURE_CLIENT_ID": true, "AZURE_CLIENT_SECRET": true,
			"AZURE_FEDERATED_TOKEN_FILE": true},
		biz.SigningKeyVault:      {"VAULT_ADDR": true, "VAULT_TOKEN": true, "VAULT_NAMESPACE": true, "VAULT_CACERT": true},
		biz.SigningKeyKubernetes: {"KUBECONFIG": true},
	}[provider]
	if allowed == nil || len(values) > len(allowed) {
		return false
	}
	for key, value := range values {
		if !allowed[key] || len(value) == 0 || len(value) > 64*1024 || strings.ContainsAny(string(value), "\x00\r\n") {
			return false
		}
	}
	switch provider {
	case biz.SigningKeyAWSKMS:
		static := len(values["AWS_ACCESS_KEY_ID"]) > 0 && len(values["AWS_SECRET_ACCESS_KEY"]) > 0
		federated := len(values["AWS_ROLE_ARN"]) > 0 && absoluteCredentialFile(values["AWS_WEB_IDENTITY_TOKEN_FILE"])
		return (static || federated) && (len(values["AWS_REGION"]) > 0 || len(values["AWS_DEFAULT_REGION"]) > 0)
	case biz.SigningKeyGCPKMS:
		return absoluteCredentialFile(values["GOOGLE_APPLICATION_CREDENTIALS"])
	case biz.SigningKeyAzureKMS:
		return len(values["AZURE_TENANT_ID"]) > 0 && len(values["AZURE_CLIENT_ID"]) > 0 &&
			(len(values["AZURE_CLIENT_SECRET"]) > 0 || absoluteCredentialFile(values["AZURE_FEDERATED_TOKEN_FILE"]))
	case biz.SigningKeyVault:
		address, err := url.Parse(string(values["VAULT_ADDR"]))
		return err == nil && address.Scheme == "https" && address.Host != "" &&
			address.User == nil && (address.Path == "" || address.Path == "/") &&
			address.RawQuery == "" && address.Fragment == "" && len(values["VAULT_TOKEN"]) > 0 &&
			(len(values["VAULT_CACERT"]) == 0 || absoluteCredentialFile(values["VAULT_CACERT"]))
	case biz.SigningKeyKubernetes:
		return absoluteCredentialFile(values["KUBECONFIG"])
	default:
		return false
	}
}

func absoluteCredentialFile(value []byte) bool {
	return len(value) > 0 && filepath.IsAbs(string(value))
}

func clearSigningEnvironment(values map[string][]byte) {
	for key, value := range values {
		clear(value)
		delete(values, key)
	}
}

var _ biz.SignatureSigner = (*CosignSigner)(nil)
