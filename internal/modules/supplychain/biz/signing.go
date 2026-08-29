package biz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
)

var (
	ErrInvalidSigningKey = errors.New("signature signing key reference is invalid")
	ErrSignatureSigning  = errors.New("artifact signature creation failed")
)

type SigningKeyProvider string

const (
	SigningKeyAWSKMS     SigningKeyProvider = "aws_kms"
	SigningKeyGCPKMS     SigningKeyProvider = "gcp_kms"
	SigningKeyAzureKMS   SigningKeyProvider = "azure_kms"
	SigningKeyVault      SigningKeyProvider = "hashicorp_vault"
	SigningKeyKubernetes SigningKeyProvider = "kubernetes"
)

func (p SigningKeyProvider) Valid() bool {
	switch p {
	case SigningKeyAWSKMS, SigningKeyGCPKMS, SigningKeyAzureKMS, SigningKeyVault, SigningKeyKubernetes:
		return true
	default:
		return false
	}
}

type SignatureSigningRequest struct {
	ProjectID            string
	ProfileID            string
	RegistryCredentialID string
	RegistryRepository   string
	SubjectDigest        string
	KeyReference         string
}

func (r SignatureSigningRequest) Validate() (SigningKeyProvider, error) {
	if !validID(strings.TrimSpace(r.ProjectID)) || !validID(strings.TrimSpace(r.ProfileID)) ||
		!validID(strings.TrimSpace(r.RegistryCredentialID)) ||
		!validRepository(strings.TrimSpace(r.RegistryRepository)) || !validDigest(strings.TrimSpace(r.SubjectDigest)) {
		return "", ErrInvalidSigningKey
	}
	return ParseSigningKeyReference(r.KeyReference)
}

func (r SignatureSigningRequest) CanonicalSubject() string {
	return strings.TrimSpace(r.RegistryRepository) + "@" + strings.TrimSpace(r.SubjectDigest)
}

func ParseSigningKeyReference(value string) (SigningKeyProvider, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 2048 || strings.ContainsAny(value, "\r\n\x00") {
		return "", ErrInvalidSigningKey
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.Scheme == "" || parsed.Host == "" && parsed.Opaque == "" && parsed.Path == "" {
		return "", ErrInvalidSigningKey
	}
	providers := map[string]SigningKeyProvider{
		"awskms": SigningKeyAWSKMS, "gcpkms": SigningKeyGCPKMS, "azurekms": SigningKeyAzureKMS,
		"hashivault": SigningKeyVault, "k8s": SigningKeyKubernetes,
	}
	provider, ok := providers[strings.ToLower(parsed.Scheme)]
	if !ok {
		return "", ErrInvalidSigningKey
	}
	return provider, nil
}

func SigningKeyReferenceFingerprint(value string) string {
	digest := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return "sha256:" + hex.EncodeToString(digest[:])
}

type SignatureSigningResult struct {
	Provider                SigningKeyProvider
	KeyReferenceFingerprint string
}

type SignatureSigner interface {
	SignSignature(context.Context, SignatureSigningRequest) (SignatureSigningResult, error)
}

// SigningEnvironmentResolver returns only provider-specific, execution-time
// environment entries. Implementations must not return private key bytes.
type SigningEnvironmentResolver interface {
	ResolveSigningEnvironment(context.Context, string, string, SigningKeyProvider) (map[string][]byte, error)
}
