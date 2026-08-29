package biz

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/url"
	"strings"
)

const (
	SigstoreBundleMediaTypeV03 = "application/vnd.dev.sigstore.bundle.v0.3+json"
	CosignSignatureFormatV03   = "sigstore-bundle-0.3"
)

var (
	ErrInvalidSignatureTrust   = errors.New("signature trust material is invalid")
	ErrSignatureVerification   = errors.New("artifact signature verification failed")
	ErrSignatureToolVersion    = errors.New("signature verifier version does not match the pinned version")
	ErrSignatureTrustNotFound  = errors.New("signature trust material was not found")
	ErrSignatureBundleNotFound = errors.New("artifact signature bundle was not found")
)

type SignatureTrustMode string

const (
	SignatureTrustPublicKey SignatureTrustMode = "public_key"
	SignatureTrustKeyless   SignatureTrustMode = "keyless"
)

func (m SignatureTrustMode) Valid() bool {
	return m == SignatureTrustPublicKey || m == SignatureTrustKeyless
}

// SignatureTrustMaterial is resolved only for one verification operation.
// Public keys and Sigstore trusted roots are not secrets, but they remain
// outside Evidence jobs so policy rotation cannot mutate an in-flight job.
type SignatureTrustMaterial struct {
	Mode                SignatureTrustMode
	PublicKeyPEM        []byte
	TrustedRootJSON     []byte
	CertificateIdentity string
	OIDCIssuer          string
}

func (m SignatureTrustMaterial) Validate() error {
	switch m.Mode {
	case SignatureTrustPublicKey:
		if len(m.PublicKeyPEM) < 64 || len(m.PublicKeyPEM) > 64*1024 ||
			len(m.TrustedRootJSON) != 0 || m.CertificateIdentity != "" || m.OIDCIssuer != "" {
			return ErrInvalidSignatureTrust
		}
		if _, _, err := NormalizeSignaturePublicKey(m.PublicKeyPEM); err != nil {
			return err
		}
	case SignatureTrustKeyless:
		identity := strings.TrimSpace(m.CertificateIdentity)
		issuer := strings.TrimSpace(m.OIDCIssuer)
		parsed, err := url.Parse(issuer)
		if len(m.PublicKeyPEM) != 0 || len(m.TrustedRootJSON) < 64 ||
			len(m.TrustedRootJSON) > 4*1024*1024 || !json.Valid(m.TrustedRootJSON) ||
			identity == "" || identity != m.CertificateIdentity || len(identity) > 1024 ||
			issuer != m.OIDCIssuer || len(issuer) > 2048 || err != nil || parsed.Scheme != "https" ||
			parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return ErrInvalidSignatureTrust
		}
	default:
		return ErrInvalidSignatureTrust
	}
	return nil
}

func (m SignatureTrustMaterial) Fingerprint() string {
	var content []byte
	if m.Mode == SignatureTrustPublicKey {
		_, fingerprint, err := NormalizeSignaturePublicKey(m.PublicKeyPEM)
		if err != nil {
			return ""
		}
		return fingerprint
	} else {
		content = m.TrustedRootJSON
	}
	digest := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func NormalizeSignaturePublicKey(value []byte) ([]byte, string, error) {
	block, rest := pem.Decode(value)
	if block == nil || block.Type != "PUBLIC KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, "", ErrInvalidSignatureTrust
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil || !supportedSignaturePublicKey(publicKey) {
		return nil, "", ErrInvalidSignatureTrust
	}
	canonicalDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, "", ErrInvalidSignatureTrust
	}
	digest := sha256.Sum256(canonicalDER)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: canonicalDER}),
		"sha256:" + hex.EncodeToString(digest[:]), nil
}

func supportedSignaturePublicKey(value any) bool {
	switch key := value.(type) {
	case *ecdsa.PublicKey:
		return key.Curve == elliptic.P256() || key.Curve == elliptic.P384()
	case *rsa.PublicKey:
		return key.N.BitLen() >= 2048 && key.N.BitLen() <= 8192
	case ed25519.PublicKey:
		return len(key) == ed25519.PublicKeySize
	default:
		return false
	}
}

type SignatureVerificationRequest struct {
	ProjectID            string
	RegistryCredentialID string
	RegistryRepository   string
	SubjectDigest        string
	Trust                SignatureTrustMaterial
}

func (r SignatureVerificationRequest) Validate() error {
	if !validID(strings.TrimSpace(r.ProjectID)) ||
		!validID(strings.TrimSpace(r.RegistryCredentialID)) ||
		!validRepository(strings.TrimSpace(r.RegistryRepository)) ||
		!validDigest(strings.TrimSpace(r.SubjectDigest)) || r.Trust.Validate() != nil {
		return ErrInvalidSignatureTrust
	}
	return nil
}

func (r SignatureVerificationRequest) CanonicalSubject() string {
	return strings.TrimSpace(r.RegistryRepository) + "@" + strings.TrimSpace(r.SubjectDigest)
}

type SignatureVerificationResult struct {
	TrustMode       SignatureTrustMode
	TrustRootHash   string
	SignerIdentity  string
	OIDCIssuer      string
	BundleSetDigest string
	VerifierVersion string
}

type SignatureVerifier interface {
	VerifySignature(context.Context, SignatureVerificationRequest) (SignatureVerificationResult, error)
}

type SignatureTrustResolver interface {
	ResolveSignatureTrust(context.Context, SignatureTrustSnapshot) (SignatureTrustMaterial, error)
}
