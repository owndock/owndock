package biz

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
)

func TestSignatureTrustMaterialRequiresOneExactTrustMode(t *testing.T) {
	publicKey := signaturePublicKeyFixture(t)
	trustedRoot := []byte(`{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1","certificateAuthorities":[]}`)
	valid := []SignatureTrustMaterial{
		{Mode: SignatureTrustPublicKey, PublicKeyPEM: publicKey},
		{Mode: SignatureTrustKeyless, TrustedRootJSON: trustedRoot,
			CertificateIdentity: "https://github.com/owndock/repository/.github/workflows/release.yml@refs/tags/v1.0.0",
			OIDCIssuer:          "https://token.actions.githubusercontent.com"},
	}
	for _, material := range valid {
		if err := material.Validate(); err != nil || material.Fingerprint()[:7] != "sha256:" {
			t.Fatalf("valid material rejected: %#v, %v", material, err)
		}
	}
	for name, material := range map[string]SignatureTrustMaterial{
		"empty": {},
		"both": {Mode: SignatureTrustPublicKey, PublicKeyPEM: publicKey,
			TrustedRootJSON: trustedRoot},
		"keyless without identity": {Mode: SignatureTrustKeyless, TrustedRootJSON: trustedRoot,
			OIDCIssuer: "https://issuer.example"},
		"insecure issuer": {Mode: SignatureTrustKeyless, TrustedRootJSON: trustedRoot,
			CertificateIdentity: "builder@example.com", OIDCIssuer: "http://issuer.example"},
		"issuer query": {Mode: SignatureTrustKeyless, TrustedRootJSON: trustedRoot,
			CertificateIdentity: "builder@example.com", OIDCIssuer: "https://issuer.example?tenant=1"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := material.Validate(); !errors.Is(err, ErrInvalidSignatureTrust) {
				t.Fatalf("Validate() = %v", err)
			}
		})
	}
}

func TestSignatureVerificationRequestRequiresDigestSubject(t *testing.T) {
	request := SignatureVerificationRequest{
		ProjectID: "project-1", RegistryCredentialID: "registry-1",
		RegistryRepository: "registry.example.com/team/api",
		SubjectDigest:      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Trust: SignatureTrustMaterial{Mode: SignatureTrustPublicKey,
			PublicKeyPEM: signaturePublicKeyFixture(t)},
	}
	if err := request.Validate(); err != nil ||
		request.CanonicalSubject() != request.RegistryRepository+"@"+request.SubjectDigest {
		t.Fatalf("valid request rejected: %v", err)
	}
	request.SubjectDigest = "latest"
	if err := request.Validate(); !errors.Is(err, ErrInvalidSignatureTrust) {
		t.Fatalf("mutable subject error = %v", err)
	}
}

func signaturePublicKeyFixture(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}
