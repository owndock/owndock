package data

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/owndock/owndock/internal/modules/supplychain/biz"
)

func TestFileSignatureTrustResolverPinsContentAndRejectsSymlinks(t *testing.T) {
	directory := t.TempDir()
	content := append([]byte(`{"mediaType":"application/vnd.dev.sigstore.trustedroot+json","tlogs":[]}`),
		[]byte(strings.Repeat(" ", 64))...)
	digest := sha256.Sum256(content)
	snapshot := biz.SignatureTrustSnapshot{PolicyID: "policy-1", PolicyVersion: 1,
		Mode: biz.SignatureTrustKeyless, TrustedRootID: "root-1",
		TrustedRootHash:     "sha256:" + hex.EncodeToString(digest[:]),
		CertificateIdentity: "https://git.example.com/team/api/.ci/release@refs/tags/v1.0.0",
		OIDCIssuer:          "https://issuer.example.com"}
	path := filepath.Join(directory, "root-1.json")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	resolver, err := NewFileSignatureTrustResolver(directory)
	if err != nil {
		t.Fatal(err)
	}
	material, err := resolver.ResolveSignatureTrust(t.Context(), snapshot)
	if err != nil || material.Fingerprint() != snapshot.TrustedRootHash {
		t.Fatalf("resolved = %+v, %v", material, err)
	}
	if err := os.WriteFile(path, append(content, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolveSignatureTrust(t.Context(), snapshot); !errors.Is(err, biz.ErrInvalidSignatureTrust) {
		t.Fatalf("tampered root error = %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "real.json"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(directory, "real.json"), path); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolveSignatureTrust(t.Context(), snapshot); !errors.Is(err, biz.ErrSignatureTrustNotFound) {
		t.Fatalf("symlink root error = %v", err)
	}
}
