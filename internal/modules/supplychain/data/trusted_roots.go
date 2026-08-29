package data

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/owndock/owndock/internal/modules/supplychain/biz"
)

type FileSignatureTrustResolver struct{ directory string }

func NewFileSignatureTrustResolver(directory string) (*FileSignatureTrustResolver, error) {
	directory = strings.TrimSpace(directory)
	if !filepath.IsAbs(directory) {
		return nil, biz.ErrInvalidSignatureTrust
	}
	info, err := os.Stat(directory)
	if err != nil || !info.IsDir() {
		return nil, biz.ErrSignatureTrustNotFound
	}
	return &FileSignatureTrustResolver{directory: filepath.Clean(directory)}, nil
}

func (r *FileSignatureTrustResolver) ResolveSignatureTrust(_ context.Context,
	snapshot biz.SignatureTrustSnapshot) (biz.SignatureTrustMaterial, error) {
	if snapshot.Validate() != nil {
		return biz.SignatureTrustMaterial{}, biz.ErrInvalidSignatureTrust
	}
	if snapshot.Mode == biz.SignatureTrustPublicKey {
		material := biz.SignatureTrustMaterial{Mode: snapshot.Mode, PublicKeyPEM: []byte(snapshot.PublicKeyPEM)}
		if material.Validate() != nil || material.Fingerprint() != snapshot.PublicKeyFingerprint {
			return biz.SignatureTrustMaterial{}, biz.ErrInvalidSignatureTrust
		}
		return material, nil
	}
	path := filepath.Join(r.directory, snapshot.TrustedRootID+".json")
	if filepath.Dir(path) != r.directory {
		return biz.SignatureTrustMaterial{}, biz.ErrInvalidSignatureTrust
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return biz.SignatureTrustMaterial{}, biz.ErrSignatureTrustNotFound
	}
	file, err := os.Open(path)
	if err != nil {
		return biz.SignatureTrustMaterial{}, biz.ErrSignatureTrustNotFound
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) || after.Size() < 64 || after.Size() > 4*1024*1024 {
		return biz.SignatureTrustMaterial{}, biz.ErrInvalidSignatureTrust
	}
	content, err := io.ReadAll(io.LimitReader(file, 4*1024*1024+1))
	if err != nil || len(content) > 4*1024*1024 {
		clear(content)
		return biz.SignatureTrustMaterial{}, biz.ErrInvalidSignatureTrust
	}
	digest := sha256.Sum256(content)
	actual := "sha256:" + hex.EncodeToString(digest[:])
	if actual != snapshot.TrustedRootHash {
		clear(content)
		return biz.SignatureTrustMaterial{}, biz.ErrInvalidSignatureTrust
	}
	material := biz.SignatureTrustMaterial{Mode: snapshot.Mode, TrustedRootJSON: content,
		CertificateIdentity: snapshot.CertificateIdentity, OIDCIssuer: snapshot.OIDCIssuer}
	if material.Validate() != nil {
		clear(content)
		return biz.SignatureTrustMaterial{}, biz.ErrInvalidSignatureTrust
	}
	return material, nil
}

var _ biz.SignatureTrustResolver = (*FileSignatureTrustResolver)(nil)
