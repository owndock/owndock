package data

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestTrivyDatabaseSnapshotWithPrivateTLSRegistry(t *testing.T) {
	if os.Getenv("OWNDOCK_RUN_VULNERABILITY_INTEGRATION") != "1" {
		t.Skip("set OWNDOCK_RUN_VULNERABILITY_INTEGRATION=1 to run the private Trivy DB Registry test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	now := time.Now().UTC().Truncate(time.Second)
	metadata, err := json.Marshal(map[string]any{
		"Version": 2, "UpdatedAt": now.Add(-time.Hour),
		"DownloadedAt": now.Add(-30 * time.Minute), "NextUpdate": now.Add(12 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	server, caBundle, downloads := newPrivateTrivyDatabaseRegistry(t, metadata)
	defer server.Close()
	caFile := filepath.Join(t.TempDir(), "private-db-registry-ca.pem")
	if err := os.WriteFile(caFile, caBundle, 0o600); err != nil {
		t.Fatal(err)
	}
	// Even a valid ambient CA must not silently change the updater trust boundary.
	t.Setenv("SSL_CERT_FILE", caFile)
	trivy := extractTrivyExecutable(t, ctx)
	repository := strings.TrimPrefix(server.URL, "https://") + "/private/trivy-db:2"

	withoutExplicitCA, err := NewTrivyDatabaseSnapshotManager(TrivyDatabaseSnapshotOptions{
		Executable: trivy, ExpectedVersion: PinnedTrivyVersion,
		RootDirectory: filepath.Join(t.TempDir(), "without-explicit-ca"), Repositories: []string{repository},
		RetainSnapshots: 3, MinimumRetention: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := withoutExplicitCA.Update(ctx); !errors.Is(err, ErrTrivyDatabaseUpdate) {
		t.Fatalf("private DB Registry without explicit CA error = %v", err)
	}

	withExplicitCA, err := NewTrivyDatabaseSnapshotManager(TrivyDatabaseSnapshotOptions{
		Executable: trivy, ExpectedVersion: PinnedTrivyVersion,
		RootDirectory: filepath.Join(t.TempDir(), "with-explicit-ca"), Repositories: []string{repository},
		CACertFile: caFile, RetainSnapshots: 3, MinimumRetention: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := withExplicitCA.Update(ctx)
	if err != nil {
		t.Fatalf("private DB Registry with explicit CA: %v", err)
	}
	database, err := os.ReadFile(filepath.Join(snapshot.CurrentPath, "db", "trivy.db"))
	if err != nil || string(database) != "private-db-registry-fixture" {
		t.Fatalf("private DB snapshot content = %q, %v", database, err)
	}
	if snapshot.Database.SchemaVersion != 2 || snapshot.Database.NextUpdate.Before(now) || downloads.Load() == 0 {
		t.Fatalf("private DB snapshot = %+v, downloads=%d", snapshot, downloads.Load())
	}
}

func newPrivateTrivyDatabaseRegistry(t *testing.T, metadata []byte) (*httptest.Server, []byte, *atomic.Int64) {
	t.Helper()
	caCertificate, caKey, caBundle := newPrivateRegistryCA(t)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "private Trivy DB Registry"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"host.docker.internal"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCertificate, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	leafKeyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(leafPEM,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafKeyDER}))
	if err != nil {
		t.Fatal(err)
	}
	manifest, blobs := privateTrivyDatabaseArtifact(t, metadata)
	manifestDigest := digestBytes(manifest)
	downloads := &atomic.Int64{}
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		switch request.URL.Path {
		case "/v2/":
			response.WriteHeader(http.StatusOK)
		case "/v2/private/trivy-db/manifests/2", "/v2/private/trivy-db/manifests/" + manifestDigest:
			response.Header().Set("Content-Type", ociManifestMediaType)
			response.Header().Set("Docker-Content-Digest", manifestDigest)
			response.Header().Set("Content-Length", fmt.Sprint(len(manifest)))
			if request.Method != http.MethodHead {
				_, _ = response.Write(manifest)
			}
		default:
			const prefix = "/v2/private/trivy-db/blobs/"
			blob, ok := blobs[strings.TrimPrefix(request.URL.Path, prefix)]
			if !strings.HasPrefix(request.URL.Path, prefix) || !ok {
				http.NotFound(response, request)
				return
			}
			downloads.Add(1)
			response.Header().Set("Content-Type", "application/octet-stream")
			response.Header().Set("Docker-Content-Digest", digestBytes(blob))
			response.Header().Set("Content-Length", fmt.Sprint(len(blob)))
			if request.Method != http.MethodHead {
				_, _ = response.Write(blob)
			}
		}
	})
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	return server, caBundle, downloads
}

func newPrivateRegistryCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "private Trivy DB test CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func privateTrivyDatabaseArtifact(t *testing.T, metadata []byte) ([]byte, map[string][]byte) {
	t.Helper()
	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	tarWriter := tar.NewWriter(gzipWriter)
	for name, content := range map[string][]byte{
		"trivy.db": []byte("private-db-registry-fixture"), "metadata.json": metadata,
	} {
		if err := tarWriter.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(content)), ModTime: time.Unix(0, 0),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	config := []byte("{}")
	layer := compressed.Bytes()
	manifest := []byte(fmt.Sprintf(
		`{"schemaVersion":2,"mediaType":%q,"artifactType":"application/vnd.aquasec.trivy.config.v1+json","config":{"mediaType":"application/vnd.oci.empty.v1+json","digest":%q,"size":%d,"data":"e30="},"layers":[{"mediaType":"application/vnd.aquasec.trivy.db.layer.v1.tar+gzip","digest":%q,"size":%d,"annotations":{"org.opencontainers.image.title":"db.tar.gz"}}]}`,
		ociManifestMediaType, digestBytes(config), len(config), digestBytes(layer), len(layer),
	))
	return manifest, map[string][]byte{digestBytes(config): config, digestBytes(layer): append([]byte(nil), layer...)}
}
