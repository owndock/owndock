package agentcontrol

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewHTTPClientLoadsTLS13MaterialWithoutProxy(t *testing.T) {
	files := writeClientTLSFiles(t)
	client, err := NewHTTPClient(files, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T", client.Transport)
	}
	if transport.Proxy != nil ||
		transport.TLSClientConfig.MinVersion != tls.VersionTLS13 ||
		len(transport.TLSClientConfig.Certificates) != 1 {
		t.Fatalf("transport = %#v", transport)
	}
}

func TestNewHTTPClientRejectsLoosePrivateKeyAndSymlink(t *testing.T) {
	files := writeClientTLSFiles(t)
	if err := os.Chmod(files.ClientPrivateKeyFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewHTTPClient(
		files,
		time.Second,
	); !errors.Is(err, ErrConfigurationInvalid) {
		t.Fatalf("loose key error = %v", err)
	}
	if err := os.Chmod(files.ClientPrivateKeyFile, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "agent-key.pem")
	if err := os.Symlink(files.ClientPrivateKeyFile, link); err != nil {
		t.Fatal(err)
	}
	files.ClientPrivateKeyFile = link
	if _, err := NewHTTPClient(
		files,
		time.Second,
	); !errors.Is(err, ErrConfigurationInvalid) {
		t.Fatalf("symlink key error = %v", err)
	}
}

func writeClientTLSFiles(t *testing.T) TLSFiles {
	t.Helper()
	now := time.Now()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Agent Test CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign |
			x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(
		rand.Reader,
		caTemplate,
		caTemplate,
		caPublic,
		caPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	clientPublic, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Agent Test Client"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(
		rand.Reader,
		clientTemplate,
		caTemplate,
		clientPublic,
		caPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := x509.MarshalPKCS8PrivateKey(clientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	caPath := filepath.Join(directory, "ca.pem")
	clientPath := filepath.Join(directory, "agent.pem")
	keyPath := filepath.Join(directory, "agent-key.pem")
	writePEM(t, caPath, "CERTIFICATE", caDER, 0o644)
	writePEM(t, clientPath, "CERTIFICATE", clientDER, 0o644)
	writePEM(t, keyPath, "PRIVATE KEY", privateKey, 0o600)
	return TLSFiles{
		CACertificateFile:     caPath,
		ClientCertificateFile: clientPath,
		ClientPrivateKeyFile:  keyPath,
	}
}

func writePEM(
	t *testing.T,
	path, blockType string,
	value []byte,
	mode os.FileMode,
) {
	t.Helper()
	encoded := pem.EncodeToMemory(&pem.Block{
		Type:  blockType,
		Bytes: value,
	})
	if err := os.WriteFile(path, encoded, mode); err != nil {
		t.Fatal(err)
	}
}
