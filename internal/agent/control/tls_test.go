package agentcontrol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/url"
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
		len(transport.TLSClientConfig.Certificates) != 0 ||
		transport.TLSClientConfig.GetClientCertificate == nil {
		t.Fatalf("transport = %#v", transport)
	}
}

func TestHTTPClientReloadsAtomicallyReplacedCertificateForReconnect(t *testing.T) {
	files := writeClientTLSFiles(t)
	client, err := NewHTTPClient(files, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	transport := client.Transport.(*http.Transport)
	first, err := transport.TLSClientConfig.GetClientCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	replacement := writeClientTLSFiles(t)
	replaceTLSFile(t, replacement.ClientCertificateFile, files.ClientCertificateFile, 0o644)
	replaceTLSFile(t, replacement.ClientPrivateKeyFile, files.ClientPrivateKeyFile, 0o600)
	second, err := transport.TLSClientConfig.GetClientCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if first.Leaf == nil || second.Leaf == nil ||
		first.Leaf.Equal(second.Leaf) {
		t.Fatalf("certificate was not reloaded: first=%v second=%v", first.Leaf, second.Leaf)
	}
}

func TestHTTPClientRejectsUnsafeKeyReplacementDuringReconnect(t *testing.T) {
	files := writeClientTLSFiles(t)
	client, err := NewHTTPClient(files, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(files.ClientPrivateKeyFile, 0o644); err != nil {
		t.Fatal(err)
	}
	transport := client.Transport.(*http.Transport)
	if _, err := transport.TLSClientConfig.GetClientCertificate(nil); !errors.Is(err, ErrConfigurationInvalid) {
		t.Fatalf("unsafe replacement error = %v", err)
	}
}

func TestInstallClientIdentityBundleIsAtomicAndReloadable(t *testing.T) {
	files := writeClientTLSFiles(t)
	certificatePEM, err := os.ReadFile(files.ClientCertificateFile)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPEM, err := os.ReadFile(files.ClientPrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(files.CACertificateFile)
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(t.TempDir(), "agent-identity.pem")
	if err := InstallClientIdentityBundle(
		bundlePath, certificatePEM, privateKeyPEM, caPEM,
		testBundleIdentity(), time.Now(),
	); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(bundlePath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("bundle mode = %v, error = %v", info.Mode(), err)
	}
	client, err := NewHTTPClient(TLSFiles{
		CACertificateFile:     files.CACertificateFile,
		ClientCertificateFile: bundlePath, ClientPrivateKeyFile: bundlePath,
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	transport := client.Transport.(*http.Transport)
	if _, err := transport.TLSClientConfig.GetClientCertificate(nil); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPEM[len(privateKeyPEM)-1] ^= 1
	if err := InstallClientIdentityBundle(
		bundlePath, certificatePEM, privateKeyPEM, caPEM,
		testBundleIdentity(), time.Now(),
	); !errors.Is(err, ErrConfigurationInvalid) {
		t.Fatalf("mismatched key error = %v", err)
	}
	after, err := os.ReadFile(bundlePath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("invalid rotation changed the installed identity bundle")
	}
}

func TestInstallClientIdentityBundleRejectsDifferentAgentIdentity(t *testing.T) {
	files := writeClientTLSFiles(t)
	certificatePEM, _ := os.ReadFile(files.ClientCertificateFile)
	privateKeyPEM, _ := os.ReadFile(files.ClientPrivateKeyFile)
	caPEM, _ := os.ReadFile(files.CACertificateFile)
	identity := testBundleIdentity()
	identity.ManagedHostID = "another-host"
	if err := InstallClientIdentityBundle(
		filepath.Join(t.TempDir(), "agent-identity.pem"),
		certificatePEM, privateKeyPEM, caPEM, identity, time.Now(),
	); !errors.Is(err, ErrConfigurationInvalid) {
		t.Fatalf("different identity error = %v", err)
	}
}

func TestNewCertificateRotationRequestUsesFreshLocalKeyAndNoTrustedIdentity(t *testing.T) {
	first, err := NewCertificateRotationRequest(testBundleIdentity())
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewCertificateRotationRequest(testBundleIdentity())
	if err != nil {
		t.Fatal(err)
	}
	firstBlock, _ := pem.Decode(first.CSRPEM)
	secondBlock, _ := pem.Decode(second.CSRPEM)
	if firstBlock == nil || secondBlock == nil || bytes.Equal(firstBlock.Bytes, secondBlock.Bytes) {
		t.Fatal("rotation requests did not use fresh keys")
	}
	request, err := x509.ParseCertificateRequest(firstBlock.Bytes)
	if err != nil || request.CheckSignature() != nil {
		t.Fatalf("rotation CSR error = %v", err)
	}
	if len(request.URIs) != 0 || len(request.DNSNames) != 0 ||
		len(request.IPAddresses) != 0 || len(request.EmailAddresses) != 0 {
		t.Fatalf("rotation CSR contains trusted identity claims: %+v", request)
	}
	keyBlock, _ := pem.Decode(first.PrivateKeyPEM)
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := key.(ed25519.PrivateKey)
	csrPublicKey := request.PublicKey.(ed25519.PublicKey)
	if !bytes.Equal(privateKey.Public().(ed25519.PublicKey), csrPublicKey) {
		t.Fatal("rotation CSR does not match the generated private key")
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
		URIs: []*url.URL{{
			Scheme: "spiffe", Host: "owndock",
			Path: "/organizations/organization-1/managed-hosts/host-1/" +
				"agents/identity-1/instances/instance-1",
		}},
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

func testBundleIdentity() Identity {
	return Identity{
		OrganizationID: "organization-1", ManagedHostID: "host-1",
		IdentityID: "identity-1", InstanceID: "instance-1",
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

func replaceTLSFile(t *testing.T, source, target string, mode os.FileMode) {
	t.Helper()
	value, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	temporary := target + ".new"
	if err := os.WriteFile(temporary, value, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(temporary, target); err != nil {
		t.Fatal(err)
	}
}
