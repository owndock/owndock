package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"testing"
	"time"

	platformconfig "github.com/owndock/owndock/internal/platform/config"
)

type agentRegistryCloseStub struct {
	closed bool
}

func (r *agentRegistryCloseStub) Close() { r.closed = true }

func TestAgentServerRequiresAndVerifiesMutualTLS(t *testing.T) {
	now := time.Now().UTC()
	caCertificate, caKey, caPEM := testAgentCA(t, now)
	serverCertificate, serverKey := testSignedCertificate(
		t, caCertificate, caKey, now,
		"localhost", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	)
	clientCertificate, clientKey := testSignedCertificate(
		t, caCertificate, caKey, now,
		"agent", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	)
	registry := &agentRegistryCloseStub{}
	agentServer, err := NewAgentServer(
		platformconfig.Agent{
			Address: "127.0.0.1:0", HandshakeTimeout: "2s",
		},
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}),
		caPEM, serverCertificate, serverKey, registry,
	)
	if err != nil {
		t.Fatal(err)
	}
	startResult := make(chan error, 1)
	go func() { startResult <- agentServer.Start(t.Context()) }()
	var endpoint string
	for range 100 {
		endpoint = agentServer.Endpoint()
		if endpoint != "" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if endpoint == "" {
		t.Fatal("Agent server did not start listening")
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCertificate)
	clientPair, err := tls.X509KeyPair(clientCertificate, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots, ServerName: "localhost",
		Certificates: []tls.Certificate{clientPair},
	}}}
	request, err := http.NewRequestWithContext(
		t.Context(), http.MethodPost,
		"https://"+endpoint+"/api/v1/agent/connect",
		http.NoBody,
	)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d", response.StatusCode)
	}
	stopContext, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if err := agentServer.Stop(stopContext); err != nil {
		t.Fatal(err)
	}
	if err := <-startResult; err != nil {
		t.Fatal(err)
	}
	if !registry.closed {
		t.Fatal("Agent server stop did not close the connection registry")
	}
}

func testAgentCA(
	t *testing.T,
	now time.Time,
) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "OwnDock Agent Test CA"},
		NotBefore:    now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(
		rand.Reader, template, template, key.Public(), key,
	)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: der,
	})
}

func testSignedCertificate(
	t *testing.T,
	caCertificate *x509.Certificate,
	caKey *ecdsa.PrivateKey,
	now time.Time,
	commonName string,
	usages []x509.ExtKeyUsage,
) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-time.Minute), NotAfter: now.Add(30 * time.Minute),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: usages,
	}
	if commonName == "localhost" {
		template.DNSNames = []string{"localhost"}
	}
	der, err := x509.CreateCertificate(
		rand.Reader, template, caCertificate, key.Public(), caKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}
