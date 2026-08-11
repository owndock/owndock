package agentcontrol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type reconnectRequesterStub struct{ calls int }

func (r *reconnectRequesterStub) Reconnect() { r.calls++ }

type rotationRoundTripper struct {
	t           *testing.T
	ca          *x509.Certificate
	caKey       ed25519.PrivateKey
	caPEM       []byte
	now         time.Time
	failFirst   bool
	requests    int
	rotationIDs []string
	csrs        [][]byte
}

func (r *rotationRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	r.t.Helper()
	r.requests++
	if request.Method != http.MethodPost ||
		request.URL.Path != "/api/v1/agent/certificate:rotate" {
		r.t.Fatalf("rotation request = %s %s", request.Method, request.URL.Path)
	}
	var input struct {
		RotationID string `json:"rotation_id"`
		CSRPEM     string `json:"csr_pem"`
	}
	decoder := json.NewDecoder(request.Body)
	if err := decoder.Decode(&input); err != nil {
		r.t.Fatal(err)
	}
	r.rotationIDs = append(r.rotationIDs, input.RotationID)
	r.csrs = append(r.csrs, []byte(input.CSRPEM))
	if r.failFirst && r.requests == 1 {
		return nil, errors.New("response lost after Server persisted rotation")
	}
	block, _ := pem.Decode([]byte(input.CSRPEM))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		r.t.Fatalf("CSR error = %v", err)
	}
	identity := testBundleIdentity()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "owndock-agent:identity-1"},
		NotBefore:    r.now.Add(-time.Minute), NotAfter: r.now.Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs: []*url.URL{{
			Scheme: "spiffe", Host: "owndock",
			Path: "/organizations/" + identity.OrganizationID +
				"/managed-hosts/" + identity.ManagedHostID +
				"/agents/" + identity.IdentityID +
				"/instances/" + identity.InstanceID,
		}},
	}
	der, err := x509.CreateCertificate(
		rand.Reader, template, r.ca, csr.PublicKey, r.caKey,
	)
	if err != nil {
		r.t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	responseBody, err := json.Marshal(map[string]any{
		"agent_identity_id":      identity.IdentityID,
		"managed_host_id":        identity.ManagedHostID,
		"rotation_id":            input.RotationID,
		"certificate_pem":        string(certificatePEM),
		"ca_certificate_pem":     string(r.caPEM),
		"certificate_expires_at": template.NotAfter,
	})
	if err != nil {
		r.t.Fatal(err)
	}
	return &http.Response{
		StatusCode: http.StatusCreated,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(responseBody)),
		Request:    request,
	}, nil
}

func TestCertificateRotatorPersistsRequestAcrossLostResponseAndInstallsBundle(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	files, ca, caKey, caPEM := writeRotationTLSFiles(t, now)
	reconnect := &reconnectRequesterStub{}
	transport := &rotationRoundTripper{
		t: t, ca: ca, caKey: caKey, caPEM: caPEM, now: now,
		failFirst: true,
	}
	rotator, err := NewCertificateRotator(
		&http.Client{Transport: transport}, reconnect,
		CertificateRotatorConfig{
			ControlEndpoint: "https://control.example.com/api/v1/agent/connect",
			IdentityBundle:  files.ClientCertificateFile,
			CACertificate:   files.CACertificateFile,
			Identity:        testBundleIdentity(), RenewBefore: time.Hour,
			RetryDelay: time.Minute, RequestTimeout: time.Second,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := rotator.RotateNow(t.Context()); !errors.Is(err, ErrConnectionUnavailable) {
		t.Fatalf("lost response error = %v", err)
	}
	pendingPath := files.ClientCertificateFile + ".rotation-pending"
	info, err := os.Stat(pendingPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("pending rotation mode=%v", info.Mode())
	}
	if err := rotator.RecoverPending(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(transport.rotationIDs) != 2 || transport.rotationIDs[0] != transport.rotationIDs[1] ||
		!bytes.Equal(transport.csrs[0], transport.csrs[1]) {
		t.Fatalf("rotation retry changed identity: ids=%v", transport.rotationIDs)
	}
	if reconnect.calls != 1 {
		t.Fatalf("reconnect calls = %d", reconnect.calls)
	}
	if _, err := os.Stat(pendingPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending rotation was not removed: %v", err)
	}
	certificate, err := loadClientCertificate(
		files.ClientCertificateFile, files.ClientPrivateKeyFile, now,
	)
	if err != nil || certificate.Leaf.SerialNumber.Cmp(big.NewInt(99)) != 0 {
		t.Fatalf("rotated certificate=%v error=%v", certificate.Leaf, err)
	}
}

func writeRotationTLSFiles(
	t *testing.T,
	now time.Time,
) (TLSFiles, *x509.Certificate, ed25519.PrivateKey, []byte) {
	t.Helper()
	caPublic, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Agent Rotation CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(
		rand.Reader, caTemplate, caTemplate, caPublic, caKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	clientPublic, clientKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity := testBundleIdentity()
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Agent"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(2 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs: []*url.URL{{
			Scheme: "spiffe", Host: "owndock",
			Path: "/organizations/" + identity.OrganizationID +
				"/managed-hosts/" + identity.ManagedHostID +
				"/agents/" + identity.IdentityID +
				"/instances/" + identity.InstanceID,
		}},
	}
	clientDER, err := x509.CreateCertificate(
		rand.Reader, clientTemplate, ca, clientPublic, caKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	caPath := filepath.Join(directory, "agent-ca.pem")
	bundlePath := filepath.Join(directory, "agent-identity.pem")
	if err := os.WriteFile(caPath, caPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	bundle := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...,
	)
	if err := os.WriteFile(bundlePath, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	return TLSFiles{
		CACertificateFile:     caPath,
		ClientCertificateFile: bundlePath,
		ClientPrivateKeyFile:  bundlePath,
	}, ca, caKey, caPEM
}

var _ http.RoundTripper = (*rotationRoundTripper)(nil)
var _ ReconnectRequester = (*reconnectRequesterStub)(nil)
