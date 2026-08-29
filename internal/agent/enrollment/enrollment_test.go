package agentenrollment

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentconfig "github.com/owndock/owndock/internal/agent/config"
)

func TestProvisionExchangesTokenAndCommitsValidatedFiles(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	server := newEnrollmentServer(t, now, false)
	defer server.Close()
	paths := testPaths(t, true)
	options := testOptions(server, paths, now)
	result, err := Provision(
		context.Background(), options,
		[]byte("abcdefghijklmnopqrstuvwxyzABCDEFGH_12345678"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.OrganizationID != "organization-1" || result.ManagedHostID != "host-1" ||
		result.IdentityID != "identity-1" || !result.ExpiresAt.After(now) {
		t.Fatalf("result = %+v", result)
	}
	config, err := agentconfig.Load(paths.Config)
	if err != nil {
		t.Fatal(err)
	}
	if config.Control.OrganizationID != result.OrganizationID ||
		config.Control.ManagedHostID != result.ManagedHostID ||
		config.Control.IdentityID != result.IdentityID ||
		config.Control.InstanceID != result.InstanceID ||
		config.HostTerminal.Enabled || len(config.Control.Capabilities) != 11 {
		t.Fatalf("config = %+v", config)
	}
	assertMode(t, paths.Config, 0o640)
	assertMode(t, paths.CACertificate, 0o640)
	assertMode(t, paths.IdentityBundle, 0o600)
	assertMode(t, filepath.Join(paths.StateDirectory, instanceIDFileName), 0o600)
	if _, err := os.Stat(filepath.Join(paths.StateDirectory, pendingFileName)); !os.IsNotExist(err) {
		t.Fatalf("pending enrollment remains: %v", err)
	}
	if server.requests != 1 || server.token != "abcdefghijklmnopqrstuvwxyzABCDEFGH_12345678" {
		t.Fatalf("exchange requests = %d token matched = %t", server.requests, server.token != "")
	}
}

func TestRecoverCompletesPersistedResponseWithoutReusingToken(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	server := newEnrollmentServer(t, now, false)
	defer server.Close()
	paths := testPaths(t, false)
	options := testOptions(server, paths, now)
	if _, err := Provision(
		context.Background(), options,
		[]byte("abcdefghijklmnopqrstuvwxyzABCDEFGH_12345678"),
	); err == nil || !strings.Contains(err.Error(), "install Agent CA") {
		t.Fatalf("provision error = %v", err)
	}
	pending := filepath.Join(paths.StateDirectory, pendingFileName)
	assertMode(t, pending, 0o600)
	if err := os.MkdirAll(filepath.Dir(paths.Config), 0o755); err != nil {
		t.Fatal(err)
	}
	result, err := Recover(paths, now)
	if err != nil {
		t.Fatal(err)
	}
	if result.IdentityID != "identity-1" || server.requests != 1 {
		t.Fatalf("result = %+v requests = %d", result, server.requests)
	}
	if _, err := agentconfig.Load(paths.Config); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(pending); !os.IsNotExist(err) {
		t.Fatalf("pending enrollment remains: %v", err)
	}
}

func TestProvisionReusesPersistedCSRAfterAmbiguousNetworkFailure(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	server := newEnrollmentServer(t, now, false)
	server.dropFirstResponse = true
	defer server.Close()
	paths := testPaths(t, true)
	options := testOptions(server, paths, now)
	token := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGH_12345678")
	if _, err := Provision(context.Background(), options, token); err == nil {
		t.Fatal("ambiguous first response unexpectedly succeeded")
	}
	pending, exists, err := loadPending(filepath.Join(paths.StateDirectory, pendingFileName))
	if err != nil || !exists || pending.Phase != pendingPhaseRequest {
		t.Fatalf("pending request = %+v, exists = %t, err = %v", pending, exists, err)
	}
	pending.clear()
	conflict := options
	conflict.ControlEndpoint = "https://other.example:8443/api/v1/agent/connect"
	if _, err := Provision(context.Background(), conflict, token); !errors.Is(err, ErrInvalidEnrollment) {
		t.Fatalf("conflicting retry error = %v", err)
	}
	result, err := Provision(context.Background(), options, token)
	if err != nil || result.IdentityID != "identity-1" || server.requests != 2 ||
		server.firstCSR == "" || server.firstCSR != server.lastCSR {
		t.Fatalf("result=%+v err=%v requests=%d csr_reused=%t", result, err, server.requests, server.firstCSR == server.lastCSR)
	}
}

func TestProvisionRejectsCertificateBoundToAnotherHost(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	server := newEnrollmentServer(t, now, true)
	defer server.Close()
	paths := testPaths(t, true)
	options := testOptions(server, paths, now)
	if _, err := Provision(
		context.Background(), options,
		[]byte("abcdefghijklmnopqrstuvwxyzABCDEFGH_12345678"),
	); !errors.Is(err, ErrInvalidEnrollment) {
		t.Fatalf("error = %v", err)
	}
	for _, path := range []string{paths.Config, paths.CACertificate, paths.IdentityBundle} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("unsafe file was installed at %s: %v", path, err)
		}
	}
}

func TestProvisionRejectsUnsafeTokenAndEndpoint(t *testing.T) {
	paths := testPaths(t, true)
	options := Options{
		EnrollmentEndpoint: "http://server.example/api/v1/agent/enrollments:exchange",
		ControlEndpoint:    "https://control.example/api/v1/agent/connect",
		AgentVersion:       "1.0.0",
		Capabilities:       StandardCapabilities(false),
		Paths:              paths,
	}
	if _, err := Provision(context.Background(), options, []byte("short")); !errors.Is(err, ErrInvalidEnrollment) {
		t.Fatalf("error = %v", err)
	}
}

type enrollmentServer struct {
	*httptest.Server
	caFile            string
	requests          int
	token             string
	dropFirstResponse bool
	firstCSR          string
	lastCSR           string
}

func newEnrollmentServer(t *testing.T, now time.Time, wrongHost bool) *enrollmentServer {
	t.Helper()
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Agent test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	serverCertificate := issueServerCertificate(t, now, caCertificate, caKey)
	state := &enrollmentServer{}
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		state.requests++
		if request.Method != http.MethodPost ||
			request.URL.Path != "/api/v1/agent/enrollments:exchange" {
			http.NotFound(writer, request)
			return
		}
		var input exchangeRequest
		decoder := json.NewDecoder(request.Body)
		if err := decoder.Decode(&input); err != nil {
			t.Errorf("decode request: %v", err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		state.token = input.EnrollmentToken
		state.lastCSR = input.CSRPEM
		if state.requests == 1 {
			state.firstCSR = input.CSRPEM
			if state.dropFirstResponse {
				panic(http.ErrAbortHandler)
			}
		}
		block, _ := pem.Decode([]byte(input.CSRPEM))
		if block == nil {
			t.Error("missing CSR")
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil || csr.CheckSignature() != nil {
			t.Errorf("invalid CSR: %v", err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		hostID := "host-1"
		certificateHost := hostID
		if wrongHost {
			certificateHost = "host-2"
		}
		identityURI, _ := url.Parse(
			"spiffe://owndock/organizations/organization-1/managed-hosts/" + certificateHost +
				"/agents/identity-1/instances/" + input.InstanceID,
		)
		expires := now.Add(24 * time.Hour)
		leaf := &x509.Certificate{
			SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "owndock-agent:identity-1"},
			NotBefore: now.Add(-time.Minute), NotAfter: expires,
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			BasicConstraintsValid: true, URIs: []*url.URL{identityURI},
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leaf, caCertificate, csr.PublicKey, caKey)
		if err != nil {
			t.Errorf("issue certificate: %v", err)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(writer).Encode(exchangeResponse{
			AgentIdentityID: "identity-1", ManagedHostID: hostID,
			CertificatePEM:   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})),
			CACertificatePEM: string(caPEM), CertificateExpires: expires,
		})
	})
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCertificate},
	}
	server.StartTLS()
	state.Server = server
	state.caFile = filepath.Join(t.TempDir(), "server-ca.pem")
	if err := os.WriteFile(state.caFile, caPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	return state
}

func issueServerCertificate(
	t *testing.T,
	now time.Time,
	ca *x509.Certificate,
	caKey ed25519.PrivateKey,
) tls.Certificate {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, key.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func testOptions(server *enrollmentServer, paths Paths, now time.Time) Options {
	return Options{
		EnrollmentEndpoint: server.URL + "/api/v1/agent/enrollments:exchange",
		ControlEndpoint:    "https://control.example:8443/api/v1/agent/connect",
		ServerCAFile:       server.caFile,
		AgentVersion:       "1.2.3",
		Capabilities:       StandardCapabilities(false),
		RequestTimeout:     5 * time.Second,
		Paths:              paths,
		Now:                func() time.Time { return now },
	}
}

func testPaths(t *testing.T, createConfigDirectory bool) Paths {
	t.Helper()
	root := t.TempDir()
	state := filepath.Join(root, "var/lib/owndock-agent")
	if err := os.MkdirAll(filepath.Join(state, "identity"), 0o700); err != nil {
		t.Fatal(err)
	}
	configDirectory := filepath.Join(root, "etc/owndock")
	if createConfigDirectory {
		if err := os.MkdirAll(configDirectory, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	return Paths{
		Config:         filepath.Join(configDirectory, "agent.yaml"),
		CACertificate:  filepath.Join(configDirectory, "agent-ca.pem"),
		IdentityBundle: filepath.Join(state, "identity/agent-identity.pem"),
		StateDirectory: state,
	}
}

func assertMode(t *testing.T, path string, expected os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != expected {
		t.Fatalf("%s mode = %#o", path, info.Mode().Perm())
	}
}
