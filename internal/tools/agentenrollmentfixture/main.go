package main

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
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/owndock/owndock/internal/shared/agentprotocol"
)

const (
	organizationID = "conformance-organization"
	managedHostID  = "conformance-host"
	identityID     = "conformance-identity"
	exchangePath   = "/api/v1/agent/enrollments:exchange"
	maximumBody    = 64 * 1024
)

type materialPaths struct {
	directory     string
	caCertificate string
	caKey         string
	serverBundle  string
}

type exchangeRequest struct {
	EnrollmentToken string   `json:"enrollment_token"`
	InstanceID      string   `json:"instance_id"`
	AgentVersion    string   `json:"agent_version"`
	ProtocolVersion string   `json:"protocol_version"`
	Capabilities    []string `json:"capabilities"`
	CSRPEM          string   `json:"csr_pem"`
}

type exchangeResponse struct {
	AgentIdentityID    string    `json:"agent_identity_id"`
	ManagedHostID      string    `json:"managed_host_id"`
	CertificatePEM     string    `json:"certificate_pem"`
	CACertificatePEM   string    `json:"ca_certificate_pem"`
	CertificateExpires time.Time `json:"certificate_expires_at"`
}

func main() {
	if len(os.Args) < 2 {
		fatal(errors.New("usage: agentenrollmentfixture materials|serve"))
	}
	var err error
	switch os.Args[1] {
	case "materials":
		err = runMaterials(os.Args[2:])
	case "serve":
		err = runServer(os.Args[2:])
	default:
		err = errors.New("usage: agentenrollmentfixture materials|serve")
	}
	if err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	_, _ = fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func runMaterials(arguments []string) error {
	flags := flag.NewFlagSet("materials", flag.ContinueOnError)
	var output string
	flags.StringVar(&output, "output", "", "absolute empty output directory")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("materials requires --output")
	}
	paths, err := pathsFor(output)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(paths.directory, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(paths.directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("material directory must be a real directory")
	}
	entries, err := os.ReadDir(paths.directory)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return errors.New("material directory must be empty")
	}
	return generateMaterials(paths, time.Now().UTC())
}

func runServer(arguments []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	var listen, materials, readyFile, requestFile, expectedRequestFile, mode, token string
	var timeout time.Duration
	flags.StringVar(&listen, "listen", "127.0.0.1:0", "IPv4 loopback listen address")
	flags.StringVar(&materials, "materials", "", "absolute material directory")
	flags.StringVar(&readyFile, "ready-file", "", "absolute endpoint output file")
	flags.StringVar(&requestFile, "request-file", "", "absolute accepted request output file")
	flags.StringVar(&expectedRequestFile, "expected-request-file", "", "optional exact prior request")
	flags.StringVar(&mode, "mode", "respond", "drop or respond")
	flags.StringVar(&token, "token", "", "exact expected enrollment token")
	flags.DurationVar(&timeout, "timeout", 20*time.Second, "one-shot timeout")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 ||
		timeout <= 0 || token == "" || mode != "drop" && mode != "respond" {
		return errors.New("serve arguments are invalid")
	}
	if !strings.HasPrefix(listen, "127.0.0.1:") {
		return errors.New("fixture server must listen on IPv4 loopback")
	}
	paths, err := pathsFor(materials)
	if err != nil {
		return err
	}
	readyFile, err = cleanOutput(readyFile)
	if err != nil {
		return err
	}
	requestFile, err = cleanOutput(requestFile)
	if err != nil {
		return err
	}
	if expectedRequestFile != "" {
		expectedRequestFile, err = cleanInput(expectedRequestFile)
		if err != nil {
			return err
		}
	}
	serverCertificate, caCertificate, caKey, caPEM, err := loadMaterials(paths)
	if err != nil {
		return err
	}
	defer clearBytes(caKey)
	defer clearBytes(caPEM)
	listener, err := net.Listen("tcp4", listen)
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()
	endpoint := "https://" + listener.Addr().String() + exchangePath
	if err := writeFile(readyFile, []byte(endpoint+"\n"), 0o600); err != nil {
		return err
	}
	completed := make(chan error, 1)
	handler := &enrollmentHandler{
		mode: mode, token: token, requestFile: requestFile,
		expectedRequestFile: expectedRequestFile,
		caCertificate:       caCertificate, caKey: caKey, caPEM: caPEM,
		completed: completed,
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	tlsListener := tls.NewListener(listener, &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCertificate},
		NextProtos: []string{"http/1.1"},
	})
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(tlsListener) }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case result := <-completed:
		shutdownContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownContext)
		return result
	case serveErr := <-serveDone:
		if !errors.Is(serveErr, http.ErrServerClosed) {
			return serveErr
		}
		return nil
	case <-timer.C:
		_ = server.Close()
		return errors.New("enrollment fixture timed out")
	}
}

type enrollmentHandler struct {
	mode                string
	token               string
	requestFile         string
	expectedRequestFile string
	caCertificate       *x509.Certificate
	caKey               ed25519.PrivateKey
	caPEM               []byte
	completed           chan<- error
	once                sync.Once
}

func (handler *enrollmentHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	handler.once.Do(func() {
		err := handler.handle(writer, request)
		handler.completed <- err
	})
}

func (handler *enrollmentHandler) handle(writer http.ResponseWriter, request *http.Request) error {
	if request.Method != http.MethodPost || request.URL.Path != exchangePath ||
		request.URL.RawQuery != "" || request.Header.Get("Content-Type") != "application/json" {
		return errors.New("unexpected enrollment request metadata")
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maximumBody+1))
	if err != nil || len(body) == 0 || len(body) > maximumBody {
		return errors.New("invalid enrollment request body")
	}
	defer clearBytes(body)
	var input exchangeRequest
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return fmt.Errorf("decode enrollment request: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("enrollment request contains trailing data")
	}
	if input.EnrollmentToken != handler.token || input.InstanceID != "conformance-instance" ||
		input.ProtocolVersion != agentprotocol.Version || input.AgentVersion != "0.0.0-system" ||
		len(input.Capabilities) == 0 {
		return errors.New("enrollment request identity or version is invalid")
	}
	canonical, err := json.Marshal(input)
	if err != nil {
		return err
	}
	defer clearBytes(canonical)
	if handler.expectedRequestFile != "" {
		expected, readErr := os.ReadFile(handler.expectedRequestFile)
		if readErr != nil {
			return readErr
		}
		defer clearBytes(expected)
		if string(expected) != string(canonical) {
			return errors.New("retried enrollment request did not reuse the exact CSR and metadata")
		}
	}
	if err := writeFile(handler.requestFile, canonical, 0o600); err != nil {
		return err
	}
	if handler.mode == "drop" {
		hijacker, ok := writer.(http.Hijacker)
		if !ok {
			return errors.New("enrollment response connection cannot be interrupted")
		}
		connection, _, err := hijacker.Hijack()
		if err != nil {
			return err
		}
		return connection.Close()
	}
	certificatePEM, expires, err := issueClientCertificate(
		handler.caCertificate, handler.caKey, input.InstanceID, input.CSRPEM, time.Now().UTC(),
	)
	if err != nil {
		return err
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusCreated)
	return json.NewEncoder(writer).Encode(exchangeResponse{
		AgentIdentityID: identityID, ManagedHostID: managedHostID,
		CertificatePEM: string(certificatePEM), CACertificatePEM: string(handler.caPEM),
		CertificateExpires: expires,
	})
}

func generateMaterials(paths materialPaths, now time.Time) error {
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "OwnDock enrollment conformance CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour),
		BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		return err
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caKeyDER, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		return err
	}
	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: caKeyDER})
	defer clearBytes(caKeyPEM)
	_, serverKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCertificate, serverKey.Public(), caKey)
	if err != nil {
		return err
	}
	serverKeyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		return err
	}
	serverBundle := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKeyDER})...,
	)
	defer clearBytes(serverBundle)
	if err := writeFile(paths.caCertificate, caPEM, 0o600); err != nil {
		return err
	}
	if err := writeFile(paths.caKey, caKeyPEM, 0o600); err != nil {
		return err
	}
	return writeFile(paths.serverBundle, serverBundle, 0o600)
}

func loadMaterials(paths materialPaths) (tls.Certificate, *x509.Certificate, ed25519.PrivateKey, []byte, error) {
	serverPEM, err := readRegular(paths.serverBundle, 0o077)
	if err != nil {
		return tls.Certificate{}, nil, nil, nil, err
	}
	defer clearBytes(serverPEM)
	serverCertificate, err := tls.X509KeyPair(serverPEM, serverPEM)
	if err != nil {
		return tls.Certificate{}, nil, nil, nil, err
	}
	caPEM, err := readRegular(paths.caCertificate, 0o077)
	if err != nil {
		return tls.Certificate{}, nil, nil, nil, err
	}
	block, rest := pem.Decode(caPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		clearBytes(caPEM)
		return tls.Certificate{}, nil, nil, nil, errors.New("invalid fixture CA certificate")
	}
	caCertificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !caCertificate.IsCA {
		clearBytes(caPEM)
		return tls.Certificate{}, nil, nil, nil, errors.New("invalid fixture CA certificate")
	}
	caKeyPEM, err := readRegular(paths.caKey, 0o077)
	if err != nil {
		clearBytes(caPEM)
		return tls.Certificate{}, nil, nil, nil, err
	}
	defer clearBytes(caKeyPEM)
	keyBlock, keyRest := pem.Decode(caKeyPEM)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" || len(strings.TrimSpace(string(keyRest))) != 0 {
		clearBytes(caPEM)
		return tls.Certificate{}, nil, nil, nil, errors.New("invalid fixture CA key")
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	caKey, ok := parsedKey.(ed25519.PrivateKey)
	if err != nil || !ok || !caKey.Public().(ed25519.PublicKey).Equal(caCertificate.PublicKey) {
		clearBytes(caPEM)
		return tls.Certificate{}, nil, nil, nil, errors.New("fixture CA key does not match certificate")
	}
	return serverCertificate, caCertificate, caKey, caPEM, nil
}

func issueClientCertificate(
	ca *x509.Certificate,
	caKey ed25519.PrivateKey,
	instanceID string,
	csrValue string,
	now time.Time,
) ([]byte, time.Time, error) {
	block, rest := pem.Decode([]byte(csrValue))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, time.Time{}, errors.New("invalid enrollment CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return nil, time.Time{}, errors.New("invalid enrollment CSR")
	}
	identityURI, err := url.Parse(
		"spiffe://owndock/organizations/" + organizationID + "/managed-hosts/" + managedHostID +
			"/agents/" + identityID + "/instances/" + instanceID,
	)
	if err != nil {
		return nil, time.Time{}, err
	}
	expires := now.Add(24 * time.Hour).UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "owndock-agent:" + identityID},
		NotBefore: now.Add(-time.Minute), NotAfter: expires,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true, URIs: []*url.URL{identityURI},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, ca, csr.PublicKey, caKey)
	if err != nil {
		return nil, time.Time{}, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), expires, nil
}

func pathsFor(directory string) (materialPaths, error) {
	cleaned, err := cleanAbsolute(directory)
	if err != nil {
		return materialPaths{}, err
	}
	return materialPaths{
		directory: cleaned, caCertificate: filepath.Join(cleaned, "ca.pem"),
		caKey: filepath.Join(cleaned, "ca-key.pem"), serverBundle: filepath.Join(cleaned, "server.pem"),
	}, nil
}

func cleanOutput(value string) (string, error) {
	cleaned, err := cleanAbsolute(value)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(filepath.Dir(cleaned))
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("output parent must be a real directory")
	}
	if _, err := os.Lstat(cleaned); err == nil || !errors.Is(err, os.ErrNotExist) {
		return "", errors.New("output path must not exist")
	}
	return cleaned, nil
}

func cleanInput(value string) (string, error) {
	cleaned, err := cleanAbsolute(value)
	if err != nil {
		return "", err
	}
	contents, err := readRegular(cleaned, 0o077)
	if err != nil {
		return "", err
	}
	clearBytes(contents)
	return cleaned, nil
}

func cleanAbsolute(value string) (string, error) {
	if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value {
		return "", errors.New("path must be clean and absolute")
	}
	return value, nil
}

func readRegular(path string, forbiddenMode os.FileMode) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&forbiddenMode != 0 || info.Size() > maximumBody {
		return nil, errors.New("fixture input must be a private regular file")
	}
	return os.ReadFile(path)
}

func writeFile(path string, value []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err = file.Write(value); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(path)
	}
	return err
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
