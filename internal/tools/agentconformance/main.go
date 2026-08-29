package main

import (
	"bufio"
	"bytes"
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

	agentconfig "github.com/owndock/owndock/internal/agent/config"
	"github.com/owndock/owndock/internal/shared/agentprotocol"
)

const (
	organizationID = "conformance-organization"
	hostID         = "conformance-host"
	identityID     = "conformance-identity"
	instanceID     = "conformance-instance"
	contentType    = "application/x-ndjson"
)

type materialPaths struct {
	directory    string
	ca           string
	caKey        string
	serverBundle string
	clientCert   string
	clientKey    string
	clientBundle string
	bootID       string
	state        string
	config       string
}

type fixtureIdentity struct {
	organizationID string
	hostID         string
	identityID     string
	instanceID     string
}

func newFixtureIdentity(host, identity, instance string) (fixtureIdentity, error) {
	for _, value := range []string{host, identity, instance} {
		if value == "" || len(value) > 128 || value[0] == '.' {
			return fixtureIdentity{}, errors.New("fixture identity is invalid")
		}
		for _, character := range value {
			if character >= 'a' && character <= 'z' ||
				character >= 'A' && character <= 'Z' ||
				character >= '0' && character <= '9' ||
				character == '-' || character == '_' || character == '.' {
				continue
			}
			return fixtureIdentity{}, errors.New("fixture identity is invalid")
		}
	}
	return fixtureIdentity{
		organizationID: organizationID, hostID: host,
		identityID: identity, instanceID: instance,
	}, nil
}

type agentFrame struct {
	Type     string      `json:"type"`
	Sequence uint64      `json:"sequence"`
	Hello    *agentHello `json:"hello,omitempty"`
}

type agentHello struct {
	OrganizationID  string   `json:"organization_id"`
	ManagedHostID   string   `json:"managed_host_id"`
	AgentIdentityID string   `json:"agent_identity_id"`
	InstanceID      string   `json:"instance_id"`
	BootID          string   `json:"boot_id"`
	AgentVersion    string   `json:"agent_version"`
	ProtocolVersion string   `json:"protocol_version"`
	Capabilities    []string `json:"capabilities"`
}

type serverFrame struct {
	Type                     string    `json:"type"`
	Sequence                 uint64    `json:"sequence"`
	SessionID                string    `json:"session_id,omitempty"`
	ProtocolVersion          string    `json:"protocol_version,omitempty"`
	HeartbeatIntervalSeconds int64     `json:"heartbeat_interval_seconds,omitempty"`
	MaxFrameBytes            int       `json:"max_frame_bytes,omitempty"`
	AcknowledgedSequence     uint64    `json:"acknowledged_sequence,omitempty"`
	ServerTime               time.Time `json:"server_time,omitzero"`
}

func main() {
	if len(os.Args) < 2 {
		fatal(errors.New("usage: agentconformance materials|identity|config|serve|serve-dual|rotation-serve"))
	}
	var err error
	switch os.Args[1] {
	case "materials":
		err = runMaterials(os.Args[2:])
	case "identity":
		err = runIdentity(os.Args[2:])
	case "config":
		err = runConfig(os.Args[2:])
	case "serve":
		err = runServer(os.Args[2:])
	case "serve-dual":
		err = runDualServer(os.Args[2:])
	case "rotation-serve":
		err = runRotationServer(os.Args[2:])
	default:
		err = errors.New("usage: agentconformance materials|identity|config|serve|serve-dual|rotation-serve")
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
	var output, fixtureHostID, fixtureIdentityID, fixtureInstanceID string
	flags.StringVar(&output, "output", "", "absolute output directory")
	flags.StringVar(&fixtureHostID, "host-id", hostID, "fixture managed host ID")
	flags.StringVar(&fixtureIdentityID, "identity-id", identityID, "fixture Agent identity ID")
	flags.StringVar(&fixtureInstanceID, "instance-id", instanceID, "fixture Agent instance ID")
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
	directoryInfo, err := os.Lstat(paths.directory)
	if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("conformance material directory must not be a symlink")
	}
	entries, err := os.ReadDir(paths.directory)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return errors.New("conformance material directory must be empty")
	}
	if err := os.Mkdir(paths.state, 0o700); err != nil {
		return err
	}
	if err := writeFile(paths.bootID, []byte("conformance-boot\n"), 0o600); err != nil {
		return err
	}
	fixtureIdentity, err := newFixtureIdentity(fixtureHostID, fixtureIdentityID, fixtureInstanceID)
	if err != nil {
		return err
	}
	return generatePKI(paths, fixtureIdentity, time.Now().UTC())
}

func runIdentity(arguments []string) error {
	flags := flag.NewFlagSet("identity", flag.ContinueOnError)
	var authority, output, fixtureHostID, fixtureIdentityID, fixtureInstanceID string
	flags.StringVar(&authority, "authority", "", "absolute authority material directory")
	flags.StringVar(&output, "output", "", "absolute empty output directory")
	flags.StringVar(&fixtureHostID, "host-id", "", "fixture managed host ID")
	flags.StringVar(&fixtureIdentityID, "identity-id", identityID, "fixture Agent identity ID")
	flags.StringVar(&fixtureInstanceID, "instance-id", instanceID, "fixture Agent instance ID")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("identity arguments are invalid")
	}
	authorityPaths, err := pathsFor(authority)
	if err != nil {
		return err
	}
	outputPaths, err := pathsFor(output)
	if err != nil || authorityPaths.directory == outputPaths.directory {
		return errors.New("identity output must differ from its authority")
	}
	identity, err := newFixtureIdentity(fixtureHostID, fixtureIdentityID, fixtureInstanceID)
	if err != nil {
		return err
	}
	if err := initializeMaterialDirectory(outputPaths); err != nil {
		return err
	}
	caCertificate, caPrivate, caPEM, err := loadRotationIssuer(authorityPaths)
	if err != nil {
		return err
	}
	defer clearBytes(caPrivate)
	defer clearBytes(caPEM)
	if err := writeFile(outputPaths.ca, caPEM, 0o644); err != nil {
		return err
	}
	return issueFixtureClientIdentity(
		outputPaths, identity, big.NewInt(5), caCertificate, caPrivate, time.Now().UTC(),
	)
}

func initializeMaterialDirectory(paths materialPaths) error {
	if err := os.MkdirAll(paths.directory, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(paths.directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("conformance material directory must be a real directory")
	}
	entries, err := os.ReadDir(paths.directory)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return errors.New("conformance material directory must be empty")
	}
	if err := os.Mkdir(paths.state, 0o700); err != nil {
		return err
	}
	return writeFile(paths.bootID, []byte("conformance-boot\n"), 0o600)
}

func runConfig(arguments []string) error {
	flags := flag.NewFlagSet("config", flag.ContinueOnError)
	var output, endpoint, fixtureHostID, fixtureIdentityID, fixtureInstanceID string
	var enableRotation bool
	flags.StringVar(&output, "output", "", "absolute material directory")
	flags.StringVar(&endpoint, "endpoint", "", "Agent control HTTPS endpoint")
	flags.BoolVar(&enableRotation, "enable-rotation", false, "enable immediate conformance rotation")
	flags.StringVar(&fixtureHostID, "host-id", hostID, "fixture managed host ID")
	flags.StringVar(&fixtureIdentityID, "identity-id", identityID, "fixture Agent identity ID")
	flags.StringVar(&fixtureInstanceID, "instance-id", instanceID, "fixture Agent instance ID")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("config requires --output and --endpoint")
	}
	paths, err := pathsFor(output)
	if err != nil {
		return err
	}
	fixtureIdentity, err := newFixtureIdentity(fixtureHostID, fixtureIdentityID, fixtureInstanceID)
	if err != nil {
		return err
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() != "127.0.0.1" ||
		parsed.Path != "/api/v1/agent/connect" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("conformance endpoint is invalid")
	}
	for _, required := range []string{
		paths.ca, paths.clientCert, paths.clientKey, paths.bootID,
	} {
		if _, err := regularFile(required); err != nil {
			return err
		}
	}
	config := agentconfig.Defaults()
	config.Control.Endpoint = endpoint
	config.Control.OrganizationID = fixtureIdentity.organizationID
	config.Control.ManagedHostID = fixtureIdentity.hostID
	config.Control.IdentityID = fixtureIdentity.identityID
	config.Control.InstanceID = fixtureIdentity.instanceID
	config.Control.BootIDFile = paths.bootID
	config.Control.CACertificateFile = paths.ca
	if enableRotation {
		config.Control.ClientCertificateFile = paths.clientBundle
		config.Control.ClientPrivateKeyFile = paths.clientBundle
	} else {
		config.Control.ClientCertificateFile = paths.clientCert
		config.Control.ClientPrivateKeyFile = paths.clientKey
	}
	config.Control.ReconnectMinimum = "100ms"
	config.Control.ReconnectMaximum = "500ms"
	config.Control.ReconnectStableAfter = "1s"
	config.Control.Capabilities = []string{agentprotocol.CapabilityRuntimeProbe}
	config.Runtime.StateDirectory = paths.state
	config.CertificateRotation.Enabled = enableRotation
	if enableRotation {
		config.CertificateRotation.RenewBefore = "24h"
		config.CertificateRotation.RetryDelay = "1m"
		config.CertificateRotation.RequestTimeout = "2s"
	}
	value, err := agentconfig.MarshalYAML(config)
	if err != nil {
		return err
	}
	return writeFile(paths.config, value, 0o600)
}

func runServer(arguments []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	var listen, materialDirectory, readyFile, resultFile string
	var fixtureHostID, fixtureIdentityID, fixtureInstanceID string
	var timeout time.Duration
	var expectedClientSerial int64
	flags.StringVar(&listen, "listen", "127.0.0.1:0", "loopback listen address")
	flags.StringVar(&materialDirectory, "materials", "", "absolute material directory")
	flags.StringVar(&readyFile, "ready-file", "", "absolute endpoint output file")
	flags.StringVar(&resultFile, "result-file", "", "absolute result output file")
	flags.Int64Var(&expectedClientSerial, "expected-client-serial", 0, "optional exact client certificate serial")
	flags.StringVar(&fixtureHostID, "host-id", hostID, "fixture managed host ID")
	flags.StringVar(&fixtureIdentityID, "identity-id", identityID, "fixture Agent identity ID")
	flags.StringVar(&fixtureInstanceID, "instance-id", instanceID, "fixture Agent instance ID")
	flags.DurationVar(&timeout, "timeout", 30*time.Second, "one-shot conformance timeout")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || timeout <= 0 {
		return errors.New("serve arguments are invalid")
	}
	paths, err := pathsFor(materialDirectory)
	if err != nil {
		return err
	}
	fixtureIdentity, err := newFixtureIdentity(fixtureHostID, fixtureIdentityID, fixtureInstanceID)
	if err != nil {
		return err
	}
	readyFile, err = cleanAbsoluteOutput(readyFile)
	if err != nil {
		return err
	}
	resultFile, err = cleanAbsoluteOutput(resultFile)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(listen, "127.0.0.1:") {
		return errors.New("conformance server must listen on IPv4 loopback")
	}
	serverPEM, err := os.ReadFile(paths.serverBundle)
	if err != nil {
		return err
	}
	serverCertificate, err := tls.X509KeyPair(serverPEM, serverPEM)
	clearBytes(serverPEM)
	if err != nil {
		return err
	}
	caPEM, err := os.ReadFile(paths.ca)
	if err != nil {
		return err
	}
	clientRoots := x509.NewCertPool()
	if !clientRoots.AppendCertsFromPEM(caPEM) {
		return errors.New("parse conformance CA")
	}
	listener, err := net.Listen("tcp4", listen)
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()
	endpoint := "https://" + listener.Addr().String() + "/api/v1/agent/connect"
	if err := writeFile(readyFile, []byte(endpoint+"\n"), 0o600); err != nil {
		return err
	}

	completed := make(chan error, 1)
	handler := &conformanceHandler{
		resultFile: resultFile, completed: completed,
		expectedClientSerial: expectedClientSerial, identity: fixtureIdentity,
	}
	server := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler:           handler,
	}
	tlsListener := tls.NewListener(listener, &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCertificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientRoots,
		NextProtos:   []string{"http/1.1"},
	})
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(tlsListener) }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-completed:
		shutdownContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownContext)
		if err != nil {
			return err
		}
	case err := <-serveDone:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-timer.C:
		_ = server.Close()
		return errors.New("Agent conformance timed out")
	}
	return nil
}

func runDualServer(arguments []string) error {
	flags := flag.NewFlagSet("serve-dual", flag.ContinueOnError)
	var listen, materialDirectory, readyFile, resultA, resultB string
	var hostA, hostB, fixtureIdentityID, fixtureInstanceID, onlyHost string
	var timeout time.Duration
	flags.StringVar(&listen, "listen", "127.0.0.1:0", "loopback listen address")
	flags.StringVar(&materialDirectory, "materials", "", "authority material directory")
	flags.StringVar(&readyFile, "ready-file", "", "absolute endpoint output file")
	flags.StringVar(&resultA, "result-a", "", "Host A result output file")
	flags.StringVar(&resultB, "result-b", "", "Host B result output file")
	flags.StringVar(&hostA, "host-a", "conformance-host-a", "first managed host ID")
	flags.StringVar(&hostB, "host-b", "conformance-host-b", "second managed host ID")
	flags.StringVar(&fixtureIdentityID, "identity-id", identityID, "fixture Agent identity ID")
	flags.StringVar(&fixtureInstanceID, "instance-id", instanceID, "fixture Agent instance ID")
	flags.StringVar(&onlyHost, "only-host", "", "temporarily accept only this Host")
	flags.DurationVar(&timeout, "timeout", 30*time.Second, "conformance timeout")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || timeout <= 0 ||
		hostA == hostB || onlyHost != "" && onlyHost != hostA && onlyHost != hostB {
		return errors.New("serve-dual arguments are invalid")
	}
	if !strings.HasPrefix(listen, "127.0.0.1:") {
		return errors.New("dual conformance server must listen on IPv4 loopback")
	}
	identityA, err := newFixtureIdentity(hostA, fixtureIdentityID, fixtureInstanceID)
	if err != nil {
		return err
	}
	identityB, err := newFixtureIdentity(hostB, fixtureIdentityID, fixtureInstanceID)
	if err != nil {
		return err
	}
	paths, err := pathsFor(materialDirectory)
	if err != nil {
		return err
	}
	for target, value := range map[string]*string{
		"ready": &readyFile, "result-a": &resultA, "result-b": &resultB,
	} {
		cleaned, cleanErr := cleanAbsoluteOutput(*value)
		if cleanErr != nil {
			return fmt.Errorf("%s output: %w", target, cleanErr)
		}
		*value = cleaned
	}
	serverPEM, err := os.ReadFile(paths.serverBundle)
	if err != nil {
		return err
	}
	serverCertificate, err := tls.X509KeyPair(serverPEM, serverPEM)
	clearBytes(serverPEM)
	if err != nil {
		return err
	}
	caPEM, err := os.ReadFile(paths.ca)
	if err != nil {
		return err
	}
	clientRoots := x509.NewCertPool()
	if !clientRoots.AppendCertsFromPEM(caPEM) {
		return errors.New("parse dual conformance CA")
	}
	listener, err := net.Listen("tcp4", listen)
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()
	endpoint := "https://" + listener.Addr().String() + "/api/v1/agent/connect"
	if err := writeFile(readyFile, []byte(endpoint+"\n"), 0o600); err != nil {
		return err
	}
	completed := make(chan error, 1)
	handler := &dualConformanceHandler{
		identities: map[string]fixtureIdentity{hostA: identityA, hostB: identityB},
		results:    map[string]string{hostA: resultA, hostB: resultB},
		onlyHost:   onlyHost, states: make(map[string]bool), completed: completed,
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	tlsListener := tls.NewListener(listener, &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCertificate},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots,
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
		return errors.New("dual Agent conformance timed out")
	}
}

type dualConformanceHandler struct {
	identities map[string]fixtureIdentity
	results    map[string]string
	onlyHost   string
	states     map[string]bool
	completed  chan<- error
	mu         sync.Mutex
	once       sync.Once
}

func (handler *dualConformanceHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	host, identity := handler.matchIdentity(request)
	if host == "" {
		http.Error(writer, "unknown Agent identity", http.StatusUnauthorized)
		handler.once.Do(func() { handler.completed <- errors.New("unknown dual Agent identity") })
		return
	}
	if handler.onlyHost != "" && host != handler.onlyHost {
		child := &conformanceHandler{resultFile: handler.results[host], identity: identity}
		if err := child.handle(writer, request); err != nil {
			handler.once.Do(func() { handler.completed <- err })
		}
		return
	}
	handler.mu.Lock()
	if handler.states[host] {
		handler.mu.Unlock()
		child := &conformanceHandler{resultFile: handler.results[host], identity: identity}
		if err := child.handle(writer, request); err != nil {
			handler.once.Do(func() { handler.completed <- err })
		}
		return
	}
	handler.states[host] = true
	handler.mu.Unlock()
	child := &conformanceHandler{resultFile: handler.results[host], identity: identity}
	err := child.handle(writer, request)
	if err != nil {
		handler.mu.Lock()
		delete(handler.states, host)
		handler.mu.Unlock()
		handler.once.Do(func() { handler.completed <- err })
		return
	}
	handler.mu.Lock()
	required := len(handler.identities)
	if handler.onlyHost != "" {
		required = 1
	}
	finished := len(handler.states) == required
	handler.mu.Unlock()
	if finished {
		handler.once.Do(func() { handler.completed <- nil })
	}
}

func (handler *dualConformanceHandler) matchIdentity(request *http.Request) (string, fixtureIdentity) {
	if request.TLS == nil || len(request.TLS.VerifiedChains) == 0 ||
		len(request.TLS.PeerCertificates) == 0 || len(request.TLS.PeerCertificates[0].URIs) != 1 {
		return "", fixtureIdentity{}
	}
	actual := request.TLS.PeerCertificates[0].URIs[0].String()
	for host, identity := range handler.identities {
		if actual == fixtureIdentityURI(identity) {
			return host, identity
		}
	}
	return "", fixtureIdentity{}
}

func fixtureIdentityURI(identity fixtureIdentity) string {
	return "spiffe://owndock/organizations/" + identity.organizationID +
		"/managed-hosts/" + identity.hostID + "/agents/" + identity.identityID +
		"/instances/" + identity.instanceID
}

type rotationRequest struct {
	RotationID string `json:"rotation_id"`
	CSRPEM     string `json:"csr_pem"`
}

type rotationResponse struct {
	AgentIdentityID      string    `json:"agent_identity_id"`
	ManagedHostID        string    `json:"managed_host_id"`
	RotationID           string    `json:"rotation_id"`
	CertificatePEM       string    `json:"certificate_pem"`
	CACertificatePEM     string    `json:"ca_certificate_pem"`
	CertificateExpiresAt time.Time `json:"certificate_expires_at"`
}

func runRotationServer(arguments []string) error {
	flags := flag.NewFlagSet("rotation-serve", flag.ContinueOnError)
	var listen, materialDirectory, readyFile, requestFile, expectedRequestFile, mode string
	var timeout time.Duration
	flags.StringVar(&listen, "listen", "127.0.0.1:0", "loopback listen address")
	flags.StringVar(&materialDirectory, "materials", "", "absolute material directory")
	flags.StringVar(&readyFile, "ready-file", "", "absolute endpoint output file")
	flags.StringVar(&requestFile, "request-file", "", "absolute canonical request output file")
	flags.StringVar(&expectedRequestFile, "expected-request-file", "", "exact prior request for recovery")
	flags.StringVar(&mode, "mode", "", "drop or respond")
	flags.DurationVar(&timeout, "timeout", 30*time.Second, "one-shot conformance timeout")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || timeout <= 0 ||
		mode != "drop" && mode != "respond" || mode == "respond" && expectedRequestFile == "" {
		return errors.New("rotation-serve arguments are invalid")
	}
	if !strings.HasPrefix(listen, "127.0.0.1:") {
		return errors.New("rotation conformance server must listen on IPv4 loopback")
	}
	paths, err := pathsFor(materialDirectory)
	if err != nil {
		return err
	}
	readyFile, err = cleanAbsoluteOutput(readyFile)
	if err != nil {
		return err
	}
	requestFile, err = cleanAbsoluteOutput(requestFile)
	if err != nil {
		return err
	}
	if expectedRequestFile != "" {
		expectedRequestFile, err = cleanAbsoluteInput(expectedRequestFile)
		if err != nil {
			return err
		}
	}
	serverPEM, err := os.ReadFile(paths.serverBundle)
	if err != nil {
		return err
	}
	serverCertificate, err := tls.X509KeyPair(serverPEM, serverPEM)
	clearBytes(serverPEM)
	if err != nil {
		return err
	}
	caCertificate, caPrivate, caPEM, err := loadRotationIssuer(paths)
	if err != nil {
		return err
	}
	defer clearBytes(caPrivate)
	defer clearBytes(caPEM)
	clientRoots := x509.NewCertPool()
	if !clientRoots.AppendCertsFromPEM(caPEM) {
		return errors.New("parse rotation conformance CA")
	}
	listener, err := net.Listen("tcp4", listen)
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()
	endpoint := "https://" + listener.Addr().String() + "/api/v1/agent/connect"
	if err := writeFile(readyFile, []byte(endpoint+"\n"), 0o600); err != nil {
		return err
	}
	completed := make(chan error, 1)
	handler := &rotationHandler{
		mode: mode, requestFile: requestFile, expectedRequestFile: expectedRequestFile,
		caCertificate: caCertificate, caPrivate: caPrivate, caPEM: caPEM,
		completed: completed,
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	tlsListener := tls.NewListener(listener, &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCertificate},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots,
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
		return errors.New("Agent rotation conformance timed out")
	}
}

type rotationHandler struct {
	mode                string
	requestFile         string
	expectedRequestFile string
	caCertificate       *x509.Certificate
	caPrivate           ed25519.PrivateKey
	caPEM               []byte
	completed           chan<- error
	once                sync.Once
}

func (handler *rotationHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path == "/api/v1/agent/connect" {
		http.Error(writer, "control stream unavailable during rotation fixture", http.StatusServiceUnavailable)
		return
	}
	if request.URL.Path != "/api/v1/agent/certificate:rotate" {
		http.NotFound(writer, request)
		return
	}
	err := handler.handle(writer, request)
	handler.once.Do(func() { handler.completed <- err })
}

func (handler *rotationHandler) handle(writer http.ResponseWriter, request *http.Request) error {
	if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/json" ||
		request.URL.RawQuery != "" || request.TLS == nil || len(request.TLS.VerifiedChains) == 0 {
		return errors.New("invalid Agent rotation request metadata")
	}
	peer := request.TLS.PeerCertificates[0]
	expectedURI := "spiffe://owndock/organizations/" + organizationID +
		"/managed-hosts/" + hostID + "/agents/" + identityID +
		"/instances/" + instanceID
	if peer.SerialNumber == nil || !peer.SerialNumber.IsInt64() || peer.SerialNumber.Int64() != 3 ||
		len(peer.URIs) != 1 || peer.URIs[0].String() != expectedURI {
		return errors.New("rotation was not authenticated by the original Agent certificate")
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, 64*1024+1))
	if err != nil || len(body) == 0 || len(body) > 64*1024 {
		return errors.New("invalid Agent rotation request body")
	}
	defer clearBytes(body)
	var input rotationRequest
	if err := decodeStrict(body, &input); err != nil || input.RotationID == "" ||
		len(input.RotationID) > 128 || len(input.CSRPEM) == 0 || len(input.CSRPEM) > 16*1024 {
		return errors.New("invalid Agent rotation request")
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
		if !bytes.Equal(expected, canonical) {
			return errors.New("recovered rotation changed its rotation ID or CSR")
		}
	}
	if err := writeFile(handler.requestFile, canonical, 0o600); err != nil {
		return err
	}
	if handler.mode == "drop" {
		hijacker, ok := writer.(http.Hijacker)
		if !ok {
			return errors.New("rotation response connection cannot be interrupted")
		}
		connection, _, err := hijacker.Hijack()
		if err != nil {
			return err
		}
		return connection.Close()
	}
	certificatePEM, expires, err := issueRotatedCertificate(
		handler.caCertificate, handler.caPrivate, input.CSRPEM, time.Now().UTC(),
	)
	if err != nil {
		return err
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusCreated)
	return json.NewEncoder(writer).Encode(rotationResponse{
		AgentIdentityID: identityID, ManagedHostID: hostID, RotationID: input.RotationID,
		CertificatePEM: string(certificatePEM), CACertificatePEM: string(handler.caPEM),
		CertificateExpiresAt: expires,
	})
}

func loadRotationIssuer(paths materialPaths) (*x509.Certificate, ed25519.PrivateKey, []byte, error) {
	caPEM, err := os.ReadFile(paths.ca)
	if err != nil {
		return nil, nil, nil, err
	}
	block, rest := pem.Decode(caPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		clearBytes(caPEM)
		return nil, nil, nil, errors.New("invalid conformance CA certificate")
	}
	caCertificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !caCertificate.IsCA {
		clearBytes(caPEM)
		return nil, nil, nil, errors.New("invalid conformance CA certificate")
	}
	info, err := regularFile(paths.caKey)
	if err != nil || info.Mode().Perm()&0o077 != 0 {
		clearBytes(caPEM)
		return nil, nil, nil, errors.New("conformance CA key must be private")
	}
	keyPEM, err := os.ReadFile(paths.caKey)
	if err != nil {
		clearBytes(caPEM)
		return nil, nil, nil, err
	}
	defer clearBytes(keyPEM)
	keyBlock, keyRest := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" || len(bytes.TrimSpace(keyRest)) != 0 {
		clearBytes(caPEM)
		return nil, nil, nil, errors.New("invalid conformance CA key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	caPrivate, ok := parsed.(ed25519.PrivateKey)
	if err != nil || !ok || !caPrivate.Public().(ed25519.PublicKey).Equal(caCertificate.PublicKey) {
		clearBytes(caPEM)
		return nil, nil, nil, errors.New("conformance CA key does not match certificate")
	}
	return caCertificate, caPrivate, caPEM, nil
}

func issueRotatedCertificate(
	ca *x509.Certificate,
	caPrivate ed25519.PrivateKey,
	csrValue string,
	now time.Time,
) ([]byte, time.Time, error) {
	block, rest := pem.Decode([]byte(csrValue))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, time.Time{}, errors.New("invalid rotation CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return nil, time.Time{}, errors.New("invalid rotation CSR")
	}
	identityURI, err := url.Parse(
		"spiffe://owndock/organizations/" + organizationID + "/managed-hosts/" + hostID +
			"/agents/" + identityID + "/instances/" + instanceID,
	)
	if err != nil {
		return nil, time.Time{}, err
	}
	expires := now.Add(30 * 24 * time.Hour).UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(4), Subject: pkix.Name{CommonName: "OwnDock Agent Rotated Client"},
		NotBefore: now.Add(-time.Minute), NotAfter: expires,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:        []*url.URL{identityURI},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, ca, csr.PublicKey, caPrivate)
	if err != nil {
		return nil, time.Time{}, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), expires, nil
}

type conformanceHandler struct {
	resultFile           string
	completed            chan<- error
	expectedClientSerial int64
	identity             fixtureIdentity
	once                 sync.Once
}

func (h *conformanceHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	err := h.handle(writer, request)
	h.once.Do(func() { h.completed <- err })
}

func (h *conformanceHandler) handle(writer http.ResponseWriter, request *http.Request) error {
	if request.Method != http.MethodPost || request.URL.Path != "/api/v1/agent/connect" ||
		request.Header.Get("Content-Type") != contentType || request.TLS == nil ||
		len(request.TLS.VerifiedChains) == 0 {
		http.Error(writer, "invalid conformance request", http.StatusBadRequest)
		return errors.New("invalid Agent conformance request")
	}
	peer := request.TLS.PeerCertificates[0]
	expectedURI := "spiffe://owndock/organizations/" + h.identity.organizationID +
		"/managed-hosts/" + h.identity.hostID + "/agents/" + h.identity.identityID +
		"/instances/" + h.identity.instanceID
	if len(peer.URIs) != 1 || peer.URIs[0].String() != expectedURI {
		http.Error(writer, "invalid conformance identity", http.StatusUnauthorized)
		return errors.New("Agent conformance certificate identity is invalid")
	}
	if h.expectedClientSerial > 0 &&
		(peer.SerialNumber == nil || !peer.SerialNumber.IsInt64() ||
			peer.SerialNumber.Int64() != h.expectedClientSerial) {
		http.Error(writer, "invalid conformance certificate serial", http.StatusUnauthorized)
		return errors.New("Agent conformance certificate serial is invalid")
	}
	controller := http.NewResponseController(writer)
	if err := controller.EnableFullDuplex(); err != nil {
		return err
	}
	scanner := bufio.NewScanner(request.Body)
	scanner.Buffer(make([]byte, 4096), 64*1024)
	if !scanner.Scan() {
		return errors.New("Agent hello is missing")
	}
	var helloFrame agentFrame
	if err := decodeStrict(scanner.Bytes(), &helloFrame); err != nil {
		return fmt.Errorf("decode Agent hello: %w", err)
	}
	if helloFrame.Type != "hello" || helloFrame.Sequence != 1 || helloFrame.Hello == nil {
		return errors.New("Agent hello shape is invalid")
	}
	hello := helloFrame.Hello
	if hello.OrganizationID != h.identity.organizationID || hello.ManagedHostID != h.identity.hostID ||
		hello.AgentIdentityID != h.identity.identityID || hello.InstanceID != h.identity.instanceID ||
		hello.BootID != "conformance-boot" || hello.AgentVersion == "" ||
		hello.ProtocolVersion != agentprotocol.Version ||
		len(hello.Capabilities) != 1 ||
		hello.Capabilities[0] != agentprotocol.CapabilityRuntimeProbe {
		return errors.New("Agent hello identity, version, or capabilities are invalid")
	}
	writer.Header().Set("Content-Type", contentType)
	writer.WriteHeader(http.StatusOK)
	encoder := json.NewEncoder(writer)
	if err := encoder.Encode(serverFrame{
		Type: "hello_ack", Sequence: 1,
		SessionID: "conformance-session", ProtocolVersion: agentprotocol.Version,
		HeartbeatIntervalSeconds: 1, MaxFrameBytes: 64 * 1024,
		ServerTime: time.Now().UTC(),
	}); err != nil {
		return err
	}
	if err := controller.Flush(); err != nil {
		return err
	}
	if !scanner.Scan() {
		return errors.New("Agent heartbeat is missing")
	}
	var heartbeat agentFrame
	if err := decodeStrict(scanner.Bytes(), &heartbeat); err != nil {
		return fmt.Errorf("decode Agent heartbeat: %w", err)
	}
	if heartbeat.Type != "heartbeat" || heartbeat.Sequence <= helloFrame.Sequence ||
		heartbeat.Hello != nil {
		return errors.New("Agent heartbeat shape is invalid")
	}
	if err := encoder.Encode(serverFrame{
		Type: "heartbeat_ack", Sequence: 2,
		AcknowledgedSequence: heartbeat.Sequence,
		ServerTime:           time.Now().UTC(),
	}); err != nil {
		return err
	}
	if err := controller.Flush(); err != nil {
		return err
	}
	result := fmt.Sprintf(
		"agent_version=%s\nprotocol_version=%s\nmanaged_host_id=%s\ncertificate_serial=%s\nstatus=passed\n",
		hello.AgentVersion,
		hello.ProtocolVersion,
		hello.ManagedHostID,
		peer.SerialNumber.String(),
	)
	return writeFile(h.resultFile, []byte(result), 0o600)
}

func decodeStrict(value []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("frame contains more than one JSON value")
	}
	return nil
}

func generatePKI(paths materialPaths, identity fixtureIdentity, now time.Time) error {
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "OwnDock Agent Conformance CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		return err
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if err := writeFile(paths.ca, caPEM, 0o644); err != nil {
		return err
	}
	caKeyDER, err := x509.MarshalPKCS8PrivateKey(caPrivate)
	if err != nil {
		return err
	}
	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: caKeyDER})
	defer clearBytes(caKeyPEM)
	if err := writeFile(paths.caKey, caKeyPEM, 0o600); err != nil {
		return err
	}
	if err := issueCertificate(
		paths.serverBundle, "", "OwnDock Agent Conformance Server", big.NewInt(2),
		x509.ExtKeyUsageServerAuth, []net.IP{net.ParseIP("127.0.0.1")}, nil,
		caCertificate, caPrivate, now, true,
	); err != nil {
		return err
	}
	return issueFixtureClientIdentity(paths, identity, big.NewInt(3), caCertificate, caPrivate, now)
}

func issueFixtureClientIdentity(
	paths materialPaths,
	identity fixtureIdentity,
	serial *big.Int,
	caCertificate *x509.Certificate,
	caPrivate ed25519.PrivateKey,
	now time.Time,
) error {
	identityURI, err := url.Parse(
		"spiffe://owndock/organizations/" + identity.organizationID +
			"/managed-hosts/" + identity.hostID + "/agents/" + identity.identityID +
			"/instances/" + identity.instanceID,
	)
	if err != nil {
		return err
	}
	if err := issueCertificate(
		paths.clientCert, paths.clientKey,
		"OwnDock Agent Conformance Client", serial,
		x509.ExtKeyUsageClientAuth, nil, []*url.URL{identityURI},
		caCertificate, caPrivate, now, false,
	); err != nil {
		return err
	}
	certificatePEM, err := os.ReadFile(paths.clientCert)
	if err != nil {
		return err
	}
	privateKeyPEM, err := os.ReadFile(paths.clientKey)
	if err != nil {
		return err
	}
	defer clearBytes(privateKeyPEM)
	return writeFile(paths.clientBundle, append(certificatePEM, privateKeyPEM...), 0o600)
}

func issueCertificate(
	certificateOutput, privateKeyOutput, commonName string,
	serial *big.Int,
	usage x509.ExtKeyUsage,
	addresses []net.IP,
	identities []*url.URL,
	ca *x509.Certificate,
	caPrivate ed25519.PrivateKey,
	now time.Time,
	combined bool,
) error {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: commonName},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(12 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
		IPAddresses: addresses, URIs: identities,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, ca, publicKey, caPrivate)
	if err != nil {
		return err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	defer clearBytes(privatePEM)
	if combined {
		return writeFile(certificateOutput, append(certificatePEM, privatePEM...), 0o600)
	}
	if strings.TrimSpace(privateKeyOutput) == "" {
		return errors.New("client certificate output is invalid")
	}
	if err := writeFile(certificateOutput, certificatePEM, 0o644); err != nil {
		return err
	}
	return writeFile(privateKeyOutput, privatePEM, 0o600)
}

func pathsFor(directory string) (materialPaths, error) {
	directory = filepath.Clean(strings.TrimSpace(directory))
	if !filepath.IsAbs(directory) || directory == "/" {
		return materialPaths{}, errors.New("conformance output must be an absolute non-root directory")
	}
	return materialPaths{
		directory:    directory,
		ca:           filepath.Join(directory, "ca.pem"),
		caKey:        filepath.Join(directory, "ca-key.pem"),
		serverBundle: filepath.Join(directory, "server.pem"),
		clientCert:   filepath.Join(directory, "client.pem"),
		clientKey:    filepath.Join(directory, "client-key.pem"),
		clientBundle: filepath.Join(directory, "client-identity.pem"),
		bootID:       filepath.Join(directory, "boot-id"),
		state:        filepath.Join(directory, "state"),
		config:       filepath.Join(directory, "agent.yaml"),
	}, nil
}

func cleanAbsoluteOutput(path string) (string, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if !filepath.IsAbs(path) || path == "/" {
		return "", errors.New("conformance output file must be absolute")
	}
	return path, nil
}

func cleanAbsoluteInput(path string) (string, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if !filepath.IsAbs(path) || path == "/" {
		return "", errors.New("conformance input file must be absolute")
	}
	if _, err := regularFile(path); err != nil {
		return "", err
	}
	return path, nil
}

func regularFile(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("conformance input must be a regular file")
	}
	return info, nil
}

func writeFile(path string, value []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".owndock-conformance-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(mode); err != nil {
		return err
	}
	if _, err := temporary.Write(value); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
