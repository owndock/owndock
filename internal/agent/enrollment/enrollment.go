package agentenrollment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	agentconfig "github.com/owndock/owndock/internal/agent/config"
	agentcontrol "github.com/owndock/owndock/internal/agent/control"
	"github.com/owndock/owndock/internal/shared/agentprotocol"
)

const (
	ProtocolVersion       = agentprotocol.Version
	maximumTokenBytes     = 256
	maximumResponseBytes  = 64 * 1024
	maximumMaterialBytes  = 1024 * 1024
	pendingFileName       = "enrollment-pending-v1.json"
	instanceIDFileName    = "instance-id"
	pendingSchemaVersion  = 1
	defaultRequestTimeout = 30 * time.Second
	pendingPhaseRequest   = "request"
	pendingPhaseResponse  = "response"
)

var (
	ErrInvalidEnrollment = errors.New("Agent enrollment configuration is invalid")
	ErrExchangeRejected  = errors.New("Agent enrollment exchange was rejected")
	ErrPendingEnrollment = errors.New("an Agent enrollment response is pending local installation")
	ErrPendingRequest    = errors.New("an Agent enrollment request is pending; retry with the original token and arguments")
	validVersion         = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
)

type Paths struct {
	Config         string
	CACertificate  string
	IdentityBundle string
	StateDirectory string
}

type Options struct {
	EnrollmentEndpoint string
	ControlEndpoint    string
	ServerCAFile       string
	InstanceID         string
	AgentVersion       string
	Capabilities       []string
	HostTerminal       bool
	RequestTimeout     time.Duration
	Paths              Paths
	Now                func() time.Time
}

type Result struct {
	OrganizationID string
	ManagedHostID  string
	IdentityID     string
	InstanceID     string
	ExpiresAt      time.Time
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

type pendingEnrollment struct {
	SchemaVersion      int                `json:"schema_version"`
	Phase              string             `json:"phase"`
	EnrollmentEndpoint string             `json:"enrollment_endpoint"`
	ControlEndpoint    string             `json:"control_endpoint"`
	ServerCAFile       string             `json:"server_ca_file,omitempty"`
	InstanceID         string             `json:"instance_id"`
	AgentVersion       string             `json:"agent_version"`
	Capabilities       []string           `json:"capabilities"`
	HostTerminal       bool               `json:"host_terminal"`
	CSRPEM             []byte             `json:"csr_pem,omitempty"`
	PrivateKeyPEM      []byte             `json:"private_key_pem"`
	Config             agentconfig.Config `json:"config,omitzero"`
	CertificatePEM     []byte             `json:"certificate_pem,omitempty"`
	CACertificatePEM   []byte             `json:"ca_certificate_pem,omitempty"`
	ExpiresAt          time.Time          `json:"expires_at,omitzero"`
}

// StandardCapabilities enables deployment, inventory and container terminal
// support. Host terminal access remains an explicit enrollment decision.
func StandardCapabilities(hostTerminal bool) []string {
	values := []string{
		agentprotocol.CapabilityRuntimeProbe,
		agentprotocol.CapabilityDeploymentPrepare,
		agentprotocol.CapabilityDeploymentStage,
		agentprotocol.CapabilityDeploymentActivate,
		agentprotocol.CapabilityDeploymentCancel,
		agentprotocol.CapabilityCutoverRelease,
		agentprotocol.CapabilityInventoryPrepare,
		agentprotocol.CapabilityInventoryChunk,
		agentprotocol.CapabilityInventoryRelease,
		agentprotocol.CapabilityInventoryEvents,
		agentprotocol.CapabilityTerminalContainer,
	}
	if hostTerminal {
		values = append(values, agentprotocol.CapabilityTerminalHost)
	}
	return values
}

// Provision persists the private key and CSR before the network exchange,
// reuses that exact request after an ambiguous network failure, validates the
// fixed certificate identity and commits config last.
func Provision(ctx context.Context, options Options, token []byte) (Result, error) {
	options, enrollmentURL, err := normalizeOptions(options)
	if err != nil {
		return Result{}, err
	}
	pendingPath := filepath.Join(options.Paths.StateDirectory, pendingFileName)
	pending, exists, err := loadPending(pendingPath)
	if err != nil {
		return Result{}, err
	}
	defer pending.clear()
	if exists && pending.Phase == pendingPhaseResponse {
		return Result{}, ErrPendingEnrollment
	}
	tokenValue, err := normalizeToken(token)
	if err != nil {
		return Result{}, err
	}
	defer clearBytes(tokenValue)
	instanceID, err := ensureInstanceID(options.Paths.StateDirectory, options.InstanceID)
	if err != nil {
		return Result{}, err
	}
	if exists {
		if pending.Phase != pendingPhaseRequest || !pending.matches(options, instanceID) {
			return Result{}, ErrInvalidEnrollment
		}
	} else {
		csrPEM, privateKeyPEM, requestErr := newCertificateRequest()
		if requestErr != nil {
			return Result{}, requestErr
		}
		pending = pendingEnrollment{
			SchemaVersion: pendingSchemaVersion, Phase: pendingPhaseRequest,
			EnrollmentEndpoint: options.EnrollmentEndpoint,
			ControlEndpoint:    options.ControlEndpoint, ServerCAFile: options.ServerCAFile,
			InstanceID: instanceID, AgentVersion: options.AgentVersion,
			Capabilities: append([]string(nil), options.Capabilities...),
			HostTerminal: options.HostTerminal,
			CSRPEM:       csrPEM, PrivateKeyPEM: privateKeyPEM,
		}
		if err := persistPending(pendingPath, pending); err != nil {
			return Result{}, err
		}
	}
	credentials, err := exchange(
		ctx, options, enrollmentURL, tokenValue, instanceID, pending.CSRPEM,
	)
	if err != nil {
		return Result{}, err
	}
	identity, leaf, err := identityFromCertificate(
		[]byte(credentials.CertificatePEM), pending.PrivateKeyPEM,
		credentials.ManagedHostID, credentials.AgentIdentityID, instanceID,
	)
	if err != nil || leaf.NotAfter.Unix() != credentials.CertificateExpires.Unix() {
		return Result{}, ErrInvalidEnrollment
	}
	config := provisionedConfig(options, identity)
	if _, err := agentconfig.MarshalYAML(config); err != nil {
		return Result{}, ErrInvalidEnrollment
	}
	now := options.Now().UTC()
	if err := agentcontrol.ValidateClientIdentityBundle(
		[]byte(credentials.CertificatePEM), pending.PrivateKeyPEM,
		[]byte(credentials.CACertificatePEM), identity, now,
	); err != nil {
		return Result{}, ErrInvalidEnrollment
	}
	pending.Phase = pendingPhaseResponse
	pending.CSRPEM = nil
	pending.Config = config
	pending.CertificatePEM = []byte(credentials.CertificatePEM)
	pending.CACertificatePEM = []byte(credentials.CACertificatePEM)
	pending.ExpiresAt = credentials.CertificateExpires.UTC()
	if err := persistPending(pendingPath, pending); err != nil {
		return Result{}, err
	}
	return installPending(options.Paths, pending, now)
}

// Recover completes local installation after an exchange response was safely
// persisted but the original process stopped before config commit.
func Recover(paths Paths, now time.Time) (Result, error) {
	if err := validatePaths(paths); err != nil {
		return Result{}, err
	}
	pendingPath := filepath.Join(paths.StateDirectory, pendingFileName)
	pending, exists, err := loadPending(pendingPath)
	if err != nil {
		return Result{}, err
	}
	if exists && pending.Phase == pendingPhaseRequest {
		pending.clear()
		return Result{}, ErrPendingRequest
	}
	if !exists || pending.Phase != pendingPhaseResponse {
		pending.clear()
		return Result{}, ErrPendingEnrollment
	}
	defer pending.clear()
	return installPending(paths, pending, now.UTC())
}

func loadPending(path string) (pendingEnrollment, bool, error) {
	value, err := readSecureFile(path, maximumMaterialBytes, true)
	if errors.Is(err, os.ErrNotExist) {
		return pendingEnrollment{}, false, nil
	}
	if err != nil {
		return pendingEnrollment{}, false, fmt.Errorf("read pending Agent enrollment: %w", err)
	}
	defer clearBytes(value)
	var pending pendingEnrollment
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&pending); err != nil {
		return pendingEnrollment{}, false, ErrInvalidEnrollment
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		pending.clear()
		return pendingEnrollment{}, false, ErrInvalidEnrollment
	}
	if pending.SchemaVersion != pendingSchemaVersion ||
		pending.Phase != pendingPhaseRequest && pending.Phase != pendingPhaseResponse ||
		len(pending.PrivateKeyPEM) == 0 {
		pending.clear()
		return pendingEnrollment{}, false, ErrInvalidEnrollment
	}
	return pending, true, nil
}

func persistPending(path string, pending pendingEnrollment) error {
	value, err := json.Marshal(pending)
	if err != nil {
		return fmt.Errorf("encode pending Agent enrollment: %w", err)
	}
	defer clearBytes(value)
	if len(value) > maximumMaterialBytes {
		return ErrInvalidEnrollment
	}
	if err := replaceRegularFile(path, value, 0o600); err != nil {
		return fmt.Errorf("persist pending Agent enrollment: %w", err)
	}
	return nil
}

func (pending pendingEnrollment) matches(options Options, instanceID string) bool {
	return pending.SchemaVersion == pendingSchemaVersion && pending.Phase == pendingPhaseRequest &&
		pending.EnrollmentEndpoint == options.EnrollmentEndpoint &&
		pending.ControlEndpoint == options.ControlEndpoint && pending.ServerCAFile == options.ServerCAFile &&
		pending.InstanceID == instanceID && pending.AgentVersion == options.AgentVersion &&
		pending.HostTerminal == options.HostTerminal &&
		equalStrings(pending.Capabilities, options.Capabilities) &&
		len(pending.CSRPEM) > 0 && len(pending.CSRPEM) <= 16*1024 &&
		len(pending.PrivateKeyPEM) <= maximumMaterialBytes
}

func normalizeOptions(options Options) (Options, *url.URL, error) {
	enrollmentURL, err := validateEndpoint(
		options.EnrollmentEndpoint, "/api/v1/agent/enrollments:exchange",
	)
	if err != nil {
		return Options{}, nil, err
	}
	if _, err := validateEndpoint(options.ControlEndpoint, "/api/v1/agent/connect"); err != nil {
		return Options{}, nil, err
	}
	if !validVersion.MatchString(options.AgentVersion) || len(options.AgentVersion) > 64 ||
		agentconfig.ValidateCapabilities(options.Capabilities) != nil ||
		hasCapability(options.Capabilities, agentprotocol.CapabilityTerminalHost) != options.HostTerminal ||
		validatePaths(options.Paths) != nil {
		return Options{}, nil, ErrInvalidEnrollment
	}
	if options.RequestTimeout == 0 {
		options.RequestTimeout = defaultRequestTimeout
	}
	if options.RequestTimeout < time.Second || options.RequestTimeout > 2*time.Minute {
		return Options{}, nil, ErrInvalidEnrollment
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if strings.TrimSpace(options.ServerCAFile) != "" {
		path := filepath.Clean(strings.TrimSpace(options.ServerCAFile))
		if !filepath.IsAbs(path) {
			return Options{}, nil, ErrInvalidEnrollment
		}
		options.ServerCAFile = path
	}
	options.Capabilities = append([]string(nil), options.Capabilities...)
	return options, enrollmentURL, nil
}

func validateEndpoint(raw, expectedPath string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
		parsed.User != nil || parsed.Path != expectedPath || parsed.RawQuery != "" ||
		parsed.Fragment != "" {
		return nil, ErrInvalidEnrollment
	}
	return parsed, nil
}

func validatePaths(paths Paths) error {
	values := []string{paths.Config, paths.CACertificate, paths.IdentityBundle, paths.StateDirectory}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		clean := filepath.Clean(strings.TrimSpace(value))
		if !filepath.IsAbs(clean) || clean != value {
			return ErrInvalidEnrollment
		}
		if _, exists := seen[clean]; exists {
			return ErrInvalidEnrollment
		}
		seen[clean] = struct{}{}
	}
	return nil
}

func normalizeToken(value []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(value)
	if len(trimmed) < 32 || len(trimmed) > maximumTokenBytes {
		return nil, ErrInvalidEnrollment
	}
	for _, character := range trimmed {
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' || character == '-' || character == '_' {
			continue
		}
		return nil, ErrInvalidEnrollment
	}
	return append([]byte(nil), trimmed...), nil
}

func ensureInstanceID(stateDirectory, requested string) (string, error) {
	path := filepath.Join(stateDirectory, instanceIDFileName)
	value, err := readSecureFile(path, 256, false)
	if err == nil {
		stored := strings.TrimSpace(string(value))
		clearBytes(value)
		if !validIdentifier(stored) || requested != "" && stored != requested {
			return "", ErrInvalidEnrollment
		}
		return stored, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("read Agent instance ID: %w", err)
	}
	instanceID := strings.TrimSpace(requested)
	if instanceID == "" {
		random := make([]byte, 16)
		if _, err := rand.Read(random); err != nil {
			return "", fmt.Errorf("generate Agent instance ID: %w", err)
		}
		instanceID = "instance-" + hex.EncodeToString(random)
		clearBytes(random)
	}
	if !validIdentifier(instanceID) {
		return "", ErrInvalidEnrollment
	}
	if err := replaceRegularFile(path, []byte(instanceID+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("persist Agent instance ID: %w", err)
	}
	return instanceID, nil
}

func newCertificateRequest() ([]byte, []byte, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate Agent enrollment key: %w", err)
	}
	requestDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "owndock-agent-enrollment"},
	}, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create Agent enrollment CSR: %w", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("encode Agent enrollment key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: requestDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), nil
}

func exchange(
	ctx context.Context,
	options Options,
	endpoint *url.URL,
	token []byte,
	instanceID string,
	csrPEM []byte,
) (exchangeResponse, error) {
	roots, err := serverRoots(options.ServerCAFile)
	if err != nil {
		return exchangeResponse{}, err
	}
	requestValue := exchangeRequest{
		EnrollmentToken: string(token), InstanceID: instanceID,
		AgentVersion: options.AgentVersion, ProtocolVersion: ProtocolVersion,
		Capabilities: append([]string(nil), options.Capabilities...),
		CSRPEM:       string(csrPEM),
	}
	body, err := json.Marshal(requestValue)
	if err != nil {
		return exchangeResponse{}, fmt.Errorf("encode Agent enrollment request: %w", err)
	}
	defer clearBytes(body)
	requestContext, cancel := context.WithTimeout(ctx, options.RequestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(
		requestContext, http.MethodPost, endpoint.String(), bytes.NewReader(body),
	)
	if err != nil {
		return exchangeResponse{}, ErrInvalidEnrollment
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	transport := &http.Transport{
		Proxy:             nil,
		DialContext:       (&net.Dialer{Timeout: options.RequestTimeout, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2: true, DisableCompression: true,
		TLSHandshakeTimeout:   options.RequestTimeout,
		ResponseHeaderTimeout: options.RequestTimeout,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("Agent enrollment redirects are not allowed")
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return exchangeResponse{}, fmt.Errorf("exchange Agent enrollment: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maximumResponseBytes))
		return exchangeResponse{}, fmt.Errorf("%w: HTTP %d", ErrExchangeRejected, response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return exchangeResponse{}, ErrInvalidEnrollment
	}
	limited := io.LimitReader(response.Body, maximumResponseBytes+1)
	responseValue, err := io.ReadAll(limited)
	if err != nil || len(responseValue) > maximumResponseBytes {
		return exchangeResponse{}, ErrInvalidEnrollment
	}
	var credentials exchangeResponse
	decoder := json.NewDecoder(bytes.NewReader(responseValue))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&credentials); err != nil {
		return exchangeResponse{}, ErrInvalidEnrollment
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return exchangeResponse{}, ErrInvalidEnrollment
	}
	if !validIdentifier(credentials.AgentIdentityID) ||
		!validIdentifier(credentials.ManagedHostID) ||
		credentials.CertificateExpires.IsZero() ||
		len(credentials.CertificatePEM) > maximumMaterialBytes ||
		len(credentials.CACertificatePEM) > maximumMaterialBytes {
		return exchangeResponse{}, ErrInvalidEnrollment
	}
	return credentials, nil
}

func serverRoots(path string) (*x509.CertPool, error) {
	if path == "" {
		roots, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("load system certificate roots: %w", err)
		}
		return roots, nil
	}
	value, err := readSecureFile(path, maximumMaterialBytes, false)
	if err != nil {
		return nil, fmt.Errorf("read Agent enrollment server CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(value) {
		return nil, ErrInvalidEnrollment
	}
	return roots, nil
}

func identityFromCertificate(
	certificatePEM, privateKeyPEM []byte,
	expectedHost, expectedIdentity, expectedInstance string,
) (agentcontrol.Identity, *x509.Certificate, error) {
	pair, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil || len(pair.Certificate) != 1 {
		return agentcontrol.Identity{}, nil, ErrInvalidEnrollment
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || len(leaf.URIs) != 1 {
		return agentcontrol.Identity{}, nil, ErrInvalidEnrollment
	}
	uri := leaf.URIs[0]
	segments := strings.Split(strings.Trim(uri.Path, "/"), "/")
	if uri.Scheme != "spiffe" || uri.Host != "owndock" || uri.RawQuery != "" ||
		uri.Fragment != "" || len(segments) != 8 ||
		segments[0] != "organizations" || segments[2] != "managed-hosts" ||
		segments[4] != "agents" || segments[6] != "instances" {
		return agentcontrol.Identity{}, nil, ErrInvalidEnrollment
	}
	identity := agentcontrol.Identity{
		OrganizationID: segments[1], ManagedHostID: segments[3],
		IdentityID: segments[5], InstanceID: segments[7],
	}
	if !validIdentifier(identity.OrganizationID) || identity.ManagedHostID != expectedHost ||
		identity.IdentityID != expectedIdentity || identity.InstanceID != expectedInstance {
		return agentcontrol.Identity{}, nil, ErrInvalidEnrollment
	}
	return identity, leaf, nil
}

func provisionedConfig(options Options, identity agentcontrol.Identity) agentconfig.Config {
	config := agentconfig.Defaults()
	config.Control.Endpoint = options.ControlEndpoint
	config.Control.OrganizationID = identity.OrganizationID
	config.Control.ManagedHostID = identity.ManagedHostID
	config.Control.IdentityID = identity.IdentityID
	config.Control.InstanceID = identity.InstanceID
	config.Control.CACertificateFile = options.Paths.CACertificate
	config.Control.ClientCertificateFile = options.Paths.IdentityBundle
	config.Control.ClientPrivateKeyFile = options.Paths.IdentityBundle
	config.Control.Capabilities = append([]string(nil), options.Capabilities...)
	config.Runtime.StateDirectory = options.Paths.StateDirectory
	config.HostTerminal.Enabled = options.HostTerminal
	config.HostTerminal.User = "owndock-agent"
	config.CertificateRotation.Enabled = true
	return config
}

func installPending(paths Paths, pending pendingEnrollment, now time.Time) (Result, error) {
	if pending.SchemaVersion != pendingSchemaVersion || pending.Phase != pendingPhaseResponse ||
		pending.ExpiresAt.IsZero() ||
		!now.Before(pending.ExpiresAt) || pending.Config.Control.CACertificateFile != paths.CACertificate ||
		pending.Config.Control.ClientCertificateFile != paths.IdentityBundle ||
		pending.Config.Control.ClientPrivateKeyFile != paths.IdentityBundle ||
		pending.Config.Runtime.StateDirectory != paths.StateDirectory {
		return Result{}, ErrInvalidEnrollment
	}
	configValue, err := agentconfig.MarshalYAML(pending.Config)
	if err != nil {
		return Result{}, ErrInvalidEnrollment
	}
	identity := agentcontrol.Identity{
		OrganizationID: pending.Config.Control.OrganizationID,
		ManagedHostID:  pending.Config.Control.ManagedHostID,
		IdentityID:     pending.Config.Control.IdentityID,
		InstanceID:     pending.Config.Control.InstanceID,
	}
	if err := agentcontrol.ValidateClientIdentityBundle(
		pending.CertificatePEM, pending.PrivateKeyPEM, pending.CACertificatePEM,
		identity, now,
	); err != nil {
		return Result{}, ErrInvalidEnrollment
	}
	if err := replaceRegularFile(paths.CACertificate, pending.CACertificatePEM, 0o640); err != nil {
		return Result{}, fmt.Errorf("install Agent CA: %w", err)
	}
	if err := agentcontrol.InstallClientIdentityBundle(
		paths.IdentityBundle, pending.CertificatePEM, pending.PrivateKeyPEM,
		pending.CACertificatePEM, identity, now,
	); err != nil {
		return Result{}, fmt.Errorf("install Agent identity: %w", err)
	}
	// Config is the completion marker. systemd cannot start a partially
	// provisioned Agent because its unit requires this path.
	if err := replaceRegularFile(paths.Config, configValue, 0o640); err != nil {
		return Result{}, fmt.Errorf("install Agent config: %w", err)
	}
	pendingPath := filepath.Join(paths.StateDirectory, pendingFileName)
	if err := os.Remove(pendingPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return Result{}, fmt.Errorf("remove pending Agent enrollment: %w", err)
	}
	if err := syncDirectory(paths.StateDirectory); err != nil {
		return Result{}, err
	}
	return Result{
		OrganizationID: identity.OrganizationID, ManagedHostID: identity.ManagedHostID,
		IdentityID: identity.IdentityID, InstanceID: identity.InstanceID,
		ExpiresAt: pending.ExpiresAt.UTC(),
	}, nil
}

func replaceRegularFile(path string, value []byte, mode os.FileMode) (result error) {
	directory := filepath.Dir(path)
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrInvalidEnrollment
	}
	info, err = os.Lstat(path)
	if err == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o007 != 0) {
		return ErrInvalidEnrollment
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".owndock-agent-enrollment-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		if result != nil {
			_ = os.Remove(temporaryPath)
		}
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
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func readSecureFile(path string, maximum int64, private bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	unsafePermissions := info.Mode().Perm()&0o022 != 0
	if private {
		unsafePermissions = info.Mode().Perm()&0o077 != 0
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() > maximum || unsafePermissions {
		return nil, ErrInvalidEnrollment
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(value)) > maximum {
		return nil, ErrInvalidEnrollment
	}
	return value, nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func hasCapability(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func validIdentifier(value string) bool {
	if value == "" || len(value) > 128 || value == "." || value == ".." || value[0] == '.' {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func (pending *pendingEnrollment) clear() {
	clearBytes(pending.CSRPEM)
	clearBytes(pending.CertificatePEM)
	clearBytes(pending.CACertificatePEM)
	clearBytes(pending.PrivateKeyPEM)
}
