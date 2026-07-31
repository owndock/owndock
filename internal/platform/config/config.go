package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	kratosconfig "github.com/go-kratos/kratos/v2/config"
	"github.com/go-kratos/kratos/v2/config/file"
)

const (
	defaultHTTPTimeout           = 30 * time.Second
	defaultShutdownTimeout       = 15 * time.Second
	defaultTraceSampleRatio      = 1.0
	defaultMongoURIEnv           = "OWNDOCK_MONGODB_URI"
	defaultMongoDatabase         = "owndock"
	defaultMongoConnect          = 10 * time.Second
	defaultMongoOperation        = 5 * time.Second
	defaultMongoMaxIdle          = 5 * time.Minute
	defaultMongoMaxPoolSize      = 100
	defaultBootstrapTokenEnv     = "OWNDOCK_BOOTSTRAP_TOKEN"
	defaultSessionTTL            = 24 * time.Hour
	defaultMaximumActiveSessions = 10
	defaultLoginAttemptLimit     = 5
	defaultLoginAttemptWindow    = 15 * time.Minute
	defaultWorkerPoll            = 2 * time.Second
	defaultWorkerLease           = 30 * time.Second
	defaultWorkerOperation       = 10 * time.Minute
	defaultInventoryPoll         = 2 * time.Second
	defaultInventorySync         = 5 * time.Minute
	defaultInventoryRetry        = 30 * time.Second
	defaultInventoryLease        = 2 * time.Minute
	defaultInventoryOperation    = time.Minute
	defaultInventoryCommand      = 20 * time.Second
	defaultInventoryConcurrency  = 2
	defaultInventoryCandidates   = 256
	defaultInventoryChunkBytes   = 48 * 1024
	defaultAgentCACertEnv        = "OWNDOCK_AGENT_CA_CERT_PEM"
	defaultAgentCAKeyEnv         = "OWNDOCK_AGENT_CA_KEY_PEM"
	defaultEnrollmentTTL         = 15 * time.Minute
	defaultAgentCertTTL          = 30 * 24 * time.Hour
	defaultAgentAddress          = "0.0.0.0:8443"
	defaultAgentServerCertEnv    = "OWNDOCK_AGENT_SERVER_CERT_PEM"
	defaultAgentServerKeyEnv     = "OWNDOCK_AGENT_SERVER_KEY_PEM"
	defaultAgentHandshake        = 10 * time.Second
	defaultAgentHeartbeat        = 10 * time.Second
	defaultAgentHeartbeatTimeout = 30 * time.Second
	defaultAgentMaxFrameBytes    = 64 * 1024
	defaultAgentOutboundBuffer   = 32
	defaultAgentCompletedCache   = 256
)

// Config is the process configuration root. Keep transport and infrastructure
// configuration here; domain rules belong to their owning module.
type Config struct {
	Server        Server        `json:"server"`
	Observability Observability `json:"observability"`
	Development   Development   `json:"development"`
	Database      Database      `json:"database"`
	Product       Product       `json:"product"`
	Runtime       Runtime       `json:"runtime"`
	Security      Security      `json:"security"`
}

type Server struct {
	HTTP  HTTP  `json:"http"`
	Agent Agent `json:"agent"`
}

type HTTP struct {
	Address         string `json:"address"`
	Timeout         string `json:"timeout"`
	ShutdownTimeout string `json:"shutdown_timeout"`
}

type Agent struct {
	Enabled               bool     `json:"enabled"`
	Address               string   `json:"address"`
	ServerCertificateEnv  string   `json:"server_certificate_env"`
	ServerPrivateKeyEnv   string   `json:"server_private_key_env"`
	HandshakeTimeout      string   `json:"handshake_timeout"`
	HeartbeatInterval     string   `json:"heartbeat_interval"`
	HeartbeatTimeout      string   `json:"heartbeat_timeout"`
	MaxFrameBytes         int      `json:"max_frame_bytes"`
	OutboundBuffer        int      `json:"outbound_buffer"`
	CompletedCommandCache int      `json:"completed_command_cache"`
	ProtocolVersions      []string `json:"protocol_versions"`
}

type Observability struct {
	Tracing Tracing `json:"tracing"`
}

type Tracing struct {
	Enabled     bool    `json:"enabled"`
	Endpoint    string  `json:"endpoint"`
	Insecure    bool    `json:"insecure"`
	SampleRatio float64 `json:"sample_ratio"`
}

// Development contains explicitly non-production switches. Features in this
// section must remain disabled in the checked-in default configuration.
type Development struct {
	EnableEngineeringSamples bool `json:"enable_engineering_samples"`
}

type Product struct {
	Enabled bool `json:"enabled"`
}

type Runtime struct {
	DeploymentWorker DeploymentWorker `json:"deployment_worker"`
	InventoryWorker  InventoryWorker  `json:"inventory_worker"`
}

type DeploymentWorker struct {
	Enabled          bool   `json:"enabled"`
	PollInterval     string `json:"poll_interval"`
	LeaseDuration    string `json:"lease_duration"`
	OperationTimeout string `json:"operation_timeout"`
}

type InventoryWorker struct {
	Enabled          bool   `json:"enabled"`
	PollInterval     string `json:"poll_interval"`
	SyncInterval     string `json:"sync_interval"`
	RetryInterval    string `json:"retry_interval"`
	LeaseDuration    string `json:"lease_duration"`
	OperationTimeout string `json:"operation_timeout"`
	CommandTimeout   string `json:"command_timeout"`
	Concurrency      int    `json:"concurrency"`
	CandidateLimit   int    `json:"candidate_limit"`
	MaxChunkBytes    int    `json:"max_chunk_bytes"`
}

type Security struct {
	BootstrapTokenEnv  string   `json:"bootstrap_token_env"`
	SessionTTL         string   `json:"session_ttl"`
	MaxActiveSessions  int      `json:"max_active_sessions"`
	LoginAttemptLimit  int      `json:"login_attempt_limit"`
	LoginAttemptWindow string   `json:"login_attempt_window"`
	AgentPKI           AgentPKI `json:"agent_pki"`
}

type AgentPKI struct {
	Enabled          bool   `json:"enabled"`
	CACertificateEnv string `json:"ca_certificate_env"`
	CAPrivateKeyEnv  string `json:"ca_private_key_env"`
	EnrollmentTTL    string `json:"enrollment_ttl"`
	CertificateTTL   string `json:"certificate_ttl"`
}

type Database struct {
	Mongo Mongo `json:"mongo"`
}

type Mongo struct {
	Enabled          bool   `json:"enabled"`
	URIEnv           string `json:"uri_env"`
	Database         string `json:"database"`
	ConnectTimeout   string `json:"connect_timeout"`
	OperationTimeout string `json:"operation_timeout"`
	MaxIdleTime      string `json:"max_idle_time"`
	MinPoolSize      uint64 `json:"min_pool_size"`
	MaxPoolSize      uint64 `json:"max_pool_size"`
}

func Load(path string) (Config, error) {
	c := kratosconfig.New(kratosconfig.WithSource(file.NewSource(path)))
	defer func() { _ = c.Close() }()

	if err := c.Load(); err != nil {
		return Config{}, fmt.Errorf("load config: %w", err)
	}

	cfg := Config{
		Server: Server{Agent: Agent{
			Address:               defaultAgentAddress,
			ServerCertificateEnv:  defaultAgentServerCertEnv,
			ServerPrivateKeyEnv:   defaultAgentServerKeyEnv,
			HandshakeTimeout:      defaultAgentHandshake.String(),
			HeartbeatInterval:     defaultAgentHeartbeat.String(),
			HeartbeatTimeout:      defaultAgentHeartbeatTimeout.String(),
			MaxFrameBytes:         defaultAgentMaxFrameBytes,
			OutboundBuffer:        defaultAgentOutboundBuffer,
			CompletedCommandCache: defaultAgentCompletedCache,
			ProtocolVersions:      []string{"v1"},
		}},
		Observability: Observability{
			Tracing: Tracing{SampleRatio: defaultTraceSampleRatio},
		},
		Database: Database{
			Mongo: Mongo{
				URIEnv:           defaultMongoURIEnv,
				Database:         defaultMongoDatabase,
				ConnectTimeout:   defaultMongoConnect.String(),
				OperationTimeout: defaultMongoOperation.String(),
				MaxIdleTime:      defaultMongoMaxIdle.String(),
				MaxPoolSize:      defaultMongoMaxPoolSize,
			},
		},
		Security: Security{
			BootstrapTokenEnv:  defaultBootstrapTokenEnv,
			SessionTTL:         defaultSessionTTL.String(),
			MaxActiveSessions:  defaultMaximumActiveSessions,
			LoginAttemptLimit:  defaultLoginAttemptLimit,
			LoginAttemptWindow: defaultLoginAttemptWindow.String(),
			AgentPKI: AgentPKI{
				CACertificateEnv: defaultAgentCACertEnv,
				CAPrivateKeyEnv:  defaultAgentCAKeyEnv,
				EnrollmentTTL:    defaultEnrollmentTTL.String(),
				CertificateTTL:   defaultAgentCertTTL.String(),
			},
		},
		Runtime: Runtime{
			DeploymentWorker: DeploymentWorker{
				PollInterval:     defaultWorkerPoll.String(),
				LeaseDuration:    defaultWorkerLease.String(),
				OperationTimeout: defaultWorkerOperation.String(),
			},
			InventoryWorker: InventoryWorker{
				PollInterval:     defaultInventoryPoll.String(),
				SyncInterval:     defaultInventorySync.String(),
				RetryInterval:    defaultInventoryRetry.String(),
				LeaseDuration:    defaultInventoryLease.String(),
				OperationTimeout: defaultInventoryOperation.String(),
				CommandTimeout:   defaultInventoryCommand.String(),
				Concurrency:      defaultInventoryConcurrency,
				CandidateLimit:   defaultInventoryCandidates,
				MaxChunkBytes:    defaultInventoryChunkBytes,
			},
		},
	}
	if err := c.Scan(&cfg); err != nil {
		return Config{}, fmt.Errorf("scan config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.Server.HTTP.Address) == "" {
		return fmt.Errorf("server.http.address is required")
	}
	if _, err := c.Server.HTTP.TimeoutDuration(); err != nil {
		return fmt.Errorf("server.http.timeout: %w", err)
	}
	if _, err := c.Server.HTTP.ShutdownTimeoutDuration(); err != nil {
		return fmt.Errorf("server.http.shutdown_timeout: %w", err)
	}
	if err := c.Server.Agent.Validate(
		c.Product.Enabled,
		c.Database.Mongo.Enabled,
		c.Security.AgentPKI.Enabled,
	); err != nil {
		return fmt.Errorf("server.agent: %w", err)
	}
	if err := c.Observability.Tracing.Validate(); err != nil {
		return fmt.Errorf("observability.tracing: %w", err)
	}
	if err := c.Database.Mongo.Validate(); err != nil {
		return fmt.Errorf("database.mongo: %w", err)
	}
	if err := c.Security.Validate(c.Product.Enabled); err != nil {
		return fmt.Errorf("security: %w", err)
	}
	if c.Product.Enabled && !c.Database.Mongo.Enabled {
		return fmt.Errorf("product.enabled requires database.mongo.enabled")
	}
	if err := c.Runtime.DeploymentWorker.Validate(c.Product.Enabled, c.Database.Mongo.Enabled); err != nil {
		return fmt.Errorf("runtime.deployment_worker: %w", err)
	}
	if err := c.Runtime.InventoryWorker.Validate(c.Product.Enabled, c.Database.Mongo.Enabled); err != nil {
		return fmt.Errorf("runtime.inventory_worker: %w", err)
	}
	return nil
}

func (a Agent) Validate(productEnabled, mongoEnabled, agentPKIEnabled bool) error {
	if !a.Enabled {
		return nil
	}
	if !productEnabled || !mongoEnabled || !agentPKIEnabled {
		return fmt.Errorf("enabled Agent server requires product, MongoDB, and Agent PKI")
	}
	if strings.TrimSpace(a.Address) == "" {
		return fmt.Errorf("address is required when enabled")
	}
	if strings.TrimSpace(a.ServerCertificateEnv) == "" ||
		strings.TrimSpace(a.ServerPrivateKeyEnv) == "" {
		return fmt.Errorf("server certificate and private key environment names are required")
	}
	handshakeTimeout, err := a.HandshakeTimeoutDuration()
	if err != nil {
		return fmt.Errorf("handshake_timeout: %w", err)
	}
	heartbeatInterval, err := a.HeartbeatIntervalDuration()
	if err != nil {
		return fmt.Errorf("heartbeat_interval: %w", err)
	}
	heartbeatTimeout, err := a.HeartbeatTimeoutDuration()
	if err != nil {
		return fmt.Errorf("heartbeat_timeout: %w", err)
	}
	if handshakeTimeout <= 0 || heartbeatInterval <= 0 ||
		heartbeatTimeout <= heartbeatInterval {
		return fmt.Errorf("timeouts must be positive and heartbeat_timeout must exceed heartbeat_interval")
	}
	if a.MaxFrameBytes < 1024 || a.MaxFrameBytes > 1024*1024 {
		return fmt.Errorf("max_frame_bytes must be between 1024 and 1048576")
	}
	if a.OutboundBuffer < 1 || a.OutboundBuffer > 1024 {
		return fmt.Errorf("outbound_buffer must be between 1 and 1024")
	}
	if a.CompletedCommandCache < 1 || a.CompletedCommandCache > 4096 {
		return fmt.Errorf("completed_command_cache must be between 1 and 4096")
	}
	if len(a.ProtocolVersions) == 0 {
		return fmt.Errorf("at least one protocol version is required")
	}
	seen := make(map[string]struct{}, len(a.ProtocolVersions))
	for _, version := range a.ProtocolVersions {
		version = strings.TrimSpace(version)
		if version == "" {
			return fmt.Errorf("protocol versions must not be empty")
		}
		if _, exists := seen[version]; exists {
			return fmt.Errorf("protocol versions must be unique")
		}
		seen[version] = struct{}{}
	}
	return nil
}

func (a Agent) HandshakeTimeoutDuration() (time.Duration, error) {
	return parseDuration(a.HandshakeTimeout, defaultAgentHandshake)
}

func (a Agent) HeartbeatIntervalDuration() (time.Duration, error) {
	return parseDuration(a.HeartbeatInterval, defaultAgentHeartbeat)
}

func (a Agent) HeartbeatTimeoutDuration() (time.Duration, error) {
	return parseDuration(a.HeartbeatTimeout, defaultAgentHeartbeatTimeout)
}

func (a Agent) Materials() ([]byte, []byte, error) {
	certificate, err := requiredEnvironmentValue(a.ServerCertificateEnv)
	if err != nil {
		return nil, nil, err
	}
	privateKey, err := requiredEnvironmentValue(a.ServerPrivateKeyEnv)
	if err != nil {
		return nil, nil, err
	}
	return []byte(certificate), []byte(privateKey), nil
}

func (w DeploymentWorker) Validate(productEnabled, mongoEnabled bool) error {
	if !w.Enabled {
		return nil
	}
	if !productEnabled || !mongoEnabled {
		return fmt.Errorf("enabled worker requires product and MongoDB")
	}
	if _, err := w.PollIntervalDuration(); err != nil {
		return fmt.Errorf("poll_interval: %w", err)
	}
	if _, err := w.LeaseDurationValue(); err != nil {
		return fmt.Errorf("lease_duration: %w", err)
	}
	if _, err := w.OperationTimeoutDuration(); err != nil {
		return fmt.Errorf("operation_timeout: %w", err)
	}
	return nil
}

func (w DeploymentWorker) PollIntervalDuration() (time.Duration, error) {
	return parseDuration(w.PollInterval, defaultWorkerPoll)
}

func (w DeploymentWorker) LeaseDurationValue() (time.Duration, error) {
	return parseDuration(w.LeaseDuration, defaultWorkerLease)
}

func (w DeploymentWorker) OperationTimeoutDuration() (time.Duration, error) {
	return parseDuration(w.OperationTimeout, defaultWorkerOperation)
}

func (w InventoryWorker) Validate(productEnabled, mongoEnabled bool) error {
	if !w.Enabled {
		return nil
	}
	if !productEnabled || !mongoEnabled {
		return fmt.Errorf("enabled worker requires product and MongoDB")
	}
	if _, err := w.PollIntervalDuration(); err != nil {
		return fmt.Errorf("poll_interval: %w", err)
	}
	if _, err := w.SyncIntervalDuration(); err != nil {
		return fmt.Errorf("sync_interval: %w", err)
	}
	if _, err := w.RetryIntervalDuration(); err != nil {
		return fmt.Errorf("retry_interval: %w", err)
	}
	lease, err := w.LeaseDurationValue()
	if err != nil {
		return fmt.Errorf("lease_duration: %w", err)
	}
	operation, err := w.OperationTimeoutDuration()
	if err != nil {
		return fmt.Errorf("operation_timeout: %w", err)
	}
	command, err := w.CommandTimeoutDuration()
	if err != nil {
		return fmt.Errorf("command_timeout: %w", err)
	}
	if lease <= operation {
		return fmt.Errorf("lease_duration must exceed operation_timeout")
	}
	if command > operation || command > time.Minute {
		return fmt.Errorf("command_timeout must not exceed operation_timeout or 1m")
	}
	if w.ConcurrencyValue() < 1 || w.ConcurrencyValue() > 32 {
		return fmt.Errorf("concurrency must be between 1 and 32")
	}
	if w.CandidateLimitValue() < 1 || w.CandidateLimitValue() > 1000 {
		return fmt.Errorf("candidate_limit must be between 1 and 1000")
	}
	if w.MaxChunkBytesValue() < 4*1024 ||
		w.MaxChunkBytesValue() > defaultInventoryChunkBytes {
		return fmt.Errorf("max_chunk_bytes must be between 4096 and 49152")
	}
	return nil
}

func (w InventoryWorker) PollIntervalDuration() (time.Duration, error) {
	return parseDuration(w.PollInterval, defaultInventoryPoll)
}

func (w InventoryWorker) SyncIntervalDuration() (time.Duration, error) {
	return parseDuration(w.SyncInterval, defaultInventorySync)
}

func (w InventoryWorker) RetryIntervalDuration() (time.Duration, error) {
	return parseDuration(w.RetryInterval, defaultInventoryRetry)
}

func (w InventoryWorker) LeaseDurationValue() (time.Duration, error) {
	return parseDuration(w.LeaseDuration, defaultInventoryLease)
}

func (w InventoryWorker) OperationTimeoutDuration() (time.Duration, error) {
	return parseDuration(w.OperationTimeout, defaultInventoryOperation)
}

func (w InventoryWorker) CommandTimeoutDuration() (time.Duration, error) {
	return parseDuration(w.CommandTimeout, defaultInventoryCommand)
}

func (w InventoryWorker) ConcurrencyValue() int {
	if w.Concurrency == 0 {
		return defaultInventoryConcurrency
	}
	return w.Concurrency
}

func (w InventoryWorker) CandidateLimitValue() int {
	if w.CandidateLimit == 0 {
		return defaultInventoryCandidates
	}
	return w.CandidateLimit
}

func (w InventoryWorker) MaxChunkBytesValue() int {
	if w.MaxChunkBytes == 0 {
		return defaultInventoryChunkBytes
	}
	return w.MaxChunkBytes
}

func (m Mongo) Validate() error {
	if !m.Enabled {
		return nil
	}
	if strings.TrimSpace(m.URIEnv) == "" {
		return fmt.Errorf("uri_env is required when enabled")
	}
	if strings.TrimSpace(m.Database) == "" {
		return fmt.Errorf("database is required when enabled")
	}
	if _, err := m.ConnectTimeoutDuration(); err != nil {
		return fmt.Errorf("connect_timeout: %w", err)
	}
	if _, err := m.OperationTimeoutDuration(); err != nil {
		return fmt.Errorf("operation_timeout: %w", err)
	}
	if _, err := m.MaxIdleTimeDuration(); err != nil {
		return fmt.Errorf("max_idle_time: %w", err)
	}
	if m.MaxPoolSize == 0 {
		return fmt.Errorf("max_pool_size must be greater than zero")
	}
	if m.MinPoolSize > m.MaxPoolSize {
		return fmt.Errorf("min_pool_size must not exceed max_pool_size")
	}
	return nil
}

func (m Mongo) URI() (string, error) {
	name := strings.TrimSpace(m.URIEnv)
	if name == "" {
		return "", fmt.Errorf("uri_env is required")
	}
	value, ok := os.LookupEnv(name)
	if !ok || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("environment variable %s is required", name)
	}
	return strings.TrimSpace(value), nil
}

func (m Mongo) ConnectTimeoutDuration() (time.Duration, error) {
	return parseDuration(m.ConnectTimeout, defaultMongoConnect)
}

func (m Mongo) OperationTimeoutDuration() (time.Duration, error) {
	return parseDuration(m.OperationTimeout, defaultMongoOperation)
}

func (m Mongo) MaxIdleTimeDuration() (time.Duration, error) {
	return parseDuration(m.MaxIdleTime, defaultMongoMaxIdle)
}

func (s Security) Validate(productEnabled bool) error {
	if !productEnabled {
		return nil
	}
	if strings.TrimSpace(s.BootstrapTokenEnv) == "" {
		return fmt.Errorf("bootstrap_token_env is required when product is enabled")
	}
	if _, err := s.SessionTTLDuration(); err != nil {
		return fmt.Errorf("session_ttl: %w", err)
	}
	if maximum := s.MaxActiveSessionsValue(); maximum < 1 ||
		maximum > 100 {
		return fmt.Errorf(
			"max_active_sessions must be between 1 and 100",
		)
	}
	if limit := s.LoginAttemptLimitValue(); limit < 1 || limit > 100 {
		return fmt.Errorf("login_attempt_limit must be between 1 and 100")
	}
	window, err := s.LoginAttemptWindowDuration()
	if err != nil || window < time.Minute || window > 24*time.Hour {
		return fmt.Errorf(
			"login_attempt_window must be between 1m and 24h",
		)
	}
	if err := s.AgentPKI.Validate(); err != nil {
		return fmt.Errorf("agent_pki: %w", err)
	}
	return nil
}

func (p AgentPKI) Validate() error {
	if !p.Enabled {
		return nil
	}
	if strings.TrimSpace(p.CACertificateEnv) == "" {
		return fmt.Errorf("ca_certificate_env is required when enabled")
	}
	if strings.TrimSpace(p.CAPrivateKeyEnv) == "" {
		return fmt.Errorf("ca_private_key_env is required when enabled")
	}
	enrollmentTTL, err := p.EnrollmentTTLDuration()
	if err != nil {
		return fmt.Errorf("enrollment_ttl: %w", err)
	}
	certificateTTL, err := p.CertificateTTLDuration()
	if err != nil {
		return fmt.Errorf("certificate_ttl: %w", err)
	}
	if certificateTTL <= enrollmentTTL {
		return fmt.Errorf("certificate_ttl must be greater than enrollment_ttl")
	}
	return nil
}

func (p AgentPKI) EnrollmentTTLDuration() (time.Duration, error) {
	return parseDuration(p.EnrollmentTTL, defaultEnrollmentTTL)
}

func (p AgentPKI) CertificateTTLDuration() (time.Duration, error) {
	return parseDuration(p.CertificateTTL, defaultAgentCertTTL)
}

func (p AgentPKI) Materials() ([]byte, []byte, error) {
	certificate, err := requiredEnvironmentValue(p.CACertificateEnv)
	if err != nil {
		return nil, nil, err
	}
	privateKey, err := requiredEnvironmentValue(p.CAPrivateKeyEnv)
	if err != nil {
		return nil, nil, err
	}
	return []byte(certificate), []byte(privateKey), nil
}

func (s Security) SessionTTLDuration() (time.Duration, error) {
	return parseDuration(s.SessionTTL, defaultSessionTTL)
}

func (s Security) MaxActiveSessionsValue() int {
	if s.MaxActiveSessions == 0 {
		return defaultMaximumActiveSessions
	}
	return s.MaxActiveSessions
}

func (s Security) LoginAttemptLimitValue() int {
	if s.LoginAttemptLimit == 0 {
		return defaultLoginAttemptLimit
	}
	return s.LoginAttemptLimit
}

func (s Security) LoginAttemptWindowDuration() (time.Duration, error) {
	return parseDuration(
		s.LoginAttemptWindow,
		defaultLoginAttemptWindow,
	)
}

func (s Security) BootstrapToken() (string, error) {
	name := strings.TrimSpace(s.BootstrapTokenEnv)
	if name == "" {
		return "", fmt.Errorf("bootstrap_token_env is required")
	}
	value, ok := os.LookupEnv(name)
	if !ok || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("environment variable %s is required for bootstrap", name)
	}
	return strings.TrimSpace(value), nil
}

func requiredEnvironmentValue(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("environment variable name is required")
	}
	value, ok := os.LookupEnv(name)
	if !ok || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("environment variable %s is required", name)
	}
	return value, nil
}

func (t Tracing) Validate() error {
	if !t.Enabled {
		return nil
	}

	endpoint := strings.TrimSpace(t.Endpoint)
	if endpoint == "" {
		return fmt.Errorf("endpoint is required when enabled")
	}
	if strings.Contains(endpoint, "://") {
		return fmt.Errorf("endpoint must use host:port format")
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || strings.TrimSpace(host) == "" {
		return fmt.Errorf("endpoint must use host:port format")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return fmt.Errorf("endpoint port must be between 1 and 65535")
	}
	if t.SampleRatio < 0 || t.SampleRatio > 1 {
		return fmt.Errorf("sample_ratio must be between 0 and 1")
	}
	return nil
}

func (t Tracing) EffectiveSampleRatio() float64 {
	return t.SampleRatio
}

func (h HTTP) TimeoutDuration() (time.Duration, error) {
	return parseDuration(h.Timeout, defaultHTTPTimeout)
}

func (h HTTP) ShutdownTimeoutDuration() (time.Duration, error) {
	return parseDuration(h.ShutdownTimeout, defaultShutdownTimeout)
}

func parseDuration(value string, fallback time.Duration) (time.Duration, error) {
	if strings.TrimSpace(value) == "" {
		return fallback, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, err
	}
	if duration <= 0 {
		return 0, fmt.Errorf("must be greater than zero")
	}
	return duration, nil
}
