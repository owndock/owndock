package config

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	kratosconfig "github.com/go-kratos/kratos/v2/config"
	"github.com/go-kratos/kratos/v2/config/file"

	"github.com/owndock/owndock/internal/shared/agentprotocol"
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
	defaultUserInvitationTTL     = 24 * time.Hour
	defaultMaximumActiveSessions = 10
	defaultLoginAttemptLimit     = 5
	defaultLoginAttemptWindow    = 15 * time.Minute
	defaultIngressSourceLimit    = 600
	defaultIngressGlobalLimit    = 6000
	defaultIngressRateWindow     = time.Minute
	defaultSourceProbeTimeout    = 10 * time.Second
	defaultBuildTriggerLimit     = 60
	defaultBuildTriggerWindow    = time.Minute
	defaultBuildWebhookLimit     = 120
	defaultBuildWebhookWindow    = time.Minute
	defaultBuildWebhookMaxBody   = int64(1024 * 1024)
	defaultWorkerPoll            = 2 * time.Second
	defaultWorkerLease           = 30 * time.Second
	defaultWorkerOperation       = 10 * time.Minute
	defaultBuildWorkerPoll       = 2 * time.Second
	defaultBuildWorkerLease      = 30 * time.Second
	defaultBuildWorkerOperation  = 2*time.Hour + 15*time.Minute
	defaultBuildCheckoutTimeout  = 10 * time.Minute
	defaultBuildWorkspaceRoot    = "/var/lib/owndock/builds"
	defaultBuildWorkspaceBytes   = int64(5 * 1024 * 1024 * 1024)
	defaultBuildWorkspaceQuota   = int64(8 * 1024 * 1024 * 1024)
	defaultBuildWorkspaceFiles   = int64(250000)
	defaultBuildWorkspaceDepth   = 64
	defaultBuildLogRetention     = 7 * 24 * time.Hour
	defaultBuildLogMaxBytes      = int64(10 * 1024 * 1024)
	defaultBuildLogChunkBytes    = 16 * 1024
	defaultBuildMetricsAddress   = "127.0.0.1:9091"
	defaultBuildEgressAddress    = "0.0.0.0:3128"
	defaultBuildEgressDial       = 10 * time.Second
	defaultBuildEgressIdle       = 2 * time.Minute
	defaultBuildEgressConcurrent = 128
	defaultEvidenceWorkerPoll    = 2 * time.Second
	defaultEvidenceWorkerLease   = 30 * time.Second
	defaultEvidenceOperation     = 30 * time.Minute
	defaultEvidenceSyftPath      = "/usr/local/bin/syft"
	defaultEvidenceCosignPath    = "/usr/local/bin/cosign"
	defaultEvidenceTrivyPath     = "/usr/local/bin/trivy"
	defaultEvidenceTrivyCache    = "/var/lib/owndock/trivy-db/current"
	defaultEvidenceScanFreshness = 24 * time.Hour
	defaultEvidenceTrustRoots    = "/etc/owndock/trusted-roots"
	defaultEvidenceDocumentBytes = int64(16 * 1024 * 1024)
	defaultEvidenceLayerBytes    = int64(256 * 1024 * 1024)
	defaultEvidenceMetrics       = "127.0.0.1:9092"
	defaultInventoryPoll         = 2 * time.Second
	defaultInventorySync         = 5 * time.Minute
	defaultInventoryRetry        = 30 * time.Second
	defaultInventoryLease        = 2 * time.Minute
	defaultInventoryOperation    = time.Minute
	defaultInventoryCommand      = 20 * time.Second
	defaultInventoryEventPoll    = time.Second
	defaultInventoryEventWait    = 2 * time.Second
	defaultInventoryConcurrency  = 2
	defaultInventoryEventWorkers = 4
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
	maximumSecretFileBytes       = 8 * 1024
)

const (
	defaultVulnerabilityPoll       = 5 * time.Minute
	defaultVulnerabilityRetry      = 6 * time.Hour
	defaultVulnerabilityOperation  = 30 * time.Second
	defaultVulnerabilityCandidates = 100
)

// Config is the process configuration root. Keep transport and infrastructure
// configuration here; domain rules belong to their owning module.
type Config struct {
	Server        Server        `json:"server"`
	Observability Observability `json:"observability"`
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
	Address            string   `json:"address"`
	Timeout            string   `json:"timeout"`
	ShutdownTimeout    string   `json:"shutdown_timeout"`
	CORSAllowedOrigins []string `json:"cors_allowed_origins"`
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

type Product struct {
	Enabled                             bool   `json:"enabled"`
	SourceProbeTimeout                  string `json:"source_probe_timeout"`
	SourceGitCACertFile                 string `json:"source_git_ca_cert_file"`
	SourceGitHTTPSProxy                 string `json:"source_git_https_proxy"`
	RegistryCACertFile                  string `json:"registry_ca_cert_file"`
	RegistryHTTPSProxy                  string `json:"registry_https_proxy"`
	BuildTriggerRateLimit               int    `json:"build_trigger_rate_limit"`
	BuildTriggerRateWindow              string `json:"build_trigger_rate_window"`
	BuildWebhookRateLimit               int    `json:"build_webhook_rate_limit"`
	BuildWebhookRateWindow              string `json:"build_webhook_rate_window"`
	BuildWebhookMaxBodyBytes            int64  `json:"build_webhook_max_body_bytes"`
	VulnerabilityRescanEnabled          bool   `json:"vulnerability_rescan_enabled"`
	VulnerabilityRescanPollInterval     string `json:"vulnerability_rescan_poll_interval"`
	VulnerabilityRescanRetryInterval    string `json:"vulnerability_rescan_retry_interval"`
	VulnerabilityRescanOperationTimeout string `json:"vulnerability_rescan_operation_timeout"`
	VulnerabilityRescanCandidateLimit   int    `json:"vulnerability_rescan_candidate_limit"`
}

type Runtime struct {
	DeploymentWorker DeploymentWorker `json:"deployment_worker"`
	InventoryWorker  InventoryWorker  `json:"inventory_worker"`
	BuildWorker      BuildWorker      `json:"build_worker"`
	BuildEgress      BuildEgress      `json:"build_egress_gateway"`
	EvidenceWorker   EvidenceWorker   `json:"evidence_worker"`
}

type BuildWorker struct {
	Enabled                bool   `json:"enabled"`
	PollInterval           string `json:"poll_interval"`
	LeaseDuration          string `json:"lease_duration"`
	OperationTimeout       string `json:"operation_timeout"`
	CheckoutTimeout        string `json:"checkout_timeout"`
	WorkspaceRoot          string `json:"workspace_root"`
	RequireWorkspaceQuota  bool   `json:"require_workspace_hard_quota"`
	WorkspaceQuotaBytes    int64  `json:"workspace_hard_quota_bytes"`
	MaxWorkspaceBytes      int64  `json:"max_workspace_bytes"`
	MaxWorkspaceFiles      int64  `json:"max_workspace_files"`
	MaxWorkspaceDepth      int    `json:"max_workspace_depth"`
	GitExecutable          string `json:"git_executable"`
	GitVersion             string `json:"git_version"`
	BuildKitEndpoint       string `json:"buildkit_endpoint"`
	BuildKitServerName     string `json:"buildkit_server_name"`
	BuildKitCACertFile     string `json:"buildkit_ca_cert_file"`
	BuildKitClientCertFile string `json:"buildkit_client_cert_file"`
	BuildKitClientKeyFile  string `json:"buildkit_client_key_file"`
	BuildEgressProxyURL    string `json:"build_egress_proxy_url"`
	LogRetention           string `json:"log_retention"`
	LogMaxBytes            int64  `json:"log_max_bytes"`
	LogChunkBytes          int    `json:"log_chunk_bytes"`
	MetricsAddress         string `json:"metrics_address"`
}

type BuildEgress struct {
	Enabled             bool                     `json:"enabled"`
	Address             string                   `json:"address"`
	DialTimeout         string                   `json:"dial_timeout"`
	IdleTimeout         string                   `json:"idle_timeout"`
	MaximumConnections  int                      `json:"maximum_connections"`
	AllowedDestinations []BuildEgressDestination `json:"allowed_destinations"`
}

type BuildEgressDestination struct {
	Authority    string `json:"authority"`
	AllowPrivate bool   `json:"allow_private"`
}

// EvidenceWorker configures the isolated SBOM generation and OCI publication
// process. It intentionally has no general command or arbitrary Registry
// endpoint options; each job carries a previously validated digest subject.
type EvidenceWorker struct {
	Enabled                bool   `json:"enabled"`
	PollInterval           string `json:"poll_interval"`
	LeaseDuration          string `json:"lease_duration"`
	OperationTimeout       string `json:"operation_timeout"`
	SyftExecutable         string `json:"syft_executable"`
	SyftVersion            string `json:"syft_version"`
	CosignExecutable       string `json:"cosign_executable"`
	CosignVersion          string `json:"cosign_version"`
	TrivyExecutable        string `json:"trivy_executable"`
	TrivyVersion           string `json:"trivy_version"`
	TrivyCacheDirectory    string `json:"trivy_cache_directory"`
	VulnerabilityFreshness string `json:"vulnerability_freshness"`
	TrustedRootsDirectory  string `json:"trusted_roots_directory"`
	MaxDocumentBytes       int64  `json:"max_document_bytes"`
	MaxLayerBytes          int64  `json:"max_layer_bytes"`
	MetricsAddress         string `json:"metrics_address"`
}

type DeploymentWorker struct {
	Enabled          bool   `json:"enabled"`
	PollInterval     string `json:"poll_interval"`
	LeaseDuration    string `json:"lease_duration"`
	OperationTimeout string `json:"operation_timeout"`
}

type InventoryWorker struct {
	Enabled           bool   `json:"enabled"`
	PollInterval      string `json:"poll_interval"`
	SyncInterval      string `json:"sync_interval"`
	RetryInterval     string `json:"retry_interval"`
	EventPollInterval string `json:"event_poll_interval"`
	EventWait         string `json:"event_wait"`
	LeaseDuration     string `json:"lease_duration"`
	OperationTimeout  string `json:"operation_timeout"`
	CommandTimeout    string `json:"command_timeout"`
	Concurrency       int    `json:"concurrency"`
	EventConcurrency  int    `json:"event_concurrency"`
	CandidateLimit    int    `json:"candidate_limit"`
	MaxChunkBytes     int    `json:"max_chunk_bytes"`
}

type Security struct {
	BootstrapTokenEnv  string   `json:"bootstrap_token_env"`
	BootstrapTokenFile string   `json:"bootstrap_token_file"`
	SessionTTL         string   `json:"session_ttl"`
	MaxActiveSessions  int      `json:"max_active_sessions"`
	UserInvitationTTL  string   `json:"user_invitation_ttl"`
	LoginAttemptLimit  int      `json:"login_attempt_limit"`
	LoginAttemptWindow string   `json:"login_attempt_window"`
	IngressSourceLimit int      `json:"ingress_source_limit"`
	IngressGlobalLimit int      `json:"ingress_global_limit"`
	IngressRateWindow  string   `json:"ingress_rate_window"`
	TrustedProxyCIDRs  []string `json:"trusted_proxy_cidrs"`
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
	URIFile          string `json:"uri_file"`
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
			ProtocolVersions:      []string{agentprotocol.Version},
		}},
		Observability: Observability{
			Tracing: Tracing{SampleRatio: defaultTraceSampleRatio},
		},
		Product: Product{
			SourceProbeTimeout:                  defaultSourceProbeTimeout.String(),
			BuildTriggerRateLimit:               defaultBuildTriggerLimit,
			BuildTriggerRateWindow:              defaultBuildTriggerWindow.String(),
			BuildWebhookRateLimit:               defaultBuildWebhookLimit,
			BuildWebhookRateWindow:              defaultBuildWebhookWindow.String(),
			BuildWebhookMaxBodyBytes:            defaultBuildWebhookMaxBody,
			VulnerabilityRescanPollInterval:     defaultVulnerabilityPoll.String(),
			VulnerabilityRescanRetryInterval:    defaultVulnerabilityRetry.String(),
			VulnerabilityRescanOperationTimeout: defaultVulnerabilityOperation.String(),
			VulnerabilityRescanCandidateLimit:   defaultVulnerabilityCandidates,
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
			UserInvitationTTL:  defaultUserInvitationTTL.String(),
			LoginAttemptLimit:  defaultLoginAttemptLimit,
			LoginAttemptWindow: defaultLoginAttemptWindow.String(),
			IngressSourceLimit: defaultIngressSourceLimit,
			IngressGlobalLimit: defaultIngressGlobalLimit,
			IngressRateWindow:  defaultIngressRateWindow.String(),
			AgentPKI: AgentPKI{
				CACertificateEnv: defaultAgentCACertEnv,
				CAPrivateKeyEnv:  defaultAgentCAKeyEnv,
				EnrollmentTTL:    defaultEnrollmentTTL.String(),
				CertificateTTL:   defaultAgentCertTTL.String(),
			},
		},
		Runtime: Runtime{
			BuildWorker: BuildWorker{
				PollInterval: defaultBuildWorkerPoll.String(), LeaseDuration: defaultBuildWorkerLease.String(),
				OperationTimeout: defaultBuildWorkerOperation.String(), CheckoutTimeout: defaultBuildCheckoutTimeout.String(),
				WorkspaceRoot: defaultBuildWorkspaceRoot, RequireWorkspaceQuota: true,
				WorkspaceQuotaBytes: defaultBuildWorkspaceQuota, MaxWorkspaceBytes: defaultBuildWorkspaceBytes,
				MaxWorkspaceFiles: defaultBuildWorkspaceFiles, MaxWorkspaceDepth: defaultBuildWorkspaceDepth,
				GitExecutable: "git", GitVersion: "2.55.0",
				BuildKitEndpoint: "unix:///run/owndock-buildkit/buildkitd.sock",
				LogRetention:     defaultBuildLogRetention.String(), LogMaxBytes: defaultBuildLogMaxBytes,
				LogChunkBytes: defaultBuildLogChunkBytes, MetricsAddress: defaultBuildMetricsAddress,
			},
			BuildEgress: BuildEgress{
				Address: defaultBuildEgressAddress, DialTimeout: defaultBuildEgressDial.String(),
				IdleTimeout: defaultBuildEgressIdle.String(), MaximumConnections: defaultBuildEgressConcurrent,
			},
			EvidenceWorker: EvidenceWorker{
				PollInterval: defaultEvidenceWorkerPoll.String(), LeaseDuration: defaultEvidenceWorkerLease.String(),
				OperationTimeout: defaultEvidenceOperation.String(), SyftExecutable: defaultEvidenceSyftPath,
				SyftVersion: "1.50.0", CosignExecutable: defaultEvidenceCosignPath,
				CosignVersion: "3.0.6", TrustedRootsDirectory: defaultEvidenceTrustRoots,
				TrivyExecutable: defaultEvidenceTrivyPath, TrivyVersion: "0.74.0",
				TrivyCacheDirectory:    defaultEvidenceTrivyCache,
				VulnerabilityFreshness: defaultEvidenceScanFreshness.String(),
				MaxDocumentBytes:       defaultEvidenceDocumentBytes,
				MaxLayerBytes:          defaultEvidenceLayerBytes,
				MetricsAddress:         defaultEvidenceMetrics,
			},
			DeploymentWorker: DeploymentWorker{
				PollInterval:     defaultWorkerPoll.String(),
				LeaseDuration:    defaultWorkerLease.String(),
				OperationTimeout: defaultWorkerOperation.String(),
			},
			InventoryWorker: InventoryWorker{
				PollInterval:      defaultInventoryPoll.String(),
				SyncInterval:      defaultInventorySync.String(),
				RetryInterval:     defaultInventoryRetry.String(),
				EventPollInterval: defaultInventoryEventPoll.String(),
				EventWait:         defaultInventoryEventWait.String(),
				LeaseDuration:     defaultInventoryLease.String(),
				OperationTimeout:  defaultInventoryOperation.String(),
				CommandTimeout:    defaultInventoryCommand.String(),
				Concurrency:       defaultInventoryConcurrency,
				EventConcurrency:  defaultInventoryEventWorkers,
				CandidateLimit:    defaultInventoryCandidates,
				MaxChunkBytes:     defaultInventoryChunkBytes,
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
	if err := c.Server.HTTP.ValidateCORSAllowedOrigins(); err != nil {
		return fmt.Errorf("server.http.cors_allowed_origins: %w", err)
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
	if err := c.Product.Validate(); err != nil {
		return fmt.Errorf("product: %w", err)
	}
	if err := c.Runtime.BuildWorker.Validate(c.Database.Mongo.Enabled); err != nil {
		return fmt.Errorf("runtime.build_worker: %w", err)
	}
	if err := c.Runtime.BuildEgress.Validate(); err != nil {
		return fmt.Errorf("runtime.build_egress_gateway: %w", err)
	}
	if err := c.Runtime.EvidenceWorker.Validate(c.Database.Mongo.Enabled); err != nil {
		return fmt.Errorf("runtime.evidence_worker: %w", err)
	}
	if err := c.Runtime.DeploymentWorker.Validate(c.Product.Enabled, c.Database.Mongo.Enabled); err != nil {
		return fmt.Errorf("runtime.deployment_worker: %w", err)
	}
	if err := c.Runtime.InventoryWorker.Validate(c.Product.Enabled, c.Database.Mongo.Enabled); err != nil {
		return fmt.Errorf("runtime.inventory_worker: %w", err)
	}
	return nil
}

// ValidateCORSAllowedOrigins accepts only exact browser origins. Wildcards and
// cross-origin credentials are deliberately unsupported by the API transport.
func (h HTTP) ValidateCORSAllowedOrigins() error {
	if len(h.CORSAllowedOrigins) > 32 {
		return fmt.Errorf("must contain at most 32 entries")
	}
	seen := make(map[string]struct{}, len(h.CORSAllowedOrigins))
	for _, rawOrigin := range h.CORSAllowedOrigins {
		origin := strings.TrimSpace(rawOrigin)
		if origin == "" || origin != rawOrigin || strings.Contains(origin, "*") {
			return fmt.Errorf("must contain exact origins without whitespace or wildcards")
		}
		parsed, err := url.Parse(origin)
		if err != nil || parsed.Host == "" || parsed.User != nil ||
			parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" {
			return fmt.Errorf("%q must be an origin without path, query, fragment, or user info", origin)
		}
		if parsed.Scheme != "https" && parsed.Scheme != "http" {
			return fmt.Errorf("%q must use https or loopback http", origin)
		}
		hostname := parsed.Hostname()
		if hostname == "" || strings.HasSuffix(hostname, ".") || parsed.Host != strings.ToLower(parsed.Host) {
			return fmt.Errorf("%q must use a canonical lowercase host", origin)
		}
		if port := parsed.Port(); port != "" {
			value, parseErr := strconv.Atoi(port)
			if parseErr != nil || value < 1 || value > 65535 {
				return fmt.Errorf("%q has an invalid port", origin)
			}
		}
		if parsed.Scheme == "http" && !isLoopbackOriginHost(hostname) {
			return fmt.Errorf("%q must use https outside loopback development", origin)
		}
		if origin != parsed.Scheme+"://"+parsed.Host {
			return fmt.Errorf("%q must be a canonical origin without a trailing slash", origin)
		}
		if _, exists := seen[origin]; exists {
			return fmt.Errorf("must not contain duplicate origins")
		}
		seen[origin] = struct{}{}
	}
	return nil
}

func isLoopbackOriginHost(host string) bool {
	if host == "localhost" {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func (p Product) Validate() error {
	if p.VulnerabilityRescanEnabled && !p.Enabled {
		return fmt.Errorf("vulnerability_rescan_enabled requires product.enabled")
	}
	timeout, err := p.SourceProbeTimeoutDuration()
	if err != nil {
		return fmt.Errorf("source_probe_timeout: %w", err)
	}
	if timeout < time.Second || timeout > 30*time.Second {
		return fmt.Errorf("source_probe_timeout must be between 1s and 30s")
	}
	if caFile := strings.TrimSpace(p.SourceGitCACertFile); caFile != p.SourceGitCACertFile ||
		(caFile != "" && !filepath.IsAbs(caFile)) {
		return fmt.Errorf("source_git_ca_cert_file must be an absolute path without surrounding whitespace")
	}
	if proxy := strings.TrimSpace(p.SourceGitHTTPSProxy); proxy != p.SourceGitHTTPSProxy ||
		(proxy != "" && !validSourceGitHTTPSProxy(proxy)) {
		return fmt.Errorf("source_git_https_proxy must be a credential-free canonical HTTP(S) origin")
	}
	if caFile := strings.TrimSpace(p.RegistryCACertFile); caFile != p.RegistryCACertFile ||
		(caFile != "" && !filepath.IsAbs(caFile)) {
		return fmt.Errorf("registry_ca_cert_file must be an absolute path without surrounding whitespace")
	}
	if proxy := strings.TrimSpace(p.RegistryHTTPSProxy); proxy != p.RegistryHTTPSProxy ||
		(proxy != "" && !validSourceGitHTTPSProxy(proxy)) {
		return fmt.Errorf("registry_https_proxy must be a credential-free canonical HTTP(S) origin")
	}
	if p.BuildTriggerRateLimitValue() < 1 || p.BuildTriggerRateLimitValue() > 10_000 {
		return fmt.Errorf("build_trigger_rate_limit must be between 1 and 10000")
	}
	window, err := p.BuildTriggerRateWindowDuration()
	if err != nil {
		return fmt.Errorf("build_trigger_rate_window: %w", err)
	}
	if window < time.Second || window > 24*time.Hour {
		return fmt.Errorf("build_trigger_rate_window must be between 1s and 24h")
	}
	if p.BuildWebhookRateLimitValue() < 1 || p.BuildWebhookRateLimitValue() > 10_000 {
		return fmt.Errorf("build_webhook_rate_limit must be between 1 and 10000")
	}
	webhookWindow, err := p.BuildWebhookRateWindowDuration()
	if err != nil {
		return fmt.Errorf("build_webhook_rate_window: %w", err)
	}
	if webhookWindow < time.Second || webhookWindow > 24*time.Hour {
		return fmt.Errorf("build_webhook_rate_window must be between 1s and 24h")
	}
	if value := p.BuildWebhookMaxBodyBytesValue(); value < 1024 || value > 5*1024*1024 {
		return fmt.Errorf("build_webhook_max_body_bytes must be between 1024 and 5242880")
	}
	rescanPoll, err := p.VulnerabilityRescanPollIntervalDuration()
	if err != nil {
		return fmt.Errorf("vulnerability_rescan_poll_interval: %w", err)
	}
	if rescanPoll < 10*time.Second || rescanPoll > time.Hour {
		return fmt.Errorf("vulnerability_rescan_poll_interval must be between 10s and 1h")
	}
	rescanRetry, err := p.VulnerabilityRescanRetryIntervalDuration()
	if err != nil {
		return fmt.Errorf("vulnerability_rescan_retry_interval: %w", err)
	}
	if rescanRetry < time.Hour || rescanRetry > 7*24*time.Hour {
		return fmt.Errorf("vulnerability_rescan_retry_interval must be between 1h and 168h")
	}
	rescanOperation, err := p.VulnerabilityRescanOperationTimeoutDuration()
	if err != nil {
		return fmt.Errorf("vulnerability_rescan_operation_timeout: %w", err)
	}
	if rescanOperation < time.Second || rescanOperation > 5*time.Minute {
		return fmt.Errorf("vulnerability_rescan_operation_timeout must be between 1s and 5m")
	}
	if value := p.VulnerabilityRescanCandidateLimitValue(); value < 1 || value > 1000 {
		return fmt.Errorf("vulnerability_rescan_candidate_limit must be between 1 and 1000")
	}
	return nil
}

func validSourceGitHTTPSProxy(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") ||
		strings.HasSuffix(parsed.Hostname(), ".") || parsed.Host != strings.ToLower(parsed.Host) {
		return false
	}
	if port := parsed.Port(); port != "" {
		number, portErr := strconv.Atoi(port)
		if portErr != nil || number < 1 || number > 65535 {
			return false
		}
	}
	return parsed.String() == value
}

func (p Product) SourceProbeTimeoutDuration() (time.Duration, error) {
	return parseDuration(p.SourceProbeTimeout, defaultSourceProbeTimeout)
}

func (p Product) BuildTriggerRateWindowDuration() (time.Duration, error) {
	return parseDuration(p.BuildTriggerRateWindow, defaultBuildTriggerWindow)
}

func (p Product) BuildTriggerRateLimitValue() int {
	if p.BuildTriggerRateLimit == 0 {
		return defaultBuildTriggerLimit
	}
	return p.BuildTriggerRateLimit
}

func (p Product) BuildWebhookMaxBodyBytesValue() int64 {
	if p.BuildWebhookMaxBodyBytes == 0 {
		return defaultBuildWebhookMaxBody
	}
	return p.BuildWebhookMaxBodyBytes
}

func (p Product) BuildWebhookRateWindowDuration() (time.Duration, error) {
	return parseDuration(p.BuildWebhookRateWindow, defaultBuildWebhookWindow)
}

func (p Product) BuildWebhookRateLimitValue() int {
	if p.BuildWebhookRateLimit == 0 {
		return defaultBuildWebhookLimit
	}
	return p.BuildWebhookRateLimit
}

func (p Product) VulnerabilityRescanPollIntervalDuration() (time.Duration, error) {
	return parseDuration(p.VulnerabilityRescanPollInterval, defaultVulnerabilityPoll)
}

func (p Product) VulnerabilityRescanRetryIntervalDuration() (time.Duration, error) {
	return parseDuration(p.VulnerabilityRescanRetryInterval, defaultVulnerabilityRetry)
}

func (p Product) VulnerabilityRescanOperationTimeoutDuration() (time.Duration, error) {
	return parseDuration(p.VulnerabilityRescanOperationTimeout, defaultVulnerabilityOperation)
}

func (p Product) VulnerabilityRescanCandidateLimitValue() int {
	if p.VulnerabilityRescanCandidateLimit == 0 {
		return defaultVulnerabilityCandidates
	}
	return p.VulnerabilityRescanCandidateLimit
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
		if version != agentprotocol.Version {
			return fmt.Errorf(
				"protocol version %q is not implemented; supported version is %q",
				version,
				agentprotocol.Version,
			)
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

func (w BuildWorker) Validate(mongoEnabled bool) error {
	host, port, metricsErr := net.SplitHostPort(w.MetricsAddressValue())
	portNumber, portErr := strconv.Atoi(port)
	if metricsErr != nil || portErr != nil || portNumber < 1 || portNumber > 65535 ||
		(host != "" && net.ParseIP(host) == nil && host != "localhost") {
		return fmt.Errorf("metrics_address must be a valid host:port")
	}
	logRetention, err := w.BuildLogRetentionDuration()
	if err != nil || logRetention < time.Hour || logRetention > 30*24*time.Hour {
		return fmt.Errorf("log_retention must be between 1h and 720h")
	}
	if w.BuildLogMaxBytesValue() < 1024*1024 || w.BuildLogMaxBytesValue() > 100*1024*1024 {
		return fmt.Errorf("log_max_bytes must be between 1 MiB and 100 MiB")
	}
	if w.BuildLogChunkBytesValue() < 4*1024 || w.BuildLogChunkBytesValue() > 64*1024 ||
		int64(w.BuildLogChunkBytesValue()) > w.BuildLogMaxBytesValue() {
		return fmt.Errorf("log_chunk_bytes must be between 4 KiB and 64 KiB and not exceed log_max_bytes")
	}
	if !w.Enabled {
		return nil
	}
	if !mongoEnabled {
		return fmt.Errorf("enabled requires database.mongo.enabled")
	}
	poll, err := w.PollIntervalDuration()
	if err != nil || poll < 100*time.Millisecond || poll > time.Minute {
		return fmt.Errorf("poll_interval must be between 100ms and 1m")
	}
	lease, err := w.LeaseDurationValue()
	if err != nil || lease < 3*time.Second || lease > 10*time.Minute {
		return fmt.Errorf("lease_duration must be between 3s and 10m")
	}
	operation, err := w.OperationTimeoutDuration()
	if err != nil || operation < time.Minute || operation > 3*time.Hour {
		return fmt.Errorf("operation_timeout must be between 1m and 3h")
	}
	checkout, err := w.CheckoutTimeoutDuration()
	if err != nil || checkout < time.Minute || checkout > operation {
		return fmt.Errorf("checkout_timeout must be between 1m and operation_timeout")
	}
	if !filepath.IsAbs(strings.TrimSpace(w.WorkspaceRoot)) || strings.TrimSpace(w.GitExecutable) == "" ||
		strings.TrimSpace(w.GitVersion) != "2.55.0" {
		return fmt.Errorf("workspace_root must be absolute and Git must be pinned to 2.55.0")
	}
	if w.MaxWorkspaceBytes < 1024*1024 || w.MaxWorkspaceBytes > 200*1024*1024*1024 ||
		w.MaxWorkspaceFiles < 100 || w.MaxWorkspaceFiles > 1000000 ||
		w.MaxWorkspaceDepth < 8 || w.MaxWorkspaceDepth > 256 {
		return fmt.Errorf("workspace resource limits are invalid")
	}
	if w.WorkspaceHardQuotaBytesValue() < w.MaxWorkspaceBytes ||
		w.WorkspaceHardQuotaBytesValue() > 400*1024*1024*1024 {
		return fmt.Errorf("workspace_hard_quota_bytes must cover max_workspace_bytes and not exceed 400 GiB")
	}
	if err := w.validateBuildKit(); err != nil {
		return err
	}
	if !validBuildEgressProxyURL(w.BuildEgressProxyURL) {
		return fmt.Errorf("build_egress_proxy_url must be a canonical credential-free HTTP origin")
	}
	return nil
}

func validBuildEgressProxyURL(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || value != strings.ToLower(value) {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Hostname() == "" ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.String() != value {
		return false
	}
	_, port, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		return false
	}
	portNumber, err := strconv.Atoi(port)
	return err == nil && portNumber >= 1 && portNumber <= 65535
}

func (g BuildEgress) Validate() error {
	if !g.Enabled {
		return nil
	}
	host, port, err := net.SplitHostPort(strings.TrimSpace(g.AddressValue()))
	portNumber, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || portNumber < 1 || portNumber > 65535 ||
		(host != "" && net.ParseIP(host) == nil) {
		return fmt.Errorf("address must be an IP host and valid port")
	}
	dial, err := g.DialTimeoutDuration()
	if err != nil || dial < time.Second || dial > time.Minute {
		return fmt.Errorf("dial_timeout must be between 1s and 1m")
	}
	idle, err := g.IdleTimeoutDuration()
	if err != nil || idle < 10*time.Second || idle > 30*time.Minute {
		return fmt.Errorf("idle_timeout must be between 10s and 30m")
	}
	if g.MaximumConnectionsValue() < 1 || g.MaximumConnectionsValue() > 4096 {
		return fmt.Errorf("maximum_connections must be between 1 and 4096")
	}
	if len(g.AllowedDestinations) == 0 || len(g.AllowedDestinations) > 256 {
		return fmt.Errorf("allowed_destinations must contain between 1 and 256 entries")
	}
	seen := make(map[string]struct{}, len(g.AllowedDestinations))
	for _, destination := range g.AllowedDestinations {
		value := destination.Authority
		if value == "" || value != strings.TrimSpace(value) || value != strings.ToLower(value) ||
			strings.ContainsAny(value, "/?#@") {
			return fmt.Errorf("destination authority must be canonical lowercase host:port")
		}
		host, port, splitErr := net.SplitHostPort(value)
		portNumber, portErr := strconv.Atoi(port)
		if splitErr != nil || portErr != nil || !validBuildEgressHost(host) || portNumber < 1 || portNumber > 65535 ||
			strings.HasSuffix(host, ".") {
			return fmt.Errorf("destination authority must be canonical lowercase host:port")
		}
		if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil && prohibitedBuildEgressIP(ip, destination.AllowPrivate) {
			return fmt.Errorf("destination authority contains a prohibited IP address")
		}
		if _, duplicate := seen[value]; duplicate {
			return fmt.Errorf("destination authorities must be unique")
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validBuildEgressHost(host string) bool {
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	if len(host) < 1 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func prohibitedBuildEgressIP(ip net.IP, allowPrivate bool) bool {
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	return !allowPrivate && ip.IsPrivate()
}

func (g BuildEgress) AddressValue() string {
	if strings.TrimSpace(g.Address) == "" {
		return defaultBuildEgressAddress
	}
	return strings.TrimSpace(g.Address)
}

func (g BuildEgress) DialTimeoutDuration() (time.Duration, error) {
	return parseDuration(g.DialTimeout, defaultBuildEgressDial)
}

func (g BuildEgress) IdleTimeoutDuration() (time.Duration, error) {
	return parseDuration(g.IdleTimeout, defaultBuildEgressIdle)
}

func (g BuildEgress) MaximumConnectionsValue() int {
	if g.MaximumConnections == 0 {
		return defaultBuildEgressConcurrent
	}
	return g.MaximumConnections
}

func (w BuildWorker) validateBuildKit() error {
	parsed, err := url.Parse(strings.TrimSpace(w.BuildKitEndpoint))
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("BuildKit endpoint is invalid")
	}
	switch parsed.Scheme {
	case "unix":
		if parsed.Host != "" || !filepath.IsAbs(parsed.Path) ||
			strings.Contains(strings.ToLower(parsed.Path), "docker.sock") ||
			w.BuildKitServerName != "" || w.BuildKitCACertFile != "" ||
			w.BuildKitClientCertFile != "" || w.BuildKitClientKeyFile != "" {
			return fmt.Errorf("BuildKit Unix endpoint must be a dedicated absolute socket")
		}
	case "tcp":
		if parsed.Path != "" || parsed.Hostname() == "" {
			return fmt.Errorf("BuildKit TCP endpoint is invalid")
		}
		if _, _, err := net.SplitHostPort(parsed.Host); err != nil ||
			strings.TrimSpace(w.BuildKitServerName) == "" ||
			!filepath.IsAbs(w.BuildKitCACertFile) ||
			!filepath.IsAbs(w.BuildKitClientCertFile) ||
			!filepath.IsAbs(w.BuildKitClientKeyFile) {
			return fmt.Errorf("BuildKit TCP endpoint requires mTLS file paths and server name")
		}
	default:
		return fmt.Errorf("BuildKit endpoint must use unix or mTLS tcp")
	}
	return nil
}

func (w BuildWorker) PollIntervalDuration() (time.Duration, error) {
	return parseDuration(w.PollInterval, defaultBuildWorkerPoll)
}
func (w BuildWorker) LeaseDurationValue() (time.Duration, error) {
	return parseDuration(w.LeaseDuration, defaultBuildWorkerLease)
}
func (w BuildWorker) OperationTimeoutDuration() (time.Duration, error) {
	return parseDuration(w.OperationTimeout, defaultBuildWorkerOperation)
}
func (w BuildWorker) CheckoutTimeoutDuration() (time.Duration, error) {
	return parseDuration(w.CheckoutTimeout, defaultBuildCheckoutTimeout)
}
func (w BuildWorker) WorkspaceHardQuotaBytesValue() int64 {
	if w.WorkspaceQuotaBytes == 0 {
		return defaultBuildWorkspaceQuota
	}
	return w.WorkspaceQuotaBytes
}
func (w BuildWorker) BuildLogRetentionDuration() (time.Duration, error) {
	return parseDuration(w.LogRetention, defaultBuildLogRetention)
}
func (w BuildWorker) BuildLogMaxBytesValue() int64 {
	if w.LogMaxBytes == 0 {
		return defaultBuildLogMaxBytes
	}
	return w.LogMaxBytes
}
func (w BuildWorker) BuildLogChunkBytesValue() int {
	if w.LogChunkBytes == 0 {
		return defaultBuildLogChunkBytes
	}
	return w.LogChunkBytes
}
func (w BuildWorker) MetricsAddressValue() string {
	if strings.TrimSpace(w.MetricsAddress) == "" {
		return defaultBuildMetricsAddress
	}
	return strings.TrimSpace(w.MetricsAddress)
}

func (w EvidenceWorker) Validate(mongoEnabled bool) error {
	if err := validateWorkerMetricsAddress(w.MetricsAddressValue()); err != nil {
		return err
	}
	if w.MaxDocumentBytesValue() < 1024*1024 || w.MaxDocumentBytesValue() > 64*1024*1024 {
		return fmt.Errorf("max_document_bytes must be between 1 MiB and 64 MiB")
	}
	if w.MaxLayerBytesValue() < 1024*1024 || w.MaxLayerBytesValue() > 4*1024*1024*1024 {
		return fmt.Errorf("max_layer_bytes must be between 1 MiB and 4 GiB")
	}
	if !w.Enabled {
		return nil
	}
	if !mongoEnabled {
		return fmt.Errorf("enabled requires database.mongo.enabled")
	}
	poll, err := w.PollIntervalDuration()
	if err != nil || poll < 100*time.Millisecond || poll > time.Minute {
		return fmt.Errorf("poll_interval must be between 100ms and 1m")
	}
	lease, err := w.LeaseDurationValue()
	if err != nil || lease < 3*time.Second || lease > 10*time.Minute {
		return fmt.Errorf("lease_duration must be between 3s and 10m")
	}
	operation, err := w.OperationTimeoutDuration()
	if err != nil || operation < time.Minute || operation > time.Hour {
		return fmt.Errorf("operation_timeout must be between 1m and 1h")
	}
	if !filepath.IsAbs(strings.TrimSpace(w.SyftExecutable)) ||
		strings.TrimPrefix(strings.TrimSpace(w.SyftVersion), "v") != "1.50.0" {
		return fmt.Errorf("Syft executable must be absolute and version must be pinned to 1.50.0")
	}
	if !filepath.IsAbs(strings.TrimSpace(w.CosignExecutable)) ||
		strings.TrimPrefix(strings.TrimSpace(w.CosignVersion), "v") != "3.0.6" {
		return fmt.Errorf("Cosign executable must be absolute and version must be pinned to 3.0.6")
	}
	if !filepath.IsAbs(strings.TrimSpace(w.TrivyExecutable)) ||
		strings.TrimPrefix(strings.TrimSpace(w.TrivyVersion), "v") != "0.74.0" {
		return fmt.Errorf("Trivy executable must be absolute and version must be pinned to 0.74.0")
	}
	if !filepath.IsAbs(strings.TrimSpace(w.TrivyCacheDirectory)) {
		return fmt.Errorf("trivy_cache_directory must be absolute")
	}
	freshness, err := w.VulnerabilityFreshnessDuration()
	if err != nil || freshness < time.Hour || freshness > 30*24*time.Hour {
		return fmt.Errorf("vulnerability_freshness must be between 1h and 720h")
	}
	if !filepath.IsAbs(strings.TrimSpace(w.TrustedRootsDirectory)) {
		return fmt.Errorf("trusted_roots_directory must be absolute")
	}
	return nil
}

func (w EvidenceWorker) VulnerabilityFreshnessDuration() (time.Duration, error) {
	return parseDuration(w.VulnerabilityFreshness, defaultEvidenceScanFreshness)
}

func (w EvidenceWorker) PollIntervalDuration() (time.Duration, error) {
	return parseDuration(w.PollInterval, defaultEvidenceWorkerPoll)
}

func (w EvidenceWorker) LeaseDurationValue() (time.Duration, error) {
	return parseDuration(w.LeaseDuration, defaultEvidenceWorkerLease)
}

func (w EvidenceWorker) OperationTimeoutDuration() (time.Duration, error) {
	return parseDuration(w.OperationTimeout, defaultEvidenceOperation)
}

func (w EvidenceWorker) MaxDocumentBytesValue() int64 {
	if w.MaxDocumentBytes == 0 {
		return defaultEvidenceDocumentBytes
	}
	return w.MaxDocumentBytes
}

func (w EvidenceWorker) MaxLayerBytesValue() int64 {
	if w.MaxLayerBytes == 0 {
		return defaultEvidenceLayerBytes
	}
	return w.MaxLayerBytes
}

func (w EvidenceWorker) MetricsAddressValue() string {
	if strings.TrimSpace(w.MetricsAddress) == "" {
		return defaultEvidenceMetrics
	}
	return strings.TrimSpace(w.MetricsAddress)
}

func validateWorkerMetricsAddress(value string) error {
	host, port, splitErr := net.SplitHostPort(value)
	portNumber, portErr := strconv.Atoi(port)
	if splitErr != nil || portErr != nil || portNumber < 1 || portNumber > 65535 ||
		(host != "" && net.ParseIP(host) == nil && host != "localhost") {
		return fmt.Errorf("metrics_address must be a valid host:port")
	}
	return nil
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
	if _, err := w.EventPollIntervalDuration(); err != nil {
		return fmt.Errorf("event_poll_interval: %w", err)
	}
	eventWait, err := w.EventWaitDuration()
	if err != nil {
		return fmt.Errorf("event_wait: %w", err)
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
	if eventWait < time.Second || eventWait > 10*time.Second ||
		eventWait%time.Second != 0 || eventWait >= command {
		return fmt.Errorf("event_wait must be whole seconds between 1s and 10s and shorter than command_timeout")
	}
	if w.ConcurrencyValue() < 1 || w.ConcurrencyValue() > 32 {
		return fmt.Errorf("concurrency must be between 1 and 32")
	}
	if w.EventConcurrencyValue() < 1 || w.EventConcurrencyValue() > 32 {
		return fmt.Errorf("event_concurrency must be between 1 and 32")
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

func (w InventoryWorker) EventPollIntervalDuration() (time.Duration, error) {
	return parseDuration(w.EventPollInterval, defaultInventoryEventPoll)
}

func (w InventoryWorker) EventWaitDuration() (time.Duration, error) {
	return parseDuration(w.EventWait, defaultInventoryEventWait)
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

func (w InventoryWorker) EventConcurrencyValue() int {
	if w.EventConcurrency == 0 {
		return defaultInventoryEventWorkers
	}
	return w.EventConcurrency
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
	hasEnvironment := strings.TrimSpace(m.URIEnv) != ""
	hasFile := strings.TrimSpace(m.URIFile) != ""
	if hasEnvironment == hasFile {
		return fmt.Errorf("exactly one of uri_env or uri_file is required when enabled")
	}
	if hasFile && !validSecretFilePath(m.URIFile) {
		return fmt.Errorf("uri_file must be a trimmed absolute path")
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
	if strings.TrimSpace(m.URIFile) != "" {
		return readSecretFile(m.URIFile, "MongoDB URI")
	}
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
	hasEnvironment := strings.TrimSpace(s.BootstrapTokenEnv) != ""
	hasFile := strings.TrimSpace(s.BootstrapTokenFile) != ""
	if hasEnvironment == hasFile {
		return fmt.Errorf("exactly one of bootstrap_token_env or bootstrap_token_file is required when product is enabled")
	}
	if hasFile && !validSecretFilePath(s.BootstrapTokenFile) {
		return fmt.Errorf("bootstrap_token_file must be a trimmed absolute path")
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
	invitationTTL, err := s.UserInvitationTTLDuration()
	if err != nil || invitationTTL < 15*time.Minute || invitationTTL > 7*24*time.Hour {
		return fmt.Errorf("user_invitation_ttl must be between 15m and 168h")
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
	sourceLimit, globalLimit := s.IngressSourceLimitValue(), s.IngressGlobalLimitValue()
	if sourceLimit < 1 || sourceLimit > 100000 {
		return fmt.Errorf("ingress_source_limit must be between 1 and 100000")
	}
	if globalLimit < sourceLimit || globalLimit > 1000000 {
		return fmt.Errorf("ingress_global_limit must be between ingress_source_limit and 1000000")
	}
	ingressWindow, err := s.IngressRateWindowDuration()
	if err != nil || ingressWindow < time.Second || ingressWindow > time.Hour {
		return fmt.Errorf("ingress_rate_window must be between 1s and 1h")
	}
	if len(s.TrustedProxyCIDRs) > 64 {
		return fmt.Errorf("trusted_proxy_cidrs must contain at most 64 entries")
	}
	seenProxyCIDRs := make(map[string]struct{}, len(s.TrustedProxyCIDRs))
	for _, rawCIDR := range s.TrustedProxyCIDRs {
		rawCIDR = strings.TrimSpace(rawCIDR)
		_, network, parseErr := net.ParseCIDR(rawCIDR)
		if parseErr != nil || network.String() != rawCIDR {
			return fmt.Errorf("trusted_proxy_cidrs must contain canonical CIDR values")
		}
		prefixBits, _ := network.Mask.Size()
		if prefixBits == 0 {
			return fmt.Errorf("trusted_proxy_cidrs must contain canonical CIDR values")
		}
		if _, exists := seenProxyCIDRs[rawCIDR]; exists {
			return fmt.Errorf("trusted_proxy_cidrs must not contain duplicates")
		}
		seenProxyCIDRs[rawCIDR] = struct{}{}
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

func (s Security) UserInvitationTTLDuration() (time.Duration, error) {
	return parseDuration(s.UserInvitationTTL, defaultUserInvitationTTL)
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

func (s Security) IngressSourceLimitValue() int {
	if s.IngressSourceLimit == 0 {
		return defaultIngressSourceLimit
	}
	return s.IngressSourceLimit
}

func (s Security) IngressGlobalLimitValue() int {
	if s.IngressGlobalLimit == 0 {
		return defaultIngressGlobalLimit
	}
	return s.IngressGlobalLimit
}

func (s Security) IngressRateWindowDuration() (time.Duration, error) {
	return parseDuration(s.IngressRateWindow, defaultIngressRateWindow)
}

func (s Security) LoginAttemptWindowDuration() (time.Duration, error) {
	return parseDuration(
		s.LoginAttemptWindow,
		defaultLoginAttemptWindow,
	)
}

func (s Security) BootstrapToken() (string, error) {
	if strings.TrimSpace(s.BootstrapTokenFile) != "" {
		return readSecretFile(s.BootstrapTokenFile, "bootstrap token")
	}
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

func validSecretFilePath(path string) bool {
	return path != "" && path == strings.TrimSpace(path) && filepath.IsAbs(path)
}

func readSecretFile(path, description string) (string, error) {
	if !validSecretFilePath(path) {
		return "", fmt.Errorf("%s file must be a trimmed absolute path", description)
	}
	before, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("read %s file metadata: %w", description, err)
	}
	if !before.Mode().IsRegular() || before.Mode().Perm()&0o022 != 0 ||
		before.Size() <= 0 || before.Size() > maximumSecretFileBytes {
		return "", fmt.Errorf("%s file must be regular, not group/world writable, and no larger than %d bytes", description, maximumSecretFileBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s file: %w", description, err)
	}
	defer func() { _ = file.Close() }()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return "", fmt.Errorf("%s file changed while opening", description)
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximumSecretFileBytes+1))
	if err != nil {
		return "", fmt.Errorf("read %s file: %w", description, err)
	}
	if len(contents) > maximumSecretFileBytes {
		return "", fmt.Errorf("%s file exceeds %d bytes", description, maximumSecretFileBytes)
	}
	value := strings.TrimSpace(string(contents))
	if value == "" || strings.ContainsAny(value, "\x00\r\n") {
		return "", fmt.Errorf("%s file must contain exactly one non-empty line", description)
	}
	return value, nil
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
