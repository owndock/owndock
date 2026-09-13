package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConfigValidate(t *testing.T) {
	cfg := Config{Server: Server{HTTP: HTTP{
		Address:         "127.0.0.1:8000",
		Timeout:         "5s",
		ShutdownTimeout: "10s",
	}}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	timeout, err := cfg.Server.HTTP.TimeoutDuration()
	if err != nil {
		t.Fatalf("TimeoutDuration() error = %v", err)
	}
	if timeout != 5*time.Second {
		t.Fatalf("TimeoutDuration() = %v, want %v", timeout, 5*time.Second)
	}

	invalid := cfg
	invalid.Runtime.EvidenceEgress = EgressGateway{Enabled: true}
	if err := invalid.Validate(); err == nil {
		t.Fatal("Config accepted an enabled Evidence egress gateway without destinations")
	}
}

func TestConfigRejectsInvalidDuration(t *testing.T) {
	cfg := Config{Server: Server{HTTP: HTTP{
		Address: "127.0.0.1:8000",
		Timeout: "not-a-duration",
	}}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want an error")
	}
}

func TestHTTPValidatesExactCORSOrigins(t *testing.T) {
	valid := HTTP{CORSAllowedOrigins: []string{
		"https://console.owndock.net",
		"https://console.owndock.net:8443",
		"http://localhost:3000",
		"http://127.0.0.1:3000",
		"http://[::1]:3000",
	}}
	if err := valid.ValidateCORSAllowedOrigins(); err != nil {
		t.Fatalf("valid origins rejected: %v", err)
	}

	tests := []struct {
		name    string
		origins []string
	}{
		{name: "wildcard", origins: []string{"*"}},
		{name: "subdomain wildcard", origins: []string{"https://*.owndock.net"}},
		{name: "non TLS remote", origins: []string{"http://console.owndock.net"}},
		{name: "path", origins: []string{"https://console.owndock.net/app"}},
		{name: "trailing slash", origins: []string{"https://console.owndock.net/"}},
		{name: "query", origins: []string{"https://console.owndock.net?tenant=one"}},
		{name: "fragment", origins: []string{"https://console.owndock.net#fragment"}},
		{name: "user info", origins: []string{"https://user@console.owndock.net"}},
		{name: "uppercase host", origins: []string{"https://Console.owndock.net"}},
		{name: "bad port", origins: []string{"https://console.owndock.net:70000"}},
		{name: "whitespace", origins: []string{" https://console.owndock.net"}},
		{name: "duplicate", origins: []string{"https://console.owndock.net", "https://console.owndock.net"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := (HTTP{CORSAllowedOrigins: test.origins}).ValidateCORSAllowedOrigins(); err == nil {
				t.Fatalf("origins %v were accepted", test.origins)
			}
		})
	}

	tooMany := HTTP{CORSAllowedOrigins: make([]string, 33)}
	for index := range tooMany.CORSAllowedOrigins {
		tooMany.CORSAllowedOrigins[index] = "https://console" + string(rune('a'+index%26)) + ".owndock.net"
	}
	if err := tooMany.ValidateCORSAllowedOrigins(); err == nil {
		t.Fatal("more than 32 origins were accepted")
	}
}

func TestTracingValidation(t *testing.T) {
	tests := []struct {
		name    string
		tracing Tracing
		wantErr bool
	}{
		{name: "disabled needs no collector"},
		{name: "enabled", tracing: Tracing{Enabled: true, Endpoint: "collector:4318", SampleRatio: 0.25}},
		{name: "missing endpoint", tracing: Tracing{Enabled: true}, wantErr: true},
		{name: "URL endpoint", tracing: Tracing{Enabled: true, Endpoint: "http://collector:4318"}, wantErr: true},
		{name: "invalid port", tracing: Tracing{Enabled: true, Endpoint: "collector:70000"}, wantErr: true},
		{name: "invalid ratio", tracing: Tracing{Enabled: true, Endpoint: "collector:4318", SampleRatio: 1.1}, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.tracing.Validate()
			if (err != nil) != test.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestTracingEffectiveSampleRatio(t *testing.T) {
	if got := (Tracing{SampleRatio: 0.25}).EffectiveSampleRatio(); got != 0.25 {
		t.Fatalf("EffectiveSampleRatio() = %v, want 0.25", got)
	}
}

func TestLoadDefaultsTraceSampleRatio(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := []byte("server:\n  http:\n    address: 127.0.0.1:8000\n")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := cfg.Observability.Tracing.SampleRatio; got != defaultTraceSampleRatio {
		t.Fatalf("sample ratio = %v, want %v", got, defaultTraceSampleRatio)
	}
	if cfg.Database.Mongo.Enabled {
		t.Fatal("MongoDB must be disabled by default")
	}
	if cfg.Product.Enabled {
		t.Fatal("product API must be disabled by default")
	}
	if cfg.Product.VulnerabilityRescanEnabled ||
		cfg.Product.VulnerabilityRescanPollInterval != defaultVulnerabilityPoll.String() ||
		cfg.Product.VulnerabilityRescanRetryInterval != defaultVulnerabilityRetry.String() ||
		cfg.Product.VulnerabilityRescanOperationTimeout != defaultVulnerabilityOperation.String() ||
		cfg.Product.VulnerabilityRescanCandidateLimitValue() != defaultVulnerabilityCandidates {
		t.Fatalf("vulnerability rescan defaults = %+v", cfg.Product)
	}
	if len(cfg.Server.HTTP.CORSAllowedOrigins) != 0 {
		t.Fatalf("CORS allowed origins = %v, want none", cfg.Server.HTTP.CORSAllowedOrigins)
	}
	if cfg.Runtime.DeploymentWorker.Enabled {
		t.Fatal("deployment worker must be disabled by default")
	}
	if !cfg.Runtime.BuildWorker.RequireWorkspaceQuota ||
		cfg.Runtime.BuildWorker.WorkspaceHardQuotaBytesValue() != defaultBuildWorkspaceQuota {
		t.Fatalf("Build Worker hard quota defaults = %t/%d",
			cfg.Runtime.BuildWorker.RequireWorkspaceQuota,
			cfg.Runtime.BuildWorker.WorkspaceHardQuotaBytesValue())
	}
	if cfg.Runtime.EvidenceWorker.Enabled ||
		cfg.Runtime.EvidenceWorker.SyftExecutable != defaultEvidenceSyftPath ||
		cfg.Runtime.EvidenceWorker.SyftVersion != "1.50.0" ||
		cfg.Runtime.EvidenceWorker.CosignExecutable != defaultEvidenceCosignPath ||
		cfg.Runtime.EvidenceWorker.CosignVersion != "3.0.6" ||
		cfg.Runtime.EvidenceWorker.TrivyExecutable != defaultEvidenceTrivyPath ||
		cfg.Runtime.EvidenceWorker.TrivyVersion != "0.74.0" ||
		cfg.Runtime.EvidenceWorker.TrivyCacheDirectory != defaultEvidenceTrivyCache ||
		cfg.Runtime.EvidenceWorker.TrustedRootsDirectory != defaultEvidenceTrustRoots ||
		cfg.Runtime.EvidenceWorker.MaxDocumentBytesValue() != defaultEvidenceDocumentBytes ||
		cfg.Runtime.EvidenceWorker.MaxLayerBytesValue() != defaultEvidenceLayerBytes ||
		cfg.Runtime.EvidenceWorker.VulnerabilityFreshness != defaultEvidenceScanFreshness.String() ||
		cfg.Runtime.EvidenceWorker.MetricsAddressValue() != defaultEvidenceMetrics {
		t.Fatalf("evidence worker defaults = %+v", cfg.Runtime.EvidenceWorker)
	}
	if cfg.Runtime.InventoryWorker.Enabled ||
		cfg.Runtime.InventoryWorker.ConcurrencyValue() != defaultInventoryConcurrency ||
		cfg.Runtime.InventoryWorker.EventConcurrencyValue() != defaultInventoryEventWorkers ||
		cfg.Runtime.InventoryWorker.CandidateLimitValue() != defaultInventoryCandidates ||
		cfg.Runtime.InventoryWorker.MaxChunkBytesValue() != defaultInventoryChunkBytes {
		t.Fatalf("inventory worker defaults = %+v", cfg.Runtime.InventoryWorker)
	}
	if cfg.Server.Agent.Enabled ||
		cfg.Server.Agent.Address != defaultAgentAddress ||
		cfg.Server.Agent.MaxFrameBytes != defaultAgentMaxFrameBytes ||
		cfg.Server.Agent.OutboundBuffer != defaultAgentOutboundBuffer ||
		cfg.Server.Agent.CompletedCommandCache != defaultAgentCompletedCache ||
		len(cfg.Server.Agent.ProtocolVersions) != 1 ||
		cfg.Server.Agent.ProtocolVersions[0] != "v1" {
		t.Fatalf("Agent server defaults = %+v", cfg.Server.Agent)
	}
	if duration, err := cfg.Runtime.DeploymentWorker.LeaseDurationValue(); err != nil || duration != defaultWorkerLease {
		t.Fatalf("worker lease duration = %v, %v", duration, err)
	}
	if cfg.Security.BootstrapTokenEnv != defaultBootstrapTokenEnv {
		t.Fatalf("bootstrap token env = %q, want %q", cfg.Security.BootstrapTokenEnv, defaultBootstrapTokenEnv)
	}
	sessionTTL, err := cfg.Security.SessionTTLDuration()
	if err != nil || sessionTTL != defaultSessionTTL {
		t.Fatalf("session TTL = %v, %v; want %v", sessionTTL, err, defaultSessionTTL)
	}
	if maximum := cfg.Security.MaxActiveSessionsValue(); maximum !=
		defaultMaximumActiveSessions {
		t.Fatalf(
			"maximum active sessions = %d, want %d",
			maximum,
			defaultMaximumActiveSessions,
		)
	}
	if cfg.Security.LoginAttemptLimitValue() !=
		defaultLoginAttemptLimit {
		t.Fatalf(
			"login attempt limit = %d, want %d",
			cfg.Security.LoginAttemptLimitValue(),
			defaultLoginAttemptLimit,
		)
	}
	loginWindow, err := cfg.Security.LoginAttemptWindowDuration()
	if err != nil || loginWindow != defaultLoginAttemptWindow {
		t.Fatalf(
			"login attempt window = %v, %v; want %v",
			loginWindow,
			err,
			defaultLoginAttemptWindow,
		)
	}
	if cfg.Security.IngressSourceLimitValue() != defaultIngressSourceLimit ||
		cfg.Security.IngressGlobalLimitValue() != defaultIngressGlobalLimit {
		t.Fatalf("ingress limits = %d/%d, want %d/%d",
			cfg.Security.IngressSourceLimitValue(), cfg.Security.IngressGlobalLimitValue(),
			defaultIngressSourceLimit, defaultIngressGlobalLimit)
	}
	ingressWindow, err := cfg.Security.IngressRateWindowDuration()
	if err != nil || ingressWindow != defaultIngressRateWindow {
		t.Fatalf("ingress rate window = %v, %v; want %v", ingressWindow, err, defaultIngressRateWindow)
	}
	if len(cfg.Security.TrustedProxyCIDRs) != 0 {
		t.Fatalf("trusted proxy CIDRs = %v, want none", cfg.Security.TrustedProxyCIDRs)
	}
	if cfg.Security.AgentPKI.Enabled ||
		cfg.Security.AgentPKI.CACertificateEnv != defaultAgentCACertEnv ||
		cfg.Security.AgentPKI.CAPrivateKeyEnv != defaultAgentCAKeyEnv {
		t.Fatalf("Agent PKI defaults = %+v", cfg.Security.AgentPKI)
	}
	if cfg.Database.Mongo.URIEnv != defaultMongoURIEnv ||
		cfg.Database.Mongo.Database != defaultMongoDatabase ||
		cfg.Database.Mongo.MaxPoolSize != defaultMongoMaxPoolSize {
		t.Fatalf("MongoDB defaults = %+v", cfg.Database.Mongo)
	}
}

func TestProductValidatesVulnerabilityRescanConfiguration(t *testing.T) {
	product := Product{
		Enabled: true, SourceProbeTimeout: "10s",
		BuildTriggerRateLimit: 60, BuildTriggerRateWindow: "1m",
		BuildWebhookRateLimit: 120, BuildWebhookRateWindow: "1m",
		BuildWebhookMaxBodyBytes:   1024 * 1024,
		VulnerabilityRescanEnabled: true, VulnerabilityRescanPollInterval: "5m",
		VulnerabilityRescanRetryInterval: "6h", VulnerabilityRescanOperationTimeout: "30s",
		VulnerabilityRescanCandidateLimit: 100,
	}
	if err := product.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Product){
		"product disabled":    func(item *Product) { item.Enabled = false },
		"poll too short":      func(item *Product) { item.VulnerabilityRescanPollInterval = "9s" },
		"invalid poll":        func(item *Product) { item.VulnerabilityRescanPollInterval = "often" },
		"retry too short":     func(item *Product) { item.VulnerabilityRescanRetryInterval = "59m" },
		"invalid retry":       func(item *Product) { item.VulnerabilityRescanRetryInterval = "later" },
		"operation too long":  func(item *Product) { item.VulnerabilityRescanOperationTimeout = "6m" },
		"invalid operation":   func(item *Product) { item.VulnerabilityRescanOperationTimeout = "soon" },
		"too many candidates": func(item *Product) { item.VulnerabilityRescanCandidateLimit = 1001 },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := product
			mutate(&invalid)
			if err := invalid.Validate(); err == nil {
				t.Fatal("invalid vulnerability rescan configuration accepted")
			}
		})
	}
}

func TestLoadCommunityDeploymentConfig(t *testing.T) {
	path := filepath.Join("..", "..", "..", "deploy", "community.config.yaml")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.Product.Enabled || !cfg.Database.Mongo.Enabled ||
		cfg.Database.Mongo.URIEnv != "" || cfg.Database.Mongo.URIFile != "/run/secrets/owndock-mongodb-uri" ||
		cfg.Security.BootstrapTokenEnv != "" || cfg.Security.BootstrapTokenFile != "/run/secrets/owndock-bootstrap-token" ||
		!cfg.Runtime.DeploymentWorker.Enabled || !cfg.Runtime.InventoryWorker.Enabled {
		t.Fatalf("community deployment config = %+v", cfg)
	}
}

func TestAgentPKIValidationAndMaterialLoading(t *testing.T) {
	pki := AgentPKI{
		Enabled:          true,
		CACertificateEnv: "TEST_AGENT_CA_CERT",
		CAPrivateKeyEnv:  "TEST_AGENT_CA_KEY",
		EnrollmentTTL:    "15m",
		CertificateTTL:   "720h",
	}
	if err := pki.Validate(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_AGENT_CA_CERT", "certificate")
	t.Setenv("TEST_AGENT_CA_KEY", "private-key")
	certificate, privateKey, err := pki.Materials()
	if err != nil || string(certificate) != "certificate" ||
		string(privateKey) != "private-key" {
		t.Fatalf("materials = %q %q, error = %v", certificate, privateKey, err)
	}
	pki.CertificateTTL = "5m"
	if err := pki.Validate(); err == nil {
		t.Fatal("Agent PKI accepted certificate TTL shorter than enrollment TTL")
	}
}

func TestAgentServerValidationAndMaterialLoading(t *testing.T) {
	agent := Agent{
		Enabled: true, Address: "127.0.0.1:8443",
		ServerCertificateEnv: "TEST_AGENT_SERVER_CERT",
		ServerPrivateKeyEnv:  "TEST_AGENT_SERVER_KEY",
		HandshakeTimeout:     "5s", HeartbeatInterval: "10s",
		HeartbeatTimeout: "30s", MaxFrameBytes: 65536,
		OutboundBuffer: 32, CompletedCommandCache: 256,
		ProtocolVersions: []string{"v1"},
	}
	if err := agent.Validate(true, true, true); err != nil {
		t.Fatal(err)
	}
	agent.ProtocolVersions = []string{"v2"}
	if err := agent.Validate(true, true, true); err == nil {
		t.Fatal("Agent server accepted a protocol without an implemented wire adapter")
	}
	agent.ProtocolVersions = []string{"v1"}
	t.Setenv("TEST_AGENT_SERVER_CERT", "certificate")
	t.Setenv("TEST_AGENT_SERVER_KEY", "private-key")
	certificate, privateKey, err := agent.Materials()
	if err != nil || string(certificate) != "certificate" ||
		string(privateKey) != "private-key" {
		t.Fatalf("materials = %q %q, error = %v", certificate, privateKey, err)
	}
	if err := agent.Validate(false, true, true); err == nil {
		t.Fatal("Agent server accepted disabled product")
	}
	agent.HeartbeatTimeout = "5s"
	if err := agent.Validate(true, true, true); err == nil {
		t.Fatal("Agent server accepted heartbeat timeout shorter than interval")
	}
	agent.HeartbeatTimeout = "30s"
	agent.OutboundBuffer = 0
	if err := agent.Validate(true, true, true); err == nil {
		t.Fatal("Agent server accepted an empty outbound buffer")
	}
}

func TestDeploymentWorkerRequiresProductAndMongoDB(t *testing.T) {
	worker := DeploymentWorker{
		Enabled: true, PollInterval: "1s", LeaseDuration: "30s", OperationTimeout: "5m",
	}
	if err := worker.Validate(false, true); err == nil {
		t.Fatal("worker accepted disabled product")
	}
	if err := worker.Validate(true, false); err == nil {
		t.Fatal("worker accepted disabled MongoDB")
	}
	if err := worker.Validate(true, true); err != nil {
		t.Fatalf("valid worker error = %v", err)
	}
	worker.PollInterval = "invalid"
	if err := worker.Validate(true, true); err == nil {
		t.Fatal("worker accepted invalid poll interval")
	}
}

func TestBuildWorkerRequiresDedicatedBuildKitEndpoint(t *testing.T) {
	worker := BuildWorker{
		Enabled: true, PollInterval: "2s", LeaseDuration: "30s", OperationTimeout: "2h15m",
		CheckoutTimeout: "10m", WorkspaceRoot: "/var/lib/owndock/builds",
		MaxWorkspaceBytes: 5 * 1024 * 1024 * 1024, MaxWorkspaceFiles: 250000, MaxWorkspaceDepth: 64,
		GitExecutable: "git", GitVersion: "2.55.0",
		BuildKitEndpoint:    "unix:///run/owndock-buildkit/buildkitd.sock",
		BuildEgressProxyURL: "http://build-egress-gateway:3128",
	}
	if err := worker.Validate(true); err != nil {
		t.Fatalf("dedicated Unix BuildKit endpoint rejected: %v", err)
	}
	for _, proxyURL := range []string{
		"", "https://build-egress-gateway:3128", "http://user:secret@build-egress-gateway:3128",
		"http://build-egress-gateway:3128/path", "http://Build-Egress-Gateway:3128",
	} {
		invalid := worker
		invalid.BuildEgressProxyURL = proxyURL
		if err := invalid.Validate(true); err == nil {
			t.Fatalf("Build Worker accepted unsafe egress proxy URL %q", proxyURL)
		}
	}
	worker.MaxWorkspaceDepth = 7
	if err := worker.Validate(true); err == nil {
		t.Fatal("Build Worker accepted an unsafe workspace path depth")
	}
	worker.MaxWorkspaceDepth = 64
	worker.WorkspaceQuotaBytes = worker.MaxWorkspaceBytes - 1
	if err := worker.Validate(true); err == nil {
		t.Fatal("Build Worker accepted a hard quota smaller than the workspace byte limit")
	}
	worker.WorkspaceQuotaBytes = 8 * 1024 * 1024 * 1024
	worker.BuildKitEndpoint = "unix:///var/run/docker.sock"
	if err := worker.Validate(true); err == nil {
		t.Fatal("Docker socket was accepted as BuildKit endpoint")
	}
	worker.BuildKitEndpoint = "tcp://buildkit:1234"
	if err := worker.Validate(true); err == nil {
		t.Fatal("unauthenticated BuildKit TCP endpoint was accepted")
	}
	worker.BuildKitServerName = "buildkit"
	worker.BuildKitCACertFile = "/etc/owndock/buildkit/ca.pem"
	worker.BuildKitClientCertFile = "/etc/owndock/buildkit/worker-cert.pem"
	worker.BuildKitClientKeyFile = "/etc/owndock/buildkit/worker-key.pem"
	if err := worker.Validate(true); err != nil {
		t.Fatalf("mTLS BuildKit endpoint rejected: %v", err)
	}
	worker.LogRetention = "31d"
	if err := worker.Validate(true); err == nil {
		t.Fatal("Build Worker accepted excessive log retention")
	}
	worker.LogRetention = "168h"
	worker.LogMaxBytes = 512 * 1024
	if err := worker.Validate(true); err == nil {
		t.Fatal("Build Worker accepted an unsafe log byte cap")
	}
	worker.LogMaxBytes = 10 * 1024 * 1024
	worker.LogChunkBytes = 128 * 1024
	if err := worker.Validate(true); err == nil {
		t.Fatal("Build Worker accepted an oversized log chunk")
	}
	worker.LogChunkBytes = 16 * 1024
	worker.MetricsAddress = "http://127.0.0.1:9091"
	if err := worker.Validate(true); err == nil {
		t.Fatal("Build Worker accepted an invalid metrics address")
	}
}

func TestBuildEgressGatewayRequiresExplicitSafeDestinations(t *testing.T) {
	gateway := EgressGateway{
		Enabled: true, Address: "0.0.0.0:3128", DialTimeout: "10s", IdleTimeout: "2m",
		MaximumConnections: 128,
		AllowedDestinations: []EgressDestination{
			{Authority: "registry-1.docker.io:443"},
			{Authority: "registry.internal:5000", AllowPrivate: true},
		},
	}
	if err := gateway.Validate(); err != nil {
		t.Fatalf("valid Build egress gateway error = %v", err)
	}
	for name, mutate := range map[string]func(*EgressGateway){
		"empty": func(item *EgressGateway) { item.AllowedDestinations = nil },
		"duplicate": func(item *EgressGateway) {
			item.AllowedDestinations = append(item.AllowedDestinations, item.AllowedDestinations[0])
		},
		"uppercase": func(item *EgressGateway) {
			item.AllowedDestinations = []EgressDestination{{Authority: "Registry.Example:443"}}
		},
		"userinfo": func(item *EgressGateway) {
			item.AllowedDestinations = []EgressDestination{{Authority: "user@registry.example:443"}}
		},
		"private without opt in": func(item *EgressGateway) {
			item.AllowedDestinations = []EgressDestination{{Authority: "10.0.0.1:443"}}
		},
		"loopback with opt in": func(item *EgressGateway) {
			item.AllowedDestinations = []EgressDestination{{Authority: "127.0.0.1:443", AllowPrivate: true}}
		},
		"link local with opt in": func(item *EgressGateway) {
			item.AllowedDestinations = []EgressDestination{{Authority: "169.254.169.254:80", AllowPrivate: true}}
		},
		"hostname bind": func(item *EgressGateway) { item.Address = "gateway:3128" },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := gateway
			invalid.AllowedDestinations = append([]EgressDestination(nil), gateway.AllowedDestinations...)
			mutate(&invalid)
			if err := invalid.Validate(); err == nil {
				t.Fatal("unsafe Build egress gateway configuration accepted")
			}
		})
	}
}

func TestEvidenceWorkerRequiresPinnedSyftAndMongoDB(t *testing.T) {
	worker := EvidenceWorker{
		Enabled: true, PollInterval: "2s", LeaseDuration: "30s", OperationTimeout: "30m",
		SyftExecutable: "/usr/local/bin/syft", SyftVersion: "1.50.0",
		CosignExecutable: "/usr/local/bin/cosign", CosignVersion: "3.0.6",
		TrivyExecutable: "/usr/local/bin/trivy", TrivyVersion: "0.74.0",
		TrivyCacheDirectory: "/var/lib/owndock/trivy-db/current", VulnerabilityFreshness: "24h",
		TrustedRootsDirectory: "/etc/owndock/trusted-roots",
		MaxDocumentBytes:      16 * 1024 * 1024, MaxLayerBytes: 256 * 1024 * 1024,
		MetricsAddress: "127.0.0.1:9092",
	}
	if err := worker.Validate(false); err == nil {
		t.Fatal("Evidence Worker accepted disabled MongoDB")
	}
	if err := worker.Validate(true); err != nil {
		t.Fatalf("valid Evidence Worker error = %v", err)
	}
	for name, mutate := range map[string]func(*EvidenceWorker){
		"relative Syft":     func(item *EvidenceWorker) { item.SyftExecutable = "syft" },
		"unpinned Syft":     func(item *EvidenceWorker) { item.SyftVersion = "1.51.0" },
		"relative Cosign":   func(item *EvidenceWorker) { item.CosignExecutable = "cosign" },
		"unpinned Cosign":   func(item *EvidenceWorker) { item.CosignVersion = "3.0.7" },
		"relative Trivy":    func(item *EvidenceWorker) { item.TrivyExecutable = "trivy" },
		"unpinned Trivy":    func(item *EvidenceWorker) { item.TrivyVersion = "0.75.0" },
		"relative Trivy DB": func(item *EvidenceWorker) { item.TrivyCacheDirectory = "trivy-cache" },
		"short freshness":   func(item *EvidenceWorker) { item.VulnerabilityFreshness = "30m" },
		"relative roots":    func(item *EvidenceWorker) { item.TrustedRootsDirectory = "trusted-roots" },
		"small report":      func(item *EvidenceWorker) { item.MaxDocumentBytes = 1024 },
		"small layer":       func(item *EvidenceWorker) { item.MaxLayerBytes = 1024 },
		"long operation": func(item *EvidenceWorker) {
			item.OperationTimeout = "2h"
		},
		"remote metrics hostname": func(item *EvidenceWorker) {
			item.MetricsAddress = "metrics.example.com:9092"
		},
	} {
		t.Run(name, func(t *testing.T) {
			invalid := worker
			mutate(&invalid)
			if err := invalid.Validate(true); err == nil {
				t.Fatalf("invalid Evidence Worker accepted: %+v", invalid)
			}
		})
	}
}

func TestInventoryWorkerValidation(t *testing.T) {
	worker := InventoryWorker{
		Enabled: true, PollInterval: "1s", SyncInterval: "5m",
		RetryInterval: "30s", EventPollInterval: "1s", EventWait: "2s",
		LeaseDuration:    "2m",
		OperationTimeout: "1m", CommandTimeout: "20s",
		Concurrency: 2, EventConcurrency: 4,
		CandidateLimit: 256, MaxChunkBytes: 48 * 1024,
	}
	if err := worker.Validate(false, true); err == nil {
		t.Fatal("inventory worker accepted disabled product")
	}
	if err := worker.Validate(true, true); err != nil {
		t.Fatalf("valid inventory worker error = %v", err)
	}
	worker.LeaseDuration = "30s"
	if err := worker.Validate(true, true); err == nil {
		t.Fatal("inventory worker accepted a lease shorter than its operation timeout")
	}
	worker.LeaseDuration = "2m"
	worker.EventWait = "500ms"
	if err := worker.Validate(true, true); err == nil {
		t.Fatal("inventory worker accepted a sub-second event wait")
	}
	worker.EventWait = "2s"
	worker.MaxChunkBytes = 512 * 1024
	if err := worker.Validate(true, true); err == nil {
		t.Fatal("inventory worker accepted chunks larger than the Agent contract")
	}
}

func TestProductRequiresMongoDBAndSecurity(t *testing.T) {
	cfg := Config{
		Server:   Server{HTTP: HTTP{Address: "127.0.0.1:8000"}},
		Product:  Product{Enabled: true},
		Security: Security{BootstrapTokenEnv: "TEST_BOOTSTRAP_TOKEN", SessionTTL: "1h"},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() error = nil without MongoDB")
	}
	cfg.Database.Mongo = Mongo{
		Enabled: true, URIEnv: "TEST_MONGODB_URI", Database: "test", MaxPoolSize: 10,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	cfg.Security.BootstrapTokenEnv = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() error = nil without bootstrap token env")
	}
}

func TestProductSourceProbeTimeoutValidation(t *testing.T) {
	for _, value := range []string{"1s", "10s", "30s", ""} {
		if err := (Product{SourceProbeTimeout: value}).Validate(); err != nil {
			t.Errorf("Product timeout %q error = %v", value, err)
		}
	}
	for _, value := range []string{"500ms", "31s", "invalid"} {
		if err := (Product{SourceProbeTimeout: value}).Validate(); err == nil {
			t.Errorf("Product timeout %q accepted", value)
		}
	}
}

func TestProductSourceGitNetworkValidation(t *testing.T) {
	for _, product := range []Product{
		{},
		{SourceGitCACertFile: "/etc/owndock/git/ca.pem"},
		{RegistryCACertFile: "/etc/owndock/registry/ca.pem"},
		{RegistryHTTPSProxy: "http://proxy.internal:3128"},
		{RegistryHTTPSProxy: "https://127.0.0.1:8443"},
		{SourceGitHTTPSProxy: "http://proxy.internal:3128"},
		{SourceGitHTTPSProxy: "https://127.0.0.1:8443"},
	} {
		if err := product.Validate(); err != nil {
			t.Errorf("Product %+v error = %v", product, err)
		}
	}
	for _, product := range []Product{
		{SourceGitCACertFile: "relative/ca.pem"},
		{SourceGitCACertFile: " /etc/ca.pem"},
		{RegistryCACertFile: "relative/ca.pem"},
		{RegistryCACertFile: " /etc/registry-ca.pem"},
		{RegistryHTTPSProxy: "http://user:secret@proxy.internal:3128"},
		{RegistryHTTPSProxy: "http://proxy.internal:3128/path"},
		{RegistryHTTPSProxy: "socks5://proxy.internal:1080"},
		{RegistryHTTPSProxy: "http://PROXY.internal:3128"},
		{RegistryHTTPSProxy: "http://proxy.internal:65536"},
		{SourceGitHTTPSProxy: "http://user:secret@proxy.internal:3128"},
		{SourceGitHTTPSProxy: "http://proxy.internal:3128/path"},
		{SourceGitHTTPSProxy: "socks5://proxy.internal:1080"},
		{SourceGitHTTPSProxy: "http://PROXY.internal:3128"},
		{SourceGitHTTPSProxy: "http://proxy.internal:65536"},
	} {
		if err := product.Validate(); err == nil {
			t.Errorf("Product %+v accepted", product)
		}
	}
}

func TestProductBuildTriggerRateValidation(t *testing.T) {
	for _, product := range []Product{
		{},
		{BuildTriggerRateLimit: 1, BuildTriggerRateWindow: "1s"},
		{BuildTriggerRateLimit: 10_000, BuildTriggerRateWindow: "24h"},
	} {
		if err := product.Validate(); err != nil {
			t.Errorf("Product %+v error = %v", product, err)
		}
	}
	for _, product := range []Product{
		{BuildTriggerRateLimit: -1},
		{BuildTriggerRateLimit: 10_001},
		{BuildTriggerRateWindow: "500ms"},
		{BuildTriggerRateWindow: "25h"},
	} {
		if err := product.Validate(); err == nil {
			t.Errorf("Product %+v accepted", product)
		}
	}
}

func TestProductBuildWebhookBodyLimitValidation(t *testing.T) {
	for _, value := range []int64{0, 1024, 1024 * 1024, 5 * 1024 * 1024} {
		product := Product{BuildWebhookMaxBodyBytes: value}
		if err := product.Validate(); err != nil {
			t.Errorf("Product webhook body limit %d error = %v", value, err)
		}
	}
	for _, value := range []int64{-1, 1023, 5*1024*1024 + 1} {
		if err := (Product{BuildWebhookMaxBodyBytes: value}).Validate(); err == nil {
			t.Errorf("Product webhook body limit %d accepted", value)
		}
	}
	if got := (Product{}).BuildWebhookMaxBodyBytesValue(); got != 1024*1024 {
		t.Fatalf("default webhook body limit = %d", got)
	}
}

func TestProductBuildWebhookRateValidation(t *testing.T) {
	for _, product := range []Product{
		{},
		{BuildWebhookRateLimit: 1, BuildWebhookRateWindow: "1s"},
		{BuildWebhookRateLimit: 10_000, BuildWebhookRateWindow: "24h"},
	} {
		if err := product.Validate(); err != nil {
			t.Errorf("Product %+v error = %v", product, err)
		}
	}
	for _, product := range []Product{
		{BuildWebhookRateLimit: -1},
		{BuildWebhookRateLimit: 10_001},
		{BuildWebhookRateWindow: "500ms"},
		{BuildWebhookRateWindow: "25h"},
	} {
		if err := product.Validate(); err == nil {
			t.Errorf("Product %+v accepted", product)
		}
	}
	if got := (Product{}).BuildWebhookRateLimitValue(); got != 120 {
		t.Fatalf("default webhook rate limit = %d", got)
	}
	if got, err := (Product{}).BuildWebhookRateWindowDuration(); err != nil || got != time.Minute {
		t.Fatalf("default webhook rate window = %s/%v", got, err)
	}
}

func TestLoginProtectionConfigurationValidation(t *testing.T) {
	securityConfig := Security{
		BootstrapTokenEnv:  "TEST_BOOTSTRAP_TOKEN",
		SessionTTL:         "1h",
		LoginAttemptLimit:  5,
		LoginAttemptWindow: "15m",
	}
	if err := securityConfig.Validate(true); err != nil {
		t.Fatal(err)
	}
	securityConfig.LoginAttemptLimit = 101
	if err := securityConfig.Validate(true); err == nil {
		t.Fatal("accepted excessive login attempt limit")
	}
	securityConfig.LoginAttemptLimit = 5
	securityConfig.LoginAttemptWindow = "30s"
	if err := securityConfig.Validate(true); err == nil {
		t.Fatal("accepted login attempt window below one minute")
	}
}

func TestIngressProtectionConfigurationValidation(t *testing.T) {
	valid := Security{
		BootstrapTokenEnv: "TEST_BOOTSTRAP_TOKEN", SessionTTL: "1h",
		IngressSourceLimit: 600, IngressGlobalLimit: 6000, IngressRateWindow: "1m",
		TrustedProxyCIDRs: []string{"10.0.0.0/8", "2001:db8::/32"},
	}
	if err := valid.Validate(true); err != nil {
		t.Fatalf("valid ingress policy: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Security)
	}{
		{name: "negative source limit", mutate: func(value *Security) { value.IngressSourceLimit = -1 }},
		{name: "source limit too high", mutate: func(value *Security) { value.IngressSourceLimit = 100001 }},
		{name: "negative global limit", mutate: func(value *Security) { value.IngressGlobalLimit = -1 }},
		{name: "global below source", mutate: func(value *Security) { value.IngressGlobalLimit = 599 }},
		{name: "global too high", mutate: func(value *Security) { value.IngressGlobalLimit = 1000001 }},
		{name: "window too short", mutate: func(value *Security) { value.IngressRateWindow = "500ms" }},
		{name: "window too long", mutate: func(value *Security) { value.IngressRateWindow = "61m" }},
		{name: "invalid CIDR", mutate: func(value *Security) { value.TrustedProxyCIDRs = []string{"not-a-cidr"} }},
		{name: "non-canonical CIDR", mutate: func(value *Security) { value.TrustedProxyCIDRs = []string{"10.1.2.3/8"} }},
		{name: "trust every IPv4 peer", mutate: func(value *Security) { value.TrustedProxyCIDRs = []string{"0.0.0.0/0"} }},
		{name: "trust every IPv6 peer", mutate: func(value *Security) { value.TrustedProxyCIDRs = []string{"::/0"} }},
		{name: "duplicate CIDR", mutate: func(value *Security) { value.TrustedProxyCIDRs = []string{"10.0.0.0/8", "10.0.0.0/8"} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			candidate.TrustedProxyCIDRs = append([]string(nil), valid.TrustedProxyCIDRs...)
			test.mutate(&candidate)
			if err := candidate.Validate(true); err == nil {
				t.Fatal("invalid ingress policy was accepted")
			}
		})
	}

	tooMany := valid
	tooMany.TrustedProxyCIDRs = make([]string, 65)
	for index := range tooMany.TrustedProxyCIDRs {
		tooMany.TrustedProxyCIDRs[index] = "10.0.0.0/8"
	}
	if err := tooMany.Validate(true); err == nil {
		t.Fatal("more than 64 trusted proxy CIDRs were accepted")
	}
}

func TestUserInvitationTTLValidation(t *testing.T) {
	for _, value := range []string{"", "15m", "24h", "168h"} {
		securityConfig := Security{BootstrapTokenEnv: "TEST_BOOTSTRAP_TOKEN", SessionTTL: "1h",
			MaxActiveSessions: 10, LoginAttemptLimit: 5, LoginAttemptWindow: "15m",
			UserInvitationTTL: value}
		if err := securityConfig.Validate(true); err != nil {
			t.Errorf("invitation TTL %q error = %v", value, err)
		}
	}
	for _, value := range []string{"14m59s", "169h", "invalid"} {
		securityConfig := Security{BootstrapTokenEnv: "TEST_BOOTSTRAP_TOKEN", SessionTTL: "1h",
			MaxActiveSessions: 10, LoginAttemptLimit: 5, LoginAttemptWindow: "15m",
			UserInvitationTTL: value}
		if err := securityConfig.Validate(true); err == nil {
			t.Errorf("invitation TTL %q accepted", value)
		}
	}
	if got, err := (Security{}).UserInvitationTTLDuration(); err != nil || got != 24*time.Hour {
		t.Fatalf("default invitation TTL = %s/%v", got, err)
	}
}

func TestSessionPolicyConfigurationValidation(t *testing.T) {
	securityConfig := Security{
		BootstrapTokenEnv: "TEST_BOOTSTRAP_TOKEN",
		SessionTTL:        "1h",
		MaxActiveSessions: 10,
	}
	if err := securityConfig.Validate(true); err != nil {
		t.Fatal(err)
	}
	securityConfig.MaxActiveSessions = 101
	if err := securityConfig.Validate(true); err == nil {
		t.Fatal("accepted excessive active session limit")
	}
}

func TestBootstrapTokenReadsOnlyNamedEnvironmentVariable(t *testing.T) {
	t.Setenv("TEST_BOOTSTRAP_TOKEN", " bootstrap-secret ")
	token, err := (Security{BootstrapTokenEnv: "TEST_BOOTSTRAP_TOKEN"}).BootstrapToken()
	if err != nil {
		t.Fatalf("BootstrapToken() error = %v", err)
	}
	if token != "bootstrap-secret" {
		t.Fatalf("BootstrapToken() = %q", token)
	}
}

func TestBootstrapTokenReadsRestrictedSecretFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bootstrap-token")
	if err := os.WriteFile(path, []byte("bootstrap-secret\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	securityConfig := Security{BootstrapTokenFile: path, SessionTTL: "1h"}
	if err := securityConfig.Validate(true); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	token, err := securityConfig.BootstrapToken()
	if err != nil || token != "bootstrap-secret" {
		t.Fatalf("BootstrapToken() = %q, %v", token, err)
	}
	securityConfig.BootstrapTokenEnv = "TEST_BOOTSTRAP_TOKEN"
	if err := securityConfig.Validate(true); err == nil {
		t.Fatal("environment and file bootstrap sources were accepted together")
	}
}

func TestMongoValidation(t *testing.T) {
	valid := Mongo{
		Enabled:          true,
		URIEnv:           "TEST_MONGODB_URI",
		Database:         "test",
		ConnectTimeout:   "2s",
		OperationTimeout: "1s",
		MaxIdleTime:      "1m",
		MaxPoolSize:      10,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	tests := []Mongo{
		{Enabled: true, Database: "test", MaxPoolSize: 10},
		{Enabled: true, URIEnv: "TEST_MONGODB_URI", MaxPoolSize: 10},
		{Enabled: true, URIEnv: "TEST_MONGODB_URI", Database: "test"},
		{Enabled: true, URIEnv: "TEST_MONGODB_URI", Database: "test", ConnectTimeout: "bad", MaxPoolSize: 10},
		{Enabled: true, URIEnv: "TEST_MONGODB_URI", Database: "test", MinPoolSize: 11, MaxPoolSize: 10},
	}
	for _, cfg := range tests {
		if err := cfg.Validate(); err == nil {
			t.Errorf("Validate(%+v) error = nil, want an error", cfg)
		}
	}
}

func TestMongoURIReadsOnlyNamedEnvironmentVariable(t *testing.T) {
	t.Setenv("TEST_MONGODB_URI", " mongodb://localhost:27017 ")
	uri, err := (Mongo{URIEnv: "TEST_MONGODB_URI"}).URI()
	if err != nil {
		t.Fatalf("URI() error = %v", err)
	}
	if uri != "mongodb://localhost:27017" {
		t.Fatalf("URI() = %q", uri)
	}
}

func TestMongoURIReadsRestrictedSecretFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "mongodb-uri")
	if err := os.WriteFile(path, []byte("mongodb://mongo:27017/?replicaSet=rs0\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	mongoConfig := Mongo{Enabled: true, URIFile: path, Database: "test", MaxPoolSize: 10}
	if err := mongoConfig.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	uri, err := mongoConfig.URI()
	if err != nil || uri != "mongodb://mongo:27017/?replicaSet=rs0" {
		t.Fatalf("URI() = %q, %v", uri, err)
	}

	mongoConfig.URIEnv = "TEST_MONGODB_URI"
	if err := mongoConfig.Validate(); err == nil {
		t.Fatal("environment and file MongoDB URI sources were accepted together")
	}
}

func TestSecretFileRejectsUnsafeInputs(t *testing.T) {
	directory := t.TempDir()
	writable := filepath.Join(directory, "writable")
	if err := os.WriteFile(writable, []byte("secret"), 0o622); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0o622); err != nil {
		t.Fatal(err)
	}
	multiline := filepath.Join(directory, "multiline")
	if err := os.WriteFile(multiline, []byte("first\nsecond\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	oversized := filepath.Join(directory, "oversized")
	if err := os.WriteFile(oversized, make([]byte, maximumSecretFileBytes+1), 0o400); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "symlink")
	if err := os.Symlink(multiline, symlink); err != nil {
		t.Fatal(err)
	}

	for name, path := range map[string]string{
		"relative":   "relative/secret",
		"whitespace": " " + multiline,
		"writable":   writable,
		"multiline":  multiline,
		"oversized":  oversized,
		"symlink":    symlink,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := readSecretFile(path, "test secret"); err == nil {
				t.Fatal("unsafe secret file was accepted")
			}
		})
	}
}
