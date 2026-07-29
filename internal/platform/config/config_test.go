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
	if cfg.Development.EnableEngineeringSamples {
		t.Fatal("engineering samples must be disabled by default")
	}
	if cfg.Database.Mongo.Enabled {
		t.Fatal("MongoDB must be disabled by default")
	}
	if cfg.Product.Enabled {
		t.Fatal("product API must be disabled by default")
	}
	if cfg.Runtime.DeploymentWorker.Enabled {
		t.Fatal("deployment worker must be disabled by default")
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
		ProtocolVersions: []string{"v1", "v1.1"},
	}
	if err := agent.Validate(true, true, true); err != nil {
		t.Fatal(err)
	}
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
