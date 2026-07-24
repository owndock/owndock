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
	if cfg.Security.BootstrapTokenEnv != defaultBootstrapTokenEnv {
		t.Fatalf("bootstrap token env = %q, want %q", cfg.Security.BootstrapTokenEnv, defaultBootstrapTokenEnv)
	}
	sessionTTL, err := cfg.Security.SessionTTLDuration()
	if err != nil || sessionTTL != defaultSessionTTL {
		t.Fatalf("session TTL = %v, %v; want %v", sessionTTL, err, defaultSessionTTL)
	}
	if cfg.Database.Mongo.URIEnv != defaultMongoURIEnv ||
		cfg.Database.Mongo.Database != defaultMongoDatabase ||
		cfg.Database.Mongo.MaxPoolSize != defaultMongoMaxPoolSize {
		t.Fatalf("MongoDB defaults = %+v", cfg.Database.Mongo)
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
