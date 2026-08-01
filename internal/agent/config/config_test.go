package agentconfig

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadCheckedInAgentConfig(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test file")
	}
	path := filepath.Join(
		filepath.Dir(file),
		"..",
		"..",
		"..",
		"configs",
		"agent.yaml",
	)
	config, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.Control.MaxFrameBytes != 65536 ||
		config.Control.MaxConcurrentCommands != 4 ||
		len(config.Control.Capabilities) != 9 ||
		config.Runtime.ResultCacheSize != 256 ||
		config.Runtime.CutoverWatermarkSize != 16384 {
		t.Fatalf("config = %#v", config)
	}
}

func TestLoadAppliesSafeDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yaml")
	value := []byte(`
control:
  endpoint: https://control.example.com:8443/api/v1/agent/connect
  organization_id: organization-1
  managed_host_id: host-1
  identity_id: identity-1
  instance_id: instance-1
  ca_certificate_file: /etc/owndock/agent-ca.pem
  client_certificate_file: /etc/owndock/agent.pem
  client_private_key_file: /etc/owndock/agent-key.pem
runtime: {}
`)
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.Control.BootIDFile != defaultBootIDFile ||
		len(config.Control.Capabilities) != len(baselineCapabilities()) ||
		config.Runtime.DockerSocket != defaultDockerSocket ||
		config.Runtime.StateDirectory != defaultStateDirectory ||
		config.Runtime.ResultCacheSize != defaultResultCacheSize ||
		config.Runtime.CutoverWatermarkSize !=
			defaultCutoverWatermarkSize {
		t.Fatalf("defaults = %#v", config)
	}
}

func TestLoadRejectsPartialInventoryCapabilities(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yaml")
	value := []byte(`
control:
  endpoint: https://control.example.com:8443/api/v1/agent/connect
  organization_id: organization-1
  managed_host_id: host-1
  identity_id: identity-1
  instance_id: instance-1
  ca_certificate_file: /etc/owndock/agent-ca.pem
  client_certificate_file: /etc/owndock/agent.pem
  client_private_key_file: /etc/owndock/agent-key.pem
  capabilities:
    - runtime.probe
    - runtime.inventory.prepare
runtime: {}
`)
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("partial inventory capabilities error = %v", err)
	}
}

func TestLoadRejectsInsecureControlURLAndPaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yaml")
	value := []byte(`
control:
  endpoint: http://control.example.com/api/v1/agent/connect?token=secret
  organization_id: organization-1
  managed_host_id: host-1
  identity_id: identity-1
  instance_id: instance-1
  ca_certificate_file: relative-ca.pem
  client_certificate_file: /etc/owndock/agent.pem
  client_private_key_file: /etc/owndock/agent-key.pem
runtime: {}
`)
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("error = %v", err)
	}
}

func TestReadBootIDUsesBoundedRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "boot-id")
	if err := os.WriteFile(path, []byte("boot-id-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	value, err := ReadBootID(path)
	if err != nil {
		t.Fatal(err)
	}
	if value != "boot-id-1" {
		t.Fatalf("boot ID = %q", value)
	}
	if err := os.WriteFile(path, make([]byte, 257), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBootID(path); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("error = %v", err)
	}
}
