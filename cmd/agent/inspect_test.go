package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigInspectionReturnsOnlyValidatedManagedIngressState(t *testing.T) {
	for _, test := range []struct {
		name         string
		enabled      bool
		capabilities string
		want         string
	}{
		{name: "disabled", want: "{\"managed_ingress\":false}\n"},
		{name: "enabled", enabled: true, capabilities: `
    - ingress.prepare
    - ingress.commit
    - ingress.abort`, want: "{\"managed_ingress\":true}\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "agent.yaml")
			value := fmt.Sprintf(`
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
    - runtime.probe%s
runtime: {}
ingress:
  enabled: %t
`, test.capabilities, test.enabled)
			if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			if err := runConfigInspection([]string{"-conf", path}, &output, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			if output.String() != test.want {
				t.Fatalf("inspection = %q, want %q", output.String(), test.want)
			}
		})
	}
}

func TestConfigInspectionRejectsInvalidConfigAndArguments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(path, []byte("ingress:\n  enabled: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, arguments := range [][]string{{"-conf", path}, {"-conf", path, "extra"}} {
		var output bytes.Buffer
		if err := runConfigInspection(arguments, &output, &bytes.Buffer{}); err == nil {
			t.Fatalf("arguments %q accepted invalid input", arguments)
		}
		if output.Len() != 0 {
			t.Fatalf("arguments %q emitted output %q", arguments, output.String())
		}
	}
}
