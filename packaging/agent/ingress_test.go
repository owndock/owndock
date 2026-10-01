package agentpackaging_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestIngressGatewayPackageHasFixedLeastPrivilegeBoundary(t *testing.T) {
	repository := repositoryRoot(t)
	directory := filepath.Join(repository, "packaging", "agent")
	composeValue, err := os.ReadFile(filepath.Join(directory, "owndock-ingress.compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	compose := string(composeValue)
	for _, required := range []string{
		"caddy:2.11.4-alpine@sha256:6aeddd44c3078b0f9a35206472a11420648a79c184603ef95957d0a20044cb2b",
		`user: "${OWNDOCK_INGRESS_UID:?required}:${OWNDOCK_INGRESS_GID:?required}"`,
		"read_only: true", "cap_drop:", "- ALL", "cap_add:", "- NET_BIND_SERVICE",
		"no-new-privileges:true",
		`- "80:8080/tcp"`, `- "443:8443/tcp"`, "--resume",
		"source: /run/owndock-ingress", "source: /var/lib/owndock-ingress/data",
		"name: owndock-ingress", "pids_limit: 256", "mem_limit: 512m",
	} {
		if !strings.Contains(compose, required) {
			t.Fatalf("Ingress Compose file is missing %q", required)
		}
	}
	for _, forbidden := range []string{"latest", "docker.sock", "privileged: true", "network_mode: host", "2019:"} {
		if strings.Contains(strings.ToLower(compose), forbidden) {
			t.Fatalf("Ingress Compose file contains forbidden %q", forbidden)
		}
	}
	var security struct {
		Services map[string]struct {
			CapDrop []string `yaml:"cap_drop"`
			CapAdd  []string `yaml:"cap_add"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(composeValue, &security); err != nil {
		t.Fatal(err)
	}
	gateway := security.Services["gateway"]
	if !slices.Equal(gateway.CapDrop, []string{"ALL"}) ||
		!slices.Equal(gateway.CapAdd, []string{"NET_BIND_SERVICE"}) {
		t.Fatalf("Ingress Gateway capabilities = drop %v add %v",
			gateway.CapDrop, gateway.CapAdd)
	}

	bootstrapValue, err := os.ReadFile(filepath.Join(directory, "owndock-ingress-bootstrap.json"))
	if err != nil {
		t.Fatal(err)
	}
	var bootstrap map[string]any
	if json.Unmarshal(bootstrapValue, &bootstrap) != nil {
		t.Fatal("Ingress bootstrap is not JSON")
	}
	bootstrapText := string(bootstrapValue)
	if !strings.Contains(bootstrapText, "unix//run/owndock-ingress/admin.sock|0660") ||
		strings.Contains(bootstrapText, "2019") {
		t.Fatalf("unsafe Ingress bootstrap: %s", bootstrapText)
	}
}

func TestIngressImageLockMatchesComposeAndBothArchitectures(t *testing.T) {
	repository := repositoryRoot(t)
	directory := filepath.Join(repository, "packaging", "agent")
	value, err := os.ReadFile(filepath.Join(directory, "owndock-ingress-image.json"))
	if err != nil {
		t.Fatal(err)
	}
	var lock struct {
		Tag         string            `json:"tag"`
		IndexDigest string            `json:"index_digest"`
		Platforms   map[string]string `json:"platforms"`
	}
	if err := json.Unmarshal(value, &lock); err != nil {
		t.Fatal(err)
	}
	if lock.Tag != "2.11.4-alpine" || !strings.HasPrefix(lock.IndexDigest, "sha256:") ||
		len(lock.Platforms) != 2 || lock.Platforms["linux/amd64"] == "" ||
		lock.Platforms["linux/arm64/v8"] == "" {
		t.Fatalf("image lock = %#v", lock)
	}
	compose, err := os.ReadFile(filepath.Join(directory, "owndock-ingress.compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(compose), "caddy:"+lock.Tag+"@"+lock.IndexDigest) {
		t.Fatal("Ingress Compose image does not match the image lock")
	}
}

func TestIngressSystemdUnitUsesDedicatedIdentityAndLocalSocket(t *testing.T) {
	repository := repositoryRoot(t)
	value, err := os.ReadFile(filepath.Join(repository, "packaging", "agent", "owndock-ingress.service"))
	if err != nil {
		t.Fatal(err)
	}
	unit := string(value)
	for _, required := range []string{
		"User=owndock-ingress", "Group=owndock-agent", "SupplementaryGroups=docker",
		"RuntimeDirectory=owndock-ingress", "NoNewPrivileges=yes", "ProtectSystem=strict",
		"CapabilityBoundingSet=", "ReadWritePaths=/run/owndock-ingress /var/lib/owndock-ingress",
		"[ -S /run/owndock-ingress/admin.sock ]", "owndock-ingress.compose.yaml",
	} {
		if !strings.Contains(unit, required+"\n") &&
			required != "[ -S /run/owndock-ingress/admin.sock ]" &&
			required != "owndock-ingress.compose.yaml" {
			t.Fatalf("Ingress unit is missing %q", required)
		}
		if (required == "[ -S /run/owndock-ingress/admin.sock ]" ||
			required == "owndock-ingress.compose.yaml") && !strings.Contains(unit, required) {
			t.Fatalf("Ingress unit is missing %q", required)
		}
	}
	for _, forbidden := range []string{"privileged", "docker.sock", "AmbientCapabilities=CAP_"} {
		if strings.Contains(unit, forbidden) {
			t.Fatalf("Ingress unit contains forbidden %q", forbidden)
		}
	}
}

func TestAgentInstallerRestoresIngressSelectionFromValidatedConfig(t *testing.T) {
	repository := repositoryRoot(t)
	value, err := os.ReadFile(filepath.Join(repository, "packaging", "agent", "owndock-agentctl"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(value)
	for _, required := range []string{
		"agent_ingress_enabled()", "inspect-config --conf", `'{"managed_ingress":true}'`,
		`'{"managed_ingress":false}'`, `systemctl enable --now "$INGRESS_SERVICE"`,
		`systemctl disable --now "$INGRESS_SERVICE"`,
		`secure_ingress_release()`, `secure_ingress_release "$RELEASES_DIR/$version"`,
		`chown root:"$AGENT_GROUP"`,
		`Agent restart failed and the previous Ingress release could not be restored`,
		`verify TCP ports 80 and 443 are free`,
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("Agent installer is missing recovered Ingress behavior %q", required)
		}
	}
}
