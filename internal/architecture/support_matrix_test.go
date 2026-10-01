package architecture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	agentpreflight "github.com/owndock/owndock/internal/agent/preflight"
)

func TestSupportMatrixTracksLockedBaselines(t *testing.T) {
	root := repositoryRoot(t)
	matrix := readSupportFile(t, filepath.Join(root, "docs", "support-matrix.md"))
	dockerImage := sourceImage(t, filepath.Join(root, "internal", "agent", "runtime", "docker_probe_integration_test.go"), "docker:")
	if !strings.HasPrefix(dockerImage, "docker:"+agentpreflight.SupportedDockerVersion+"-dind@sha256:") {
		t.Fatalf("Agent preflight Docker %s does not match integration image %s",
			agentpreflight.SupportedDockerVersion, dockerImage)
	}
	communityVerifier := readSupportFile(t, filepath.Join(root, "packaging", "release", "verify-community-release"))
	if !strings.Contains(communityVerifier, `values["docker_engine"] != "`+agentpreflight.SupportedDockerVersion+`"`) ||
		!strings.Contains(communityVerifier, "owndock-community-compatibility-v2") {
		t.Fatal("community release verifier does not enforce the Agent host support baseline")
	}

	for _, baseline := range []struct {
		name   string
		value  string
		source string
	}{
		{name: "Go", value: goDirective(t, filepath.Join(root, "go.mod")), source: "go.mod"},
		{name: "Kratos", value: requiredModuleVersion(t, filepath.Join(root, "go.mod"), "github.com/go-kratos/kratos/v2"), source: "go.mod"},
		{name: "MongoDB Go Driver", value: requiredModuleVersion(t, filepath.Join(root, "go.mod"), "go.mongodb.org/mongo-driver/v2"), source: "go.mod"},
		{name: "MongoDB", value: composeImage(t, filepath.Join(root, "deploy", "community.compose.yaml"), "mongo:"), source: "deploy/community.compose.yaml"},
		{name: "supported operating system", value: "Ubuntu Server " + agentpreflight.SupportedOSVersion, source: "Agent preflight"},
		{name: "Docker integration Engine", value: dockerImage, source: "internal/agent/runtime/docker_probe_integration_test.go"},
		{name: "Managed ingress", value: ingressImage(t, filepath.Join(root, "packaging", "agent", "owndock-ingress-image.json")), source: "packaging/agent/owndock-ingress-image.json"},
	} {
		if baseline.value == "" {
			t.Fatalf("%s baseline is empty in %s", baseline.name, baseline.source)
		}
		if !strings.Contains(matrix, baseline.value) {
			t.Errorf("support matrix does not contain %s baseline %q from %s", baseline.name, baseline.value, baseline.source)
		}
	}
}

func readSupportFile(t *testing.T, path string) string {
	t.Helper()
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(value)
}

func goDirective(t *testing.T, path string) string {
	t.Helper()
	for _, line := range strings.Split(readSupportFile(t, path), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "go" {
			return fields[1]
		}
	}
	t.Fatalf("go directive is missing from %s", path)
	return ""
}

func requiredModuleVersion(t *testing.T, path, module string) string {
	t.Helper()
	for _, line := range strings.Split(readSupportFile(t, path), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == module {
			return strings.TrimPrefix(fields[1], "v")
		}
	}
	t.Fatalf("module %s is missing from %s", module, path)
	return ""
}

func composeImage(t *testing.T, path, prefix string) string {
	t.Helper()
	for _, line := range strings.Split(readSupportFile(t, path), "\n") {
		value := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "image:"))
		if strings.HasPrefix(value, prefix) {
			return value
		}
	}
	t.Fatalf("image %s is missing from %s", prefix, path)
	return ""
}

func sourceImage(t *testing.T, path, prefix string) string {
	t.Helper()
	for _, field := range strings.FieldsFunc(readSupportFile(t, path), func(r rune) bool {
		return r == '"' || r == '\'' || r == ' ' || r == '\n' || r == '\t'
	}) {
		if strings.HasPrefix(field, prefix) && strings.Contains(field, "@sha256:") {
			return field
		}
	}
	t.Fatalf("image %s is missing from %s", prefix, path)
	return ""
}

func ingressImage(t *testing.T, path string) string {
	t.Helper()
	var lock struct {
		Repository  string `json:"repository"`
		Tag         string `json:"tag"`
		IndexDigest string `json:"index_digest"`
	}
	if err := json.Unmarshal([]byte(readSupportFile(t, path)), &lock); err != nil {
		t.Fatal(err)
	}
	if lock.Repository == "" || lock.Tag == "" || lock.IndexDigest == "" {
		t.Fatalf("incomplete ingress image lock in %s", path)
	}
	parts := strings.Split(lock.Repository, "/")
	return parts[len(parts)-1] + ":" + lock.Tag + "@" + lock.IndexDigest
}
