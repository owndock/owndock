package architecture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type composeSecurityContract struct {
	Services map[string]struct {
		Volumes     []string `yaml:"volumes"`
		ReadOnly    bool     `yaml:"read_only"`
		Tmpfs       []string `yaml:"tmpfs"`
		CapDrop     []string `yaml:"cap_drop"`
		SecurityOpt []string `yaml:"security_opt"`
		PidsLimit   int      `yaml:"pids_limit"`
		MemLimit    string   `yaml:"mem_limit"`
		CPUs        float64  `yaml:"cpus"`
		Restart     string   `yaml:"restart"`
	} `yaml:"services"`
}

func TestVulnerabilityDatabaseUpdaterAndEvidenceWorkerKeepSeparateMountAuthority(t *testing.T) {
	root := repositoryRoot(t)
	worker := readComposeSecurityContract(t, filepath.Join(root, "deploy", "evidence-worker.compose.yaml"))
	updater := readComposeSecurityContract(t, filepath.Join(root, "deploy", "vulnerability-db-updater.compose.yaml"))
	workerService := worker.Services["evidence-worker"]
	updaterService := updater.Services["vulnerability-db-updater"]
	if !containsExact(workerService.Volumes,
		"${OWNDOCK_TRIVY_DATABASE_ROOT:?required}:/var/lib/owndock/trivy-db:ro") {
		t.Fatal("Evidence Worker must receive only a read-only Trivy database parent mount")
	}
	if !containsExact(updaterService.Volumes,
		"${OWNDOCK_TRIVY_DATABASE_ROOT:?required}:/var/lib/owndock/trivy-db:rw") {
		t.Fatal("the one-shot updater must be the only service with a writable Trivy database mount")
	}
	assertRestrictedService(t, "evidence-worker", workerService.ReadOnly, workerService.CapDrop,
		workerService.SecurityOpt, workerService.PidsLimit, workerService.MemLimit, workerService.CPUs)
	assertRestrictedService(t, "vulnerability-db-updater", updaterService.ReadOnly, updaterService.CapDrop,
		updaterService.SecurityOpt, updaterService.PidsLimit, updaterService.MemLimit, updaterService.CPUs)
	if updaterService.Restart != "no" || len(updaterService.Tmpfs) != 1 ||
		!strings.Contains(updaterService.Tmpfs[0], "size=268435456") {
		t.Fatal("updater must remain a bounded one-shot job with a reviewed temporary download limit")
	}
}

func TestVulnerabilityDatabaseUpdaterImagePinsToolAndNonRootIdentity(t *testing.T) {
	content, err := os.ReadFile(filepath.Join(repositoryRoot(t), "Dockerfile.vulnerability-db-updater"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	for _, required := range []string{
		"aquasec/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969",
		"USER 65532:65532",
		"ENTRYPOINT [\"/usr/local/bin/owndock-vulnerability-db-updater\"]",
		"COPY --chown=65532:65532",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("updater image contract is missing %q", required)
		}
	}
}

func readComposeSecurityContract(t *testing.T, path string) composeSecurityContract {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var contract composeSecurityContract
	if err := yaml.Unmarshal(content, &contract); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return contract
}

func assertRestrictedService(t *testing.T, name string, readOnly bool, capabilities, security []string,
	pids int, memory string, cpus float64) {
	t.Helper()
	if !readOnly || !containsExact(capabilities, "ALL") ||
		!containsExact(security, "no-new-privileges:true") || pids <= 0 || memory == "" || cpus <= 0 {
		t.Fatalf("%s must keep read-only root, no capabilities, no-new-privileges and finite resources", name)
	}
}

func containsExact(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
