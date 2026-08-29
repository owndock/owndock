package agentpackaging_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAgentManagerInstallsUpgradesAndRollsBackAtomically(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Agent packages target Linux and POSIX staging hosts")
	}
	repository := repositoryRoot(t)
	root := t.TempDir()
	packageOne := createPackage(t, repository, "1.0.0", "first")
	runManager(t, root, packageOne, true, "install")
	assertCurrent(t, root, "1.0.0")
	assertFile(t, filepath.Join(root, "opt/owndock-agent/releases/1.0.0/VERSION"), "1.0.0\n")
	assertMode(t, filepath.Join(root, "var/lib/owndock-agent/identity"), 0o700)
	assertMode(t, filepath.Join(root, "etc/owndock/agent.yaml.example"), 0o640)
	preserved := map[string]string{
		"etc/owndock/agent.yaml":                                      "operator-config",
		"var/lib/owndock-agent/identity/agent-identity.pem":           "machine-identity",
		"var/lib/owndock-agent/deployment-cutover-watermarks-v1.json": "monotonic-state",
	}
	for path, value := range preserved {
		if err := os.WriteFile(filepath.Join(root, path), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "usr/local/sbin/owndock-agentctl")); err != nil {
		t.Fatalf("stable manager: %v", err)
	}
	unitTarget, err := os.Readlink(filepath.Join(root, "etc/systemd/system/owndock-agent.service"))
	if err != nil {
		t.Fatalf("systemd unit symlink: %v", err)
	}
	if unitTarget != "/opt/owndock-agent/current/owndock-agent.service" {
		t.Fatalf("systemd unit target = %q", unitTarget)
	}

	packageTwo := createPackage(t, repository, "1.1.0", "second")
	runManager(t, root, packageTwo, true, "install")
	assertCurrent(t, root, "1.1.0")
	if _, err := os.Stat(filepath.Join(root, "opt/owndock-agent/releases/1.0.0/owndock-agent")); err != nil {
		t.Fatalf("previous release was not retained: %v", err)
	}

	stableManager := filepath.Join(root, "usr/local/sbin/owndock-agentctl")
	runScript(t, root, stableManager, true, "rollback", "--version", "1.0.0")
	assertCurrent(t, root, "1.0.0")
	runScript(t, root, stableManager, true, "status")
	for path, expected := range preserved {
		value, err := os.ReadFile(filepath.Join(root, path))
		if err != nil || string(value) != expected {
			t.Fatalf("preserved %s = %q, %v", path, value, err)
		}
	}
}

func TestAgentManagerRejectsTamperingAndVersionReplacement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Agent packages target Linux and POSIX staging hosts")
	}
	repository := repositoryRoot(t)
	root := t.TempDir()
	original := createPackage(t, repository, "2.0.0", "original")
	runManager(t, root, original, true, "install")

	tampered := createPackage(t, repository, "2.1.0", "tampered")
	if err := os.WriteFile(filepath.Join(tampered, "owndock-agent"), []byte("changed"), 0o755); err != nil {
		t.Fatal(err)
	}
	runManager(t, root, tampered, false, "install")
	assertCurrent(t, root, "2.0.0")

	conflict := createPackage(t, repository, "2.0.0", "different")
	runManager(t, root, conflict, false, "install")
	assertCurrent(t, root, "2.0.0")
	value, err := os.ReadFile(filepath.Join(root, "opt/owndock-agent/releases/2.0.0/owndock-agent"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(value), "original") {
		t.Fatalf("installed immutable release was replaced: %q", value)
	}
}

func TestSystemdUnitKeepsConfigurationReadOnlyAndIdentityWritable(t *testing.T) {
	repository := repositoryRoot(t)
	value, err := os.ReadFile(filepath.Join(repository, "packaging/agent/owndock-agent.service"))
	if err != nil {
		t.Fatal(err)
	}
	unit := string(value)
	for _, required := range []string{
		"User=owndock-agent", "Group=owndock-agent", "SupplementaryGroups=docker",
		"NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes",
		"SystemCallArchitectures=native",
		"CapabilityBoundingSet=", "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
		"ReadWritePaths=/var/lib/owndock-agent",
		"ConditionPathExists=/var/lib/owndock-agent/identity/agent-identity.pem",
	} {
		if !strings.Contains(unit, required+"\n") {
			t.Fatalf("systemd unit is missing %q", required)
		}
	}
	if strings.Contains(unit, "ReadWritePaths=/etc") ||
		strings.Contains(strings.ToLower(unit), "token") ||
		strings.Contains(unit, "Environment=") {
		t.Fatalf("systemd unit expands the writable or secret boundary:\n%s", unit)
	}
}

func createPackage(t *testing.T, repository, version, marker string) string {
	t.Helper()
	directory := t.TempDir()
	for _, name := range []string{"owndock-agentctl", "owndock-agent.service"} {
		value, err := os.ReadFile(filepath.Join(repository, "packaging/agent", name))
		if err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0o644)
		if name == "owndock-agentctl" {
			mode = 0o755
		}
		if err := os.WriteFile(filepath.Join(directory, name), value, mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(directory, "VERSION"), []byte(version+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "agent.yaml.example"), []byte("control: {}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	binary := []byte("#!/bin/sh\nprintf 'owndock-agent " + version + " (" + marker + ", test)\\n'\n")
	if err := os.WriteFile(filepath.Join(directory, "owndock-agent"), binary, 0o755); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(binary)
	if err := os.WriteFile(
		filepath.Join(directory, "owndock-agent.sha256"),
		[]byte(hex.EncodeToString(digest[:])+"\n"), 0o644,
	); err != nil {
		t.Fatal(err)
	}
	return directory
}

func runManager(t *testing.T, root, packageDirectory string, succeed bool, arguments ...string) {
	t.Helper()
	runScript(t, root, filepath.Join(packageDirectory, "owndock-agentctl"), succeed, arguments...)
}

func runScript(t *testing.T, root, script string, succeed bool, arguments ...string) {
	t.Helper()
	command := exec.Command("sh", append([]string{script}, arguments...)...)
	command.Env = append(
		os.Environ(),
		"OWNDOCK_AGENT_INSTALL_ROOT="+root,
		"OWNDOCK_AGENT_OFFLINE=1",
	)
	output, err := command.CombinedOutput()
	if succeed && err != nil {
		t.Fatalf("%s %v: %v\n%s", script, arguments, err, output)
	}
	if !succeed && err == nil {
		t.Fatalf("%s %v unexpectedly succeeded\n%s", script, arguments, output)
	}
}

func assertCurrent(t *testing.T, root, version string) {
	t.Helper()
	target, err := os.Readlink(filepath.Join(root, "opt/owndock-agent/current"))
	if err != nil {
		t.Fatal(err)
	}
	if target != "releases/"+version {
		t.Fatalf("current target = %q", target)
	}
}

func assertMode(t *testing.T, path string, expected os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != expected {
		t.Fatalf("%s mode = %#o", path, info.Mode().Perm())
	}
}

func assertFile(t *testing.T, path, expected string) {
	t.Helper()
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(value) != expected {
		t.Fatalf("%s = %q, want %q", path, value, expected)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
}
