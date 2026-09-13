package deploy

import (
	"crypto/sha256"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareCommunitySecrets(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "secrets")
	command := exec.Command("sh", "prepare-community-secrets.sh", directory)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("prepare secrets: %v: %s", err, output)
	}

	names := []string{
		"mongodb-root-username",
		"mongodb-root-password",
		"mongodb-app-password",
		"mongodb-tools-password",
		"mongodb-keyfile",
		"owndock-bootstrap-token",
		"owndock-mongodb-uri",
		"owndock-mongodb-tools.yaml",
	}
	values := make(map[string]string, len(names))
	for _, name := range names {
		path := filepath.Join(directory, name)
		info, statErr := os.Lstat(path)
		if statErr != nil {
			t.Fatalf("stat %s: %v", name, statErr)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o400 {
			t.Fatalf("%s mode = %s, want regular 0400", name, info.Mode())
		}
		contents, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("read %s: %v", name, readErr)
		}
		values[name] = strings.TrimSpace(string(contents))
		if values[name] == "" || strings.ContainsRune(values[name], '\x00') {
			t.Fatalf("%s is empty or contains NUL", name)
		}
		if name != "mongodb-keyfile" && strings.ContainsAny(values[name], "\r\n") {
			t.Fatalf("%s does not contain one non-empty line", name)
		}
		if strings.Contains(string(output), values[name]) {
			t.Fatalf("command output exposed %s", name)
		}
	}

	parsed, err := url.Parse(values["owndock-mongodb-uri"])
	if err != nil {
		t.Fatalf("parse MongoDB URI: %v", err)
	}
	password, hasPassword := parsed.User.Password()
	if parsed.User.Username() != "owndock-app" ||
		!hasPassword || password != values["mongodb-app-password"] ||
		parsed.Host != "mongodb:27017" || parsed.Query().Get("replicaSet") != "rs0" ||
		parsed.Query().Get("authSource") != "owndock" {
		t.Fatal("generated MongoDB URI does not match the generated credentials and Replica Set")
	}
	toolsURI := fmt.Sprintf(
		"mongodb://owndock-tools:%s@mongodb:27017/?replicaSet=rs0&authSource=admin",
		values["mongodb-tools-password"],
	)
	if values["owndock-mongodb-tools.yaml"] != fmt.Sprintf("uri: %q", toolsURI) {
		t.Fatal("Database Tools config does not contain the generated application URI")
	}

	retry := exec.Command("sh", "prepare-community-secrets.sh", directory)
	retryOutput, retryErr := retry.CombinedOutput()
	if retryErr == nil {
		t.Fatal("secret preparation replaced existing files")
	}
	for _, value := range values {
		if strings.Contains(string(retryOutput), value) {
			t.Fatal("retry error exposed a generated secret")
		}
	}
}

func TestCommunityMongoInitializationPinsFeatureCompatibilityVersion(t *testing.T) {
	contents, err := os.ReadFile("mongodb/init-replica-set.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(contents)
	for _, required := range []string{
		`const expected = "8.3"`,
		`setFeatureCompatibilityVersion: expected`,
		`confirm: true`,
		`featureCompatibilityVersion: 1`,
		`current.featureCompatibilityVersion.version === expected`,
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("MongoDB initialization does not enforce %q", required)
		}
	}
}

func TestEvidenceWorkerComposeHasNoDirectEgressRoute(t *testing.T) {
	contents, err := os.ReadFile("evidence-worker.compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	compose := string(contents)
	for _, required := range []string{
		`image: ${OWNDOCK_EGRESS_GATEWAY_IMAGE:?set an immutable image digest}`,
		`command: ["-scope", "evidence", "-conf", "/etc/owndock/config.yaml"]`,
		`ipv4_address: ${OWNDOCK_EVIDENCE_EGRESS_GATEWAY_IP:-172.31.241.2}`,
		"evidence-boundary:\n",
		"    internal: true\n",
		"      - data\n      - evidence-boundary\n",
		"      evidence-egress-uplink:\n",
	} {
		if !strings.Contains(compose, required) {
			t.Fatalf("Evidence Worker Compose is missing %q", required)
		}
	}
	workerStart := strings.Index(compose, "  evidence-worker:\n")
	networkStart := strings.Index(compose, "\nnetworks:\n")
	if workerStart < 0 || networkStart <= workerStart {
		t.Fatal("Evidence Worker Compose service boundaries are invalid")
	}
	workerService := compose[workerStart:networkStart]
	if strings.Contains(workerService, "evidence-egress-uplink") {
		t.Fatal("Evidence Worker must not join the uplink network")
	}
}

func TestCommunityBackupAndRestoreSafety(t *testing.T) {
	fixture := []byte("compressed-mongodb-archive-fixture")
	directory := t.TempDir()
	binDirectory := filepath.Join(directory, "bin")
	if err := os.Mkdir(binDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	docker := filepath.Join(binDirectory, "docker")
	dockerFixture := `#!/bin/sh
set -eu
printf '%s\n' "$*" >>"$FAKE_DOCKER_LOG"
case " $* " in
  *" ps --status running --services "*) printf '%s\n' "${FAKE_DOCKER_SERVICES:-mongodb}" ;;
  *" exec -T mongodb mongodump "*) printf '%s' 'compressed-mongodb-archive-fixture' ;;
  *" exec -T mongodb sh -eu -c "*) printf '%s\n' "${FAKE_DOCKER_COLLECTION_COUNT:-0}" ;;
  *" exec -T mongodb mongorestore "*) cat >"$FAKE_RESTORE_MARKER" ;;
  *) echo "unexpected docker invocation" >&2; exit 3 ;;
esac
`
	if err := os.WriteFile(docker, []byte(dockerFixture), 0o700); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(directory, "docker.log")
	baseEnvironment := append(os.Environ(),
		"PATH="+binDirectory+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAKE_DOCKER_LOG="+logPath,
	)

	archive := filepath.Join(directory, "backup.archive.gz")
	backup := exec.Command("sh", "backup-community.sh", archive)
	backup.Env = baseEnvironment
	if output, err := backup.CombinedOutput(); err != nil {
		t.Fatalf("backup: %v: %s", err, output)
	}
	contents, err := os.ReadFile(archive)
	if err != nil || string(contents) != string(fixture) {
		t.Fatalf("backup archive = %q, %v", contents, err)
	}
	for _, path := range []string{archive, archive + ".sha256"} {
		info, statErr := os.Stat(path)
		if statErr != nil {
			t.Fatalf("stat %s: %v", path, statErr)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %v, want 0600", path, info.Mode())
		}
	}
	wantDigest := fmt.Sprintf("%x", sha256.Sum256(fixture))
	checksum, err := os.ReadFile(archive + ".sha256")
	if err != nil || !strings.HasPrefix(string(checksum), wantDigest+"  ") {
		t.Fatalf("backup checksum = %q, %v", checksum, err)
	}
	backupAgain := exec.Command("sh", "backup-community.sh", archive)
	backupAgain.Env = baseEnvironment
	if output, err := backupAgain.CombinedOutput(); err == nil || strings.Contains(string(output), string(fixture)) {
		t.Fatalf("existing backup was replaced or exposed: %v: %s", err, output)
	}
	runningOutput := filepath.Join(directory, "running.archive.gz")
	backupWhileRunning := exec.Command("sh", "backup-community.sh", runningOutput)
	backupWhileRunning.Env = append(baseEnvironment, "FAKE_DOCKER_SERVICES=mongodb\nserver")
	if output, err := backupWhileRunning.CombinedOutput(); err == nil || strings.Contains(string(output), string(fixture)) {
		t.Fatalf("backup while server was running succeeded or exposed data: %v: %s", err, output)
	}

	marker := filepath.Join(directory, "restored.archive")
	restoreWithoutConfirmation := exec.Command("sh", "restore-community.sh", archive, archive+".sha256")
	restoreWithoutConfirmation.Env = append(baseEnvironment, "FAKE_RESTORE_MARKER="+marker)
	if output, err := restoreWithoutConfirmation.CombinedOutput(); err == nil {
		t.Fatalf("restore without confirmation succeeded: %s", output)
	}
	restore := exec.Command("sh", "restore-community.sh", archive, archive+".sha256")
	restore.Env = append(baseEnvironment,
		"FAKE_RESTORE_MARKER="+marker,
		"OWNDOCK_RESTORE_CONFIRM=empty-owndock-database",
	)
	if output, err := restore.CombinedOutput(); err != nil {
		t.Fatalf("restore: %v: %s", err, output)
	}
	restored, err := os.ReadFile(marker)
	if err != nil || string(restored) != string(fixture) {
		t.Fatalf("restored archive = %q, %v", restored, err)
	}
	log, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(log), "mongodump --config /run/secrets/owndock-mongodb-tools-config --db owndock") ||
		!strings.Contains(string(log), "mongorestore --config /run/secrets/owndock-mongodb-tools-config") ||
		strings.Contains(string(log), "compressed-mongodb-archive-fixture") {
		t.Fatalf("unexpected Docker command log: %s", log)
	}
	nonemptyMarker := filepath.Join(directory, "nonempty-restored.archive")
	restoreNonempty := exec.Command("sh", "restore-community.sh", archive, archive+".sha256")
	restoreNonempty.Env = append(baseEnvironment,
		"FAKE_RESTORE_MARKER="+nonemptyMarker,
		"FAKE_DOCKER_COLLECTION_COUNT=1",
		"OWNDOCK_RESTORE_CONFIRM=empty-owndock-database",
	)
	if output, err := restoreNonempty.CombinedOutput(); err == nil {
		t.Fatalf("restore into non-empty database succeeded: %s", output)
	}
	if _, err := os.Stat(nonemptyMarker); !os.IsNotExist(err) {
		t.Fatalf("restore consumed archive for non-empty database: %v", err)
	}
}

func TestCommunityProcessIntegrationRequiresImmutableDistinctReleases(t *testing.T) {
	validDigest := strings.Repeat("a", 64)
	validPrevious := "ghcr.io/owndock/owndock@sha256:" + validDigest
	validCurrent := "ghcr.io/owndock/owndock@sha256:" + strings.Repeat("b", 64)
	tests := []struct {
		name string
		args []string
	}{
		{name: "missing arguments", args: nil},
		{name: "mutable published tag", args: []string{
			"ghcr.io/owndock/owndock:1.0.0", "1.0.0", validCurrent, "1.1.0",
		}},
		{name: "short digest", args: []string{
			"ghcr.io/owndock/owndock@sha256:abcd", "1.0.0", validCurrent, "1.1.0",
		}},
		{name: "same image", args: []string{
			validPrevious, "1.0.0", validPrevious, "1.1.0",
		}},
		{name: "version prefix", args: []string{
			validPrevious, "v1.0.0", validCurrent, "1.1.0",
		}},
		{name: "same version", args: []string{
			validPrevious, "1.0.0", validCurrent, "1.0.0",
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := exec.Command("sh", append(
				[]string{"community_process_integration_test.sh"},
				test.args...,
			)...)
			if output, err := command.CombinedOutput(); err == nil {
				t.Fatalf("unsafe integration input succeeded: %s", output)
			}
		})
	}
}
