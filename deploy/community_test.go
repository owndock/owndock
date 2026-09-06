package deploy

import (
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
		"mongodb-keyfile",
		"owndock-bootstrap-token",
		"owndock-mongodb-uri",
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
	if parsed.User.Username() != values["mongodb-root-username"] ||
		!hasPassword || password != values["mongodb-root-password"] ||
		parsed.Host != "mongodb:27017" || parsed.Query().Get("replicaSet") != "rs0" ||
		parsed.Query().Get("authSource") != "admin" {
		t.Fatal("generated MongoDB URI does not match the generated credentials and Replica Set")
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
