package main

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentenrollment "github.com/owndock/owndock/internal/agent/enrollment"
)

func TestEnrollmentFixtureDropsAndReplaysExactRequest(t *testing.T) {
	const token = "fixture-token-0123456789-abcdefghijklmnop"
	root := t.TempDir()
	materials := filepath.Join(root, "materials")
	if err := runMaterials([]string{"--output", materials}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ca.pem", "ca-key.pem", "server.pem"} {
		info, err := os.Lstat(filepath.Join(materials, name))
		if err != nil {
			t.Fatalf("inspect material %s: %v", name, err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("material %s mode = %v", name, info.Mode())
		}
	}

	firstReady := filepath.Join(root, "first-ready")
	firstRequest := filepath.Join(root, "first-request")
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- runServer([]string{
			"--materials", materials,
			"--ready-file", firstReady,
			"--request-file", firstRequest,
			"--mode", "drop",
			"--token", token,
			"--timeout", "5s",
		})
	}()
	endpoint := waitForEndpoint(t, firstReady)
	paths := enrollmentPaths(t)
	options := enrollmentOptions(endpoint, materials, paths)
	if _, err := agentenrollment.Provision(context.Background(), options, []byte(token)); err == nil {
		t.Fatal("dropped enrollment response unexpectedly succeeded")
	}
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}

	parsed, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	secondReady := filepath.Join(root, "second-ready")
	secondRequest := filepath.Join(root, "second-request")
	secondDone := make(chan error, 1)
	go func() {
		secondDone <- runServer([]string{
			"--listen", parsed.Host,
			"--materials", materials,
			"--ready-file", secondReady,
			"--request-file", secondRequest,
			"--expected-request-file", firstRequest,
			"--mode", "respond",
			"--token", token,
			"--timeout", "5s",
		})
	}()
	if actual := waitForEndpoint(t, secondReady); actual != endpoint {
		t.Fatalf("recovery endpoint = %q, want %q", actual, endpoint)
	}
	result, err := agentenrollment.Provision(context.Background(), options, []byte(token))
	if err != nil {
		t.Fatal(err)
	}
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
	if result.OrganizationID != organizationID || result.ManagedHostID != managedHostID ||
		result.IdentityID != identityID || result.InstanceID != "conformance-instance" {
		t.Fatalf("enrollment result = %+v", result)
	}
	first, err := os.ReadFile(firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(secondRequest)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) || strings.Contains(string(first), "PRIVATE KEY") {
		t.Fatal("retry did not preserve a secret-safe exact request")
	}
	if _, err := os.Stat(filepath.Join(paths.StateDirectory, "enrollment-pending-v1.json")); !os.IsNotExist(err) {
		t.Fatalf("pending enrollment remains: %v", err)
	}
}

func enrollmentOptions(endpoint, materials string, paths agentenrollment.Paths) agentenrollment.Options {
	return agentenrollment.Options{
		EnrollmentEndpoint: endpoint,
		ControlEndpoint:    "https://127.0.0.1:8443/api/v1/agent/connect",
		ServerCAFile:       filepath.Join(materials, "ca.pem"),
		InstanceID:         "conformance-instance",
		AgentVersion:       "0.0.0-system",
		Capabilities:       agentenrollment.StandardCapabilities(false),
		RequestTimeout:     3 * time.Second,
		Paths:              paths,
	}
}

func enrollmentPaths(t *testing.T) agentenrollment.Paths {
	t.Helper()
	root := t.TempDir()
	state := filepath.Join(root, "state")
	config := filepath.Join(root, "config")
	if err := os.MkdirAll(filepath.Join(state, "identity"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(config, 0o700); err != nil {
		t.Fatal(err)
	}
	return agentenrollment.Paths{
		Config:         filepath.Join(config, "agent.yaml"),
		CACertificate:  filepath.Join(config, "agent-ca.pem"),
		IdentityBundle: filepath.Join(state, "identity", "agent-identity.pem"),
		StateDirectory: state,
	}
}

func waitForEndpoint(t *testing.T, path string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		value, err := os.ReadFile(path)
		if err == nil && len(value) > 0 {
			return strings.TrimSpace(string(value))
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("endpoint file %s was not ready", path)
	return ""
}
