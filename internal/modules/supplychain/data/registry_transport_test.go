package data

import (
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegistryHTTPClientUsesExplicitSupplementalCA(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	untrusted, err := newRegistryHTTPClient(false, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, requestErr := untrusted.Get(server.URL)
	if response != nil {
		_ = response.Body.Close()
	}
	if requestErr == nil {
		t.Fatal("self-signed Registry was trusted without an explicit CA")
	}

	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	trusted, err := newRegistryHTTPClient(false, certificate)
	if err != nil {
		t.Fatalf("newRegistryHTTPClient(explicit CA) error = %v", err)
	}
	response, err = trusted.Get(server.URL)
	if err != nil {
		t.Fatalf("GET with explicit Registry CA error = %v", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d", response.StatusCode)
	}
	if _, err := newRegistryHTTPClient(false, []byte("not a certificate")); !errors.Is(err, errInvalidRegistryTrust) {
		t.Fatalf("invalid in-memory bundle error = %v", err)
	}
}

func TestRegistryCABundleLoadingAndSnapshotAreFailClosed(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	server.Close()
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	directory := t.TempDir()
	caFile := filepath.Join(directory, "registry-ca.pem")
	if err := os.WriteFile(caFile, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadRegistryCABundle(caFile)
	if err != nil || string(loaded) != string(bundle) {
		t.Fatalf("LoadRegistryCABundle() = %d bytes, %v", len(loaded), err)
	}
	loaded[0] = 'X'
	content, err := os.ReadFile(caFile)
	if err != nil || string(content) != string(bundle) {
		t.Fatal("loaded bundle aliases or modifies its source file")
	}

	snapshot, cleanup, err := SnapshotRegistryCABundle(directory, bundle)
	if err != nil {
		t.Fatalf("SnapshotRegistryCABundle() error = %v", err)
	}
	snapshotInfo, err := os.Stat(snapshot)
	if err != nil || snapshotInfo.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot mode = %v, %v", snapshotInfo, err)
	}
	parentInfo, err := os.Stat(filepath.Dir(snapshot))
	if err != nil || parentInfo.Mode().Perm() != 0o700 {
		t.Fatalf("snapshot directory mode = %v, %v", parentInfo, err)
	}
	cleanup()
	if _, err := os.Stat(snapshot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("snapshot remains after cleanup: %v", err)
	}

	invalid := filepath.Join(directory, "invalid.pem")
	if err := os.WriteFile(invalid, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "registry-ca-link.pem")
	if err := os.Symlink(caFile, symlink); err != nil {
		t.Fatal(err)
	}
	oversized := filepath.Join(directory, "oversized.pem")
	if err := os.WriteFile(oversized, []byte(strings.Repeat("x", int(maximumRegistryCABundleBytes)+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"relative.pem", " " + caFile, invalid, symlink, directory, oversized} {
		if _, err := LoadRegistryCABundle(path); !errors.Is(err, errInvalidRegistryTrust) {
			t.Errorf("LoadRegistryCABundle(%q) error = %v", path, err)
		}
	}
	if path, cleanupEmpty, err := SnapshotRegistryCABundle(directory, nil); err != nil || path != "" {
		t.Fatalf("empty snapshot = %q, %v", path, err)
	} else {
		cleanupEmpty()
	}
}

func TestRegistryCAEnvironmentIsExplicit(t *testing.T) {
	base := []string{"HOME=/tmp"}
	if got := registryCAEnvironment(base, ""); len(got) != 1 {
		t.Fatalf("environment without CA = %v", got)
	}
	got := registryCAEnvironment(base, "/run/owndock/registry-ca.pem")
	if len(got) != 2 || got[1] != "SSL_CERT_FILE=/run/owndock/registry-ca.pem" {
		t.Fatalf("environment with CA = %v", got)
	}
}

func TestRegistryRedirectPolicyAllowsOnlySameOrigin(t *testing.T) {
	request := func(rawURL string) *http.Request {
		parsed, err := url.Parse(rawURL)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Request{URL: parsed}
	}
	for _, testCase := range []struct {
		name       string
		allowPlain bool
		from       string
		to         string
		viaCount   int
		want       error
	}{
		{name: "same HTTPS origin", from: "https://registry.example.com/v2/a", to: "https://registry.example.com/v2/b"},
		{name: "same loopback HTTP origin", allowPlain: true, from: "http://127.0.0.1:5000/v2/a", to: "http://127.0.0.1:5000/v2/b"},
		{name: "cross host", from: "https://registry.example.com/v2/a", to: "https://objects.example.com/blob", want: errUnsafeRegistryRedirect},
		{name: "cross port", from: "https://registry.example.com:443/v2/a", to: "https://registry.example.com:5443/v2/b", want: errUnsafeRegistryRedirect},
		{name: "HTTPS downgrade", allowPlain: true, from: "https://registry.example.com/v2/a", to: "http://127.0.0.1:5000/v2/b", want: errUnsafeRegistryRedirect},
		{name: "plain remote", allowPlain: true, from: "http://registry.example.com/v2/a", to: "http://registry.example.com/v2/b", want: errUnsafeRegistryRedirect},
		{name: "userinfo", from: "https://registry.example.com/v2/a", to: "https://user@registry.example.com/v2/b", want: errUnsafeRegistryRedirect},
		{name: "too many", from: "https://registry.example.com/v2/a", to: "https://registry.example.com/v2/b", viaCount: 3, want: errUnsafeRegistryRedirect},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			viaCount := testCase.viaCount
			if viaCount == 0 {
				viaCount = 1
			}
			via := make([]*http.Request, viaCount)
			for index := range via {
				via[index] = request(testCase.from)
			}
			err := registryRedirectPolicy(testCase.allowPlain)(request(testCase.to), via)
			if !errors.Is(err, testCase.want) {
				t.Fatalf("redirect error = %v, want %v", err, testCase.want)
			}
		})
	}
}
