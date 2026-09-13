package data

import (
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRegistryHTTPClientUsesExplicitSupplementalCA(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	untrusted, err := newRegistryHTTPClient(false, nil, "")
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
	trusted, err := newRegistryHTTPClient(false, certificate, "")
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
	if _, err := newRegistryHTTPClient(false, []byte("not a certificate"), ""); !errors.Is(err, errInvalidRegistryTrust) {
		t.Fatalf("invalid in-memory bundle error = %v", err)
	}
}

func TestRegistryHTTPClientUsesOnlyExplicitProxy(t *testing.T) {
	registry := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(registry.Close)
	proxy, connections := startRegistryCONNECTProxy(t)
	t.Cleanup(proxy.Close)
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: registry.Certificate().Raw})
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("https_proxy", "http://127.0.0.1:1")

	direct, err := newRegistryHTTPClient(false, certificate, "")
	if err != nil {
		t.Fatal(err)
	}
	response, err := direct.Get(registry.URL)
	if err != nil {
		t.Fatalf("direct Registry request inherited ambient proxy: %v", err)
	}
	_ = response.Body.Close()
	if connections.Load() != 0 {
		t.Fatal("direct Registry request used the explicit test proxy")
	}

	proxied, err := newRegistryHTTPClient(false, certificate, proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	response, err = proxied.Get(registry.URL)
	if err != nil {
		t.Fatalf("explicitly proxied Registry request: %v", err)
	}
	_ = response.Body.Close()
	if connections.Load() != 1 {
		t.Fatalf("Registry proxy CONNECT count = %d, want 1", connections.Load())
	}

	tlsProxy, tlsConnections := startRegistryTLSCONNECTProxy(t)
	t.Cleanup(tlsProxy.Close)
	tlsProxyCertificate := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: tlsProxy.Certificate().Raw,
	})
	tlsProxied, err := newRegistryHTTPClient(
		false, append(certificate, tlsProxyCertificate...), tlsProxy.URL,
	)
	if err != nil {
		t.Fatal(err)
	}
	response, err = tlsProxied.Get(registry.URL)
	if err != nil {
		t.Fatalf("explicitly TLS-proxied Registry request: %v", err)
	}
	_ = response.Body.Close()
	if tlsConnections.Load() != 1 {
		t.Fatalf("TLS Registry proxy CONNECT count = %d, want 1", tlsConnections.Load())
	}
}

func TestRegistryProxyValidationAndEnvironment(t *testing.T) {
	for _, value := range []string{"", "http://proxy.internal:3128", "https://127.0.0.1:8443"} {
		if _, err := parseRegistryHTTPSProxy(value); err != nil {
			t.Errorf("valid Registry proxy %q error = %v", value, err)
		}
	}
	for _, value := range []string{
		" http://proxy.internal:3128", "http://user:secret@proxy.internal:3128",
		"http://proxy.internal:3128/path", "socks5://proxy.internal:1080",
		"http://PROXY.internal:3128", "http://proxy.internal:65536",
	} {
		if _, err := parseRegistryHTTPSProxy(value); !errors.Is(err, errInvalidRegistryProxy) {
			t.Errorf("invalid Registry proxy %q error = %v", value, err)
		}
	}
	base := []string{"HOME=/tmp"}
	if got := registryProxyEnvironment(base, ""); len(got) != 1 {
		t.Fatalf("environment without proxy = %v", got)
	}
	got := registryProxyEnvironment(base, "http://proxy.internal:3128")
	for _, expected := range []string{
		"HTTP_PROXY=http://proxy.internal:3128", "HTTPS_PROXY=http://proxy.internal:3128",
		"http_proxy=http://proxy.internal:3128", "https_proxy=http://proxy.internal:3128",
		"NO_PROXY=", "no_proxy=",
	} {
		if !containsEnvironmentEntry(got, expected) {
			t.Errorf("Registry proxy environment is missing %q: %v", expected, got)
		}
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

func startRegistryCONNECTProxy(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	connections := &atomic.Int64{}
	return httptest.NewServer(registryCONNECTProxyHandler(connections)), connections
}

func startRegistryTLSCONNECTProxy(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	connections := &atomic.Int64{}
	return httptest.NewTLSServer(registryCONNECTProxyHandler(connections)), connections
}

func registryCONNECTProxyHandler(connections *atomic.Int64) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodConnect || request.Header.Get("Proxy-Authorization") != "" {
			http.Error(response, "CONNECT required", http.StatusMethodNotAllowed)
			return
		}
		upstream, err := net.DialTimeout("tcp", request.Host, 5*time.Second)
		if err != nil {
			http.Error(response, "upstream unavailable", http.StatusBadGateway)
			return
		}
		hijacker, ok := response.(http.Hijacker)
		if !ok {
			_ = upstream.Close()
			http.Error(response, "tunnel unsupported", http.StatusInternalServerError)
			return
		}
		client, buffer, err := hijacker.Hijack()
		if err != nil {
			_ = upstream.Close()
			return
		}
		connections.Add(1)
		_, _ = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = buffer.Flush()
		go tunnelRegistryConnections(client, upstream)
	})
}

func tunnelRegistryConnections(left, right net.Conn) {
	defer left.Close()
	defer right.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(left, right); done <- struct{}{} }()
	go func() { _, _ = io.Copy(right, left); done <- struct{}{} }()
	<-done
}

func containsEnvironmentEntry(environment []string, expected string) bool {
	for _, entry := range environment {
		if entry == expected {
			return true
		}
	}
	return false
}
