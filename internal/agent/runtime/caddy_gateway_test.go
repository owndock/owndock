package agentruntime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/shared/agentprotocol"
)

func TestBuildCaddyConfigIsDeterministicAndConstrained(t *testing.T) {
	routes := []agentprotocol.IngressRoute{
		ingressRoute("route-1", 2, "deployment-1", 3),
		ingressRoute("route-2", 1, "deployment-2", 4),
	}
	routes[1].TLSMode = agentprotocol.IngressTLSDisabled
	command := ingressCommand(t, 8, routes)
	first, configID, err := buildCaddyConfig(DefaultCaddyAdminSocket, command)
	if err != nil {
		t.Fatal(err)
	}
	second, secondID, err := buildCaddyConfig(DefaultCaddyAdminSocket, command)
	if err != nil || string(first) != string(second) || configID != secondID {
		t.Fatalf("config is not deterministic: %v", err)
	}
	if configID != "owndock-config-"+strings.TrimPrefix(command.ConfigDigest, "sha256:") {
		t.Fatalf("config ID = %q", configID)
	}
	var document map[string]any
	if err := json.Unmarshal(first, &document); err != nil {
		t.Fatal(err)
	}
	encoded := string(first)
	for _, required := range []string{
		`"listen":"unix//run/owndock-ingress/admin.sock|0660"`,
		`"module":"file_system"`, `"root":"/data/caddy"`,
		`"listen":[":8080",":8443"]`, `"strict_sni_host":true`,
		`"skip":["route-2.example.com"]`, `"status_code":404`,
		`"dial":"deployment-1:8080"`, `"stream_close_delay":"5m"`,
		`"header":{"X-OwnDock-Route-Probe"`, `"response":{"set":{"X-OwnDock-Route-Probe"`,
	} {
		if !strings.Contains(encoded, required) {
			t.Fatalf("generated config missing %s: %s", required, encoded)
		}
	}
	for _, forbidden := range []string{"docker.sock", "authorization", "certificate_pem", "caddyfile"} {
		if strings.Contains(strings.ToLower(encoded), forbidden) {
			t.Fatalf("generated config contains forbidden %q", forbidden)
		}
	}
}

func TestCaddyGatewayPrivateProbeUsesHostTLSAndExactMarker(t *testing.T) {
	command := ingressCommand(t, 2,
		[]agentprotocol.IngressRoute{ingressRoute("route-1", 1, "deployment-1", 1)})
	command.ProbeRouteIDs = []string{"route-1"}
	token := caddyProbeToken(command.ConfigDigest, "route-1")
	var seen *http.Request
	gateway := &CaddyGateway{timeout: time.Second, probeClient: &http.Client{
		Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			seen = request
			header := make(http.Header)
			header.Set(caddyProbeHeader, token)
			return &http.Response{StatusCode: http.StatusNotFound,
				Header: header,
				Body:   io.NopCloser(strings.NewReader("application response"))}, nil
		}),
	}}
	if err := gateway.Probe(t.Context(), command); err != nil {
		t.Fatal(err)
	}
	if seen == nil || seen.URL.Scheme != "https" || seen.URL.Host != "route-1.example.com:443" ||
		seen.Host != "route-1.example.com:443" || seen.Header.Get(caddyProbeHeader) != token {
		t.Fatalf("probe request = %#v", seen)
	}
	gateway.probeClient = &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader("unmarked"))}, nil
	})}
	if err := gateway.Probe(t.Context(), command); !errors.Is(err, ErrIngressBackendUnhealthy) {
		t.Fatalf("unmarked response error = %v", err)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestBuildCaddyConfigDoesNotExposeHTTPSForDevelopmentOnlyRoutes(t *testing.T) {
	route := ingressRoute("route-1", 1, "deployment-1", 1)
	route.TLSMode = agentprotocol.IngressTLSDisabled
	value, _, err := buildCaddyConfig(DefaultCaddyAdminSocket,
		ingressCommand(t, 1, []agentprotocol.IngressRoute{route}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(value), `:8443`) || strings.Contains(string(value), `strict_sni_host`) {
		t.Fatalf("development-only config exposes HTTPS: %s", value)
	}
}

func TestGeneratedConfigValidatesWithRealCaddy(t *testing.T) {
	binary := os.Getenv("OWNDOCK_CADDY_BINARY")
	if binary == "" {
		t.Skip("set OWNDOCK_CADDY_BINARY to the fixed Caddy binary")
	}
	info, err := os.Lstat(binary)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("Caddy binary must be a regular non-symlink file")
	}
	command := ingressCommand(t, 3,
		[]agentprotocol.IngressRoute{ingressRoute("route-1", 1, "deployment-1", 1)})
	value, _, err := buildCaddyConfig(DefaultCaddyAdminSocket, command)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "caddy.json")
	if err := os.WriteFile(configPath, value, 0o600); err != nil {
		t.Fatal(err)
	}
	process := exec.Command(binary, "validate", "--config", configPath)
	process.Env = append(os.Environ(), "XDG_DATA_HOME="+t.TempDir(), "XDG_CONFIG_HOME="+t.TempDir())
	if output, err := process.CombinedOutput(); err != nil {
		t.Fatalf("caddy validate: %v: %s", err, output)
	}
}

func TestCaddyGatewayLoadsOnceAndRecognizesResumedConfig(t *testing.T) {
	command := ingressCommand(t, 2,
		[]agentprotocol.IngressRoute{ingressRoute("route-1", 1, "deployment-1", 1)})
	configID := "owndock-config-" + strings.TrimPrefix(command.ConfigDigest, "sha256:")
	var loaded atomic.Bool
	var loads atomic.Int32
	gateway, shutdown := newCaddyGatewayTestServer(t, func(response http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/id/"+configID:
			if !loaded.Load() {
				http.Error(response, "missing", http.StatusNotFound)
				return
			}
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`{"@id":"` + configID + `"}`))
		case request.Method == http.MethodPost && request.URL.Path == "/load":
			if request.Header.Get("Content-Type") != "application/json" {
				t.Errorf("content type = %q", request.Header.Get("Content-Type"))
			}
			loads.Add(1)
			loaded.Store(true)
			response.WriteHeader(http.StatusOK)
		default:
			http.Error(response, "unexpected", http.StatusBadRequest)
		}
	})
	defer shutdown()
	for range 2 {
		digest, err := gateway.Apply(context.Background(), command)
		if err != nil || digest != command.ConfigDigest {
			t.Fatalf("Apply() = %q, %v", digest, err)
		}
	}
	if loads.Load() != 1 {
		t.Fatalf("loads = %d, want 1", loads.Load())
	}
}

func TestCaddyGatewayClassifiesPortConflictWithoutReturningRawError(t *testing.T) {
	gateway, shutdown := newCaddyGatewayTestServer(t, func(response http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet {
			http.Error(response, "missing", http.StatusNotFound)
			return
		}
		http.Error(response, "listen tcp :8080: bind: address already in use secret-marker",
			http.StatusBadRequest)
	})
	defer shutdown()
	command := ingressCommand(t, 1,
		[]agentprotocol.IngressRoute{ingressRoute("route-1", 1, "deployment-1", 1)})
	if _, err := gateway.Apply(context.Background(), command); !errors.Is(err, ErrIngressPortConflict) ||
		strings.Contains(err.Error(), "secret-marker") {
		t.Fatalf("Apply() error = %v", err)
	}
}

func TestCaddyGatewayFailsClosedWhenSocketIsMissing(t *testing.T) {
	directory := shortSocketDirectory(t)
	gateway, err := NewCaddyGateway(CaddyGatewayConfig{AdminSocket: filepath.Join(directory, "missing.sock"),
		RequestTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	command := ingressCommand(t, 1, nil)
	if _, err := gateway.Apply(context.Background(), command); !errors.Is(err, ErrIngressGatewayUnavailable) {
		t.Fatalf("Apply() error = %v", err)
	}
}

func newCaddyGatewayTestServer(t *testing.T, handler http.HandlerFunc) (*CaddyGateway, func()) {
	t.Helper()
	directory := shortSocketDirectory(t)
	socket := filepath.Join(directory, "admin.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	go func() { _ = server.Serve(listener) }()
	gateway, err := NewCaddyGateway(CaddyGatewayConfig{AdminSocket: socket, RequestTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return gateway, func() {
		_ = server.Close()
		_ = listener.Close()
	}
}

func shortSocketDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "owndock-caddy-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}
