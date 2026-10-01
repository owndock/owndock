package agentruntime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	containertypes "github.com/moby/moby/api/types/container"
	networktypes "github.com/moby/moby/api/types/network"
	"github.com/testcontainers/testcontainers-go"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/owndock/owndock/internal/shared/agentprotocol"
)

const agentCaddyIntegrationImage = "caddy:2.11.4-alpine@sha256:6aeddd44c3078b0f9a35206472a11420648a79c184603ef95957d0a20044cb2b"

const caddyIntegrationPort = "8080/tcp"

func TestCaddyGatewayRealTrafficCutoverRollbackAndResumeIntegration(t *testing.T) {
	if os.Getenv("OWNDOCK_RUN_INGRESS_INTEGRATION") != "1" {
		t.Skip("set OWNDOCK_RUN_INGRESS_INTEGRATION=1 to run the managed ingress integration test")
	}
	if runtime.GOOS != "linux" {
		t.Skip("managed ingress Unix socket integration requires a Linux Docker host")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	network, err := tcnetwork.New(ctx)
	if err != nil {
		t.Fatalf("create ingress network: %v", err)
	}
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()
		if err := network.Remove(cleanupContext); err != nil {
			t.Errorf("remove ingress network: %v", err)
		}
	})

	aliases := map[string]string{}
	for _, backend := range []struct {
		deploymentID string
		body         string
	}{
		{deploymentID: "ingress-deployment-a-old", body: "application-a-old"},
		{deploymentID: "ingress-deployment-a-new", body: "application-a-new"},
		{deploymentID: "ingress-deployment-b", body: "application-b"},
	} {
		alias, err := agentprotocol.DeploymentBackendAlias(backend.deploymentID)
		if err != nil {
			t.Fatal(err)
		}
		aliases[backend.deploymentID] = alias
		startIngressBackend(t, ctx, network.Name, alias, backend.body)
	}
	protocolBinary := buildIngressProtocolBackend(t)
	for _, backend := range []struct {
		deploymentID string
		body         string
	}{
		{deploymentID: "ingress-deployment-protocol-old", body: "protocol-old"},
		{deploymentID: "ingress-deployment-protocol-new", body: "protocol-new"},
	} {
		alias, err := agentprotocol.DeploymentBackendAlias(backend.deploymentID)
		if err != nil {
			t.Fatal(err)
		}
		aliases[backend.deploymentID] = alias
		startIngressProtocolBackend(t, ctx, network.Name, alias, backend.body, protocolBinary)
	}

	socketDirectory, err := os.MkdirTemp("/tmp", "owndock-ingress-")
	if err != nil {
		t.Fatalf("create ingress socket directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(socketDirectory); err != nil {
			t.Errorf("remove ingress socket directory: %v", err)
		}
	})
	if err := os.Chmod(socketDirectory, 0o700); err != nil {
		t.Fatalf("restrict ingress socket directory: %v", err)
	}
	adminSocket := filepath.Join(socketDirectory, "admin.sock")
	caddy, publicAddress := startIngressCaddy(t, ctx, network.Name, socketDirectory, adminSocket)
	waitForUnixSocket(t, ctx, adminSocket)

	gateway, err := NewCaddyGateway(CaddyGatewayConfig{
		AdminSocket: adminSocket, RequestTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	gateway.probeClient = ingressIntegrationHTTPClient(publicAddress)
	store, err := NewFileIngressFenceStore(restrictedTempDirectory(t), 8)
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewIngressExecutor(store, gateway)
	if err != nil {
		t.Fatal(err)
	}

	first := ingressIntegrationCommand(t, 1, []agentprotocol.IngressRoute{
		ingressIntegrationRoute("route-a", 1, "ingress-deployment-a-old", 1,
			"application-a.example.com", aliases["ingress-deployment-a-old"]),
		ingressIntegrationRoute("route-b", 1, "ingress-deployment-b", 1,
			"application-b.example.com", aliases["ingress-deployment-b"]),
		ingressIntegrationProtocolRoute("route-c", 1, "ingress-deployment-protocol-old", 1,
			"protocol.example.com", aliases["ingress-deployment-protocol-old"]),
	}, "route-a", "route-b", "route-c")
	if _, err := executor.Prepare(ctx, first); err != nil {
		t.Fatalf("prepare initial routes: %v", err)
	}
	if _, err := executor.Commit(ctx, first); err != nil {
		t.Fatalf("commit initial routes: %v", err)
	}
	assertIngressResponse(t, ctx, publicAddress, "application-a.example.com", http.StatusOK, "application-a-old")
	assertIngressResponse(t, ctx, publicAddress, "application-b.example.com", http.StatusOK, "application-b")
	assertIngressResponse(t, ctx, publicAddress, "protocol.example.com", http.StatusOK, "protocol-old")
	assertIngressResponse(t, ctx, publicAddress, "unknown.example.com", http.StatusNotFound, "")
	oldWebSocket := openIngressWebSocket(t, ctx, publicAddress, "protocol.example.com")
	oldStream := openIngressStream(t, ctx, publicAddress, "protocol.example.com", "protocol-old")

	second := ingressIntegrationCommand(t, 2, []agentprotocol.IngressRoute{
		ingressIntegrationRoute("route-a", 2, "ingress-deployment-a-new", 2,
			"application-a.example.com", aliases["ingress-deployment-a-new"]),
		first.Routes[1],
		ingressIntegrationProtocolRoute("route-c", 2, "ingress-deployment-protocol-new", 2,
			"protocol.example.com", aliases["ingress-deployment-protocol-new"]),
	}, "route-a", "route-c")
	if _, err := executor.Prepare(ctx, second); err != nil {
		t.Fatalf("prepare candidate route: %v", err)
	}
	cutoverAt := time.Now()
	assertIngressResponse(t, ctx, publicAddress, "application-a.example.com", http.StatusOK, "application-a-new")
	assertIngressResponse(t, ctx, publicAddress, "protocol.example.com", http.StatusOK, "protocol-new")
	oldWebSocket.exchange(t, "after-prepare", "protocol-old:after-prepare")
	newWebSocket := openIngressWebSocket(t, ctx, publicAddress, "protocol.example.com")
	newWebSocket.exchange(t, "new-connection", "protocol-new:new-connection")
	oldStream.assertSurvivesAfter(t, cutoverAt, "protocol-old")
	_ = oldWebSocket.connection.Close()
	_ = newWebSocket.connection.Close()
	if _, err := executor.Abort(ctx, second); err != nil {
		t.Fatalf("abort candidate route: %v", err)
	}
	assertIngressResponse(t, ctx, publicAddress, "application-a.example.com", http.StatusOK, "application-a-old")
	assertIngressResponse(t, ctx, publicAddress, "application-b.example.com", http.StatusOK, "application-b")
	assertIngressResponse(t, ctx, publicAddress, "protocol.example.com", http.StatusOK, "protocol-old")

	third := ingressIntegrationCommand(t, 3, []agentprotocol.IngressRoute{
		ingressIntegrationRoute("route-a", 3, "ingress-deployment-a-new", 3,
			"application-a.example.com", aliases["ingress-deployment-a-new"]),
		first.Routes[1],
		ingressIntegrationProtocolRoute("route-c", 3, "ingress-deployment-protocol-new", 3,
			"protocol.example.com", aliases["ingress-deployment-protocol-new"]),
	}, "route-a", "route-c")
	if _, err := executor.Prepare(ctx, third); err != nil {
		t.Fatalf("prepare replacement route: %v", err)
	}
	if _, err := executor.Commit(ctx, third); err != nil {
		t.Fatalf("commit replacement route: %v", err)
	}
	assertIngressResponse(t, ctx, publicAddress, "application-a.example.com", http.StatusOK, "application-a-new")
	assertIngressResponse(t, ctx, publicAddress, "protocol.example.com", http.StatusOK, "protocol-new")

	missingAlias, err := agentprotocol.DeploymentBackendAlias("ingress-deployment-missing")
	if err != nil {
		t.Fatal(err)
	}
	fourth := ingressIntegrationCommand(t, 4, []agentprotocol.IngressRoute{
		ingressIntegrationRoute("route-a", 4, "ingress-deployment-missing", 4,
			"application-a.example.com", missingAlias),
		first.Routes[1],
		third.Routes[2],
	}, "route-a")
	if _, err := executor.Prepare(ctx, fourth); !errors.Is(err, ErrIngressBackendUnhealthy) {
		t.Fatalf("unhealthy replacement error = %v", err)
	}
	assertIngressResponse(t, ctx, publicAddress, "application-a.example.com", http.StatusOK, "application-a-new")
	assertIngressResponse(t, ctx, publicAddress, "application-b.example.com", http.StatusOK, "application-b")
	assertIngressResponse(t, ctx, publicAddress, "protocol.example.com", http.StatusOK, "protocol-new")

	stopTimeout := 10 * time.Second
	if err := caddy.Stop(ctx, &stopTimeout); err != nil {
		t.Fatalf("stop ingress gateway: %v", err)
	}
	if err := caddy.Start(ctx); err != nil {
		t.Fatalf("restart ingress gateway: %v", err)
	}
	waitForUnixSocket(t, ctx, adminSocket)
	publicAddress = ingressContainerAddress(t, ctx, caddy)
	if err := waitForIngressResponse(ctx, publicAddress,
		"application-a.example.com", "application-a-new"); err != nil {
		logs, logsErr := boundedIngressContainerLogs(ctx, caddy)
		t.Fatalf("resumed ingress did not become ready: %v; logs=%q logs_error=%v",
			err, logs, logsErr)
	}
	assertIngressResponse(t, ctx, publicAddress, "application-b.example.com", http.StatusOK, "application-b")
	assertIngressResponse(t, ctx, publicAddress, "protocol.example.com", http.StatusOK, "protocol-new")
	if _, err := executor.Commit(ctx, third); err != nil {
		t.Fatalf("reconcile resumed committed config: %v", err)
	}
}

func startIngressBackend(
	t *testing.T,
	ctx context.Context,
	networkName string,
	alias string,
	body string,
) {
	t.Helper()
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:          agentDockerIntegrationImage,
			Networks:       []string{networkName},
			NetworkAliases: map[string][]string{networkName: {alias}},
			Files: []testcontainers.ContainerFile{{
				Reader: strings.NewReader(body), ContainerFilePath: "/usr/share/nginx/html/index.html",
				FileMode: 0o444,
			}},
			WaitingFor: wait.ForLog("start worker processes").WithStartupTimeout(30 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start ingress backend %s: %v", alias, err)
	}
	terminateIngressContainer(t, container, "backend "+alias)
}

func startIngressCaddy(
	t *testing.T,
	ctx context.Context,
	networkName string,
	socketDirectory string,
	adminSocket string,
) (testcontainers.Container, string) {
	t.Helper()
	dataDirectory := filepath.Join(socketDirectory, "data")
	configDirectory := filepath.Join(socketDirectory, "config")
	for _, directory := range []string{dataDirectory, configDirectory} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatalf("create ingress persistence directory: %v", err)
		}
	}
	bootstrap := fmt.Sprintf(`{
  "@id": "owndock-ingress-bootstrap",
  "admin": {"listen": %q, "config": {"persist": true}},
  "storage": {"module": "file_system", "root": "/data/caddy"}
}`, "unix/"+adminSocket+"|0660")
	bootstrapPath := filepath.Join(socketDirectory, "bootstrap.json")
	if err := os.WriteFile(bootstrapPath, []byte(bootstrap), 0o400); err != nil {
		t.Fatalf("write ingress bootstrap: %v", err)
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        agentCaddyIntegrationImage,
			ExposedPorts: []string{caddyIntegrationPort},
			Cmd: []string{"caddy", "run", "--resume", "--config",
				"/etc/caddy/owndock-bootstrap.json"},
			Env:        map[string]string{"XDG_DATA_HOME": "/data", "XDG_CONFIG_HOME": "/config"},
			Networks:   []string{networkName},
			User:       fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
			WaitingFor: wait.ForLog("serving initial configuration").WithStartupTimeout(30 * time.Second),
			HostConfigModifier: func(config *containertypes.HostConfig) {
				config.Binds = []string{
					socketDirectory + ":" + socketDirectory,
					dataDirectory + ":/data",
					configDirectory + ":/config",
					bootstrapPath + ":/etc/caddy/owndock-bootstrap.json:ro",
				}
				config.ReadonlyRootfs = true
				config.CapDrop = []string{"ALL"}
				config.CapAdd = []string{"NET_BIND_SERVICE"}
				config.SecurityOpt = []string{"no-new-privileges:true"}
				config.Tmpfs = map[string]string{
					"/tmp": "rw,noexec,nosuid,nodev,size=16m,mode=0700",
				}
				config.PortBindings = networktypes.PortMap{
					networktypes.MustParsePort(caddyIntegrationPort): {
						{HostIP: netip.MustParseAddr("127.0.0.1")},
					},
				}
			},
		},
		Started: false,
	})
	if err != nil {
		t.Fatalf("create ingress gateway: %v", err)
	}
	terminateIngressContainer(t, container, "gateway")
	if err := container.Start(ctx); err != nil {
		logs, logsErr := boundedIngressContainerLogs(ctx, container)
		t.Fatalf("start ingress gateway: %v: logs=%q logs_error=%v", err, logs, logsErr)
	}
	return container, ingressContainerAddress(t, ctx, container)
}

func ingressContainerAddress(
	t *testing.T,
	ctx context.Context,
	container testcontainers.Container,
) string {
	t.Helper()
	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("resolve ingress gateway host: %v", err)
	}
	port, err := container.MappedPort(ctx, caddyIntegrationPort)
	if err != nil {
		t.Fatalf("resolve ingress gateway port: %v", err)
	}
	return net.JoinHostPort(host, port.Port())
}

func terminateIngressContainer(t *testing.T, container testcontainers.Container, description string) {
	t.Helper()
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()
		if err := container.Terminate(
			cleanupContext,
			testcontainers.StopContext(cleanupContext),
			testcontainers.StopTimeout(5*time.Second),
		); err != nil {
			t.Errorf("terminate ingress %s: %v", description, err)
		}
	})
}

func ingressIntegrationRoute(
	routeID string,
	revision uint64,
	deploymentID string,
	cutover uint64,
	hostname string,
	backendAlias string,
) agentprotocol.IngressRoute {
	return agentprotocol.IngressRoute{
		RouteID: routeID, Revision: revision, DeploymentID: deploymentID,
		CutoverSequence: cutover, RuntimeTargetID: "ingress-target", Hostname: hostname,
		BackendAlias: backendAlias, BackendPort: 80, TLSMode: agentprotocol.IngressTLSDisabled,
	}
}

func ingressIntegrationCommand(
	t *testing.T,
	hostRevision uint64,
	routes []agentprotocol.IngressRoute,
	probeRouteIDs ...string,
) agentprotocol.IngressCommand {
	t.Helper()
	digest, err := agentprotocol.IngressConfigDigest(hostRevision, routes)
	if err != nil {
		t.Fatal(err)
	}
	return agentprotocol.IngressCommand{
		HostRevision: hostRevision, ConfigDigest: digest, Routes: routes,
		ProbeRouteIDs: probeRouteIDs,
	}
}

func ingressIntegrationHTTPClient(address string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: nil, DisableKeepAlives: true,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", address)
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       10 * time.Second,
	}
}

func assertIngressResponse(
	t *testing.T,
	ctx context.Context,
	address string,
	hostname string,
	wantStatus int,
	wantBody string,
) {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = hostname
	response, err := ingressIntegrationHTTPClient(address).Do(request)
	if err != nil {
		t.Fatalf("request ingress host %s: %v", hostname, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumCaddyResponse+1))
	if err != nil || len(body) > maximumCaddyResponse {
		t.Fatalf("read ingress host %s response: %v", hostname, err)
	}
	if response.ProtoMajor != 1 || response.StatusCode != wantStatus ||
		wantBody != "" && strings.TrimSpace(string(body)) != wantBody {
		t.Fatalf("ingress host %s = protocol %s status %d body %q, want HTTP/1.x status %d body %q",
			hostname, response.Proto, response.StatusCode, body, wantStatus, wantBody)
	}
}

func waitForIngressResponse(
	ctx context.Context,
	address string,
	hostname string,
	wantBody string,
) error {
	deadline := time.Now().Add(20 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		requestContext, cancel := context.WithTimeout(ctx, 2*time.Second)
		request, err := http.NewRequestWithContext(requestContext, http.MethodGet, "http://"+address+"/", nil)
		if err == nil {
			request.Host = hostname
			response, requestErr := ingressIntegrationHTTPClient(address).Do(request)
			if requestErr == nil {
				body, readErr := io.ReadAll(io.LimitReader(response.Body, maximumCaddyResponse+1))
				closeErr := response.Body.Close()
				if readErr == nil && closeErr == nil && response.StatusCode == http.StatusOK &&
					strings.TrimSpace(string(body)) == wantBody {
					cancel()
					return nil
				}
				lastErr = fmt.Errorf("status %d body %q read=%v close=%v",
					response.StatusCode, body, readErr, closeErr)
			} else {
				lastErr = requestErr
			}
		} else {
			lastErr = err
		}
		cancel()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	if lastErr == nil {
		lastErr = errors.New("ingress response deadline elapsed before first attempt")
	}
	return fmt.Errorf("ingress host %s: %w", hostname, lastErr)
}

func boundedIngressContainerLogs(
	ctx context.Context,
	container testcontainers.Container,
) (string, error) {
	logs, err := container.Logs(ctx)
	if err != nil {
		return "", err
	}
	defer logs.Close()
	output, err := io.ReadAll(io.LimitReader(logs, 64*1024+1))
	if err != nil {
		return "", err
	}
	if len(output) > 64*1024 {
		return "", errors.New("Ingress Gateway logs exceed 64 KiB")
	}
	return string(output), nil
}

func waitForUnixSocket(t *testing.T, ctx context.Context, path string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		info, err := os.Lstat(path)
		if err == nil && info.Mode()&os.ModeSocket != 0 && info.Mode()&os.ModeSymlink == 0 {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for ingress admin socket: %v", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatalf("ingress admin socket %s was not created", path)
}
