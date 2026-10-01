package agentruntime

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/owndock/owndock/internal/shared/agentprotocol"
)

const integrationWebSocketKey = "MDEyMzQ1Njc4OWFiY2RlZg=="

type ingressWebSocket struct {
	connection net.Conn
	reader     *bufio.Reader
}

type ingressStream struct {
	body   io.ReadCloser
	reader *bufio.Reader
}

func ingressIntegrationProtocolRoute(
	routeID string,
	revision uint64,
	deploymentID string,
	cutover uint64,
	hostname string,
	backendAlias string,
) agentprotocol.IngressRoute {
	route := ingressIntegrationRoute(routeID, revision, deploymentID, cutover, hostname, backendAlias)
	route.BackendPort = 8080
	return route
}

func buildIngressProtocolBackend(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve ingress protocol fixture source")
	}
	output := filepath.Join(t.TempDir(), "owndock-ingress-protocol-backend")
	command := exec.Command("go", "build", "-trimpath", "-o", output, ".")
	command.Dir = filepath.Join(filepath.Dir(source), "testdata", "ingressbackend")
	command.Env = append(os.Environ(), "CGO_ENABLED=0")
	if value, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build ingress protocol fixture: %v: %s", err, value)
	}
	return output
}

func startIngressProtocolBackend(
	t *testing.T,
	ctx context.Context,
	networkName string,
	alias string,
	body string,
	binary string,
) {
	t.Helper()
	const containerBinary = "/usr/local/bin/owndock-ingress-protocol-backend"
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:          agentDockerIntegrationImage,
			Entrypoint:     []string{containerBinary},
			Cmd:            []string{},
			Env:            map[string]string{"OWNDOCK_TEST_BACKEND_BODY": body},
			Networks:       []string{networkName},
			NetworkAliases: map[string][]string{networkName: {alias}},
			Files: []testcontainers.ContainerFile{{
				HostFilePath: binary, ContainerFilePath: containerBinary, FileMode: 0o555,
			}},
			WaitingFor: wait.ForLog("ready").WithStartupTimeout(30 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start ingress protocol backend %s: %v", alias, err)
	}
	terminateIngressContainer(t, container, "protocol backend "+alias)
}

func openIngressWebSocket(
	t *testing.T,
	ctx context.Context,
	address string,
	hostname string,
) *ingressWebSocket {
	t.Helper()
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		t.Fatalf("dial ingress WebSocket: %v", err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if _, err := fmt.Fprintf(connection,
		"GET /ws HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\n\r\n",
		hostname, integrationWebSocketKey); err != nil {
		t.Fatalf("write ingress WebSocket handshake: %v", err)
	}
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read ingress WebSocket handshake: %v", err)
	}
	_ = response.Body.Close()
	digest := sha1.Sum([]byte(integrationWebSocketKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	wantAccept := base64.StdEncoding.EncodeToString(digest[:])
	if response.StatusCode != http.StatusSwitchingProtocols ||
		response.Header.Get("Sec-WebSocket-Accept") != wantAccept {
		t.Fatalf("WebSocket handshake = %d accept %q", response.StatusCode,
			response.Header.Get("Sec-WebSocket-Accept"))
	}
	return &ingressWebSocket{connection: connection, reader: reader}
}

func (socket *ingressWebSocket) exchange(t *testing.T, payload, want string) {
	t.Helper()
	if len(payload) > 125 {
		t.Fatal("integration WebSocket payload is too large")
	}
	mask := [4]byte{0x10, 0x20, 0x30, 0x40}
	frame := []byte{0x81, 0x80 | byte(len(payload))}
	frame = append(frame, mask[:]...)
	for index := range []byte(payload) {
		frame = append(frame, payload[index]^mask[index%len(mask)])
	}
	if _, err := socket.connection.Write(frame); err != nil {
		t.Fatalf("write ingress WebSocket frame: %v", err)
	}
	header := make([]byte, 2)
	if _, err := io.ReadFull(socket.reader, header); err != nil {
		t.Fatalf("read ingress WebSocket frame header: %v", err)
	}
	if header[0] != 0x81 || header[1]&0x80 != 0 || header[1]&0x7f > 125 {
		t.Fatalf("invalid ingress WebSocket frame header %x", header)
	}
	response := make([]byte, int(header[1]&0x7f))
	if _, err := io.ReadFull(socket.reader, response); err != nil {
		t.Fatalf("read ingress WebSocket frame: %v", err)
	}
	if string(response) != want {
		t.Fatalf("ingress WebSocket response = %q, want %q", response, want)
	}
}

func openIngressStream(
	t *testing.T,
	ctx context.Context,
	address string,
	hostname string,
	wantBackend string,
) *ingressStream {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = hostname
	response, err := ingressIntegrationHTTPClient(address).Do(request)
	if err != nil {
		t.Fatalf("open ingress stream: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		t.Fatalf("ingress stream status = %d", response.StatusCode)
	}
	stream := &ingressStream{body: response.Body, reader: bufio.NewReader(response.Body)}
	t.Cleanup(func() { _ = stream.body.Close() })
	line, err := stream.reader.ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "stream-start:"+wantBackend {
		t.Fatalf("ingress stream start = %q, %v", line, err)
	}
	return stream
}

func (stream *ingressStream) assertSurvivesAfter(
	t *testing.T,
	cutoverAt time.Time,
	wantBackend string,
) {
	t.Helper()
	seenAfterCutover := false
	seenEnd := false
	for {
		line, err := stream.reader.ReadString('\n')
		if err != nil {
			if err == io.EOF && seenEnd {
				break
			}
			t.Fatalf("read ingress stream: %v", err)
		}
		value := strings.TrimSpace(line)
		if value == "stream-end:"+wantBackend {
			seenEnd = true
			break
		}
		prefix := "stream-tick:" + wantBackend + ":"
		if !strings.HasPrefix(value, prefix) {
			t.Fatalf("unexpected ingress stream line %q", value)
		}
		nanoseconds, err := strconv.ParseInt(strings.TrimPrefix(value, prefix), 10, 64)
		if err != nil {
			t.Fatalf("parse ingress stream timestamp: %v", err)
		}
		if time.Unix(0, nanoseconds).After(cutoverAt) {
			seenAfterCutover = true
		}
	}
	if !seenAfterCutover || !seenEnd {
		t.Fatalf("old ingress stream did not survive cutover: after=%t end=%t",
			seenAfterCutover, seenEnd)
	}
}
