package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/owndock/owndock/internal/shared/terminalprotocol"
	testmongo "github.com/testcontainers/testcontainers-go/modules/mongodb"
)

func TestTwoServerProcessesObserveTerminalPolicyRevocationThroughReverseProxy(t *testing.T) {
	if os.Getenv("OWNDOCK_RUN_TERMINAL_PROCESS_INTEGRATION") != "1" {
		t.Skip("set OWNDOCK_RUN_TERMINAL_PROCESS_INTEGRATION=1 to run the dual Server terminal test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("Docker CLI is unavailable")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	mongoContainer, err := testmongo.Run(
		ctx,
		pinnedServerIngressMongoImage,
		testmongo.WithReplicaSet("rs0"),
	)
	if err != nil {
		t.Fatalf("start MongoDB fixture: %v", err)
	}
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if err := mongoContainer.Terminate(cleanupContext); err != nil {
			t.Errorf("terminate MongoDB fixture: %v", err)
		}
	})
	mongoURI, err := mongoContainer.ConnectionString(ctx)
	if err != nil {
		t.Fatal(err)
	}
	separator := "?"
	if strings.Contains(mongoURI, "?") {
		separator = "&"
	}
	mongoURI += separator + "directConnection=true"

	sshFixture := startTerminalSSHFixture(t)
	root := repositoryRoot(t)
	temporary := t.TempDir()
	binary := filepath.Join(temporary, "owndock-server")
	build := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", binary, "./cmd/server")
	build.Dir = root
	build.Env = append(os.Environ(), "GOCACHE=/tmp/owndock-go-cache")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build Server binary: %v\n%s", err, output)
	}

	const bootstrapToken = "terminal-process-bootstrap-token-245d2aed"
	serverA := startTerminalServerProcess(
		t, binary, root, temporary, "a", mongoURI, bootstrapToken,
		sshFixture.clientPrivateKeyPEM,
	)
	serverB := startTerminalServerProcess(
		t, binary, root, temporary, "b", mongoURI, bootstrapToken,
		sshFixture.clientPrivateKeyPEM,
	)
	client := &http.Client{Timeout: 10 * time.Second}
	var bootstrap struct {
		AccessToken string `json:"access_token"`
	}
	terminalProcessJSON(
		t,
		client,
		http.MethodPost,
		serverA.baseURL+"/api/v1/auth/bootstrap",
		map[string]string{"X-OwnDock-Bootstrap-Token": bootstrapToken},
		map[string]any{
			"organization_name": "Terminal Process",
			"email":             "owner@example.com",
			"password":          "terminal-process-owner-password",
		},
		http.StatusCreated,
		&bootstrap,
	)
	if bootstrap.AccessToken == "" {
		t.Fatal("bootstrap access token is missing")
	}
	bearer := map[string]string{"Authorization": "Bearer " + bootstrap.AccessToken}

	var host struct {
		ID string `json:"id"`
	}
	terminalProcessJSON(
		t,
		client,
		http.MethodPost,
		serverA.baseURL+"/api/v1/managed-hosts",
		bearer,
		map[string]any{
			"name":                       "Dual Server Host",
			"connection_mode":            "direct",
			"direct_ssh_ref":             "secret://dual-server",
			"direct_ssh_address":         sshFixture.address,
			"direct_ssh_user":            "owndock",
			"direct_ssh_host_key_sha256": sshFixture.hostKeySHA256,
		},
		http.StatusCreated,
		&host,
	)
	if host.ID == "" {
		t.Fatal("managed Host ID is missing")
	}
	policy := map[string]any{
		"enabled":                 true,
		"allowed_roles":           []string{"owner"},
		"environment_stages":      []string{},
		"runtime_target_ids":      []string{},
		"managed_host_ids":        []string{host.ID},
		"idle_timeout":            "5m",
		"maximum_duration":        "30m",
		"maximum_per_user":        3,
		"maximum_per_target":      3,
		"revocation_grace_period": "0s",
		"expected_version":        0,
	}
	var savedPolicy struct {
		Version uint64 `json:"version"`
	}
	terminalProcessJSON(
		t,
		client,
		http.MethodPut,
		serverB.baseURL+"/api/v1/terminal-policy",
		bearer,
		policy,
		http.StatusOK,
		&savedPolicy,
	)
	if savedPolicy.Version != 1 {
		t.Fatalf("terminal policy version = %d, want 1", savedPolicy.Version)
	}

	credentialA, cookieA := createTerminalProcessSession(
		t, client, serverA.baseURL, bearer, host.ID,
	)
	credentialB, cookieB := createTerminalProcessSession(
		t, client, serverB.baseURL, bearer, host.ID,
	)
	routes := map[string]terminalProcessBackend{
		credentialA.Session.ID: {name: "a", baseURL: serverA.baseURL},
		credentialB.Session.ID: {name: "b", baseURL: serverB.baseURL},
	}
	proxy := newTerminalProcessReverseProxy(t, routes, serverA.baseURL)
	defer proxy.Close()
	connectionA := dialTerminalProcessWSS(
		t, ctx, proxy.URL, credentialA.Session.ID, cookieA, "a", "terminal-a",
	)
	defer connectionA.CloseNow()
	connectionB := dialTerminalProcessWSS(
		t, ctx, proxy.URL, credentialB.Session.ID, cookieB, "b", "terminal-b",
	)
	defer connectionB.CloseNow()
	if sshFixture.connections.Load() != 2 {
		t.Fatalf("SSH connection count = %d, want 2", sshFixture.connections.Load())
	}
	raceCredential, raceCookie := createTerminalProcessSession(
		t, client, serverA.baseURL, bearer, host.ID,
	)
	raceTerminalProcessTicket(
		t,
		ctx,
		serverA.baseURL,
		serverB.baseURL,
		raceCredential.Session.ID,
		raceCookie,
	)
	if sshFixture.connections.Load() != 3 {
		t.Fatalf(
			"SSH connection count after ticket race = %d, want 3",
			sshFixture.connections.Load(),
		)
	}
	assertTerminalProcessSessionState(
		t,
		client,
		serverB.baseURL,
		bearer,
		raceCredential.Session.ID,
		"closed",
		"user_requested",
	)

	policy["enabled"] = false
	policy["expected_version"] = 1
	revokedAt := time.Now()
	terminalProcessJSON(
		t,
		client,
		http.MethodPut,
		proxy.URL+"/api/v1/terminal-policy",
		bearer,
		policy,
		http.StatusOK,
		nil,
	)
	assertTerminalProcessPermissionRevoked(t, ctx, connectionA)
	assertTerminalProcessPermissionRevoked(t, ctx, connectionB)
	if elapsed := time.Since(revokedAt); elapsed > 8*time.Second {
		t.Fatalf("dual Server policy revocation took %v, want <= 8s", elapsed)
	}
	assertTerminalProcessSessionClosed(
		t, client, serverB.baseURL, bearer, credentialA.Session.ID,
	)
	assertTerminalProcessSessionClosed(
		t, client, serverA.baseURL, bearer, credentialB.Session.ID,
	)

	serverA.stop(t)
	serverB.stop(t)
	for _, server := range []*terminalServerProcess{serverA, serverB} {
		server.assertLogExcludes(
			t,
			bootstrapToken,
			"terminal-process-owner-password",
			bootstrap.AccessToken,
			string(sshFixture.clientPrivateKeyPEM),
		)
	}
	sshFixture.assertNoError(t)
}

type terminalServerProcess struct {
	baseURL string
	command *exec.Cmd
	done    chan error
	logFile *os.File
	logPath string
	stopped bool
}

func startTerminalServerProcess(
	t *testing.T,
	binary, root, temporary, name, mongoURI, bootstrapToken string,
	sshPrivateKeyPEM []byte,
) *terminalServerProcess {
	t.Helper()
	address := unusedTCPAddress(t)
	configPath := filepath.Join(temporary, "config-"+name+".yaml")
	config := fmt.Sprintf(`server:
  http:
    address: %s
    timeout: 15s
    shutdown_timeout: 5s
product:
  enabled: true
security:
  bootstrap_token_env: OWNDOCK_TERMINAL_TEST_BOOTSTRAP_TOKEN
  ingress_source_limit: 100
  ingress_global_limit: 200
  ingress_rate_window: 1m
database:
  mongo:
    enabled: true
    uri_env: OWNDOCK_TERMINAL_TEST_MONGODB_URI
    database: owndock_terminal_process
    connect_timeout: 30s
    operation_timeout: 5s
`, address)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(temporary, "server-"+name+".log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "-conf", configPath)
	command.Dir = root
	command.Env = append(
		os.Environ(),
		"OWNDOCK_TERMINAL_TEST_BOOTSTRAP_TOKEN="+bootstrapToken,
		"OWNDOCK_TERMINAL_TEST_MONGODB_URI="+mongoURI,
		"OWNDOCK_MANAGED_HOST_SSH_DUAL_SERVER_PRIVATE_KEY_PEM="+string(sshPrivateKeyPEM),
	)
	command.Stdout = logFile
	command.Stderr = logFile
	if err := command.Start(); err != nil {
		_ = logFile.Close()
		t.Fatal(err)
	}
	process := &terminalServerProcess{
		baseURL: "http://" + address,
		command: command,
		done:    make(chan error, 1),
		logFile: logFile,
		logPath: logPath,
	}
	go func() {
		process.done <- command.Wait()
		close(process.done)
	}()
	t.Cleanup(func() {
		if !process.stopped && process.command.Process != nil {
			_ = process.command.Process.Kill()
			<-process.done
		}
		_ = process.logFile.Close()
	})
	waitForServerReady(t, process.baseURL, process.done, process.logPath)
	return process
}

func (p *terminalServerProcess) stop(t *testing.T) {
	t.Helper()
	if p.stopped {
		return
	}
	if err := p.command.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("stop Server: %v", err)
	}
	select {
	case err := <-p.done:
		if err != nil {
			logs, _ := os.ReadFile(p.logPath)
			t.Fatalf("Server exit: %v\n%s", err, logs)
		}
	case <-time.After(10 * time.Second):
		_ = p.command.Process.Kill()
		t.Fatal("Server did not stop within 10 seconds")
	}
	p.stopped = true
	if err := p.logFile.Close(); err != nil {
		t.Fatal(err)
	}
}

func (p *terminalServerProcess) assertLogExcludes(t *testing.T, secrets ...string) {
	t.Helper()
	logs, err := os.ReadFile(p.logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range secrets {
		if secret != "" && bytes.Contains(logs, []byte(secret)) {
			t.Fatalf("Server process log leaked a terminal fixture secret")
		}
	}
}

type terminalProcessSSHFixture struct {
	address             string
	hostKeySHA256       string
	clientPrivateKeyPEM []byte
	listener            net.Listener
	connections         atomic.Int32
	errors              chan error
}

func startTerminalSSHFixture(t *testing.T) *terminalProcessSSHFixture {
	t.Helper()
	hostSigner := terminalProcessSSHSigner(t)
	clientPrivateKeyPEM := terminalProcessSSHPrivateKeyPEM(t)
	clientSigner, err := ssh.ParsePrivateKey(clientPrivateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fixture := &terminalProcessSSHFixture{
		address:             listener.Addr().String(),
		hostKeySHA256:       ssh.FingerprintSHA256(hostSigner.PublicKey()),
		clientPrivateKeyPEM: clientPrivateKeyPEM,
		listener:            listener,
		errors:              make(chan error, 8),
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			fixture.connections.Add(1)
			go func() {
				if err := serveTerminalProcessSSH(
					connection,
					hostSigner,
					clientSigner.PublicKey(),
				); err != nil && !errors.Is(err, io.EOF) {
					fixture.errors <- err
				}
			}()
		}
	}()
	return fixture
}

func serveTerminalProcessSSH(
	connection net.Conn,
	hostSigner ssh.Signer,
	expectedClientKey ssh.PublicKey,
) error {
	defer connection.Close()
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(
			metadata ssh.ConnMetadata,
			key ssh.PublicKey,
		) (*ssh.Permissions, error) {
			if metadata.User() != "owndock" || key.Type() != expectedClientKey.Type() ||
				!bytes.Equal(key.Marshal(), expectedClientKey.Marshal()) {
				return nil, errors.New("unexpected SSH client identity")
			}
			return nil, nil
		},
	}
	config.AddHostKey(hostSigner)
	serverConnection, channels, requests, err := ssh.NewServerConn(connection, config)
	if err != nil {
		return err
	}
	defer serverConnection.Close()
	go ssh.DiscardRequests(requests)
	for channelRequest := range channels {
		if channelRequest.ChannelType() != "session" {
			_ = channelRequest.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		channel, channelRequests, err := channelRequest.Accept()
		if err != nil {
			return err
		}
		for request := range channelRequests {
			switch request.Type {
			case "pty-req", "window-change":
				_ = request.Reply(true, nil)
			case "shell":
				_ = request.Reply(true, nil)
				go func() { _, _ = io.Copy(channel, channel) }()
			case "signal":
				_ = request.Reply(true, nil)
				_ = channel.Close()
			}
		}
	}
	return nil
}

func terminalProcessSSHSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func terminalProcessSSHPrivateKeyPEM(t *testing.T) []byte {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
}

func (f *terminalProcessSSHFixture) assertNoError(t *testing.T) {
	t.Helper()
	select {
	case err := <-f.errors:
		t.Fatalf("SSH fixture error: %v", err)
	default:
	}
}

type terminalProcessCredential struct {
	Session struct {
		ID string `json:"id"`
	} `json:"session"`
}

func createTerminalProcessSession(
	t *testing.T,
	client *http.Client,
	baseURL string,
	headers map[string]string,
	hostID string,
) (terminalProcessCredential, *http.Cookie) {
	t.Helper()
	var credential terminalProcessCredential
	response := terminalProcessJSON(
		t,
		client,
		http.MethodPost,
		baseURL+"/api/v1/managed-hosts/"+hostID+"/terminal-sessions",
		headers,
		nil,
		http.StatusCreated,
		&credential,
	)
	if credential.Session.ID == "" {
		t.Fatal("terminal session ID is missing")
	}
	for _, cookie := range response.Cookies() {
		if cookie.Name == "__Secure-owndock_terminal_ticket" && cookie.Value != "" {
			return credential, cookie
		}
	}
	t.Fatal("terminal ticket cookie is missing")
	return terminalProcessCredential{}, nil
}

type terminalProcessBackend struct {
	name    string
	baseURL string
}

func newTerminalProcessReverseProxy(
	t *testing.T,
	routes map[string]terminalProcessBackend,
	defaultBaseURL string,
) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		backend := terminalProcessBackend{name: "a", baseURL: defaultBaseURL}
		for sessionID, candidate := range routes {
			if strings.Contains(request.URL.Path, "/"+sessionID+":connect") {
				backend = candidate
				break
			}
		}
		target, err := url.Parse(backend.baseURL)
		if err != nil {
			http.Error(writer, "invalid backend", http.StatusBadGateway)
			return
		}
		originalHost := request.Host
		proxy := httputil.NewSingleHostReverseProxy(target)
		director := proxy.Director
		proxy.Director = func(outbound *http.Request) {
			director(outbound)
			outbound.Host = originalHost
		}
		writer.Header().Set("X-OwnDock-Test-Backend", backend.name)
		proxy.ServeHTTP(writer, request)
	}))
}

func dialTerminalProcessWSS(
	t *testing.T,
	ctx context.Context,
	proxyURL, sessionID string,
	cookie *http.Cookie,
	expectedBackend, echo string,
) *websocket.Conn {
	t.Helper()
	connection, response, err := websocket.Dial(
		ctx,
		"ws"+strings.TrimPrefix(proxyURL, "http")+
			"/api/v1/terminal-sessions/"+sessionID+":connect",
		&websocket.DialOptions{
			Subprotocols: []string{terminalprotocol.Subprotocol},
			HTTPHeader: http.Header{
				"Origin": []string{proxyURL},
				"Cookie": []string{cookie.Name + "=" + cookie.Value},
			},
		},
	)
	if err != nil {
		t.Fatalf("dial terminal WSS: %v", err)
	}
	if response == nil || response.Header.Get("X-OwnDock-Test-Backend") != expectedBackend {
		connection.CloseNow()
		t.Fatalf("terminal WSS backend = %v, want %s", response, expectedBackend)
	}
	open, err := terminalprotocol.EncodeControl(
		terminalprotocol.Control{
			Version:  terminalprotocol.Version,
			Type:     terminalprotocol.TypeOpen,
			Sequence: 1,
			Columns:  100,
			Rows:     30,
		},
		terminalprotocol.DirectionClientToServer,
	)
	if err != nil {
		connection.CloseNow()
		t.Fatal(err)
	}
	if err := connection.Write(ctx, websocket.MessageText, open); err != nil {
		connection.CloseNow()
		t.Fatal(err)
	}
	messageType, payload, err := connection.Read(ctx)
	if err != nil || messageType != websocket.MessageText {
		connection.CloseNow()
		t.Fatalf("read terminal READY: type=%v payload=%q error=%v", messageType, payload, err)
	}
	ready, err := terminalprotocol.DecodeControl(
		payload,
		terminalprotocol.DirectionServerToClient,
	)
	if err != nil || ready.Type != terminalprotocol.TypeReady {
		connection.CloseNow()
		t.Fatalf("terminal READY = %+v, error=%v", ready, err)
	}
	if err := connection.Write(ctx, websocket.MessageBinary, []byte(echo)); err != nil {
		connection.CloseNow()
		t.Fatal(err)
	}
	messageType, payload, err = connection.Read(ctx)
	if err != nil || messageType != websocket.MessageBinary || string(payload) != echo {
		connection.CloseNow()
		t.Fatalf("terminal echo: type=%v payload=%q error=%v", messageType, payload, err)
	}
	return connection
}

type terminalProcessTicketRaceResult struct {
	connection *websocket.Conn
	ready      bool
	err        error
}

func raceTerminalProcessTicket(
	t *testing.T,
	ctx context.Context,
	serverA, serverB, sessionID string,
	cookie *http.Cookie,
) {
	t.Helper()
	connections := make([]*websocket.Conn, 0, 2)
	for _, baseURL := range []string{serverA, serverB} {
		connection, _, err := websocket.Dial(
			ctx,
			"ws"+strings.TrimPrefix(baseURL, "http")+
				"/api/v1/terminal-sessions/"+sessionID+":connect",
			&websocket.DialOptions{
				Subprotocols: []string{terminalprotocol.Subprotocol},
				HTTPHeader: http.Header{
					"Origin": []string{baseURL},
					"Cookie": []string{cookie.Name + "=" + cookie.Value},
				},
			},
		)
		if err != nil {
			t.Fatalf("dial ticket-race WSS: %v", err)
		}
		connections = append(connections, connection)
	}
	open, err := terminalprotocol.EncodeControl(
		terminalprotocol.Control{
			Version:  terminalprotocol.Version,
			Type:     terminalprotocol.TypeOpen,
			Sequence: 1,
			Columns:  100,
			Rows:     30,
		},
		terminalprotocol.DirectionClientToServer,
	)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan terminalProcessTicketRaceResult, len(connections))
	for _, connection := range connections {
		go func(connection *websocket.Conn) {
			<-start
			if err := connection.Write(ctx, websocket.MessageText, open); err != nil {
				results <- terminalProcessTicketRaceResult{connection: connection, err: err}
				return
			}
			messageType, payload, err := connection.Read(ctx)
			if err != nil {
				results <- terminalProcessTicketRaceResult{connection: connection, err: err}
				return
			}
			ready, decodeErr := terminalprotocol.DecodeControl(
				payload,
				terminalprotocol.DirectionServerToClient,
			)
			results <- terminalProcessTicketRaceResult{
				connection: connection,
				ready: messageType == websocket.MessageText &&
					decodeErr == nil && ready.Type == terminalprotocol.TypeReady,
				err: decodeErr,
			}
		}(connection)
	}
	close(start)
	var winner *websocket.Conn
	losers := 0
	for range connections {
		result := <-results
		if result.ready && result.err == nil {
			if winner != nil {
				t.Fatal("one-time terminal ticket opened more than one WSS")
			}
			winner = result.connection
			continue
		}
		if websocket.CloseStatus(result.err) != websocket.StatusPolicyViolation {
			t.Fatalf("ticket-race loser error = %v", result.err)
		}
		losers++
		_ = result.connection.CloseNow()
	}
	if winner == nil || losers != 1 {
		t.Fatalf("ticket-race result: winner=%t losers=%d", winner != nil, losers)
	}
	defer winner.CloseNow()
	if err := winner.Write(ctx, websocket.MessageBinary, []byte("ticket-winner")); err != nil {
		t.Fatal(err)
	}
	messageType, payload, err := winner.Read(ctx)
	if err != nil || messageType != websocket.MessageBinary || string(payload) != "ticket-winner" {
		t.Fatalf("ticket-race winner echo: type=%v payload=%q error=%v", messageType, payload, err)
	}
	closeMessage, err := terminalprotocol.EncodeControl(
		terminalprotocol.Control{
			Version:  terminalprotocol.Version,
			Type:     terminalprotocol.TypeClose,
			Sequence: 2,
		},
		terminalprotocol.DirectionClientToServer,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := winner.Write(ctx, websocket.MessageText, closeMessage); err != nil {
		t.Fatal(err)
	}
	if _, _, err := winner.Read(ctx); websocket.CloseStatus(err) != websocket.StatusNormalClosure {
		t.Fatalf("ticket-race winner close = %v", err)
	}
}

func assertTerminalProcessPermissionRevoked(
	t *testing.T,
	ctx context.Context,
	connection *websocket.Conn,
) {
	t.Helper()
	messageType, payload, err := connection.Read(ctx)
	if err != nil || messageType != websocket.MessageText {
		t.Fatalf("read terminal revocation: type=%v payload=%q error=%v", messageType, payload, err)
	}
	notice, err := terminalprotocol.DecodeControl(
		payload,
		terminalprotocol.DirectionServerToClient,
	)
	if err != nil || notice.Type != terminalprotocol.TypeError ||
		notice.Code != "terminal_permission_revoked" {
		t.Fatalf("terminal revocation notice = %+v, error=%v", notice, err)
	}
	_, _, err = connection.Read(ctx)
	if websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatalf("terminal revocation close = %v", err)
	}
}

func assertTerminalProcessSessionClosed(
	t *testing.T,
	client *http.Client,
	baseURL string,
	headers map[string]string,
	sessionID string,
) {
	assertTerminalProcessSessionState(
		t,
		client,
		baseURL,
		headers,
		sessionID,
		"closed",
		"permission_revoked",
	)
}

func assertTerminalProcessSessionState(
	t *testing.T,
	client *http.Client,
	baseURL string,
	headers map[string]string,
	sessionID, expectedStatus, expectedReason string,
) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var session struct {
			Status      string `json:"status"`
			CloseReason string `json:"close_reason"`
		}
		terminalProcessJSON(
			t,
			client,
			http.MethodGet,
			baseURL+"/api/v1/terminal-sessions/"+sessionID,
			headers,
			nil,
			http.StatusOK,
			&session,
		)
		if session.Status == expectedStatus && session.CloseReason == expectedReason {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf(
		"terminal session %s did not reach %s/%s",
		sessionID,
		expectedReason,
		expectedStatus,
	)
}

func terminalProcessJSON(
	t *testing.T,
	client *http.Client,
	method, target string,
	headers map[string]string,
	body any,
	expectedStatus int,
	result any,
) *http.Response {
	t.Helper()
	var payload []byte
	var err error
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request, err := http.NewRequestWithContext(
		t.Context(), method, target, bytes.NewReader(payload),
	)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != expectedStatus {
		t.Fatalf("%s %s status=%d want=%d body=%s", method, target, response.StatusCode, expectedStatus, responseBody)
	}
	if result != nil {
		if err := json.Unmarshal(responseBody, result); err != nil {
			t.Fatalf("decode %s %s response: %v body=%s", method, target, err, responseBody)
		}
	}
	return response
}
