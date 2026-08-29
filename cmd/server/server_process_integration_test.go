package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	testmongo "github.com/testcontainers/testcontainers-go/modules/mongodb"
)

const pinnedServerIngressMongoImage = "mongo:8.3.7-noble@sha256:8444a416f2fc991f15064df9f6ea31ee02877607a70fd352ea998e6dbb5714b3"

func TestServerProcessIngressDoesNotReflectSecrets(t *testing.T) {
	if os.Getenv("OWNDOCK_RUN_SERVER_INGRESS_INTEGRATION") != "1" {
		t.Skip("set OWNDOCK_RUN_SERVER_INGRESS_INTEGRATION=1 to run the Server ingress black-box test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("Docker CLI is unavailable")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	mongoContainer, err := testmongo.Run(ctx, pinnedServerIngressMongoImage, testmongo.WithReplicaSet("rs0"))
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

	root := repositoryRoot(t)
	temporary := t.TempDir()
	binary := filepath.Join(temporary, "owndock-server")
	build := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", binary, "./cmd/server")
	build.Dir = root
	build.Env = append(os.Environ(), "GOCACHE=/tmp/owndock-go-cache")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build Server binary: %v\n%s", err, output)
	}
	address := unusedTCPAddress(t)
	configPath := filepath.Join(temporary, "config.yaml")
	config := fmt.Sprintf(`server:
  http:
    address: %s
    timeout: 5s
    shutdown_timeout: 5s
product:
  enabled: true
security:
  bootstrap_token_env: OWNDOCK_INGRESS_TEST_BOOTSTRAP_TOKEN
  ingress_source_limit: 5
  ingress_global_limit: 5
  ingress_rate_window: 1m
database:
  mongo:
    enabled: true
    uri_env: OWNDOCK_INGRESS_TEST_MONGODB_URI
    database: owndock_ingress_blackbox
    connect_timeout: 30s
    operation_timeout: 5s
`, address)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	const (
		bootstrapSecret = "bootstrap-ingress-secret-7f7411e0"
		passwordSecret  = "password-ingress-secret-fcc74d09"
		requestSecret   = "request:ingress-secret-b81a6d26"
	)
	logPath := filepath.Join(temporary, "server.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	process := exec.Command(binary, "-conf", configPath)
	process.Dir = root
	process.Env = append(os.Environ(),
		"OWNDOCK_INGRESS_TEST_BOOTSTRAP_TOKEN="+bootstrapSecret,
		"OWNDOCK_INGRESS_TEST_MONGODB_URI="+mongoURI,
	)
	process.Stdout = logFile
	process.Stderr = logFile
	if err := process.Start(); err != nil {
		_ = logFile.Close()
		t.Fatal(err)
	}
	processDone := make(chan error, 1)
	go func() {
		processDone <- process.Wait()
		close(processDone)
	}()
	stopped := false
	t.Cleanup(func() {
		if !stopped && process.Process != nil {
			_ = process.Process.Kill()
			<-processDone
		}
		_ = logFile.Close()
	})
	baseURL := "http://" + address
	waitForServerReady(t, baseURL, processDone, logPath)

	client := &http.Client{Timeout: 10 * time.Second}
	assertSecretSafeResponse(t, client, http.MethodPost, baseURL+"/api/v1/auth/bootstrap",
		[]byte(`{"organization_name":"Ingress","email":"owner@example.com","password":"`+requestSecret+`"}`),
		map[string]string{"Content-Type": "application/json", "X-OwnDock-Bootstrap-Token": requestSecret},
		[]string{bootstrapSecret, requestSecret}, http.StatusForbidden)
	bootstrap := assertSecretSafeResponse(t, client, http.MethodPost, baseURL+"/api/v1/auth/bootstrap",
		[]byte(`{"organization_name":"Ingress","email":"owner@example.com","password":"`+passwordSecret+`"}`),
		map[string]string{"Content-Type": "application/json", "X-OwnDock-Bootstrap-Token": bootstrapSecret},
		[]string{bootstrapSecret, passwordSecret}, http.StatusCreated)
	var credentials struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(bootstrap, &credentials); err != nil || credentials.AccessToken == "" {
		t.Fatalf("decode bootstrap credentials: %v, body=%s", err, bootstrap)
	}
	assertSecretSafeResponse(t, client, http.MethodPost, baseURL+"/api/v1/auth/login",
		[]byte(`{"email":"owner@example.com","password":"`+requestSecret+`"}`),
		map[string]string{"Content-Type": "application/json", "X-Request-ID": requestSecret},
		[]string{bootstrapSecret, passwordSecret, requestSecret, credentials.AccessToken}, http.StatusUnauthorized)
	assertSecretSafeResponse(t, client, http.MethodGet, baseURL+"/api/v1/projects", nil,
		map[string]string{"Authorization": "Bearer " + credentials.AccessToken + requestSecret},
		[]string{bootstrapSecret, passwordSecret, requestSecret, credentials.AccessToken}, http.StatusUnauthorized)
	assertSecretSafeResponse(t, client, http.MethodPost, baseURL+"/api/v1/auth/login",
		[]byte(`{"email":"`+requestSecret), map[string]string{"Content-Type": "application/json"},
		[]string{bootstrapSecret, passwordSecret, requestSecret, credentials.AccessToken}, http.StatusBadRequest)
	assertSecretSafeResponse(t, client, http.MethodGet, baseURL+"/api/v1/projects", nil,
		map[string]string{"Authorization": "Bearer " + credentials.AccessToken},
		[]string{bootstrapSecret, passwordSecret, requestSecret, credentials.AccessToken}, http.StatusTooManyRequests)

	if err := process.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("stop Server: %v", err)
	}
	select {
	case err := <-processDone:
		if err != nil {
			t.Fatalf("Server exit: %v", err)
		}
	case <-time.After(10 * time.Second):
		_ = process.Process.Kill()
		t.Fatal("Server did not stop within 10 seconds")
	}
	stopped = true
	if err := logFile.Close(); err != nil {
		t.Fatal(err)
	}
	logs, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{bootstrapSecret, passwordSecret, requestSecret, credentials.AccessToken} {
		if bytes.Contains(logs, []byte(secret)) {
			t.Fatalf("Server process log leaked secret %q", secret)
		}
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func unusedTCPAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func waitForServerReady(t *testing.T, baseURL string, processDone <-chan error, logPath string) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		response, err := (&http.Client{Timeout: time.Second}).Get(baseURL + "/readyz")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		select {
		case err := <-processDone:
			logs, _ := os.ReadFile(logPath)
			t.Fatalf("Server exited before readiness: %v\n%s", err, logs)
		case <-time.After(200 * time.Millisecond):
		}
	}
	logs, _ := os.ReadFile(logPath)
	t.Fatalf("Server did not become ready\n%s", logs)
}

func assertSecretSafeResponse(t *testing.T, client *http.Client, method, url string, body []byte,
	headers map[string]string, secrets []string, expectedStatus int) []byte {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
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
		t.Fatalf("%s %s status=%d want=%d body=%s", method, url, response.StatusCode, expectedStatus, responseBody)
	}
	if response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("%s %s cache headers = %v", method, url, response.Header)
	}
	wire := append([]byte(fmt.Sprint(response.Header)), responseBody...)
	for _, secret := range secrets {
		if secret != "" && bytes.Contains(wire, []byte(secret)) {
			t.Fatalf("%s %s reflected secret %q", method, url, secret)
		}
	}
	return responseBody
}
