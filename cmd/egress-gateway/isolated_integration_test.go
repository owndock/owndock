package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const pinnedEgressBusyBoxImage = "busybox:1.37.0@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0"

func TestIsolatedEgressGatewayDockerIntegration(t *testing.T) {
	if os.Getenv("OWNDOCK_RUN_ISOLATED_EGRESS_INTEGRATION") != "1" {
		t.Skip("set OWNDOCK_RUN_ISOLATED_EGRESS_INTEGRATION=1 to run the isolated egress integration")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("Docker CLI is unavailable")
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("the first release supports linux/amd64 and linux/arm64")
	}
	for _, scope := range []string{"evidence", "vulnerability-db"} {
		t.Run(scope, func(t *testing.T) { runIsolatedEgressGatewayDockerIntegration(t, scope) })
	}
}

func runIsolatedEgressGatewayDockerIntegration(t *testing.T, scope string) {
	t.Helper()
	root := t.TempDir()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	boundary := "owndock-" + scope + "-boundary-test-" + suffix
	uplink := "owndock-" + scope + "-uplink-test-" + suffix
	gateway := "owndock-" + scope + "-egress-test-" + suffix
	worker := "owndock-" + scope + "-workload-test-" + suffix
	target := "owndock-" + scope + "-target-test-" + suffix
	gatewayAlias := scope + "-egress-gateway"

	runEgressDocker(t, "network", "create", "--internal", boundary)
	t.Cleanup(func() { _ = egressDockerCommand("network", "rm", boundary).Run() })
	runEgressDocker(t, "network", "create", uplink)
	t.Cleanup(func() { _ = egressDockerCommand("network", "rm", uplink).Run() })
	runEgressDocker(t, "run", "--detach", "--name", target, "--network", uplink,
		"--network-alias", "allowed-egress", "--network-alias", "denied-egress",
		pinnedEgressBusyBoxImage, "sh", "-c",
		"mkdir -p /www && printf 'approved evidence dependency\\n' >/www/dependency && exec httpd -f -p 8080 -h /www")
	t.Cleanup(func() { _ = egressDockerCommand("rm", "--force", target).Run() })

	binary, config := isolatedEgressFixture(t, root, scope)
	runEgressDocker(t, "run", "--detach", "--name", gateway, "--network", boundary,
		"--network-alias", gatewayAlias, "--read-only", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16777216",
		"--volume", binary+":/usr/local/bin/owndock-egress-gateway:ro",
		"--volume", config+":/etc/owndock/config.yaml:ro", pinnedEgressBusyBoxImage,
		"/usr/local/bin/owndock-egress-gateway", "-scope", scope, "-conf", "/etc/owndock/config.yaml")
	t.Cleanup(func() { _ = egressDockerCommand("rm", "--force", gateway).Run() })
	runEgressDocker(t, "network", "connect", uplink, gateway)
	waitForIsolatedEgressGateway(t, gateway, scope)

	runEgressDocker(t, "run", "--detach", "--name", worker, "--network", boundary,
		"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		pinnedEgressBusyBoxImage, "sleep", "300")
	t.Cleanup(func() { _ = egressDockerCommand("rm", "--force", worker).Run() })

	proxy := "http://" + gatewayAlias + ":3128"
	output := runEgressDocker(t, "exec", worker, "sh", "-c",
		"http_proxy="+proxy+" wget -qO- http://allowed-egress:8080/dependency")
	if strings.TrimSpace(output) != "approved evidence dependency" {
		t.Fatalf("allowed destination response = %q", output)
	}
	assertEgressDockerFails(t, "denied destination", "exec", worker, "sh", "-c",
		"http_proxy="+proxy+" wget -T 2 -qO- http://denied-egress:8080/dependency?secret=must-not-reflect")

	targetIP := egressDockerAddress(t, target, uplink)
	assertEgressDockerFails(t, "raw TCP bypass", "exec", worker, "sh", "-c",
		"unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy NO_PROXY no_proxy; "+
			"wget -T 2 -qO- http://"+targetIP+":8080/dependency")
	assertEgressDockerFails(t, "metadata bypass", "exec", worker, "sh", "-c",
		"unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy NO_PROXY no_proxy; "+
			"wget -T 2 -qO- http://169.254.169.254/latest/meta-data")

	gatewayIP := egressDockerAddress(t, gateway, boundary)
	runEgressDocker(t, "network", "disconnect", boundary, gateway)
	assertEgressDockerFails(t, "gateway outage", "exec", worker, "sh", "-c",
		"http_proxy="+proxy+" wget -T 2 -qO- http://allowed-egress:8080/dependency")
	runEgressDocker(t, "network", "connect", "--ip", gatewayIP, "--alias", gatewayAlias, boundary, gateway)
	waitForIsolatedEgressGateway(t, gateway, scope)
	output = runEgressDocker(t, "exec", worker, "sh", "-c",
		"http_proxy="+proxy+" wget -qO- http://allowed-egress:8080/dependency")
	if strings.TrimSpace(output) != "approved evidence dependency" {
		t.Fatalf("recovered destination response = %q", output)
	}
	if logs := runEgressDocker(t, "logs", gateway); strings.Contains(logs, "must-not-reflect") {
		t.Fatal("egress gateway logs leaked a request secret")
	}
}

func isolatedEgressFixture(t *testing.T, root, scope string) (string, string) {
	t.Helper()
	projectRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "owndock-egress-gateway")
	command := exec.Command("go", "build", "-trimpath", "-o", binary, "./cmd/egress-gateway")
	command.Dir = projectRoot
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH,
		"GOCACHE=/tmp/owndock-go-cache")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build egress gateway fixture: %v\n%s", err, output)
	}
	configKey := map[string]string{
		"evidence": "evidence_egress_gateway", "vulnerability-db": "vulnerability_database_egress_gateway",
	}[scope]
	if configKey == "" {
		t.Fatalf("unsupported test scope %q", scope)
	}
	configPath := filepath.Join(root, scope+"-egress-gateway.yaml")
	config := `server:
  http:
    address: 127.0.0.1:8000
runtime:
  ` + configKey + `:
    enabled: true
    address: 0.0.0.0:3128
    dial_timeout: 10s
    idle_timeout: 2m
    maximum_connections: 8
    allowed_destinations:
      - authority: allowed-egress:8080
        allow_private: true
`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	return binary, configPath
}

func waitForIsolatedEgressGateway(t *testing.T, container, scope string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if egressDockerCommand("exec", container, "/usr/local/bin/owndock-egress-gateway",
			"-scope", scope, "-conf", "/etc/owndock/config.yaml", "-healthcheck").Run() == nil {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("%s egress gateway did not become ready:\n%s", scope, runEgressDocker(t, "logs", container))
}

func egressDockerAddress(t *testing.T, container, network string) string {
	t.Helper()
	format := "{{(index .NetworkSettings.Networks \"" + network + "\").IPAddress}}"
	address := strings.TrimSpace(runEgressDocker(t, "inspect", "--format", format, container))
	if address == "" {
		t.Fatalf("container %s has no address on %s", container, network)
	}
	return address
}

func assertEgressDockerFails(t *testing.T, name string, arguments ...string) {
	t.Helper()
	if output, err := egressDockerCommand(arguments...).CombinedOutput(); err == nil {
		t.Fatalf("%s unexpectedly succeeded: %s", name, output)
	}
}

func runEgressDocker(t *testing.T, arguments ...string) string {
	t.Helper()
	output, err := egressDockerCommand(arguments...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(arguments, " "), err, output)
	}
	return string(output)
}

func egressDockerCommand(arguments ...string) *exec.Cmd {
	command := exec.Command("docker", arguments...)
	command.Env = append(os.Environ(), "DOCKER_CLI_HINTS=false")
	return command
}
