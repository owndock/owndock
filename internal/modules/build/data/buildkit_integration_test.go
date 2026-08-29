package data

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	controlplanebiz "github.com/owndock/owndock/internal/modules/controlplane/biz"
	controlplanedata "github.com/owndock/owndock/internal/modules/controlplane/data"
	platformconfig "github.com/owndock/owndock/internal/platform/config"
	"github.com/owndock/owndock/internal/platform/migration"
	platformmongo "github.com/owndock/owndock/internal/platform/mongo"
	"github.com/testcontainers/testcontainers-go"
	testmongo "github.com/testcontainers/testcontainers-go/modules/mongodb"
	"golang.org/x/crypto/bcrypt"

	"github.com/owndock/owndock/internal/modules/build/biz"
)

const (
	pinnedRegistryIntegrationImage = "registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"
	pinnedBusyBoxIntegrationImage  = "busybox:1.37.0@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0"
	pinnedMongoIntegrationImage    = "mongo:8.3.7-noble@sha256:8444a416f2fc991f15064df9f6ea31ee02877607a70fd352ea998e6dbb5714b3"
)

type copyingRegistrySecretResolver struct{ value string }

func (r copyingRegistrySecretResolver) ResolveRegistryPassword(context.Context, biz.BuildRegistryCredential) ([]byte, error) {
	return []byte(r.value), nil
}

func TestBuildKitRootlessMTLSRegistryIntegration(t *testing.T) {
	if os.Getenv("OWNDOCK_RUN_BUILDKIT_INTEGRATION") != "1" {
		t.Skip("set OWNDOCK_RUN_BUILDKIT_INTEGRATION=1 to run the rootless BuildKit integration")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("Docker CLI is unavailable")
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("the first release supports linux/amd64 and linux/arm64")
	}
	root := t.TempDir()
	materials := createBuildIntegrationPKI(t, root)
	password := "integration-registry-password"
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	authDirectory := filepath.Join(root, "auth")
	if err := os.Mkdir(authDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(authDirectory, "htpasswd"),
		[]byte("builder:"+string(passwordHash)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	buildKitConfig := filepath.Join(root, "buildkitd.toml")
	config := []byte("debug = false\n[registry.\"registry:5000\"]\n  ca = [\"/certs/ca.pem\"]\n" +
		"[worker.oci]\n  enabled = true\n  rootless = true\n  snapshotter = \"native\"\n" +
		"  gc = true\n  max-parallelism = 2\n  maxUsedSpace = \"4GB\"\n" +
		"  [[worker.oci.gcpolicy]]\n    all = true\n    reservedSpace = \"512MB\"\n    maxUsedSpace = \"4GB\"\n")
	if err := os.WriteFile(buildKitConfig, config, 0o600); err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	networkName := "owndock-build-boundary-test-" + suffix
	uplinkName := "owndock-build-uplink-test-" + suffix
	registryName := "owndock-registry-test-" + suffix
	buildKitName := "owndock-buildkit-test-" + suffix
	egressName := "owndock-build-egress-test-" + suffix
	targetName := "owndock-build-target-test-" + suffix
	relayName := "owndock-build-control-relay-test-" + suffix
	runDocker(t, "network", "create", "--internal", networkName)
	t.Cleanup(func() { _ = dockerCommand("network", "rm", networkName) })
	runDocker(t, "network", "create", uplinkName)
	t.Cleanup(func() { _ = dockerCommand("network", "rm", uplinkName) })
	runDocker(t, "run", "--detach", "--name", registryName, "--network", networkName,
		"--network-alias", "registry", "--publish", "127.0.0.1::5000",
		"--env", "REGISTRY_HTTP_TLS_CERTIFICATE=/certs/registry-cert.pem",
		"--env", "REGISTRY_HTTP_TLS_KEY=/certs/registry-key.pem",
		"--env", "REGISTRY_AUTH=htpasswd", "--env", "REGISTRY_AUTH_HTPASSWD_REALM=OwnDock Test",
		"--env", "REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd",
		"--volume", materials.directory+":/certs:ro", "--volume", authDirectory+":/auth:ro",
		pinnedRegistryIntegrationImage)
	t.Cleanup(func() { _ = dockerCommand("rm", "--force", registryName) })
	runDocker(t, "run", "--detach", "--name", targetName, "--network", uplinkName,
		"--network-alias", "allowed-egress", "--network-alias", "denied-egress",
		pinnedBusyBoxIntegrationImage, "sh", "-c",
		"mkdir -p /www && printf 'approved dependency\\n' > /www/dependency && exec httpd -f -p 8080 -h /www")
	t.Cleanup(func() { _ = dockerCommand("rm", "--force", targetName) })
	egressBinary, egressConfig := buildEgressGatewayFixture(t, root)
	runDocker(t, "run", "--detach", "--name", egressName, "--network", networkName,
		"--network-alias", "build-egress-gateway", "--read-only", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16777216",
		"--volume", egressBinary+":/usr/local/bin/owndock-build-egress-gateway:ro",
		"--volume", egressConfig+":/etc/owndock/config.yaml:ro", pinnedBusyBoxIntegrationImage,
		"/usr/local/bin/owndock-build-egress-gateway", "-conf", "/etc/owndock/config.yaml")
	t.Cleanup(func() { _ = dockerCommand("rm", "--force", egressName) })
	runDocker(t, "network", "connect", uplinkName, egressName)
	waitForBuildEgressGateway(t, egressName)
	egressProxyURL := "http://" + dockerNetworkAddress(t, egressName, networkName) + ":3128"
	runDocker(t, "run", "--detach", "--name", buildKitName, "--network", networkName,
		"--network-alias", "buildkit", "--security-opt", "seccomp=unconfined",
		"--security-opt", "apparmor=unconfined", "--security-opt", "systempaths=unconfined",
		"--tmpfs", "/run/user/1000:rw,nosuid,nodev,size=67108864,mode=0700,uid=1000,gid=1000",
		"--tmpfs", "/home/user/.local/tmp:rw,noexec,nosuid,nodev,size=536870912,mode=0700,uid=1000,gid=1000",
		"--tmpfs", "/home/user/.local/share/buildkit:rw,exec,nosuid,nodev,size=536870912,mode=0700,uid=1000,gid=1000",
		"--env", "HTTP_PROXY="+egressProxyURL, "--env", "HTTPS_PROXY="+egressProxyURL,
		"--env", "http_proxy="+egressProxyURL, "--env", "https_proxy="+egressProxyURL,
		"--env", "NO_PROXY=", "--env", "no_proxy=",
		"--volume", materials.directory+":/certs:ro", "--volume", buildKitConfig+":/etc/buildkit/buildkitd.toml:ro",
		PinnedBuildKitImage, "--config=/etc/buildkit/buildkitd.toml", "--addr=tcp://0.0.0.0:1234",
		"--tlscacert=/certs/ca.pem", "--tlscert=/certs/buildkit-cert.pem", "--tlskey=/certs/buildkit-key.pem")
	t.Cleanup(func() { _ = dockerCommand("rm", "--force", buildKitName) })
	runDocker(t, "run", "--detach", "--name", relayName, "--network", uplinkName,
		"--publish", "127.0.0.1::1234", "--publish", "127.0.0.1::5000", pinnedBusyBoxIntegrationImage,
		"sh", "-c", "nc -lk -p 1234 -e nc buildkit 1234 & exec nc -lk -p 5000 -e nc registry 5000")
	t.Cleanup(func() { _ = dockerCommand("rm", "--force", relayName) })
	runDocker(t, "network", "connect", networkName, relayName)
	buildKitPort := dockerPort(t, relayName, "1234/tcp")
	registryPort := dockerPort(t, relayName, "5000/tcp")
	options := BuildKitOptions{
		Endpoint: "tcp://127.0.0.1:" + buildKitPort, ServerName: "buildkit",
		CACertFile: materials.caFile, ClientCertFile: materials.workerCert,
		ClientKeyFile: materials.workerKey, EgressProxyURL: egressProxyURL,
	}
	gateway := waitForBuildKitGateway(t, options, copyingRegistrySecretResolver{value: password})
	workspace := filepath.Join(root, "success")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "Dockerfile"),
		[]byte("FROM scratch\nCOPY hello /hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "hello"), []byte("hello from OwnDock\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	request := integrationBuildRequest(workspace, "build-success", password)
	var safeBuildLogs []string
	request.LogSink = func(_ context.Context, _ biz.BuildLogStage, message string) {
		safeBuildLogs = append(safeBuildLogs, message)
	}
	output, err := gateway.Build(t.Context(), request)
	if err != nil {
		t.Fatalf("rootless BuildKit push failed: %v\n%s", err, dockerLogs(buildKitName))
	}
	if !strings.HasPrefix(output.ImageDigest, "registry:5000/team/api@sha256:") {
		t.Fatalf("pushed image digest = %q", output.ImageDigest)
	}
	if len(safeBuildLogs) == 0 || strings.Contains(strings.Join(safeBuildLogs, "\n"), password) {
		t.Fatalf("unsafe or empty Build logs = %#v", safeBuildLogs)
	}
	verifyRegistryManifest(t, registryPort, materials.caPool, password,
		"team/api", strings.TrimPrefix(buildImageName("registry:5000/team/api", request.BuildID), "registry:5000/team/api:"),
		strings.TrimPrefix(output.ImageDigest, "registry:5000/team/api@"))
	assertRegistryArtifactSecretFree(t, registryPort, materials.caPool, password,
		"team/api", strings.TrimPrefix(output.ImageDigest, "registry:5000/team/api@"), password)
	if logs := dockerLogs(buildKitName) + "\n" + dockerLogs(registryName); strings.Contains(logs, password) {
		t.Fatal("Registry credential leaked into BuildKit or Registry container logs")
	}
	assertDockerContainerExportSecretFree(t, buildKitName, password)
	assertDockerContainerExportSecretFree(t, registryName, password)
	if err := dockerCommand("exec", buildKitName, "buildctl", "--addr=tcp://127.0.0.1:1234",
		"--tlsservername=buildkit", "--tlscacert=/certs/ca.pem", "--tlscert=/certs/worker-cert.pem",
		"--tlskey=/certs/worker-key.pem", "du"); err != nil {
		t.Fatalf("BuildKit cache inspection failed: %v", err)
	}

	badAuthGateway := waitForBuildKitGateway(t, options,
		copyingRegistrySecretResolver{value: "incorrect-registry-password"})
	badAuthRequest := integrationBuildRequest(workspace, "build-bad-auth", password)
	if _, err := badAuthGateway.Build(t.Context(), badAuthRequest); err != biz.ErrRegistryAuthentication {
		t.Fatalf("wrong Registry credential error = %v", err)
	}

	for _, attack := range []struct {
		name       string
		dockerfile string
	}{
		{name: "host-network", dockerfile: "FROM " + pinnedBusyBoxIntegrationImage + "\nRUN --network=host true\n"},
		{name: "insecure-security", dockerfile: "FROM " + pinnedBusyBoxIntegrationImage + "\nRUN --security=insecure true\n"},
	} {
		t.Run("reject-malicious-dockerfile-"+attack.name, func(t *testing.T) {
			attackWorkspace := filepath.Join(root, "attack-"+attack.name)
			if err := os.Mkdir(attackWorkspace, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(attackWorkspace, "Dockerfile"), []byte(attack.dockerfile), 0o600); err != nil {
				t.Fatal(err)
			}
			attackRequest := integrationBuildRequest(attackWorkspace, "build-attack-"+attack.name, password)
			var logs []string
			attackRequest.LogSink = func(_ context.Context, _ biz.BuildLogStage, message string) {
				logs = append(logs, message)
			}
			if _, err := gateway.Build(t.Context(), attackRequest); err != biz.ErrBuildExecutionFailed {
				t.Fatalf("malicious Dockerfile error = %v", err)
			}
			if strings.Contains(strings.Join(logs, "\n"), password) {
				t.Fatal("Registry credential leaked while rejecting a malicious Dockerfile")
			}
			assertRegistryManifestMissing(t, registryPort, materials.caPool, password, "team/api",
				strings.TrimPrefix(buildImageName("registry:5000/team/api", attackRequest.BuildID), "registry:5000/team/api:"))
		})
	}
	verifyIsolatedBuildEgress(t, root, gateway, egressName, targetName, networkName,
		registryPort, materials.caPool, password)
	pruneBuildKitIntegrationCache(t, buildKitName)
	networkWorkspace := filepath.Join(root, "network-recovery")
	if err := os.Mkdir(networkWorkspace, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(networkWorkspace, "Dockerfile"),
		[]byte("FROM scratch\nCOPY hello /hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(networkWorkspace, "hello"), []byte("recover after network partition\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	networkRequest := integrationBuildRequest(networkWorkspace, "build-network-recovery", password)
	runDocker(t, "network", "disconnect", networkName, buildKitName)
	partitionContext, partitionCancel := context.WithTimeout(t.Context(), 5*time.Second)
	_, partitionErr := gateway.Build(partitionContext, networkRequest)
	partitionCancel()
	if partitionErr == nil || (!errors.Is(partitionErr, biz.ErrBuildKitUnavailable) &&
		!errors.Is(partitionErr, biz.ErrRegistryPushFailed) &&
		!errors.Is(partitionErr, biz.ErrBuildExecutionFailed) &&
		!errors.Is(partitionErr, context.DeadlineExceeded)) {
		t.Fatalf("network partition error = %v", partitionErr)
	}
	runDocker(t, "network", "connect", "--alias", "buildkit", networkName, buildKitName)
	recoveredGateway := waitForBuildKitGateway(t, options, copyingRegistrySecretResolver{value: password})
	recovered, err := recoveredGateway.Build(t.Context(), networkRequest)
	if err != nil || !strings.HasPrefix(recovered.ImageDigest, "registry:5000/team/api@sha256:") {
		t.Fatalf("network recovery Build() = %+v, %v", recovered, err)
	}

	cancelWorkspace := filepath.Join(root, "cancel")
	if err := os.Mkdir(cancelWorkspace, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cancelWorkspace, "Dockerfile"), []byte(
		"FROM "+pinnedBusyBoxIntegrationImage+"\nRUN sleep 30\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cancelGateway := waitForBuildKitGateway(t, options, copyingRegistrySecretResolver{value: password})
	cancelContext, cancel := context.WithTimeout(t.Context(), 1500*time.Millisecond)
	defer cancel()
	cancelRequest := integrationBuildRequest(cancelWorkspace, "build-cancel", password)
	if _, err := cancelGateway.Build(cancelContext, cancelRequest); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled Build() error = %v", err)
	}
	verifyBuildWorkerBinarySIGKILLDuringRealBuild(
		t, root, materials, options, networkName, registryName, buildKitName, registryPort, password,
	)
	verifyBuildKitCacheHardQuotaExhaustion(
		t, root, gateway, buildKitName, registryPort, materials.caPool, password,
	)
	assertDockerPathSecretFreeDeep(t, buildKitName, "/home/user/.local/share/buildkit", password)
}

func verifyIsolatedBuildEgress(t *testing.T, root string, gateway *BuildKitGateway,
	egressContainer, targetContainer, boundaryNetwork, registryPort string,
	roots *x509.CertPool, password string) {
	t.Helper()
	targetIP := dockerNetworkAddress(t, targetContainer, "")
	for _, test := range []struct {
		name       string
		dockerfile string
		wantError  bool
	}{
		{
			name: "allowed-through-gateway",
			dockerfile: "FROM " + pinnedBusyBoxIntegrationImage + "\n" +
				"RUN wget -q -O /dependency http://allowed-egress:8080/dependency?allowed=1 && " +
				"grep -q 'approved dependency' /dependency\n",
		},
		{
			name: "denied-destination",
			dockerfile: "FROM " + pinnedBusyBoxIntegrationImage + "\n" +
				"RUN wget -q -O /dependency http://denied-egress:8080/dependency?secret=must-not-reflect\n",
			wantError: true,
		},
		{
			name: "raw-tcp-bypass",
			dockerfile: "FROM " + pinnedBusyBoxIntegrationImage + "\n" +
				"RUN unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy NO_PROXY no_proxy; " +
				"! wget -T 2 -q -O- http://" + targetIP + ":8080/dependency\n",
		},
		{
			name: "metadata-bypass",
			dockerfile: "FROM " + pinnedBusyBoxIntegrationImage + "\n" +
				"RUN unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy NO_PROXY no_proxy; " +
				"! wget -T 2 -q -O- http://169.254.169.254/latest/meta-data\n",
		},
	} {
		t.Run("build-egress-"+test.name, func(t *testing.T) {
			request := writeIntegrationDockerfile(t, root, "egress-"+test.name, test.dockerfile, password)
			var logs []string
			request.LogSink = func(_ context.Context, _ biz.BuildLogStage, message string) {
				logs = append(logs, message)
			}
			output, err := gateway.Build(t.Context(), request)
			if test.wantError {
				if !errors.Is(err, biz.ErrBuildNetworkDenied) {
					t.Fatalf("denied Build() error = %v\nBuild logs:\n%s",
						err, strings.Join(logs, "\n"))
				}
				assertRegistryManifestMissing(t, registryPort, roots, password, "team/api",
					strings.TrimPrefix(buildImageName("registry:5000/team/api", request.BuildID), "registry:5000/team/api:"))
				return
			}
			if err != nil || !strings.HasPrefix(output.ImageDigest, "registry:5000/team/api@sha256:") {
				t.Fatalf("Build() = %+v/%v\nBuild logs:\n%s\nGateway logs:\n%s",
					output, err, strings.Join(logs, "\n"), dockerLogs(egressContainer))
			}
		})
	}

	egressBoundaryIP := dockerNetworkAddress(t, egressContainer, boundaryNetwork)
	runDocker(t, "network", "disconnect", boundaryNetwork, egressContainer)
	unavailable := writeIntegrationDockerfile(t, root, "egress-gateway-unavailable",
		"FROM "+pinnedBusyBoxIntegrationImage+"\nRUN wget -T 2 -q -O /dependency http://allowed-egress:8080/dependency?outage=1\n",
		password)
	if _, err := gateway.Build(t.Context(), unavailable); !errors.Is(err, biz.ErrBuildExecutionFailed) {
		t.Fatalf("unavailable egress gateway error = %v", err)
	}
	assertRegistryManifestMissing(t, registryPort, roots, password, "team/api",
		strings.TrimPrefix(buildImageName("registry:5000/team/api", unavailable.BuildID), "registry:5000/team/api:"))
	runDocker(t, "network", "connect", "--ip", egressBoundaryIP,
		"--alias", "build-egress-gateway", boundaryNetwork, egressContainer)
	waitForBuildEgressGateway(t, egressContainer)
	recovered := writeIntegrationDockerfile(t, root, "egress-gateway-recovered",
		"FROM "+pinnedBusyBoxIntegrationImage+"\nRUN wget -q -O /dependency http://allowed-egress:8080/dependency?recovered=1\n",
		password)
	if output, err := gateway.Build(t.Context(), recovered); err != nil ||
		!strings.HasPrefix(output.ImageDigest, "registry:5000/team/api@sha256:") {
		t.Fatalf("Build after egress gateway recovery = %+v/%v", output, err)
	}
	if logs := dockerLogs(egressContainer); strings.Contains(logs, "must-not-reflect") || strings.Contains(logs, password) {
		t.Fatal("Build egress gateway logs leaked request or Registry secret")
	}
}

func writeIntegrationDockerfile(t *testing.T, root, name, dockerfile, password string) biz.BuildExecutionRequest {
	t.Helper()
	workspace := filepath.Join(root, name)
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "Dockerfile"), []byte(dockerfile), 0o600); err != nil {
		t.Fatal(err)
	}
	return integrationBuildRequest(workspace, "build-"+name, password)
}

func dockerNetworkAddress(t *testing.T, container, network string) string {
	t.Helper()
	format := "{{range .NetworkSettings.Networks}}{{if .IPAddress}}{{.IPAddress}}{{end}}{{end}}"
	if network != "" {
		format = "{{(index .NetworkSettings.Networks " + strconv.Quote(network) + ").IPAddress}}"
	}
	command := exec.Command("docker", "inspect", "--format", format, container)
	output, err := command.CombinedOutput()
	if err != nil || net.ParseIP(strings.TrimSpace(string(output))) == nil {
		t.Fatalf("inspect container network address: %v: %s", err, output)
	}
	return strings.TrimSpace(string(output))
}

func verifyBuildKitCacheHardQuotaExhaustion(t *testing.T, root string, gateway *BuildKitGateway,
	buildKitName, registryPort string, roots *x509.CertPool, password string) {
	t.Helper()
	workspace := filepath.Join(root, "buildkit-cache-quota")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "Dockerfile"),
		[]byte("FROM scratch\nCOPY payload /payload\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "payload"), []byte("quota recovery\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const quotaFill = "/home/user/.local/share/buildkit/.owndock-quota-fill"
	if err := dockerCommand("exec", buildKitName, "dd", "if=/dev/zero", "of="+quotaFill,
		"bs=1048576", "count=1024"); err == nil {
		t.Fatal("BuildKit cache tmpfs accepted data beyond its 512 MiB hard quota")
	}
	failed := integrationBuildRequest(workspace, "build-cache-quota-exhausted", password)
	if _, err := gateway.Build(t.Context(), failed); !errors.Is(err, biz.ErrBuildResourceLimit) {
		t.Fatalf("BuildKit cache hard-quota error = %v", err)
	}
	assertRegistryManifestMissing(t, registryPort, roots, password, "team/api",
		strings.TrimPrefix(buildImageName("registry:5000/team/api", failed.BuildID), "registry:5000/team/api:"))
	runDocker(t, "exec", buildKitName, "rm", "-f", quotaFill)
	pruneBuildKitIntegrationCache(t, buildKitName)
	recovered := integrationBuildRequest(workspace, "build-after-cache-quota", password)
	var recoveredLogs []string
	recovered.LogSink = func(_ context.Context, _ biz.BuildLogStage, message string) {
		recoveredLogs = append(recoveredLogs, message)
	}
	output, err := gateway.Build(t.Context(), recovered)
	if err != nil || !strings.HasPrefix(output.ImageDigest, "registry:5000/team/api@sha256:") {
		t.Fatalf("Build after cache quota cleanup = %+v/%v\nBuild logs:\n%s\nBuildKit logs:\n%s",
			output, err, strings.Join(recoveredLogs, "\n"), dockerLogs(buildKitName))
	}
	verifyRegistryManifest(t, registryPort, roots, password, "team/api",
		strings.TrimPrefix(buildImageName("registry:5000/team/api", recovered.BuildID), "registry:5000/team/api:"),
		strings.TrimPrefix(output.ImageDigest, "registry:5000/team/api@"))
}

func pruneBuildKitIntegrationCache(t *testing.T, buildKitName string) {
	t.Helper()
	runDocker(t, "exec", buildKitName, "buildctl", "--addr=tcp://127.0.0.1:1234",
		"--tlsservername=buildkit", "--tlscacert=/certs/ca.pem", "--tlscert=/certs/worker-cert.pem",
		"--tlskey=/certs/worker-key.pem", "prune", "--all")
}

type buildIntegrationPKI struct {
	directory  string
	caFile     string
	workerCert string
	workerKey  string
	caPool     *x509.CertPool
}

func createBuildIntegrationPKI(t *testing.T, root string) buildIntegrationPKI {
	t.Helper()
	directory := filepath.Join(root, "certs")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "OwnDock Build Integration CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caFile := filepath.Join(directory, "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	issueIntegrationCertificate(t, directory, "buildkit", "buildkit", []string{"buildkit"},
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, ca, caKey, 2)
	issueIntegrationCertificate(t, directory, "worker", "worker", nil,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, ca, caKey, 3)
	issueIntegrationCertificate(t, directory, "registry", "registry", []string{"registry"},
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, ca, caKey, 4)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return buildIntegrationPKI{
		directory: directory, caFile: caFile, caPool: pool,
		workerCert: filepath.Join(directory, "worker-cert.pem"),
		workerKey:  filepath.Join(directory, "worker-key.pem"),
	}
}

func issueIntegrationCertificate(t *testing.T, directory, name, commonName string, dnsNames []string,
	usage []x509.ExtKeyUsage, ca *x509.Certificate, caKey *ecdsa.PrivateKey, serial int64) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: commonName}, DNSNames: dnsNames,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usage,
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, name+"-cert.pem"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, name+"-key.pem"),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func integrationBuildRequest(workspace, buildID, _ string) biz.BuildExecutionRequest {
	platform := biz.BuildPlatformLinuxAMD64
	if runtime.GOARCH == "arm64" {
		platform = biz.BuildPlatformLinuxARM64
	}
	return biz.BuildExecutionRequest{
		BuildID: buildID, ProjectID: "project-1", Generation: 1, Workspace: workspace,
		Configuration: biz.BuildConfigurationSnapshot{
			ConfigurationID: "configuration-1", ConfigurationVersion: 1, SourceRepositoryID: "source-1",
			DockerfilePath: "Dockerfile", ContextPath: ".", RegistryCredentialID: "registry-1",
			ImageRepository: "registry:5000/team/api", TargetPlatform: platform, TimeoutSeconds: 120,
			Resources: biz.BuildResources{CPUMilli: 2000, MemoryBytes: 2 * 1024 * 1024 * 1024, DiskBytes: 10 * 1024 * 1024 * 1024},
		},
		Credential: biz.BuildRegistryCredential{
			ID: "registry-1", ProjectID: "project-1", Server: "registry:5000",
			Username: "builder", PasswordRef: "secret://integration",
		},
	}
}

func waitForBuildKitGateway(t *testing.T, options BuildKitOptions,
	resolver biz.RegistrySecretResolver) *BuildKitGateway {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		attemptContext, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		gateway, err := NewBuildKitGateway(attemptContext, resolver, options)
		cancel()
		if err == nil {
			return gateway
		}
		lastErr = err
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("BuildKit did not become ready: %v", lastErr)
	return nil
}

func buildEgressGatewayFixture(t *testing.T, root string) (string, string) {
	t.Helper()
	projectRoot, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "owndock-build-egress-gateway")
	command := exec.Command("go", "build", "-trimpath", "-o", binary, "./cmd/build-egress-gateway")
	command.Dir = projectRoot
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH,
		"GOCACHE=/tmp/owndock-go-cache")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build egress gateway fixture: %v\n%s", err, output)
	}
	configPath := filepath.Join(root, "build-egress-gateway.yaml")
	config := `server:
  http:
    address: 127.0.0.1:8000
runtime:
  build_egress_gateway:
    enabled: true
    address: 0.0.0.0:3128
    dial_timeout: 10s
    idle_timeout: 2m
    maximum_connections: 128
    allowed_destinations:
      - authority: registry:5000
        allow_private: true
      - authority: allowed-egress:8080
        allow_private: true
      - authority: docker.io:443
      - authority: registry-1.docker.io:443
      - authority: auth.docker.io:443
      - authority: production.cloudflare.docker.com:443
      - authority: production.cloudfront.docker.com:443
`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	return binary, configPath
}

func waitForBuildEgressGateway(t *testing.T, containerName string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if dockerCommand("exec", containerName, "/usr/local/bin/owndock-build-egress-gateway",
			"-conf", "/etc/owndock/config.yaml", "-healthcheck") == nil {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("Build egress gateway did not become ready:\n%s", dockerLogs(containerName))
}

func verifyBuildWorkerBinarySIGKILLDuringRealBuild(t *testing.T, root string,
	materials buildIntegrationPKI, options BuildKitOptions, networkName, registryName,
	buildKitName, registryPort, password string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	mongoContainer, err := testmongo.Run(ctx, pinnedMongoIntegrationImage, testmongo.WithReplicaSet("rs0"))
	if err != nil {
		t.Fatalf("start Build Worker MongoDB fixture: %v", err)
	}
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if err := testcontainers.TerminateContainer(
			mongoContainer, testcontainers.StopContext(cleanupContext),
		); err != nil {
			t.Errorf("terminate Build Worker MongoDB fixture: %v", err)
		}
	})
	mongoURI, err := mongoContainer.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("Build Worker MongoDB connection string: %v", err)
	}
	separator := "?"
	if strings.Contains(mongoURI, "?") {
		separator = "&"
	}
	mongoURI += separator + "directConnection=true"
	const mongoURIEnvironment = "OWNDOCK_BUILD_PROCESS_MONGODB_URI"
	t.Setenv(mongoURIEnvironment, mongoURI)
	databaseName := fmt.Sprintf("owndock_build_process_%d", time.Now().UnixNano())
	client, err := platformmongo.Open(ctx, platformconfig.Mongo{
		Enabled: true, URIEnv: mongoURIEnvironment, Database: databaseName,
		ConnectTimeout: "30s", OperationTimeout: "5s", MaxIdleTime: "1m", MaxPoolSize: 10,
	})
	if err != nil {
		t.Fatalf("open Build Worker MongoDB fixture: %v", err)
	}
	defer func() { _ = client.Close(context.Background()) }()
	if err := migration.NewRunner(client.Database(), "build-process-seed").Run(ctx, migration.Default()); err != nil {
		t.Fatalf("migrate Build Worker MongoDB fixture: %v", err)
	}

	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Fatalf("Git CLI is unavailable: %v", err)
	}
	gitRoot := filepath.Join(root, "process-git")
	if err := os.MkdirAll(gitRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(root, "process-source")
	runFixtureGit(t, gitPath, "", "init", "--quiet", "--initial-branch=main", work)
	dockerfile := "FROM " + pinnedBusyBoxIntegrationImage + "\nRUN sleep 12\nCOPY hello /hello\n"
	if err := os.WriteFile(filepath.Join(work, "Dockerfile"), []byte(dockerfile), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "hello"), []byte("full worker recovery\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runFixtureGit(t, gitPath, work, "-c", "user.name=OwnDock Test", "-c", "user.email=test@owndock.net", "add", ".")
	runFixtureGit(t, gitPath, work, "-c", "user.name=OwnDock Test", "-c", "user.email=test@owndock.net", "commit", "--quiet", "-m", "full worker fixture")
	commitSHA := strings.TrimSpace(runFixtureGit(t, gitPath, work, "rev-parse", "HEAD"))
	bare := filepath.Join(gitRoot, "repository.git")
	runFixtureGit(t, gitPath, "", "clone", "--quiet", "--bare", work, bare)
	gitServer := httptest.NewTLSServer(gitHTTPBackend(t, gitPath, gitRoot))
	defer gitServer.Close()
	gitCAFile := filepath.Join(root, "process-git-ca.pem")
	if err := os.WriteFile(gitCAFile, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: gitServer.Certificate().Raw,
	}), 0o600); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	const (
		organizationID  = "build-process-organization"
		projectID       = "build-process-project"
		applicationID   = "build-process-application"
		sourceID        = "build-process-source"
		configurationID = "build-process-configuration"
		registryID      = "build-process-registry"
		buildID         = "build-process-build"
		actorID         = "build-process-user"
		imageRepository = "registry:5000/team/process"
	)
	repository := NewMongoRepository(client.Database())
	source, err := biz.NewSourceRepository(
		sourceID, projectID, "Process source", gitServer.URL+"/repository.git", "main", "", "", actorID, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CreateSource(ctx, source); err != nil {
		t.Fatalf("seed process Source Repository: %v", err)
	}
	controlPlaneStore := controlplanedata.NewMongoStore(client.Database())
	registryCredential, err := controlplanebiz.NewRegistryCredential(
		registryID, projectID, "Process registry", "registry:5000", "builder",
		"secret://integration", actorID, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controlPlaneStore.CreateRegistryCredential(ctx, registryCredential); err != nil {
		t.Fatalf("seed process Registry Credential: %v", err)
	}
	platform := biz.BuildPlatformLinuxAMD64
	if runtime.GOARCH == "arm64" {
		platform = biz.BuildPlatformLinuxARM64
	}
	configuration, err := biz.NewBuildConfiguration(
		configurationID, projectID, applicationID, "Process SIGKILL", sourceID,
		"Dockerfile", ".", []string{"refs/heads/main"}, registryID, imageRepository,
		platform, biz.BuildResources{}, 60, 1, false, actorID, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := biz.NewSourceRevision(sourceID, "refs/heads/main", commitSHA)
	if err != nil {
		t.Fatal(err)
	}
	build, err := biz.NewBuild(
		buildID, organizationID, projectID, applicationID, configuration, revision,
		biz.BuildTriggerSourceManual, "", "build-process-request", actorID, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CreateBuild(ctx, build); err != nil {
		t.Fatalf("seed process Build: %v", err)
	}

	projectRoot, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	workerBinary := filepath.Join(root, "owndock-build-worker")
	buildCommand := exec.CommandContext(ctx, "go", "build", "-o", workerBinary, "./cmd/build-worker")
	buildCommand.Dir = projectRoot
	buildCommand.Env = os.Environ()
	if output, err := buildCommand.CombinedOutput(); err != nil {
		t.Fatalf("build full Build Worker binary: %v: %s", err, output)
	}
	fakeGit := filepath.Join(root, "git-2.55.0")
	fakeGitScript := "#!/bin/sh\nif [ \"$#\" -eq 1 ] && [ \"$1\" = \"--version\" ]; then\n" +
		"  printf '%s\\n' 'git version 2.55.0'\n  exit 0\nfi\nexec " + shellQuote(gitPath) + " \"$@\"\n"
	if err := os.WriteFile(fakeGit, []byte(fakeGitScript), 0o700); err != nil {
		t.Fatal(err)
	}
	metricsAddress := reserveTCPAddress(t)
	workspaceRoot := filepath.Join(root, "process-workspaces")
	configFile := filepath.Join(root, "build-worker-process.yaml")
	configYAML := fmt.Sprintf(`server:
  http:
    address: 127.0.0.1:8000
database:
  mongo:
    enabled: true
    uri_env: %s
    database: %s
    connect_timeout: 30s
    operation_timeout: 5s
    max_idle_time: 1m
    max_pool_size: 10
product:
  enabled: true
  source_git_ca_cert_file: %q
runtime:
  build_worker:
    enabled: true
    poll_interval: 100ms
    lease_duration: 3s
    operation_timeout: 2m
    checkout_timeout: 1m
    workspace_root: %q
    require_workspace_hard_quota: false
    workspace_hard_quota_bytes: 134217728
    max_workspace_bytes: 104857600
    max_workspace_files: 10000
    max_workspace_depth: 64
    git_executable: %q
    git_version: 2.55.0
    buildkit_endpoint: %q
    buildkit_server_name: %s
    buildkit_ca_cert_file: %q
    buildkit_client_cert_file: %q
    buildkit_client_key_file: %q
    build_egress_proxy_url: %q
    metrics_address: %s
`, mongoURIEnvironment, databaseName, gitCAFile, workspaceRoot, fakeGit,
		options.Endpoint, options.ServerName, options.CACertFile, options.ClientCertFile,
		options.ClientKeyFile, options.EgressProxyURL, metricsAddress)
	if err := os.WriteFile(configFile, []byte(configYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	first, firstStdout, firstStderr := startBuildWorkerProcess(t, workerBinary, configFile, password)
	firstKilled := false
	defer func() {
		if !firstKilled && first.Process != nil {
			_ = first.Process.Kill()
			_, _ = first.Process.Wait()
		}
	}()
	claimed := waitForProcessBuild(t, repository, projectID, buildID, 30*time.Second,
		func(item biz.Build) bool { return item.Status == biz.BuildStatusPushing && item.Lease.Generation > 0 },
		firstStdout, firstStderr)
	time.Sleep(750 * time.Millisecond)
	if err := first.Process.Kill(); err != nil {
		t.Fatalf("SIGKILL full Build Worker binary: %v", err)
	}
	_, _ = first.Process.Wait()
	firstKilled = true
	for time.Now().Before(claimed.Lease.ExpiresAt.Add(150 * time.Millisecond)) {
		time.Sleep(25 * time.Millisecond)
	}

	second, secondStdout, secondStderr := startBuildWorkerProcess(t, workerBinary, configFile, password)
	secondStopped := false
	defer func() {
		if !secondStopped && second.Process != nil {
			_ = second.Process.Kill()
			_, _ = second.Process.Wait()
		}
	}()
	reclaimed := waitForProcessBuild(t, repository, projectID, buildID, 30*time.Second,
		func(item biz.Build) bool {
			return item.Status == biz.BuildStatusPushing &&
				item.Lease.Generation > claimed.Lease.Generation
		}, secondStdout, secondStderr)
	completed := waitForProcessBuild(t, repository, projectID, buildID, 75*time.Second,
		func(item biz.Build) bool { return item.Status == biz.BuildStatusSucceeded },
		secondStdout, secondStderr)
	if reclaimed.Lease.Generation <= claimed.Lease.Generation ||
		!strings.HasPrefix(completed.ImageDigest, imageRepository+"@sha256:") || completed.ArtifactID == "" {
		t.Fatalf("recovered full Build = %+v, reclaimed lease = %+v, killed lease = %+v",
			completed, reclaimed.Lease, claimed.Lease)
	}
	stopBuildWorkerProcess(t, second)
	secondStopped = true

	buildKitOutage := newProcessBuild(t, buildID+"-buildkit-outage", "build-process-buildkit-outage",
		organizationID, projectID, applicationID, actorID, configuration, revision)
	if _, err := repository.CreateBuild(ctx, buildKitOutage); err != nil {
		t.Fatalf("seed BuildKit outage Build: %v", err)
	}
	runDocker(t, "pause", buildKitName)
	unavailable, unavailableStdout, unavailableStderr := startBuildWorkerProcess(t, workerBinary, configFile, password)
	if err := waitBuildWorkerProcessExit(unavailable, 25*time.Second); err == nil {
		t.Fatal("Build Worker started while BuildKit was unavailable")
	}
	storedOutage, err := repository.GetBuild(ctx, projectID, buildKitOutage.ID)
	if err != nil || storedOutage.Status != biz.BuildStatusQueued || storedOutage.Lease.Generation != 0 {
		t.Fatalf("BuildKit startup outage mutated Build = %+v, %v", storedOutage, err)
	}
	runDocker(t, "unpause", buildKitName)
	_ = waitForBuildKitGateway(t, options, copyingRegistrySecretResolver{value: password})
	buildKitRecovery, buildKitRecoveryStdout, buildKitRecoveryStderr := startBuildWorkerProcess(t, workerBinary, configFile, password)
	buildKitRecovered := waitForProcessBuild(t, repository, projectID, buildKitOutage.ID, 60*time.Second,
		func(item biz.Build) bool { return item.Status == biz.BuildStatusSucceeded },
		buildKitRecoveryStdout, buildKitRecoveryStderr)
	stopBuildWorkerProcess(t, buildKitRecovery)
	if buildKitRecovered.ArtifactID == "" {
		t.Fatal("BuildKit recovery did not publish an Artifact")
	}

	registryOutage := newProcessBuild(t, buildID+"-registry-outage", "build-process-registry-outage",
		organizationID, projectID, applicationID, actorID, configuration, revision)
	if _, err := repository.CreateBuild(ctx, registryOutage); err != nil {
		t.Fatalf("seed Registry outage Build: %v", err)
	}
	runDocker(t, "network", "disconnect", networkName, registryName)
	registryFailure, registryFailureStdout, registryFailureStderr := startBuildWorkerProcess(t, workerBinary, configFile, password)
	failedRegistryBuild := waitForProcessBuild(t, repository, projectID, registryOutage.ID, 60*time.Second,
		func(item biz.Build) bool { return item.Status == biz.BuildStatusFailed },
		registryFailureStdout, registryFailureStderr)
	stopBuildWorkerProcess(t, registryFailure)
	if failedRegistryBuild.FailureCategory != biz.BuildFailureRegistryPush || failedRegistryBuild.ArtifactID != "" {
		t.Fatalf("Registry outage Build = %+v", failedRegistryBuild)
	}
	runDocker(t, "network", "connect", "--alias", "registry", networkName, registryName)
	retryRegistryBuild, err := failedRegistryBuild.Retry(
		buildID+"-registry-retry", "build-process-registry-retry", actorID, time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CreateBuild(ctx, retryRegistryBuild); err != nil {
		t.Fatalf("seed Registry recovery Build: %v", err)
	}
	registryRecovery, registryRecoveryStdout, registryRecoveryStderr := startBuildWorkerProcess(t, workerBinary, configFile, password)
	recoveredRegistryBuild := waitForProcessBuild(t, repository, projectID, retryRegistryBuild.ID, 60*time.Second,
		func(item biz.Build) bool { return item.Status == biz.BuildStatusSucceeded },
		registryRecoveryStdout, registryRecoveryStderr, buildKitName)
	stopBuildWorkerProcess(t, registryRecovery)
	if recoveredRegistryBuild.SourceBuildID != failedRegistryBuild.ID || recoveredRegistryBuild.ArtifactID == "" {
		t.Fatalf("Registry recovery Build = %+v", recoveredRegistryBuild)
	}

	mongoDockerfile := "FROM " + pinnedBusyBoxIntegrationImage +
		"\nRUN sleep 12 && echo mongo-recovery > /marker\nCOPY hello /hello\n"
	if err := os.WriteFile(filepath.Join(work, "Dockerfile"), []byte(mongoDockerfile), 0o600); err != nil {
		t.Fatal(err)
	}
	runFixtureGit(t, gitPath, work, "-c", "user.name=OwnDock Test", "-c", "user.email=test@owndock.net", "add", "Dockerfile")
	runFixtureGit(t, gitPath, work, "-c", "user.name=OwnDock Test", "-c", "user.email=test@owndock.net", "commit", "--quiet", "-m", "Mongo interruption fixture")
	runFixtureGit(t, gitPath, work, "push", "--quiet", bare, "HEAD:refs/heads/main")
	mongoCommitSHA := strings.TrimSpace(runFixtureGit(t, gitPath, work, "rev-parse", "HEAD"))
	mongoRevision, err := biz.NewSourceRevision(sourceID, "refs/heads/main", mongoCommitSHA)
	if err != nil {
		t.Fatal(err)
	}
	mongoOutage := newProcessBuild(t, buildID+"-mongo-outage", "build-process-mongo-outage",
		organizationID, projectID, applicationID, actorID, configuration, mongoRevision)
	if _, err := repository.CreateBuild(ctx, mongoOutage); err != nil {
		t.Fatalf("seed MongoDB outage Build: %v", err)
	}
	mongoRecovery, mongoRecoveryStdout, mongoRecoveryStderr := startBuildWorkerProcess(t, workerBinary, configFile, password)
	mongoStopped := false
	defer func() {
		if !mongoStopped && mongoRecovery.Process != nil {
			_ = mongoRecovery.Process.Kill()
			_, _ = mongoRecovery.Process.Wait()
		}
	}()
	mongoClaimed := waitForProcessBuild(t, repository, projectID, mongoOutage.ID, 30*time.Second,
		func(item biz.Build) bool { return item.Status == biz.BuildStatusPushing && item.Lease.Generation > 0 },
		mongoRecoveryStdout, mongoRecoveryStderr)
	mongoContainerID := mongoContainer.GetContainerID()
	if strings.TrimSpace(mongoContainerID) == "" {
		t.Fatal("MongoDB container ID is empty")
	}
	time.Sleep(750 * time.Millisecond)
	runDocker(t, "pause", mongoContainerID)
	time.Sleep(6 * time.Second)
	runDocker(t, "unpause", mongoContainerID)
	mongoReclaimed := waitForProcessBuild(t, repository, projectID, mongoOutage.ID, 30*time.Second,
		func(item biz.Build) bool { return item.Lease.Generation > mongoClaimed.Lease.Generation },
		mongoRecoveryStdout, mongoRecoveryStderr)
	mongoCompleted := waitForProcessBuild(t, repository, projectID, mongoOutage.ID, 75*time.Second,
		func(item biz.Build) bool { return item.Status == biz.BuildStatusSucceeded },
		mongoRecoveryStdout, mongoRecoveryStderr)
	stopBuildWorkerProcess(t, mongoRecovery)
	mongoStopped = true
	if mongoReclaimed.Lease.Generation <= mongoClaimed.Lease.Generation || mongoCompleted.ArtifactID == "" {
		t.Fatalf("MongoDB interruption recovery = %+v, reclaimed=%+v, initial=%+v",
			mongoCompleted, mongoReclaimed.Lease, mongoClaimed.Lease)
	}

	combinedOutput := firstStdout.String() + firstStderr.String() + secondStdout.String() + secondStderr.String() +
		unavailableStdout.String() + unavailableStderr.String() +
		buildKitRecoveryStdout.String() + buildKitRecoveryStderr.String() +
		registryFailureStdout.String() + registryFailureStderr.String() +
		registryRecoveryStdout.String() + registryRecoveryStderr.String() +
		mongoRecoveryStdout.String() + mongoRecoveryStderr.String()
	if strings.Contains(combinedOutput, password) || strings.Contains(combinedOutput, mongoURI) {
		t.Fatal("full Build Worker process leaked a credential")
	}
	verifyRegistryManifest(t, registryPort, materials.caPool, password, "team/process",
		strings.TrimPrefix(buildImageName(imageRepository, buildID), imageRepository+":"),
		strings.TrimPrefix(completed.ImageDigest, imageRepository+"@"))
}

func reserveTCPAddress(t *testing.T) string {
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

type lockedBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *lockedBuffer) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(value)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.String()
}

func startBuildWorkerProcess(t *testing.T, binary, configFile, password string) (*exec.Cmd, *lockedBuffer, *lockedBuffer) {
	t.Helper()
	command := exec.Command(binary, "-conf", configFile)
	command.Env = append(os.Environ(), "OWNDOCK_REGISTRY_INTEGRATION_PASSWORD="+password)
	stdout, stderr := &lockedBuffer{}, &lockedBuffer{}
	command.Stdout, command.Stderr = stdout, stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start full Build Worker binary: %v", err)
	}
	return command, stdout, stderr
}

func waitForProcessBuild(t *testing.T, repository *MongoRepository, projectID, buildID string,
	timeout time.Duration, ready func(biz.Build) bool, stdout, stderr *lockedBuffer,
	diagnosticContainers ...string) biz.Build {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last biz.Build
	var lastErr error
	for time.Now().Before(deadline) {
		lookupContext, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		last, lastErr = repository.GetBuild(lookupContext, projectID, buildID)
		cancel()
		if lastErr == nil && ready(last) {
			return last
		}
		if lastErr == nil && last.Terminal() {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	logContext, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	logs, logErr := repository.ReadBuildLogs(logContext, projectID, buildID,
		biz.BuildLogQuery{Limit: biz.MaximumBuildLogPageSize})
	cancel()
	var diagnostics strings.Builder
	for _, container := range diagnosticContainers {
		diagnostics.WriteString("\ncontainer ")
		diagnostics.WriteString(container)
		diagnostics.WriteString(" logs:\n")
		diagnostics.WriteString(dockerLogs(container))
	}
	t.Fatalf("full Build Worker state = %+v/%v\nbuild logs=%+v/%v\nstdout=%s\nstderr=%s%s",
		last, lastErr, logs.Entries, logErr, stdout.String(), stderr.String(), diagnostics.String())
	return biz.Build{}
}

func stopBuildWorkerProcess(t *testing.T, command *exec.Cmd) {
	t.Helper()
	if err := command.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("stop full Build Worker binary: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("full Build Worker graceful stop: %v", err)
		}
	case <-time.After(10 * time.Second):
		_ = command.Process.Kill()
		<-done
		t.Fatal("full Build Worker did not stop gracefully")
	}
}

func waitBuildWorkerProcessExit(command *exec.Cmd, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		_ = command.Process.Kill()
		<-done
		return fmt.Errorf("Build Worker process did not exit")
	}
}

func newProcessBuild(t *testing.T, buildID, idempotencyKey, organizationID, projectID,
	applicationID, actorID string, configuration biz.BuildConfiguration,
	revision biz.SourceRevision) biz.Build {
	t.Helper()
	item, err := biz.NewBuild(
		buildID, organizationID, projectID, applicationID, configuration, revision,
		biz.BuildTriggerSourceManual, "", idempotencyKey, actorID, time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	return item
}

func verifyRegistryManifest(t *testing.T, port string, roots *x509.CertPool, password,
	repository, tag, expectedDigest string) {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, ServerName: "registry", RootCAs: roots,
	}}}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
		"https://127.0.0.1:"+port+"/v2/"+repository+"/manifests/"+tag, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.SetBasicAuth("builder", password)
	request.Header.Set("Accept", strings.Join([]string{
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.oci.image.index.v1+json",
	}, ","))
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024*1024))
	if response.StatusCode != http.StatusOK || response.Header.Get("Docker-Content-Digest") != expectedDigest {
		t.Fatalf("registry manifest = %d/%q, want 200/%q", response.StatusCode,
			response.Header.Get("Docker-Content-Digest"), expectedDigest)
	}
}

type registryManifestDocument struct {
	Config struct {
		Digest string `json:"digest"`
	} `json:"config"`
	Layers []struct {
		Digest string `json:"digest"`
	} `json:"layers"`
	Manifests []struct {
		Digest string `json:"digest"`
	} `json:"manifests"`
}

func assertRegistryArtifactSecretFree(t *testing.T, port string, roots *x509.CertPool,
	password, repository, reference, forbidden string) {
	t.Helper()
	client := registryIntegrationClient(roots)
	visited := make(map[string]bool)
	var scanManifest func(string)
	scanManifest = func(current string) {
		if visited[current] {
			return
		}
		visited[current] = true
		body := registryIntegrationRead(t, client, port, password,
			"/v2/"+repository+"/manifests/"+current, 8*1024*1024)
		assertBytesDoNotContain(t, body, forbidden, "OCI manifest")
		var document registryManifestDocument
		if err := json.Unmarshal(body, &document); err != nil {
			t.Fatalf("decode OCI manifest %q: %v", current, err)
		}
		for _, child := range document.Manifests {
			scanManifest(child.Digest)
		}
		blobDigests := make([]string, 0, len(document.Layers)+1)
		if document.Config.Digest != "" {
			blobDigests = append(blobDigests, document.Config.Digest)
		}
		for _, layer := range document.Layers {
			blobDigests = append(blobDigests, layer.Digest)
		}
		for _, blobDigest := range blobDigests {
			blob := registryIntegrationRead(t, client, port, password,
				"/v2/"+repository+"/blobs/"+blobDigest, 64*1024*1024)
			assertBytesDoNotContain(t, blob, forbidden, "OCI blob")
			reader, err := gzip.NewReader(bytes.NewReader(blob))
			if err == nil {
				plain, readErr := io.ReadAll(io.LimitReader(reader, 64*1024*1024))
				_ = reader.Close()
				if readErr != nil {
					t.Fatalf("decompress OCI layer %q: %v", blobDigest, readErr)
				}
				assertBytesDoNotContain(t, plain, forbidden, "decompressed OCI layer")
			}
		}
	}
	scanManifest(reference)
}

func assertRegistryManifestMissing(t *testing.T, port string, roots *x509.CertPool,
	password, repository, reference string) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
		"https://127.0.0.1:"+port+"/v2/"+repository+"/manifests/"+reference, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.SetBasicAuth("builder", password)
	request.Header.Set("Accept", registryManifestAcceptHeader())
	response, err := registryIntegrationClient(roots).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024*1024))
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("rejected build manifest status = %d, want 404", response.StatusCode)
	}
}

func registryIntegrationRead(t *testing.T, client *http.Client, port, password, path string, limit int64) []byte {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://127.0.0.1:"+port+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.SetBasicAuth("builder", password)
	request.Header.Set("Accept", registryManifestAcceptHeader())
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || int64(len(body)) > limit || response.StatusCode != http.StatusOK {
		t.Fatalf("Registry read %s = %d bytes/status %d/error %v", path, len(body), response.StatusCode, err)
	}
	return body
}

func registryIntegrationClient(roots *x509.CertPool) *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, ServerName: "registry", RootCAs: roots,
	}}}
}

func registryManifestAcceptHeader() string {
	return strings.Join([]string{
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.oci.image.index.v1+json",
	}, ",")
}

func assertBytesDoNotContain(t *testing.T, value []byte, forbidden, location string) {
	t.Helper()
	if forbidden != "" && bytes.Contains(value, []byte(forbidden)) {
		t.Fatalf("Registry credential leaked into %s", location)
	}
}

func assertDockerContainerExportSecretFree(t *testing.T, container, forbidden string) {
	t.Helper()
	command := exec.CommandContext(t.Context(), "docker", "export", container)
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("open Docker export for %s: %v", container, err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start Docker export for %s: %v", container, err)
	}
	leaked, scanErr := readerContains(output, []byte(forbidden))
	if leaked || scanErr != nil {
		_ = command.Process.Kill()
	}
	waitErr := command.Wait()
	if scanErr != nil {
		t.Fatalf("scan Docker export for %s: %v", container, scanErr)
	}
	if leaked {
		t.Fatalf("Registry credential leaked into %s container filesystem/cache", container)
	}
	if waitErr != nil {
		t.Fatalf("Docker export for %s: %v: %s", container, waitErr, stderr.String())
	}
}

func assertDockerPathSecretFreeDeep(t *testing.T, container, path, forbidden string) {
	t.Helper()
	command := exec.CommandContext(t.Context(), "docker", "exec", container,
		"tar", "-C", path, "-cf", "-", ".")
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("open Docker cache export for %s: %v", container, err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start Docker cache export for %s: %v", container, err)
	}
	leaked, scanErr := tarStreamContainsCompressed(output, []byte(forbidden))
	if leaked || scanErr != nil {
		_ = command.Process.Kill()
	}
	waitErr := command.Wait()
	if scanErr != nil {
		t.Fatalf("scan Docker cache for %s: %v", container, scanErr)
	}
	if leaked {
		t.Fatalf("Registry credential leaked into compressed %s cache", container)
	}
	if waitErr != nil {
		t.Fatalf("Docker cache export for %s: %v: %s", container, waitErr, stderr.String())
	}
}

const (
	maximumCacheScanFiles = 100000
	maximumCacheScanFile  = int64(64 * 1024 * 1024)
	maximumCacheScanTotal = int64(512 * 1024 * 1024)
)

func tarStreamContainsCompressed(input io.Reader, forbidden []byte) (bool, error) {
	archive := tar.NewReader(input)
	var files int
	var total int64
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if !header.FileInfo().Mode().IsRegular() {
			continue
		}
		files++
		if files > maximumCacheScanFiles || header.Size < 0 || header.Size > maximumCacheScanFile ||
			header.Size > maximumCacheScanTotal-total {
			return false, fmt.Errorf("BuildKit cache scan limit exceeded")
		}
		payload, err := io.ReadAll(io.LimitReader(archive, header.Size+1))
		if err != nil {
			return false, fmt.Errorf("read BuildKit cache entry: %w", err)
		}
		if int64(len(payload)) != header.Size {
			return false, fmt.Errorf("BuildKit cache entry size changed while scanning")
		}
		total += header.Size
		leaked, err := compressedPayloadContains(payload, forbidden)
		if err != nil || leaked {
			return leaked, err
		}
	}
}

func compressedPayloadContains(payload, forbidden []byte) (bool, error) {
	if len(forbidden) == 0 {
		return false, nil
	}
	if bytes.Contains(payload, forbidden) {
		return true, nil
	}
	var decoded io.ReadCloser
	switch {
	case len(payload) >= 2 && payload[0] == 0x1f && payload[1] == 0x8b:
		reader, err := gzip.NewReader(bytes.NewReader(payload))
		if err != nil {
			return false, err
		}
		decoded = reader
	case len(payload) >= 4 && bytes.Equal(payload[:4], []byte{0x28, 0xb5, 0x2f, 0xfd}):
		reader, err := zstd.NewReader(bytes.NewReader(payload),
			zstd.WithDecoderMaxMemory(uint64(maximumCacheScanFile)),
			zstd.WithDecoderMaxWindow(uint64(maximumCacheScanFile)))
		if err != nil {
			return false, err
		}
		decoded = reader.IOReadCloser()
	default:
		return false, nil
	}
	defer decoded.Close()
	value, err := io.ReadAll(io.LimitReader(decoded, maximumCacheScanFile+1))
	if err != nil {
		return false, err
	}
	if int64(len(value)) > maximumCacheScanFile {
		return false, fmt.Errorf("compressed BuildKit cache entry exceeds scan limit")
	}
	return bytes.Contains(value, forbidden), nil
}

func TestCompressedBuildKitCacheScanner(t *testing.T) {
	const secret = "cache-secret-sentinel"
	var gzipped bytes.Buffer
	gzipWriter := gzip.NewWriter(&gzipped)
	if _, err := gzipWriter.Write([]byte("prefix-" + secret + "-suffix")); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	zstdWriter, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	zstandard := zstdWriter.EncodeAll([]byte("prefix-"+secret+"-suffix"), nil)
	zstdWriter.Close()
	for name, payload := range map[string][]byte{
		"gzip": gzipped.Bytes(),
		"zstd": zstandard,
	} {
		t.Run(name, func(t *testing.T) {
			leaked, err := compressedPayloadContains(payload, []byte(secret))
			if err != nil || !leaked {
				t.Fatalf("compressedPayloadContains() = %t, %v", leaked, err)
			}
		})
	}
	var archive bytes.Buffer
	tarWriter := tar.NewWriter(&archive)
	if err := tarWriter.WriteHeader(&tar.Header{Name: "cache/blob", Mode: 0o600, Size: int64(len(zstandard))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write(zstandard); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	leaked, err := tarStreamContainsCompressed(bytes.NewReader(archive.Bytes()), []byte(secret))
	if err != nil || !leaked {
		t.Fatalf("tarStreamContainsCompressed() = %t, %v", leaked, err)
	}
	if leaked, err := compressedPayloadContains([]byte("safe cache"), []byte(secret)); err != nil || leaked {
		t.Fatalf("safe payload = %t, %v", leaked, err)
	}
}

func readerContains(reader io.Reader, forbidden []byte) (bool, error) {
	if len(forbidden) == 0 {
		return false, nil
	}
	buffer := make([]byte, 64*1024+len(forbidden)-1)
	carried := 0
	for {
		read, err := reader.Read(buffer[carried:])
		total := carried + read
		if bytes.Contains(buffer[:total], forbidden) {
			return true, nil
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return false, nil
			}
			return false, err
		}
		carried = min(len(forbidden)-1, total)
		copy(buffer[:carried], buffer[total-carried:total])
	}
}

func dockerPort(t *testing.T, container, port string) string {
	t.Helper()
	command := exec.Command("docker", "port", container, port)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("docker port: %v: %s", err, output)
	}
	value := strings.TrimSpace(string(output))
	index := strings.LastIndexByte(value, ':')
	if index < 0 || index == len(value)-1 {
		t.Fatalf("docker port output = %q", value)
	}
	return value[index+1:]
}

func runDocker(t *testing.T, arguments ...string) {
	t.Helper()
	if err := dockerCommand(arguments...); err != nil {
		t.Fatal(err)
	}
}

func dockerCommand(arguments ...string) error {
	command := exec.Command("docker", arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker command failed: %w: %s", err, output)
	}
	return nil
}

func dockerLogs(container string) string {
	command := exec.Command("docker", "logs", "--tail", "100", container)
	output, _ := command.CombinedOutput()
	return string(output)
}
