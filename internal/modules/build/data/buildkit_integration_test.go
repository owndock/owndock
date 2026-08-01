package data

import (
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
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/owndock/owndock/internal/modules/build/biz"
)

const (
	pinnedRegistryIntegrationImage = "registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"
	pinnedBusyBoxIntegrationImage  = "busybox:1.37.0@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0"
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
	networkName := "owndock-buildkit-test-" + suffix
	registryName := "owndock-registry-test-" + suffix
	buildKitName := "owndock-buildkit-test-" + suffix
	runDocker(t, "network", "create", networkName)
	t.Cleanup(func() { _ = dockerCommand("network", "rm", networkName) })
	runDocker(t, "run", "--detach", "--name", registryName, "--network", networkName,
		"--network-alias", "registry", "--publish", "127.0.0.1::5000",
		"--env", "REGISTRY_HTTP_TLS_CERTIFICATE=/certs/registry-cert.pem",
		"--env", "REGISTRY_HTTP_TLS_KEY=/certs/registry-key.pem",
		"--env", "REGISTRY_AUTH=htpasswd", "--env", "REGISTRY_AUTH_HTPASSWD_REALM=OwnDock Test",
		"--env", "REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd",
		"--volume", materials.directory+":/certs:ro", "--volume", authDirectory+":/auth:ro",
		pinnedRegistryIntegrationImage)
	t.Cleanup(func() { _ = dockerCommand("rm", "--force", registryName) })
	runDocker(t, "run", "--detach", "--name", buildKitName, "--network", networkName,
		"--publish", "127.0.0.1::1234", "--security-opt", "seccomp=unconfined",
		"--security-opt", "apparmor=unconfined", "--security-opt", "systempaths=unconfined",
		"--tmpfs", "/run/user/1000:rw,nosuid,nodev,size=67108864,mode=0700,uid=1000,gid=1000",
		"--tmpfs", "/home/user/.local/tmp:rw,noexec,nosuid,nodev,size=536870912,mode=0700,uid=1000,gid=1000",
		"--volume", materials.directory+":/certs:ro", "--volume", buildKitConfig+":/etc/buildkit/buildkitd.toml:ro",
		PinnedBuildKitImage, "--config=/etc/buildkit/buildkitd.toml", "--addr=tcp://0.0.0.0:1234",
		"--tlscacert=/certs/ca.pem", "--tlscert=/certs/buildkit-cert.pem", "--tlskey=/certs/buildkit-key.pem")
	t.Cleanup(func() { _ = dockerCommand("rm", "--force", buildKitName) })
	buildKitPort := dockerPort(t, buildKitName, "1234/tcp")
	registryPort := dockerPort(t, registryName, "5000/tcp")
	options := BuildKitOptions{
		Endpoint: "tcp://127.0.0.1:" + buildKitPort, ServerName: "buildkit",
		CACertFile: materials.caFile, ClientCertFile: materials.workerCert,
		ClientKeyFile: materials.workerKey,
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
	runDocker(t, "network", "connect", networkName, buildKitName)
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
