package data

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	mobyclient "github.com/moby/moby/client"

	"github.com/owndock/owndock/internal/modules/deployment/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/runtimespec"
)

const dockerIntegrationImage = "nginx@sha256:1eff5a5f3fcf8431a0abb7eddf5471fec24e5e1905a2581aeacdb07a4479b92b"

type integrationFence struct {
	err error
}

func (f *integrationFence) ValidateFence(
	context.Context,
	string,
	string,
	string,
	uint64,
	time.Time,
) error {
	return f.err
}

func TestDockerGatewayEngineIntegration(t *testing.T) {
	if os.Getenv("OWNDOCK_RUN_DOCKER_INTEGRATION") != "1" {
		t.Skip("set OWNDOCK_RUN_DOCKER_INTEGRATION=1 to run the Docker Engine integration test")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	inspectionClient, err := localDockerClient()
	if err != nil {
		t.Fatalf("create Docker client: %v", err)
	}
	defer func() { _ = inspectionClient.Close() }()
	version, err := inspectionClient.ServerVersion(ctx, mobyclient.ServerVersionOptions{})
	if err != nil {
		t.Fatalf("query Docker Engine version: %v", err)
	}
	t.Logf("Docker Engine %s API %s", version.Version, version.APIVersion)

	stableName := "owndock-integration-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	fence := &integrationFence{}
	gateway := NewDockerGateway().WithFence(fence)
	gateway.pollInterval = 100 * time.Millisecond
	gateway.newEngine = func(biz.ExecutionPlan, biz.RuntimeCredential) (dockerEngine, error) {
		return localDockerClient()
	}
	healthCommand := []string{
		"/bin/sh", "-c", "wget -q -O /dev/null http://127.0.0.1/",
	}
	first := integrationExecutionPlan(stableName, "deployment-first", healthCommand)
	second := integrationExecutionPlan(stableName, "deployment-second", healthCommand)
	second.CutoverSequence = 2
	unhealthy := integrationExecutionPlan(stableName, "deployment-unhealthy", []string{
		"/bin/sh", "-c", "exit 1",
	})
	unhealthy.CutoverSequence = 3
	stale := integrationExecutionPlan(stableName, "deployment-stale", healthCommand)
	stale.CutoverSequence = 4
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()
		names := []string{stableName}
		for _, plan := range []biz.ExecutionPlan{first, second, unhealthy, stale} {
			names = append(
				names, candidateContainerName(plan), previousContainerName(plan),
			)
		}
		for _, name := range names {
			_, _ = inspectionClient.ContainerRemove(
				cleanupContext, name, mobyclient.ContainerRemoveOptions{Force: true},
			)
		}
	})

	// Runtime specs use exec-form health commands. This fixture invokes the
	// shell as an explicit executable rather than Docker's CMD-SHELL form.
	if err := gateway.Prepare(ctx, first, biz.RuntimeCredential{}); err != nil {
		t.Fatalf("prepare first deployment: %v", err)
	}
	if err := gateway.Deploy(ctx, first, biz.RuntimeCredential{}); err != nil {
		t.Fatalf("deploy first candidate: %v", err)
	}
	assertRunningDeployment(t, ctx, inspectionClient, stableName, first.DeploymentID)

	if err := gateway.Deploy(ctx, second, biz.RuntimeCredential{}); err != nil {
		t.Fatalf("replace with healthy candidate: %v", err)
	}
	assertRunningDeployment(t, ctx, inspectionClient, stableName, second.DeploymentID)
	assertContainerMissing(t, ctx, inspectionClient, previousContainerName(second))

	if err := gateway.Deploy(ctx, unhealthy, biz.RuntimeCredential{}); err == nil {
		t.Fatal("unhealthy candidate deployment succeeded")
	}
	assertRunningDeployment(t, ctx, inspectionClient, stableName, second.DeploymentID)
	assertContainerMissing(t, ctx, inspectionClient, candidateContainerName(unhealthy))

	fence.err = biz.ErrStaleExecution
	if err := gateway.Deploy(ctx, stale, biz.RuntimeCredential{}); !errors.Is(err, biz.ErrStaleExecution) {
		t.Fatalf("stale deployment error = %v", err)
	}
	assertRunningDeployment(t, ctx, inspectionClient, stableName, second.DeploymentID)
	assertContainerMissing(t, ctx, inspectionClient, candidateContainerName(stale))
	fence.err = nil

	if err := gateway.Cancel(ctx, second, biz.RuntimeCredential{}); err != nil {
		t.Fatalf("cancel current deployment: %v", err)
	}
	assertContainerMissing(t, ctx, inspectionClient, stableName)
}

func TestDockerGatewayMTLSEnginePartitionAndRecoveryIntegration(t *testing.T) {
	if os.Getenv("OWNDOCK_RUN_DOCKER_INTEGRATION") != "1" {
		t.Skip("set OWNDOCK_RUN_DOCKER_INTEGRATION=1 to run the Docker Engine integration test")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	inspectionClient, err := localDockerClient()
	if err != nil {
		t.Fatalf("create Docker client: %v", err)
	}
	defer func() { _ = inspectionClient.Close() }()
	if _, err := inspectionClient.ServerVersion(ctx, mobyclient.ServerVersionOptions{}); err != nil {
		t.Fatalf("query Docker Engine version: %v", err)
	}

	pki := newDockerIntegrationPKI(t)
	boundary := newDockerMTLSBoundary(t, inspectionClient.DaemonHost(), pki)
	connection, err := runtimeaccess.NewDirectDocker(
		"",
		"tcp://"+boundary.address(),
		pki.serverName,
		"secret://runtime-integration",
	)
	if err != nil {
		t.Fatal(err)
	}
	plan := integrationExecutionPlan(
		"owndock-mtls-integration-"+strconv.FormatInt(time.Now().UnixNano(), 36),
		"deployment-mtls",
		[]string{"/bin/sh", "-c", "exit 0"},
	)
	plan.TargetConnection = connection
	credential := biz.RuntimeCredential{DirectDocker: &biz.DirectDockerCredential{
		CACertificate:     pki.caCertificate,
		ClientCertificate: pki.clientCertificate,
		ClientKey:         pki.clientKey,
	}}
	gateway := NewDockerGateway()

	if err := gateway.Prepare(ctx, plan, credential); err != nil {
		t.Fatalf("prepare through mTLS boundary: %v", err)
	}
	if boundary.authenticatedRequests.Load() == 0 {
		t.Fatal("mTLS boundary did not observe an authenticated Docker API request")
	}

	wrongIdentity := credential
	wrongIdentity.DirectDocker = &biz.DirectDockerCredential{
		CACertificate:     pki.caCertificate,
		ClientCertificate: pki.untrustedClientCertificate,
		ClientKey:         pki.untrustedClientKey,
	}
	assertDockerIntegrationFailure(t, gateway.Prepare(ctx, plan, wrongIdentity), biz.FailureTargetUnreachable)

	invalidKey := credential
	invalidKey.DirectDocker = &biz.DirectDockerCredential{
		CACertificate:     pki.caCertificate,
		ClientCertificate: pki.clientCertificate,
		ClientKey:         []byte("runtime-private-key-sentinel"),
	}
	assertDockerIntegrationFailure(t, gateway.Prepare(ctx, plan, invalidKey), biz.FailureCredential)

	boundary.partitioned.Store(true)
	partitionContext, partitionCancel := context.WithTimeout(ctx, 5*time.Second)
	assertDockerIntegrationFailure(
		t,
		gateway.Prepare(partitionContext, plan, credential),
		biz.FailureTargetUnreachable,
	)
	partitionCancel()
	boundary.partitioned.Store(false)
	if err := gateway.Prepare(ctx, plan, credential); err != nil {
		t.Fatalf("prepare after mTLS boundary recovery: %v", err)
	}
}

type dockerIntegrationPKI struct {
	serverName                 string
	caCertificate              []byte
	serverCertificate          tls.Certificate
	clientCertificate          []byte
	clientKey                  []byte
	untrustedClientCertificate []byte
	untrustedClientKey         []byte
}

func newDockerIntegrationPKI(t *testing.T) dockerIntegrationPKI {
	t.Helper()
	ca, caKey, caPEM := createDockerIntegrationCA(t, "Docker runtime integration CA")
	serverName := "runtime.integration"
	serverCertificatePEM, serverKey := issueDockerIntegrationCertificate(
		t, ca, caKey, 2, "runtime", []string{serverName}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	)
	serverCertificate, err := tls.X509KeyPair(serverCertificatePEM, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	clientCertificate, clientKey := issueDockerIntegrationCertificate(
		t, ca, caKey, 3, "deployment-worker", nil, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	)
	untrustedCA, untrustedCAKey, _ := createDockerIntegrationCA(t, "Untrusted runtime integration CA")
	untrustedClientCertificate, untrustedClientKey := issueDockerIntegrationCertificate(
		t, untrustedCA, untrustedCAKey, 4, "untrusted-worker", nil,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	)
	return dockerIntegrationPKI{
		serverName: serverName, caCertificate: caPEM, serverCertificate: serverCertificate,
		clientCertificate: clientCertificate, clientKey: clientKey,
		untrustedClientCertificate: untrustedClientCertificate,
		untrustedClientKey:         untrustedClientKey,
	}
}

func createDockerIntegrationCA(
	t *testing.T,
	commonName string,
) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: commonName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func issueDockerIntegrationCertificate(
	t *testing.T,
	ca *x509.Certificate,
	caKey *ecdsa.PrivateKey,
	serial int64,
	commonName string,
	dnsNames []string,
	usage []x509.ExtKeyUsage,
) ([]byte, []byte) {
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
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

type dockerMTLSBoundary struct {
	server                *httptest.Server
	partitioned           atomic.Bool
	authenticatedRequests atomic.Uint64
}

type dockerPartitionListener struct {
	net.Listener
	partitioned *atomic.Bool
}

func (l dockerPartitionListener) Accept() (net.Conn, error) {
	for {
		connection, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.partitioned.Load() {
			_ = connection.Close()
			continue
		}
		return connection, nil
	}
}

func newDockerMTLSBoundary(
	t *testing.T,
	dockerHost string,
	pki dockerIntegrationPKI,
) *dockerMTLSBoundary {
	t.Helper()
	dockerURL, err := url.Parse(dockerHost)
	if err != nil || dockerURL.Scheme != "unix" || dockerURL.Path == "" {
		t.Skipf("mTLS integration requires a local Unix Docker endpoint, got %q", dockerHost)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", dockerURL.Path)
	}}
	t.Cleanup(transport.CloseIdleConnections)
	proxy := httputil.NewSingleHostReverseProxy(&url.URL{Scheme: "http", Host: "docker-engine"})
	proxy.Transport = transport
	boundary := &dockerMTLSBoundary{}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			http.Error(w, "client identity required", http.StatusUnauthorized)
			return
		}
		boundary.authenticatedRequests.Add(1)
		proxy.ServeHTTP(w, r)
	}))
	server.Listener = dockerPartitionListener{Listener: server.Listener, partitioned: &boundary.partitioned}
	clientRoots := x509.NewCertPool()
	if !clientRoots.AppendCertsFromPEM(pki.caCertificate) {
		t.Fatal("append Docker integration client CA")
	}
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{pki.serverCertificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientRoots,
		NextProtos:   []string{"http/1.1"},
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	boundary.server = server
	return boundary
}

func (b *dockerMTLSBoundary) address() string {
	return b.server.Listener.Addr().String()
}

func assertDockerIntegrationFailure(
	t *testing.T,
	err error,
	want biz.FailureCategory,
) {
	t.Helper()
	var executionError *biz.ExecutionError
	if !errors.As(err, &executionError) || executionError.Category != want {
		t.Fatalf("execution error = %v, want category %s", err, want)
	}
	if err.Error() != string(want) || strings.Contains(err.Error(), "runtime-private-key-sentinel") {
		t.Fatalf("unsafe execution error = %q", err)
	}
}

func integrationExecutionPlan(
	stableName, deploymentID string,
	healthCommand []string,
) biz.ExecutionPlan {
	connection, err := runtimeaccess.NewDirectDocker(
		"", "tcp://docker.example.com:2376", "docker.example.com", "secret://target",
	)
	if err != nil {
		panic(err)
	}
	return biz.ExecutionPlan{
		DeploymentID: deploymentID, WorkerID: "integration-worker", FencingToken: 1,
		CutoverSequence: 1,
		ProjectID:       "integration-project", ApplicationID: "integration-application",
		EnvironmentID: "integration-environment", RuntimeTargetID: "integration-target",
		ImageDigest: dockerIntegrationImage, ContainerName: stableName,
		TargetConnection: connection,
		RuntimeSpec: runtimespec.Spec{
			Ports: []runtimespec.Port{{
				Name: "http", ContainerPort: 80, Protocol: "tcp",
			}},
			Resources: runtimespec.Resources{
				CPUMilli: 100, MemoryBytes: 64 * 1024 * 1024,
			},
			HealthCheck: &runtimespec.HealthCheck{
				Command: healthCommand, IntervalSeconds: 1,
				TimeoutSeconds: 1, Retries: 1,
			},
		},
	}
}

func assertRunningDeployment(
	t *testing.T,
	ctx context.Context,
	engine *mobyclient.Client,
	name, deploymentID string,
) {
	t.Helper()
	result, err := engine.ContainerInspect(ctx, name, mobyclient.ContainerInspectOptions{})
	if err != nil {
		t.Fatalf("inspect %s: %v", name, err)
	}
	if result.Container.State == nil || !result.Container.State.Running ||
		result.Container.State.Health == nil ||
		result.Container.State.Health.Status != container.Healthy ||
		result.Container.Config == nil ||
		result.Container.Config.Labels[deploymentLabel] != deploymentID {
		t.Fatalf("container %s is not healthy deployment %s: %+v", name, deploymentID, result.Container)
	}
}

func assertContainerMissing(
	t *testing.T,
	ctx context.Context,
	engine *mobyclient.Client,
	name string,
) {
	t.Helper()
	if _, err := engine.ContainerInspect(
		ctx, name, mobyclient.ContainerInspectOptions{},
	); !cerrdefs.IsNotFound(err) {
		t.Fatalf("container %s still exists: %v", name, err)
	}
}

func localDockerClient() (*mobyclient.Client, error) {
	engine, err := mobyclient.New(
		mobyclient.FromEnv,
	)
	if err != nil {
		return nil, fmt.Errorf("create local Docker client: %w", err)
	}
	return engine, nil
}
