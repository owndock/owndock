package agentruntime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	containertypes "github.com/moby/moby/api/types/container"
	networktypes "github.com/moby/moby/api/types/network"
	mobyclient "github.com/moby/moby/client"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/owndock/owndock/internal/shared/agentprotocol"
	"github.com/owndock/owndock/internal/shared/runtimespec"
)

const agentDockerIntegrationImage = "nginx@sha256:1eff5a5f3fcf8431a0abb7eddf5471fec24e5e1905a2581aeacdb07a4479b92b"

const agentDockerDindIntegrationImage = "docker:29.6.1-dind@sha256:66d292e5c26bd33a6f6f61cacb880de2186339a524ecba1ce098dbbaceed6515"

type isolatedAgentDockerNode struct {
	container  testcontainers.Container
	executor   *DockerExecutor
	inspection *mobyclient.Client
	proxy      *dockerUnixProxy
}

type dockerUnixProxy struct {
	mu            sync.RWMutex
	remoteAddress string
}

func (p *dockerUnixProxy) loadRemoteAddress() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.remoteAddress
}

func (p *dockerUnixProxy) storeRemoteAddress(address string) {
	p.mu.Lock()
	p.remoteAddress = address
	p.mu.Unlock()
}

func TestDockerExecutorIntegration(t *testing.T) {
	if os.Getenv("OWNDOCK_RUN_DOCKER_INTEGRATION") != "1" {
		t.Skip("set OWNDOCK_RUN_DOCKER_INTEGRATION=1 to run the Agent Docker probe integration test")
	}
	stateDirectory := filepath.Join(t.TempDir(), "state")
	cache, err := NewFileResultCache(stateDirectory, 8)
	if err != nil {
		t.Fatal(err)
	}
	cutovers, err := NewFileCutoverStore(stateDirectory, 8)
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewDockerExecutor(
		"/var/run/docker.sock",
		cache,
		cutovers,
	)
	if err != nil {
		t.Fatal(err)
	}
	command := runtimeProbeCommand("integration-command", "integration-target")
	command.Deadline = time.Now().Add(10 * time.Second)
	result, err := executor.Execute(t.Context(), command)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != agentprotocol.AgentCommandSucceeded ||
		result.RuntimeProbe == nil ||
		result.RuntimeProbe.Status != agentprotocol.RuntimeProbeReady {
		t.Fatalf("result = %+v", result)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	inspectionClient, err := mobyclient.New(
		mobyclient.WithHost("unix:///var/run/docker.sock"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = inspectionClient.Close() }()

	stableName := "owndock-agent-integration-" +
		strconv.FormatInt(time.Now().UnixNano(), 36)
	deployment := agentIntegrationDeployment(stableName)
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(
			context.Background(),
			20*time.Second,
		)
		defer cleanupCancel()
		for _, name := range []string{
			stableName,
			candidateContainerName(deployment),
			previousContainerName(deployment),
		} {
			_, _ = inspectionClient.ContainerRemove(
				cleanupContext,
				name,
				mobyclient.ContainerRemoveOptions{Force: true},
			)
		}
	})

	prepare := agentIntegrationCommand(
		"agent-integration-prepare",
		agentprotocol.AgentCommandDeploymentPrepare,
		deployment,
	)
	assertAgentCommandSucceeded(
		t,
		executor,
		ctx,
		prepare,
	)
	stage := agentIntegrationCommand(
		"agent-integration-stage",
		agentprotocol.AgentCommandDeploymentStage,
		deployment,
	)
	assertAgentCommandSucceeded(t, executor, ctx, stage)
	if _, err := inspectionClient.ContainerInspect(
		ctx,
		stableName,
		mobyclient.ContainerInspectOptions{},
	); !cerrdefs.IsNotFound(err) {
		t.Fatalf("stage changed stable container: %v", err)
	}
	candidate, err := inspectionClient.ContainerInspect(
		ctx,
		candidateContainerName(deployment),
		mobyclient.ContainerInspectOptions{},
	)
	if err != nil || candidate.Container.State == nil ||
		!candidate.Container.State.Running {
		t.Fatalf("candidate = %+v, error = %v", candidate.Container, err)
	}

	activate := agentIntegrationCommand(
		"agent-integration-activate",
		agentprotocol.AgentCommandDeploymentActivate,
		deployment,
	)
	assertAgentCommandSucceeded(t, executor, ctx, activate)
	current, err := inspectionClient.ContainerInspect(
		ctx,
		stableName,
		mobyclient.ContainerInspectOptions{},
	)
	if err != nil || !ownsExecution(current, deployment) {
		t.Fatalf("current = %+v, error = %v", current.Container, err)
	}

	cancelCommand := agentIntegrationCommand(
		"agent-integration-cancel",
		agentprotocol.AgentCommandDeploymentCancel,
		deployment,
	)
	assertAgentCommandSucceeded(t, executor, ctx, cancelCommand)
	if _, err := inspectionClient.ContainerInspect(
		ctx,
		stableName,
		mobyclient.ContainerInspectOptions{},
	); !cerrdefs.IsNotFound(err) {
		t.Fatalf("cancel left stable container: %v", err)
	}
}

func TestDockerExecutorTwoIsolatedEnginesIntegration(t *testing.T) {
	if os.Getenv("OWNDOCK_RUN_DOCKER_INTEGRATION") != "1" {
		t.Skip("set OWNDOCK_RUN_DOCKER_INTEGRATION=1 to run the isolated Docker Engine integration test")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Minute)
	defer cancel()
	nodes := []*isolatedAgentDockerNode{
		startIsolatedAgentDockerNode(t, ctx, "host-a"),
		startIsolatedAgentDockerNode(t, ctx, "host-b"),
	}
	for index, node := range nodes {
		result, err := node.executor.Execute(ctx, runtimeProbeCommand(
			fmt.Sprintf("dual-host-initial-probe-%d", index+1),
			fmt.Sprintf("dual-host-target-%d", index+1),
		))
		if err != nil || result.Status != agentprotocol.AgentCommandSucceeded ||
			result.RuntimeProbe == nil || result.RuntimeProbe.Status != agentprotocol.RuntimeProbeReady {
			t.Fatalf("initial Host %d runtime probe = %+v, error = %v", index+1, result, err)
		}
	}

	stableName := "owndock-dual-host-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	deployments := []agentprotocol.DeploymentCommand{
		agentIntegrationDeployment(stableName),
		agentIntegrationDeployment(stableName),
	}
	for index := range deployments {
		deployments[index].DeploymentID = fmt.Sprintf("dual-host-deployment-%d", index+1)
		deployments[index].RuntimeTargetID = fmt.Sprintf("dual-host-target-%d", index+1)
	}
	deployAgentIntegrationFixture(t, ctx, nodes[0].executor, deployments[0], "host-a")
	assertIsolatedAgentContainer(t, ctx, nodes[0], stableName, deployments[0], true)
	assertIsolatedAgentContainer(t, ctx, nodes[1], stableName, deployments[0], false)

	deployAgentIntegrationFixture(t, ctx, nodes[1].executor, deployments[1], "host-b")
	assertIsolatedAgentContainer(t, ctx, nodes[0], stableName, deployments[0], true)
	assertIsolatedAgentContainer(t, ctx, nodes[1], stableName, deployments[1], true)

	stopIsolatedAgentDockerNode(t, ctx, nodes[0], "Host A")
	result, err := nodes[0].executor.Execute(ctx, runtimeProbeCommand(
		"dual-host-partitioned-probe-a", "dual-host-target-1",
	))
	if err != nil || result.Status != agentprotocol.AgentCommandSucceeded ||
		result.RuntimeProbe == nil || result.RuntimeProbe.Status != agentprotocol.RuntimeProbeUnreachable {
		t.Fatalf("partitioned Host A probe = %+v, error = %v", result, err)
	}
	result, err = nodes[1].executor.Execute(ctx, runtimeProbeCommand(
		"dual-host-independent-probe-b", "dual-host-target-2",
	))
	if err != nil || result.Status != agentprotocol.AgentCommandSucceeded ||
		result.RuntimeProbe == nil || result.RuntimeProbe.Status != agentprotocol.RuntimeProbeReady {
		t.Fatalf("Host B probe during Host A outage = %+v, error = %v", result, err)
	}
	assertIsolatedAgentContainer(t, ctx, nodes[1], stableName, deployments[1], true)

	restartIsolatedAgentDockerNode(t, ctx, nodes[0], "Host A")
	waitForIsolatedAgentDockerReady(t, ctx, nodes[0], "dual-host-recovered-probe-a")

	recoveryDeployment := deployments[0]
	recoveryDeployment.FencingToken = 2
	recoveryDeployment.CutoverSequence = 2
	assertAgentCommandSucceeded(t, nodes[0].executor, ctx, agentIntegrationCommand(
		"host-a-partition-prepare", agentprotocol.AgentCommandDeploymentPrepare, recoveryDeployment,
	))
	assertAgentCommandSucceeded(t, nodes[0].executor, ctx, agentIntegrationCommand(
		"host-a-partition-stage", agentprotocol.AgentCommandDeploymentStage, recoveryDeployment,
	))
	stopIsolatedAgentDockerNode(t, ctx, nodes[0], "Host A during activate")
	partitionedActivate := agentIntegrationCommand(
		"host-a-partition-activate", agentprotocol.AgentCommandDeploymentActivate, recoveryDeployment,
	)
	result, err = nodes[0].executor.Execute(ctx, partitionedActivate)
	if err != nil || result.Status != agentprotocol.AgentCommandFailed ||
		result.ErrorCode != "runtime_error" {
		t.Fatalf("partitioned Host A activate = %+v, error = %v", result, err)
	}
	result, err = nodes[1].executor.Execute(ctx, runtimeProbeCommand(
		"dual-host-partition-activate-probe-b", "dual-host-target-2",
	))
	if err != nil || result.RuntimeProbe == nil ||
		result.RuntimeProbe.Status != agentprotocol.RuntimeProbeReady {
		t.Fatalf("Host B during Host A activate partition = %+v, error = %v", result, err)
	}
	restartIsolatedAgentDockerNode(t, ctx, nodes[0], "Host A after activate partition")
	waitForIsolatedAgentDockerReady(t, ctx, nodes[0], "dual-host-activate-recovery-probe-a")
	deployAgentIntegrationFixture(t, ctx, nodes[0].executor, recoveryDeployment, "host-a-retry")
	assertIsolatedAgentContainer(t, ctx, nodes[0], stableName, recoveryDeployment, true)
	assertIsolatedAgentContainer(t, ctx, nodes[1], stableName, deployments[1], true)

	delayed := agentIntegrationCommand(
		"host-a-delayed-old-activate", agentprotocol.AgentCommandDeploymentActivate, deployments[0],
	)
	result, err = nodes[0].executor.Execute(ctx, delayed)
	if err != nil || result.Status != agentprotocol.AgentCommandFailed ||
		result.ErrorCode != "stale_execution" {
		t.Fatalf("delayed old Host A activate = %+v, error = %v", result, err)
	}
	assertIsolatedAgentContainer(t, ctx, nodes[0], stableName, recoveryDeployment, true)
}

func stopIsolatedAgentDockerNode(
	t *testing.T,
	ctx context.Context,
	node *isolatedAgentDockerNode,
	description string,
) {
	t.Helper()
	stopTimeout := 5 * time.Second
	if err := node.container.Stop(ctx, &stopTimeout); err != nil {
		t.Fatalf("stop isolated %s Docker Engine: %v", description, err)
	}
}

func restartIsolatedAgentDockerNode(
	t *testing.T,
	ctx context.Context,
	node *isolatedAgentDockerNode,
	description string,
) {
	t.Helper()
	if err := node.container.Start(ctx); err != nil {
		var logExcerpt []byte
		logs, logErr := node.container.Logs(context.Background())
		if logErr == nil {
			defer logs.Close()
			logExcerpt, _ = io.ReadAll(io.LimitReader(logs, 16*1024))
		}
		t.Fatalf("restart isolated %s Docker Engine: %v; logs=%q", description, err, logExcerpt)
	}
	node.proxy.storeRemoteAddress(
		isolatedDockerRemoteAddress(t, ctx, node.container, "2375/tcp"),
	)
}

func startIsolatedAgentDockerNode(
	t *testing.T,
	ctx context.Context,
	name string,
) *isolatedAgentDockerNode {
	t.Helper()
	const dockerPort = "2375/tcp"
	container, err := testcontainers.GenericContainer(
		ctx,
		testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image:        agentDockerDindIntegrationImage,
				ExposedPorts: []string{dockerPort},
				Env:          map[string]string{"DOCKER_TLS_CERTDIR": ""},
				Cmd: []string{
					"dockerd", "--host=tcp://0.0.0.0:2375", "--tls=false",
					"--storage-driver=vfs",
				},
				WaitingFor: wait.ForListeningPort(dockerPort).
					WithStartupTimeout(90 * time.Second),
				HostConfigModifier: func(config *containertypes.HostConfig) {
					config.Privileged = true
					config.PortBindings = networktypes.PortMap{
						networktypes.MustParsePort(dockerPort): {
							{HostIP: netip.MustParseAddr("127.0.0.1")},
						},
					}
				},
			},
			Started: true,
		},
	)
	if err != nil {
		t.Fatalf("start isolated %s Docker Engine: %v", name, err)
	}
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if err := container.Terminate(
			cleanupContext,
			testcontainers.StopContext(cleanupContext),
			testcontainers.StopTimeout(5*time.Second),
		); err != nil {
			t.Errorf("terminate isolated %s Docker Engine: %v", name, err)
		}
	})
	remoteAddress := isolatedDockerRemoteAddress(t, ctx, container, dockerPort)
	socketPath, proxy := startDockerUnixProxy(t, remoteAddress)
	cache, err := NewFileResultCache(filepath.Join(t.TempDir(), "results"), 32)
	if err != nil {
		t.Fatalf("create isolated %s result cache: %v", name, err)
	}
	cutovers, err := NewFileCutoverStore(filepath.Join(t.TempDir(), "cutovers"), 32)
	if err != nil {
		t.Fatalf("create isolated %s cutover store: %v", name, err)
	}
	executor, err := NewDockerExecutor(socketPath, cache, cutovers)
	if err != nil {
		t.Fatalf("create isolated %s executor: %v", name, err)
	}
	inspection, err := mobyclient.New(mobyclient.WithHost("unix://" + socketPath))
	if err != nil {
		t.Fatalf("create isolated %s inspection client: %v", name, err)
	}
	t.Cleanup(func() { _ = inspection.Close() })
	return &isolatedAgentDockerNode{
		container: container, executor: executor, inspection: inspection, proxy: proxy,
	}
}

func isolatedDockerRemoteAddress(
	t *testing.T,
	ctx context.Context,
	container testcontainers.Container,
	portName string,
) string {
	t.Helper()
	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("resolve isolated Docker Engine host: %v", err)
	}
	port, err := container.MappedPort(ctx, portName)
	if err != nil {
		t.Fatalf("resolve isolated Docker Engine port: %v", err)
	}
	return net.JoinHostPort(host, port.Port())
}

func startDockerUnixProxy(
	t *testing.T,
	remoteAddress string,
) (string, *dockerUnixProxy) {
	t.Helper()
	socketDirectory, err := os.MkdirTemp("/tmp", "owndock-dind-")
	if err != nil {
		t.Fatalf("create isolated Docker Unix proxy directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(socketDirectory); err != nil {
			t.Errorf("remove isolated Docker Unix proxy directory: %v", err)
		}
	})
	socketPath := filepath.Join(socketDirectory, "docker.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen on isolated Docker Unix proxy: %v", err)
	}
	proxyContext, cancelProxy := context.WithCancel(context.Background())
	proxy := &dockerUnixProxy{remoteAddress: remoteAddress}
	t.Cleanup(func() {
		cancelProxy()
		_ = listener.Close()
	})
	go func() {
		for {
			local, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go proxyDockerConnection(proxyContext, local, proxy)
		}
	}()
	return socketPath, proxy
}

func proxyDockerConnection(ctx context.Context, local net.Conn, proxy *dockerUnixProxy) {
	remote, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(
		ctx, "tcp", proxy.loadRemoteAddress(),
	)
	if err != nil {
		_ = local.Close()
		return
	}
	var closeOnce sync.Once
	closeBoth := func() {
		_ = local.Close()
		_ = remote.Close()
	}
	go func() {
		<-ctx.Done()
		closeOnce.Do(closeBoth)
	}()
	copyDone := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(remote, local)
		copyDone <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(local, remote)
		copyDone <- struct{}{}
	}()
	<-copyDone
	closeOnce.Do(closeBoth)
}

func deployAgentIntegrationFixture(
	t *testing.T,
	ctx context.Context,
	executor *DockerExecutor,
	deployment agentprotocol.DeploymentCommand,
	prefix string,
) {
	t.Helper()
	for _, step := range []struct {
		kind agentprotocol.AgentCommandKind
		name string
	}{
		{kind: agentprotocol.AgentCommandDeploymentPrepare, name: "prepare"},
		{kind: agentprotocol.AgentCommandDeploymentStage, name: "stage"},
		{kind: agentprotocol.AgentCommandDeploymentActivate, name: "activate"},
	} {
		assertAgentCommandSucceeded(t, executor, ctx, agentIntegrationCommand(
			prefix+"-"+step.name, step.kind, deployment,
		))
	}
}

func assertIsolatedAgentContainer(
	t *testing.T,
	ctx context.Context,
	node *isolatedAgentDockerNode,
	name string,
	deployment agentprotocol.DeploymentCommand,
	want bool,
) {
	t.Helper()
	inspection, err := node.inspection.ContainerInspect(
		ctx, name, mobyclient.ContainerInspectOptions{},
	)
	if !want {
		if !cerrdefs.IsNotFound(err) {
			t.Fatalf("isolated container %q unexpectedly exists: %+v, error = %v", name, inspection.Container, err)
		}
		return
	}
	if err != nil || !ownsExecution(inspection, deployment) ||
		inspection.Container.State == nil || !inspection.Container.State.Running {
		t.Fatalf("isolated container %q = %+v, error = %v", name, inspection.Container, err)
	}
}

func waitForIsolatedAgentDockerReady(
	t *testing.T,
	ctx context.Context,
	node *isolatedAgentDockerNode,
	commandPrefix string,
) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	var last agentprotocol.AgentCommandResult
	var lastErr error
	for attempt := 1; time.Now().Before(deadline); attempt++ {
		result, err := node.executor.Execute(ctx, runtimeProbeCommand(
			fmt.Sprintf("%s-%d", commandPrefix, attempt),
			"dual-host-target-1",
		))
		last, lastErr = result, err
		if err == nil && result.RuntimeProbe != nil &&
			result.RuntimeProbe.Status == agentprotocol.RuntimeProbeReady {
			return
		}
		if err != nil && !errors.Is(err, context.Canceled) &&
			!errors.Is(err, context.DeadlineExceeded) {
			t.Logf("isolated Docker recovery probe %d: %v", attempt, err)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for isolated Docker recovery: %v", ctx.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}
	t.Fatalf("isolated Docker Engine did not recover within 45 seconds: last=%+v error=%v", last, lastErr)
}

func agentIntegrationDeployment(
	stableName string,
) agentprotocol.DeploymentCommand {
	return agentprotocol.DeploymentCommand{
		DeploymentID:    "agent-integration-deployment",
		WorkerID:        "agent-integration-worker",
		FencingToken:    1,
		CutoverSequence: 1,
		RuntimeTargetID: "agent-integration-target",
		ContainerName:   stableName,
		ProjectID:       "agent-integration-project",
		ApplicationID:   "agent-integration-application",
		EnvironmentID:   "agent-integration-environment",
		ImageDigest:     agentDockerIntegrationImage,
		RuntimeSpec: runtimespec.Spec{
			Resources: runtimespec.Resources{
				CPUMilli:    100,
				MemoryBytes: 64 * 1024 * 1024,
			},
		},
	}
}

func agentIntegrationCommand(
	commandID string,
	kind agentprotocol.AgentCommandKind,
	deployment agentprotocol.DeploymentCommand,
) agentprotocol.AgentCommand {
	switch kind {
	case agentprotocol.AgentCommandDeploymentPrepare:
		deployment.ProjectID = ""
		deployment.ApplicationID = ""
		deployment.EnvironmentID = ""
		deployment.RuntimeSpec = runtimespec.Spec{}
	case agentprotocol.AgentCommandDeploymentActivate,
		agentprotocol.AgentCommandDeploymentCancel:
		deployment.ProjectID = ""
		deployment.ApplicationID = ""
		deployment.EnvironmentID = ""
		deployment.ImageDigest = ""
		deployment.RuntimeSpec = runtimespec.Spec{}
	}
	return agentprotocol.AgentCommand{
		ID:         commandID,
		Kind:       kind,
		Deadline:   time.Now().Add(2 * time.Minute),
		Deployment: &deployment,
	}
}

func assertAgentCommandSucceeded(
	t *testing.T,
	executor *DockerExecutor,
	ctx context.Context,
	command agentprotocol.AgentCommand,
) {
	t.Helper()
	result, err := executor.Execute(ctx, command)
	if err != nil ||
		result.Status != agentprotocol.AgentCommandSucceeded {
		t.Fatalf(
			"%s result = %+v, error = %v",
			command.Kind,
			result,
			err,
		)
	}
}
