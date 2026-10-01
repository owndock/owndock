package agentruntime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	mobyclient "github.com/moby/moby/client"

	applicationroutebiz "github.com/owndock/owndock/internal/modules/applicationroute/biz"
	applicationroutedata "github.com/owndock/owndock/internal/modules/applicationroute/data"
	deploymentbiz "github.com/owndock/owndock/internal/modules/deployment/biz"
	deploymentdata "github.com/owndock/owndock/internal/modules/deployment/data"
	deploymentworker "github.com/owndock/owndock/internal/modules/deployment/worker"
	managedhostbiz "github.com/owndock/owndock/internal/modules/managedhost/biz"
	"github.com/owndock/owndock/internal/shared/agentprotocol"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/runtimespec"
)

func TestManagedIngressDeploymentWorkerEngineAndGatewayIntegration(t *testing.T) {
	if os.Getenv("OWNDOCK_RUN_INGRESS_INTEGRATION") != "1" {
		t.Skip("set OWNDOCK_RUN_INGRESS_INTEGRATION=1 to run the managed ingress integration test")
	}
	if runtime.GOOS != "linux" {
		t.Skip("managed ingress Unix socket integration requires a Linux Docker host")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	inspection, err := mobyclient.New(mobyclient.WithHost("unix:///var/run/docker.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inspection.Close() })
	createManagedIngressIntegrationNetwork(t, ctx, inspection)

	stableName := "owndock-ingress-worker-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	plans := []deploymentbiz.ExecutionPlan{
		managedIngressIntegrationPlan(t, stableName, "worker-deployment-one", 1),
		managedIngressIntegrationPlan(t, stableName, "worker-deployment-two", 2),
		managedIngressIntegrationPlan(t, stableName, "worker-deployment-bad", 3),
	}
	const applicationSecret = "managed-ingress-application-secret-sentinel"
	for index := range plans {
		plans[index].RuntimeSpec.EnvironmentKeys = []string{"APPLICATION_SECRET"}
		plans[index].Environment = []string{"APPLICATION_SECRET=" + applicationSecret}
	}
	// The fixed nginx image listens on 80. A declared port of 81 lets the
	// candidate become ready while forcing the private ingress probe to fail.
	plans[2].RuntimeSpec.Ports[0].ContainerPort = 81
	cleanupManagedIngressRuntimeContainers(t, inspection, stableName, plans)

	socketDirectory, err := os.MkdirTemp("/tmp", "owndock-worker-ingress-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(socketDirectory); err != nil {
			t.Errorf("remove ingress socket directory: %v", err)
		}
	})
	if err := os.Chmod(socketDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	adminSocket := filepath.Join(socketDirectory, "admin.sock")
	caddyContainer, publicAddress := startIngressCaddy(
		t, ctx, agentprotocol.ManagedIngressNetwork, socketDirectory, adminSocket,
	)
	waitForUnixSocket(t, ctx, adminSocket)

	caddy, err := NewCaddyGateway(CaddyGatewayConfig{
		AdminSocket: adminSocket, RequestTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	caddy.probeClient = ingressIntegrationHTTPClient(publicAddress)
	ingressStateDirectory := restrictedTempDirectory(t)
	ingressStore, err := NewFileIngressFenceStore(ingressStateDirectory, 8)
	if err != nil {
		t.Fatal(err)
	}
	ingress, err := NewIngressExecutor(ingressStore, caddy)
	if err != nil {
		t.Fatal(err)
	}
	stateDirectory := filepath.Join(t.TempDir(), "agent-state")
	cache, err := NewFileResultCache(stateDirectory, 32)
	if err != nil {
		t.Fatal(err)
	}
	cutovers, err := NewFileCutoverStore(stateDirectory, 8)
	if err != nil {
		t.Fatal(err)
	}
	agent, err := NewDockerExecutor("/var/run/docker.sock", cache, cutovers)
	if err != nil {
		t.Fatal(err)
	}
	agent.newDeploymentEngine = func(socketPath string) (dockerDeploymentEngine, error) {
		engine, err := newLocalDockerDeploymentEngine(socketPath)
		if err != nil {
			return nil, err
		}
		return &managedIngressDiagnosticEngine{dockerDeploymentEngine: engine, t: t}, nil
	}
	if err := agent.WithIngress(ingress); err != nil {
		t.Fatal(err)
	}

	const hostID = "managed-ingress-host"
	dispatcher := &managedIngressIntegrationDispatcher{hostID: hostID, executor: agent, t: t}
	var commandSequence atomic.Uint64
	newCommandID := func() (string, error) {
		return fmt.Sprintf("worker-integration-command-%d", commandSequence.Add(1)), nil
	}
	clock := time.Now
	fence := &managedIngressIntegrationFence{}
	runtimeGateway, err := deploymentdata.NewAgentDockerGateway(
		dispatcher, fence, newCommandID, clock, 30*time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	routeGateway, err := applicationroutedata.NewAgentGateway(
		dispatcher, newCommandID, clock, 30*time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	serverStore := &managedIngressIntegrationCutoverStore{}
	coordinator, err := applicationroutebiz.NewCutoverCoordinator(serverStore, routeGateway)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &managedIngressIntegrationResolver{}
	executor, err := deploymentworker.NewRuntimeExecutor(
		resolver, managedIngressIntegrationCredentialResolver{}, runtimeGateway,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.WithManagedIngress(coordinator, 0); err != nil {
		t.Fatal(err)
	}

	const hostname = "worker.example.com"
	for index := range plans[:2] {
		plan := plans[index]
		resolver.plan = plan
		fence.plan = plan
		serverStore.configure(managedIngressIntegrationDesired(t, plan, hostname, uint64(index+1)))
		deployment := deploymentbiz.Deployment{
			ID: plan.DeploymentID, OrganizationID: "integration-organization",
		}
		if err := executor.Prepare(ctx, deployment); err != nil {
			t.Fatalf("prepare deployment %d: %v", index+1, err)
		}
		if err := executor.Deploy(ctx, deployment); err != nil {
			logs, logsErr := boundedIngressContainerLogs(ctx, caddyContainer)
			t.Fatalf("deploy deployment %d: %v; gateway_logs=%q logs_error=%v",
				index+1, err, logs, logsErr)
		}
		assertManagedIngressRuntimeOwner(t, ctx, inspection, stableName, plan)
		assertIngressResponse(t, ctx, publicAddress, hostname, http.StatusOK, "")
		if err := executor.MarkControlPlaneCommitted(ctx, deployment); err != nil {
			t.Fatalf("mark deployment %d committed: %v", index+1, err)
		}
		if err := executor.Commit(ctx, deployment); err != nil {
			t.Fatalf("commit deployment %d: %v", index+1, err)
		}
		if !serverStore.finished {
			t.Fatalf("deployment %d cutover was not finished", index+1)
		}
		identity := managedIngressIntegrationDeploymentCommand(plan)
		if _, err := inspection.ContainerInspect(
			ctx, previousContainerName(identity), mobyclient.ContainerInspectOptions{},
		); !cerrdefs.IsNotFound(err) {
			t.Fatalf("deployment %d previous runtime still exists: %v", index+1, err)
		}
	}

	failedPlan := plans[2]
	resolver.plan = failedPlan
	fence.plan = failedPlan
	serverStore.configure(managedIngressIntegrationDesired(t, failedPlan, hostname, 3))
	failedDeployment := deploymentbiz.Deployment{
		ID: failedPlan.DeploymentID, OrganizationID: "integration-organization",
	}
	if err := executor.Prepare(ctx, failedDeployment); err != nil {
		t.Fatalf("prepare failed deployment fixture: %v", err)
	}
	err = executor.Deploy(ctx, failedDeployment)
	if !errors.Is(err, applicationroutebiz.ErrGatewayBackendUnhealthy) {
		t.Fatalf("failed cutover error = %v", err)
	}
	if !serverStore.aborted ||
		serverStore.failure != applicationroutebiz.FailureBackendUnhealthy {
		t.Fatalf("failed cutover transaction = aborted %t failure %q",
			serverStore.aborted, serverStore.failure)
	}
	assertManagedIngressRuntimeOwner(t, ctx, inspection, stableName, plans[1])
	assertIngressResponse(t, ctx, publicAddress, hostname, http.StatusOK, "")
	failedIdentity := managedIngressIntegrationDeploymentCommand(failedPlan)
	if _, err := inspection.ContainerInspect(
		ctx, candidateContainerName(failedIdentity), mobyclient.ContainerInspectOptions{},
	); !cerrdefs.IsNotFound(err) {
		t.Fatalf("failed cutover candidate still exists: %v", err)
	}
	if fence.calls != 3 {
		t.Fatalf("activation and rollback fence calls = %d, want 3", fence.calls)
	}
	retirementStore := &managedIngressIntegrationRetirementStore{
		transaction: applicationroutebiz.RouteRetirementTransaction{
			RouteID: "worker-route", OrganizationID: "integration-organization",
			Desired: applicationroutebiz.HostDesiredConfig{
				ManagedHostID: hostID, HostRevision: 4,
				Routes: []applicationroutebiz.GatewayRoute{}, ProbeRouteIDs: []string{},
			},
		},
	}
	retirement, err := applicationroutebiz.NewRetirementCoordinator(
		retirementStore, routeGateway,
	)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		completed, retireErr := retirement.Retire(ctx, "worker-route")
		if retireErr != nil || !completed {
			t.Fatalf("retire managed route attempt %d = %t, %v", attempt+1, completed, retireErr)
		}
	}
	if retirementStore.prepared != 1 || retirementStore.committed != 1 ||
		retirementStore.finished != 1 {
		t.Fatalf("route retirement phases = %d/%d/%d", retirementStore.prepared,
			retirementStore.committed, retirementStore.finished)
	}
	assertIngressResponse(t, ctx, publicAddress, hostname, http.StatusNotFound, "")
	assertManagedIngressSecretAbsent(
		t, applicationSecret, stateDirectory, ingressStateDirectory, socketDirectory,
	)
	logs, err := caddyContainer.Logs(ctx)
	if err != nil {
		t.Fatalf("read managed Ingress Gateway logs: %v", err)
	}
	logValue, readErr := io.ReadAll(io.LimitReader(logs, 4*1024*1024+1))
	closeErr := logs.Close()
	if readErr != nil || closeErr != nil || len(logValue) > 4*1024*1024 {
		t.Fatalf("read bounded managed Ingress Gateway logs: read=%v close=%v bytes=%d",
			readErr, closeErr, len(logValue))
	}
	if bytes.Contains(logValue, []byte(applicationSecret)) {
		t.Fatal("application secret leaked into managed Ingress Gateway logs")
	}
}

type managedIngressIntegrationDispatcher struct {
	hostID   string
	executor *DockerExecutor
	t        *testing.T
}

type managedIngressDiagnosticEngine struct {
	dockerDeploymentEngine
	t *testing.T
}

func (e *managedIngressDiagnosticEngine) ContainerCreate(
	ctx context.Context,
	options mobyclient.ContainerCreateOptions,
) (mobyclient.ContainerCreateResult, error) {
	result, err := e.dockerDeploymentEngine.ContainerCreate(ctx, options)
	if err != nil {
		e.t.Logf("managed ingress Docker ContainerCreate failed: %v", err)
	}
	return result, err
}

func (e *managedIngressDiagnosticEngine) ContainerStart(
	ctx context.Context,
	containerID string,
	options mobyclient.ContainerStartOptions,
) (mobyclient.ContainerStartResult, error) {
	result, err := e.dockerDeploymentEngine.ContainerStart(ctx, containerID, options)
	if err != nil {
		e.t.Logf("managed ingress Docker ContainerStart failed: %v", err)
	}
	return result, err
}

func (e *managedIngressDiagnosticEngine) ContainerInspect(
	ctx context.Context,
	containerID string,
	options mobyclient.ContainerInspectOptions,
) (mobyclient.ContainerInspectResult, error) {
	result, err := e.dockerDeploymentEngine.ContainerInspect(ctx, containerID, options)
	if err != nil && !cerrdefs.IsNotFound(err) {
		e.t.Logf("managed ingress Docker ContainerInspect failed: %v", err)
	}
	if err == nil && result.Container.State != nil &&
		!result.Container.State.Running && result.Container.State.Status != "created" {
		e.t.Logf("managed ingress candidate stopped: status=%s exit=%d error=%q",
			result.Container.State.Status, result.Container.State.ExitCode,
			result.Container.State.Error)
	}
	return result, err
}

func (e *managedIngressDiagnosticEngine) NetworkInspect(
	ctx context.Context,
	networkID string,
	options mobyclient.NetworkInspectOptions,
) (mobyclient.NetworkInspectResult, error) {
	result, err := e.dockerDeploymentEngine.NetworkInspect(ctx, networkID, options)
	if err != nil {
		e.t.Logf("managed ingress Docker NetworkInspect failed: %v", err)
	}
	return result, err
}

func (d *managedIngressIntegrationDispatcher) Dispatch(
	ctx context.Context,
	hostID string,
	command managedhostbiz.AgentCommand,
) (managedhostbiz.AgentCommandResult, error) {
	if hostID != d.hostID {
		return managedhostbiz.AgentCommandResult{}, managedhostbiz.ErrAgentNotConnected
	}
	result, err := d.executor.Execute(ctx, command)
	if err != nil {
		d.t.Logf("managed ingress Agent command %s failed transport: %v", command.Kind, err)
	} else if result.Status != agentprotocol.AgentCommandSucceeded {
		d.t.Logf("managed ingress Agent command %s failed safely: %s", command.Kind, result.ErrorCode)
	}
	return result, err
}

type managedIngressIntegrationResolver struct {
	plan deploymentbiz.ExecutionPlan
}

func (r *managedIngressIntegrationResolver) ResolveExecution(
	context.Context,
	deploymentbiz.Deployment,
) (deploymentbiz.ExecutionPlan, error) {
	return r.plan, nil
}

type managedIngressIntegrationCredentialResolver struct{}

func (managedIngressIntegrationCredentialResolver) ResolveCredential(
	context.Context,
	runtimeaccess.Connection,
) (deploymentbiz.RuntimeCredential, error) {
	return deploymentbiz.RuntimeCredential{}, nil
}

type managedIngressIntegrationFence struct {
	plan  deploymentbiz.ExecutionPlan
	calls int
}

func (f *managedIngressIntegrationFence) ValidateFence(
	_ context.Context,
	projectID string,
	deploymentID string,
	workerID string,
	token uint64,
	_ time.Time,
) error {
	f.calls++
	if projectID != f.plan.ProjectID || deploymentID != f.plan.DeploymentID ||
		workerID != f.plan.WorkerID || token != f.plan.FencingToken {
		return deploymentbiz.ErrCutoverConflict
	}
	return nil
}

type managedIngressIntegrationCutoverStore struct {
	desired     applicationroutebiz.HostDesiredConfig
	transaction applicationroutebiz.CutoverTransaction
	exists      bool
	finished    bool
	aborted     bool
	failure     applicationroutebiz.FailureCode
}

type managedIngressIntegrationRetirementStore struct {
	transaction applicationroutebiz.RouteRetirementTransaction
	completed   bool
	prepared    int
	committed   int
	finished    int
}

func (s *managedIngressIntegrationRetirementStore) Begin(
	context.Context,
	string,
) (applicationroutebiz.RouteRetirementTransaction, bool, error) {
	return s.transaction, s.completed, nil
}

func (s *managedIngressIntegrationRetirementStore) MarkPrepared(
	_ context.Context,
	transaction applicationroutebiz.RouteRetirementTransaction,
	observation applicationroutebiz.GatewayObservation,
) error {
	if transaction.Desired.HostRevision != observation.HostRevision {
		return applicationroutebiz.ErrRetirementConflict
	}
	s.prepared++
	return nil
}

func (s *managedIngressIntegrationRetirementStore) MarkGatewayCommitted(
	_ context.Context,
	transaction applicationroutebiz.RouteRetirementTransaction,
	observation applicationroutebiz.GatewayObservation,
) error {
	if transaction.Desired.HostRevision != observation.HostRevision {
		return applicationroutebiz.ErrRetirementConflict
	}
	s.committed++
	return nil
}

func (s *managedIngressIntegrationRetirementStore) Finish(
	context.Context,
	applicationroutebiz.RouteRetirementTransaction,
) error {
	s.finished++
	s.completed = true
	return nil
}

func (s *managedIngressIntegrationCutoverStore) configure(
	desired applicationroutebiz.HostDesiredConfig,
) {
	s.desired = desired
	s.transaction = applicationroutebiz.CutoverTransaction{}
	s.exists, s.finished, s.aborted, s.failure = false, false, false, ""
}

func (*managedIngressIntegrationCutoverStore) Required(
	context.Context,
	applicationroutebiz.CutoverRequest,
) (bool, error) {
	return true, nil
}

func (s *managedIngressIntegrationCutoverStore) Begin(
	_ context.Context,
	request applicationroutebiz.CutoverRequest,
) (applicationroutebiz.CutoverTransaction, error) {
	if s.exists {
		return s.transaction, nil
	}
	s.transaction = applicationroutebiz.CutoverTransaction{
		Request: request, Desired: s.desired,
	}
	s.exists = true
	return s.transaction, nil
}

func (s *managedIngressIntegrationCutoverStore) Prepared(
	_ context.Context,
	transaction applicationroutebiz.CutoverTransaction,
	observation applicationroutebiz.GatewayObservation,
) error {
	if !s.exists || transaction.Desired.HostRevision != observation.HostRevision {
		return applicationroutebiz.ErrCutoverConflict
	}
	return nil
}

func (s *managedIngressIntegrationCutoverStore) MarkControlPlaneCommitted(
	_ context.Context,
	request applicationroutebiz.CutoverRequest,
) error {
	if !s.exists || !s.transaction.Request.SameCutover(request) {
		return applicationroutebiz.ErrCutoverConflict
	}
	s.transaction.ControlPlaneCommitted = true
	return nil
}

func (s *managedIngressIntegrationCutoverStore) Get(
	_ context.Context,
	deploymentID string,
) (applicationroutebiz.CutoverTransaction, bool, error) {
	if !s.exists || s.transaction.Request.DeploymentID != deploymentID {
		return applicationroutebiz.CutoverTransaction{}, false, nil
	}
	return s.transaction, true, nil
}

func (s *managedIngressIntegrationCutoverStore) Complete(
	_ context.Context,
	transaction applicationroutebiz.CutoverTransaction,
	observation applicationroutebiz.GatewayObservation,
) error {
	if !s.exists || transaction.Desired.HostRevision != observation.HostRevision {
		return applicationroutebiz.ErrCutoverConflict
	}
	return nil
}

func (s *managedIngressIntegrationCutoverStore) Finish(
	context.Context,
	applicationroutebiz.CutoverTransaction,
) error {
	s.exists, s.finished = false, true
	return nil
}

func (s *managedIngressIntegrationCutoverStore) Abort(
	_ context.Context,
	_ applicationroutebiz.CutoverTransaction,
	failure applicationroutebiz.FailureCode,
) error {
	s.exists, s.aborted = false, true
	s.failure = failure
	return nil
}

func managedIngressIntegrationPlan(
	t *testing.T,
	containerName string,
	deploymentID string,
	sequence uint64,
) deploymentbiz.ExecutionPlan {
	t.Helper()
	connection, err := runtimeaccess.NewAgent("managed-ingress-host")
	if err != nil {
		t.Fatal(err)
	}
	return deploymentbiz.ExecutionPlan{
		DeploymentID: deploymentID, WorkerID: "worker-one",
		FencingToken: sequence, CutoverSequence: sequence,
		ProjectID: "integration-project", ApplicationID: "integration-application",
		EnvironmentID: "integration-environment", RuntimeTargetID: "integration-target",
		ImageDigest: agentDockerIntegrationImage, TargetConnection: connection,
		ContainerName: containerName,
		RuntimeSpec: runtimespec.Spec{
			Ports:     []runtimespec.Port{{Name: "http", ContainerPort: 80, Protocol: "tcp"}},
			Resources: runtimespec.Resources{CPUMilli: 100, MemoryBytes: 64 * 1024 * 1024},
		},
	}
}

func managedIngressIntegrationDesired(
	t *testing.T,
	plan deploymentbiz.ExecutionPlan,
	hostname string,
	hostRevision uint64,
) applicationroutebiz.HostDesiredConfig {
	t.Helper()
	alias, err := agentprotocol.DeploymentBackendAlias(plan.DeploymentID)
	if err != nil {
		t.Fatal(err)
	}
	return applicationroutebiz.HostDesiredConfig{
		ManagedHostID: plan.TargetConnection.ManagedHostID,
		HostRevision:  hostRevision,
		Routes: []applicationroutebiz.GatewayRoute{{
			RouteID: "worker-route", Revision: hostRevision,
			DeploymentID: plan.DeploymentID, CutoverSequence: plan.CutoverSequence,
			RuntimeTargetID: plan.RuntimeTargetID, Hostname: hostname,
			BackendAlias: alias, BackendPort: plan.RuntimeSpec.Ports[0].ContainerPort,
			TLSMode: applicationroutebiz.TLSModeDisabled,
		}},
		ProbeRouteIDs: []string{"worker-route"},
	}
}

func managedIngressIntegrationDeploymentCommand(
	plan deploymentbiz.ExecutionPlan,
) agentprotocol.DeploymentCommand {
	return agentprotocol.DeploymentCommand{
		DeploymentID: plan.DeploymentID, WorkerID: plan.WorkerID,
		FencingToken: plan.FencingToken, CutoverSequence: plan.CutoverSequence,
		RuntimeTargetID: plan.RuntimeTargetID, ContainerName: plan.ContainerName,
	}
}

func createManagedIngressIntegrationNetwork(
	t *testing.T,
	ctx context.Context,
	client *mobyclient.Client,
) {
	t.Helper()
	if _, err := client.NetworkInspect(
		ctx, agentprotocol.ManagedIngressNetwork, mobyclient.NetworkInspectOptions{},
	); err == nil {
		t.Fatalf("managed ingress integration network %q already exists", agentprotocol.ManagedIngressNetwork)
	} else if !cerrdefs.IsNotFound(err) {
		t.Fatalf("inspect managed ingress integration network: %v", err)
	}
	created, err := client.NetworkCreate(
		ctx,
		agentprotocol.ManagedIngressNetwork,
		mobyclient.NetworkCreateOptions{Driver: "bridge"},
	)
	if err != nil {
		t.Fatalf("create managed ingress integration network: %v", err)
	}
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()
		if _, err := client.NetworkRemove(
			cleanupContext, created.ID, mobyclient.NetworkRemoveOptions{},
		); err != nil && !cerrdefs.IsNotFound(err) {
			t.Errorf("remove managed ingress integration network: %v", err)
		}
	})
}

func cleanupManagedIngressRuntimeContainers(
	t *testing.T,
	client *mobyclient.Client,
	stableName string,
	plans []deploymentbiz.ExecutionPlan,
) {
	t.Helper()
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()
		names := []string{stableName}
		for _, plan := range plans {
			identity := managedIngressIntegrationDeploymentCommand(plan)
			names = append(names, candidateContainerName(identity), previousContainerName(identity))
		}
		for _, name := range names {
			_, err := client.ContainerRemove(
				cleanupContext, name, mobyclient.ContainerRemoveOptions{Force: true, RemoveVolumes: true},
			)
			if err != nil && !cerrdefs.IsNotFound(err) {
				t.Errorf("remove managed ingress integration container %s: %v", name, err)
			}
		}
	})
}

func assertManagedIngressRuntimeOwner(
	t *testing.T,
	ctx context.Context,
	client *mobyclient.Client,
	stableName string,
	plan deploymentbiz.ExecutionPlan,
) {
	t.Helper()
	inspection, err := client.ContainerInspect(
		ctx, stableName, mobyclient.ContainerInspectOptions{},
	)
	identity := managedIngressIntegrationDeploymentCommand(plan)
	if err != nil || !ownsExecution(inspection, identity) ||
		inspection.Container.State == nil || !inspection.Container.State.Running {
		t.Fatalf("managed ingress runtime %s = %+v, error = %v", stableName, inspection.Container, err)
	}
}

func assertManagedIngressSecretAbsent(
	t *testing.T,
	secret string,
	directories ...string,
) {
	t.Helper()
	for _, directory := range directories {
		err := filepath.Walk(directory, func(path string, info os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if !info.Mode().IsRegular() {
				return nil
			}
			if info.Size() > 8*1024*1024 {
				return fmt.Errorf("managed Ingress secret-scan file is too large: %s", path)
			}
			value, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if bytes.Contains(value, []byte(secret)) {
				return fmt.Errorf("application secret leaked into %s", path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

var _ managedhostbiz.AgentCommandDispatcher = (*managedIngressIntegrationDispatcher)(nil)
var _ deploymentbiz.ExecutionResolver = (*managedIngressIntegrationResolver)(nil)
var _ deploymentbiz.CredentialResolver = managedIngressIntegrationCredentialResolver{}
var _ deploymentbiz.FenceValidator = (*managedIngressIntegrationFence)(nil)
var _ applicationroutebiz.CutoverStore = (*managedIngressIntegrationCutoverStore)(nil)
var _ applicationroutebiz.RouteRetirementStore = (*managedIngressIntegrationRetirementStore)(nil)
