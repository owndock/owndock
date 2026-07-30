package agentruntime

import (
	"context"
	"io"
	"iter"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/jsonstream"
	mobyclient "github.com/moby/moby/client"

	"github.com/owndock/owndock/internal/shared/agentprotocol"
	"github.com/owndock/owndock/internal/shared/runtimespec"
)

type agentImagePullStub struct{}

func (agentImagePullStub) Read([]byte) (int, error) { return 0, io.EOF }
func (agentImagePullStub) Close() error             { return nil }
func (agentImagePullStub) JSONMessages(
	context.Context,
) iter.Seq2[jsonstream.Message, error] {
	return func(func(jsonstream.Message, error) bool) {}
}
func (agentImagePullStub) Wait(context.Context) error { return nil }

type agentDockerEngineStub struct {
	containers  map[string]mobyclient.ContainerInspectResult
	names       map[string]string
	nextID      int
	imageExists bool
	pullAuth    string
	pullCount   int
	unhealthy   bool
}

func newAgentDockerEngineStub() *agentDockerEngineStub {
	return &agentDockerEngineStub{
		containers: make(map[string]mobyclient.ContainerInspectResult),
		names:      make(map[string]string),
	}
}

func (e *agentDockerEngineStub) Ping(
	context.Context,
	mobyclient.PingOptions,
) (mobyclient.PingResult, error) {
	return mobyclient.PingResult{}, nil
}

func (e *agentDockerEngineStub) ImageInspect(
	context.Context,
	string,
	...mobyclient.ImageInspectOption,
) (mobyclient.ImageInspectResult, error) {
	if !e.imageExists {
		return mobyclient.ImageInspectResult{}, cerrdefs.ErrNotFound
	}
	return mobyclient.ImageInspectResult{}, nil
}

func (e *agentDockerEngineStub) ImagePull(
	_ context.Context,
	_ string,
	options mobyclient.ImagePullOptions,
) (mobyclient.ImagePullResponse, error) {
	e.pullCount++
	e.pullAuth = options.RegistryAuth
	e.imageExists = true
	return agentImagePullStub{}, nil
}

func (e *agentDockerEngineStub) ContainerInspect(
	_ context.Context,
	name string,
	_ mobyclient.ContainerInspectOptions,
) (mobyclient.ContainerInspectResult, error) {
	id := name
	if namedID := e.names[name]; namedID != "" {
		id = namedID
	}
	result, exists := e.containers[id]
	if !exists {
		return mobyclient.ContainerInspectResult{}, cerrdefs.ErrNotFound
	}
	return result, nil
}

func (e *agentDockerEngineStub) ContainerCreate(
	_ context.Context,
	options mobyclient.ContainerCreateOptions,
) (mobyclient.ContainerCreateResult, error) {
	e.nextID++
	id := "container-" + strconv.Itoa(e.nextID)
	e.containers[id] = mobyclient.ContainerInspectResult{
		Container: container.InspectResponse{
			ID:     id,
			Config: options.Config,
			State: &container.State{
				Status: container.StateCreated,
			},
		},
	}
	e.names[options.Name] = id
	return mobyclient.ContainerCreateResult{ID: id}, nil
}

func (e *agentDockerEngineStub) ContainerStart(
	_ context.Context,
	id string,
	_ mobyclient.ContainerStartOptions,
) (mobyclient.ContainerStartResult, error) {
	result := e.containers[id]
	result.Container.State = &container.State{
		Status:  container.StateRunning,
		Running: true,
	}
	if result.Container.Config.Healthcheck != nil {
		status := container.Healthy
		if e.unhealthy {
			status = container.Unhealthy
		}
		result.Container.State.Health = &container.Health{Status: status}
	}
	e.containers[id] = result
	return mobyclient.ContainerStartResult{}, nil
}

func (e *agentDockerEngineStub) ContainerRemove(
	_ context.Context,
	id string,
	_ mobyclient.ContainerRemoveOptions,
) (mobyclient.ContainerRemoveResult, error) {
	if namedID := e.names[id]; namedID != "" {
		id = namedID
	}
	if _, exists := e.containers[id]; !exists {
		return mobyclient.ContainerRemoveResult{}, cerrdefs.ErrNotFound
	}
	delete(e.containers, id)
	for name, namedID := range e.names {
		if namedID == id {
			delete(e.names, name)
		}
	}
	return mobyclient.ContainerRemoveResult{}, nil
}

func (e *agentDockerEngineStub) ContainerRename(
	_ context.Context,
	id string,
	options mobyclient.ContainerRenameOptions,
) (mobyclient.ContainerRenameResult, error) {
	if _, exists := e.containers[id]; !exists {
		return mobyclient.ContainerRenameResult{}, cerrdefs.ErrNotFound
	}
	if occupied := e.names[options.NewName]; occupied != "" &&
		occupied != id {
		return mobyclient.ContainerRenameResult{},
			cerrdefs.ErrAlreadyExists
	}
	for name, namedID := range e.names {
		if namedID == id {
			delete(e.names, name)
		}
	}
	e.names[options.NewName] = id
	return mobyclient.ContainerRenameResult{}, nil
}

func (*agentDockerEngineStub) Close() error { return nil }

func TestAgentDockerDeploymentPrepareIsIdempotentAndForwardsAuth(
	t *testing.T,
) {
	executor, engine := newDeploymentExecutor(t)
	command := deploymentCommand(
		"prepare-1",
		agentprotocol.AgentCommandDeploymentPrepare,
	)
	command.Deployment.RegistryAuthorization = []byte("encoded-auth")
	first, err := executor.Execute(t.Context(), command)
	if err != nil || first.Status != agentprotocol.AgentCommandSucceeded {
		t.Fatalf("first result = %+v, error = %v", first, err)
	}
	second, err := executor.Execute(t.Context(), command)
	if err != nil || !first.Equivalent(second) {
		t.Fatalf("second result = %+v, error = %v", second, err)
	}
	if engine.pullCount != 1 || engine.pullAuth != "encoded-auth" {
		t.Fatalf(
			"pull count = %d, auth = %q",
			engine.pullCount,
			engine.pullAuth,
		)
	}
}

func TestAgentDockerDeploymentStagesAndActivatesCandidate(t *testing.T) {
	executor, engine := newDeploymentExecutor(t)
	stage := deploymentCommand(
		"stage-1",
		agentprotocol.AgentCommandDeploymentStage,
	)
	addManagedContainer(
		engine,
		stage.Deployment.ContainerName,
		"old-container",
		"old-deployment",
		1,
		0,
		true,
	)
	result, err := executor.Execute(t.Context(), stage)
	if err != nil || result.Status != agentprotocol.AgentCommandSucceeded {
		t.Fatalf("stage result = %+v, error = %v", result, err)
	}
	candidateName := candidateContainerName(*stage.Deployment)
	candidate, err := engine.ContainerInspect(
		t.Context(),
		candidateName,
		mobyclient.ContainerInspectOptions{},
	)
	if err != nil ||
		candidate.Container.Config.Labels[projectLabel] != "project-1" ||
		candidate.Container.Config.Env[0] != "MODE=production" ||
		!candidate.Container.State.Running {
		t.Fatalf("candidate = %+v, error = %v", candidate, err)
	}

	activate := deploymentCommand(
		"activate-1",
		agentprotocol.AgentCommandDeploymentActivate,
	)
	result, err = executor.Execute(t.Context(), activate)
	if err != nil || result.Status != agentprotocol.AgentCommandSucceeded {
		t.Fatalf("activate result = %+v, error = %v", result, err)
	}
	current, err := engine.ContainerInspect(
		t.Context(),
		activate.Deployment.ContainerName,
		mobyclient.ContainerInspectOptions{},
	)
	if err != nil || !ownsExecution(current, *activate.Deployment) {
		t.Fatalf("current = %+v, error = %v", current, err)
	}
	if _, exists := engine.containers["old-container"]; exists {
		t.Fatal("previous managed container was not removed")
	}
}

func TestAgentDockerDeploymentRejectsDelayedOlderActivation(t *testing.T) {
	executor, engine := newDeploymentExecutor(t)
	olderStage := deploymentCommand(
		"stage-older",
		agentprotocol.AgentCommandDeploymentStage,
	)
	olderStage.Deployment.DeploymentID = "deployment-older"
	olderStage.Deployment.CutoverSequence = 10
	newerStage := deploymentCommand(
		"stage-newer",
		agentprotocol.AgentCommandDeploymentStage,
	)
	newerStage.Deployment.DeploymentID = "deployment-newer"
	newerStage.Deployment.CutoverSequence = 11

	for _, command := range []agentprotocol.AgentCommand{
		olderStage,
		newerStage,
	} {
		result, err := executor.Execute(t.Context(), command)
		if err != nil || result.Status != agentprotocol.AgentCommandSucceeded {
			t.Fatalf(
				"%s result = %+v, error = %v",
				command.ID,
				result,
				err,
			)
		}
	}

	newerActivate := deploymentCommand(
		"activate-newer",
		agentprotocol.AgentCommandDeploymentActivate,
	)
	newerActivate.Deployment.DeploymentID = newerStage.Deployment.DeploymentID
	newerActivate.Deployment.CutoverSequence =
		newerStage.Deployment.CutoverSequence
	result, err := executor.Execute(t.Context(), newerActivate)
	if err != nil || result.Status != agentprotocol.AgentCommandSucceeded {
		t.Fatalf("newer activate result = %+v, error = %v", result, err)
	}

	olderActivate := deploymentCommand(
		"activate-older-delayed",
		agentprotocol.AgentCommandDeploymentActivate,
	)
	olderActivate.Deployment.DeploymentID = olderStage.Deployment.DeploymentID
	olderActivate.Deployment.CutoverSequence =
		olderStage.Deployment.CutoverSequence
	result, err = executor.Execute(t.Context(), olderActivate)
	if err != nil ||
		result.Status != agentprotocol.AgentCommandFailed ||
		result.ErrorCode != "stale_execution" {
		t.Fatalf("older activate result = %+v, error = %v", result, err)
	}

	current, err := engine.ContainerInspect(
		t.Context(),
		newerActivate.Deployment.ContainerName,
		mobyclient.ContainerInspectOptions{},
	)
	if err != nil || !ownsExecution(current, *newerActivate.Deployment) {
		t.Fatalf("stable container = %+v, error = %v", current, err)
	}
	if _, err := engine.ContainerInspect(
		t.Context(),
		candidateContainerName(*olderStage.Deployment),
		mobyclient.ContainerInspectOptions{},
	); !cerrdefs.IsNotFound(err) {
		t.Fatalf("delayed older candidate was not cleaned up: %v", err)
	}
}

func TestAgentDockerDeploymentRejectsOlderCommandAfterRestartWithoutStableContainer(
	t *testing.T,
) {
	stateDirectory := filepath.Join(t.TempDir(), "state")
	firstExecutor, _ := newDeploymentExecutorAt(t, stateDirectory)
	newer := deploymentCommand(
		"prepare-newer",
		agentprotocol.AgentCommandDeploymentPrepare,
	)
	newer.Deployment.DeploymentID = "deployment-newer"
	newer.Deployment.CutoverSequence = 20
	result, err := firstExecutor.Execute(t.Context(), newer)
	if err != nil || result.Status != agentprotocol.AgentCommandSucceeded {
		t.Fatalf("newer prepare result = %+v, error = %v", result, err)
	}

	restartedExecutor, restartedEngine := newDeploymentExecutorAt(
		t,
		stateDirectory,
	)
	older := deploymentCommand(
		"stage-older-after-restart",
		agentprotocol.AgentCommandDeploymentStage,
	)
	older.Deployment.DeploymentID = "deployment-older"
	older.Deployment.CutoverSequence = 19
	result, err = restartedExecutor.Execute(t.Context(), older)
	if err != nil ||
		result.Status != agentprotocol.AgentCommandFailed ||
		result.ErrorCode != "stale_execution" {
		t.Fatalf("older stage result = %+v, error = %v", result, err)
	}
	if len(restartedEngine.containers) != 0 {
		t.Fatalf(
			"older command created containers after restart: %+v",
			restartedEngine.containers,
		)
	}
	addManagedContainer(
		restartedEngine,
		candidateContainerName(*older.Deployment),
		"older-candidate",
		older.Deployment.DeploymentID,
		older.Deployment.FencingToken,
		older.Deployment.CutoverSequence,
		true,
	)
	cancelOlder := deploymentCommand(
		"cancel-older-after-restart",
		agentprotocol.AgentCommandDeploymentCancel,
	)
	cancelOlder.Deployment.DeploymentID = older.Deployment.DeploymentID
	cancelOlder.Deployment.CutoverSequence =
		older.Deployment.CutoverSequence
	result, err = restartedExecutor.Execute(t.Context(), cancelOlder)
	if err != nil || result.Status != agentprotocol.AgentCommandSucceeded {
		t.Fatalf("older cancel result = %+v, error = %v", result, err)
	}
	if _, err := restartedEngine.ContainerInspect(
		t.Context(),
		candidateContainerName(*older.Deployment),
		mobyclient.ContainerInspectOptions{},
	); !cerrdefs.IsNotFound(err) {
		t.Fatalf("older candidate was not cleaned after restart: %v", err)
	}
}

func TestAgentDockerDeploymentRejectsUnsafeCutoverAndStaleFence(
	t *testing.T,
) {
	t.Run("unmanaged stable name", func(t *testing.T) {
		executor, engine := newDeploymentExecutor(t)
		stage := deploymentCommand(
			"stage-1",
			agentprotocol.AgentCommandDeploymentStage,
		)
		addUnmanagedContainer(
			engine,
			stage.Deployment.ContainerName,
			"user-container",
		)
		result, err := executor.Execute(t.Context(), stage)
		if err != nil ||
			result.Status != agentprotocol.AgentCommandSucceeded {
			t.Fatalf("stage result = %+v, error = %v", result, err)
		}
		activate := deploymentCommand(
			"activate-1",
			agentprotocol.AgentCommandDeploymentActivate,
		)
		result, err = executor.Execute(t.Context(), activate)
		if err != nil ||
			result.Status != agentprotocol.AgentCommandFailed ||
			result.ErrorCode != "runtime_conflict" {
			t.Fatalf("activate result = %+v, error = %v", result, err)
		}
		if engine.names[activate.Deployment.ContainerName] !=
			"user-container" {
			t.Fatal("unmanaged container was replaced")
		}
	})

	t.Run("newer fence", func(t *testing.T) {
		executor, engine := newDeploymentExecutor(t)
		stage := deploymentCommand(
			"stage-1",
			agentprotocol.AgentCommandDeploymentStage,
		)
		addManagedContainer(
			engine,
			stage.Deployment.ContainerName,
			"newer",
			stage.Deployment.DeploymentID,
			stage.Deployment.FencingToken+1,
			stage.Deployment.CutoverSequence,
			true,
		)
		result, err := executor.Execute(t.Context(), stage)
		if err != nil ||
			result.Status != agentprotocol.AgentCommandFailed ||
			result.ErrorCode != "stale_execution" {
			t.Fatalf("stage result = %+v, error = %v", result, err)
		}
	})
}

func TestAgentDockerDeploymentCleansUnhealthyCandidateAndSafeCancel(
	t *testing.T,
) {
	executor, engine := newDeploymentExecutor(t)
	engine.unhealthy = true
	stage := deploymentCommand(
		"stage-1",
		agentprotocol.AgentCommandDeploymentStage,
	)
	stage.Deployment.RuntimeSpec.HealthCheck = &runtimespec.HealthCheck{
		Command:         []string{"/health"},
		IntervalSeconds: 1,
		TimeoutSeconds:  1,
		Retries:         1,
	}
	result, err := executor.Execute(t.Context(), stage)
	if err != nil ||
		result.Status != agentprotocol.AgentCommandFailed ||
		result.ErrorCode != "runtime_error" {
		t.Fatalf("stage result = %+v, error = %v", result, err)
	}
	if _, err := engine.ContainerInspect(
		t.Context(),
		candidateContainerName(*stage.Deployment),
		mobyclient.ContainerInspectOptions{},
	); !cerrdefs.IsNotFound(err) {
		t.Fatalf("unhealthy candidate error = %v", err)
	}

	engine.unhealthy = false
	cancel := deploymentCommand(
		"cancel-1",
		agentprotocol.AgentCommandDeploymentCancel,
	)
	addManagedContainer(
		engine,
		cancel.Deployment.ContainerName,
		"newer-deployment",
		"other-deployment",
		1,
		cancel.Deployment.CutoverSequence+1,
		true,
	)
	result, err = executor.Execute(t.Context(), cancel)
	if err != nil || result.Status != agentprotocol.AgentCommandSucceeded {
		t.Fatalf("cancel result = %+v, error = %v", result, err)
	}
	if _, exists := engine.containers["newer-deployment"]; !exists {
		t.Fatal("cancel removed a different deployment")
	}
}

func newDeploymentExecutor(
	t *testing.T,
) (*DockerExecutor, *agentDockerEngineStub) {
	t.Helper()
	return newDeploymentExecutorAt(
		t,
		filepath.Join(t.TempDir(), "state"),
	)
}

func newDeploymentExecutorAt(
	t *testing.T,
	stateDirectory string,
) (*DockerExecutor, *agentDockerEngineStub) {
	t.Helper()
	cache, err := NewFileResultCache(stateDirectory, 16)
	if err != nil {
		t.Fatal(err)
	}
	cutovers, err := NewFileCutoverStore(stateDirectory, 16)
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
	engine := newAgentDockerEngineStub()
	executor.newDeploymentEngine = func(
		string,
	) (dockerDeploymentEngine, error) {
		return engine, nil
	}
	executor.pollInterval = time.Millisecond
	return executor, engine
}

func deploymentCommand(
	commandID string,
	kind agentprotocol.AgentCommandKind,
) agentprotocol.AgentCommand {
	deployment := &agentprotocol.DeploymentCommand{
		DeploymentID:    "deployment-1",
		WorkerID:        "worker-1",
		FencingToken:    2,
		CutoverSequence: 1,
		RuntimeTargetID: "target-1",
		ContainerName:   "owndock-project-1-app-1",
	}
	switch kind {
	case agentprotocol.AgentCommandDeploymentPrepare:
		deployment.ImageDigest = testImageDigest()
	case agentprotocol.AgentCommandDeploymentStage:
		deployment.ProjectID = "project-1"
		deployment.ApplicationID = "application-1"
		deployment.EnvironmentID = "environment-1"
		deployment.ImageDigest = testImageDigest()
		deployment.RuntimeSpec = runtimespec.Spec{
			EnvironmentKeys: []string{"MODE"},
			Resources: runtimespec.Resources{
				CPUMilli:    runtimespec.DefaultCPUMilli,
				MemoryBytes: runtimespec.DefaultMemoryBytes,
			},
		}
		deployment.Environment = []string{"MODE=production"}
	}
	return agentprotocol.AgentCommand{
		ID:         commandID,
		Kind:       kind,
		Deadline:   time.Now().Add(time.Minute),
		Deployment: deployment,
	}
}

func testImageDigest() string {
	return "registry.example/team/api@sha256:" +
		strings.Repeat("a", 64)
}

func addManagedContainer(
	engine *agentDockerEngineStub,
	name string,
	id string,
	deploymentID string,
	fencingToken uint64,
	cutoverSequence uint64,
	running bool,
) {
	engine.containers[id] = mobyclient.ContainerInspectResult{
		Container: container.InspectResponse{
			ID: id,
			Config: &container.Config{Labels: map[string]string{
				deploymentLabel: deploymentID,
				fencingLabel:    strconv.FormatUint(fencingToken, 10),
				cutoverSequenceLabel: strconv.FormatUint(
					cutoverSequence,
					10,
				),
			}},
			State: &container.State{
				Status:  container.StateRunning,
				Running: running,
			},
		},
	}
	engine.names[name] = id
}

func addUnmanagedContainer(
	engine *agentDockerEngineStub,
	name string,
	id string,
) {
	engine.containers[id] = mobyclient.ContainerInspectResult{
		Container: container.InspectResponse{
			ID:     id,
			Config: &container.Config{},
			State: &container.State{
				Status:  container.StateRunning,
				Running: true,
			},
		},
	}
	engine.names[name] = id
}
