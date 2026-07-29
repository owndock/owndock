package data

import (
	"context"
	"errors"
	"io"
	"iter"
	"strings"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/jsonstream"
	mobyclient "github.com/moby/moby/client"

	"github.com/owndock/owndock/internal/modules/deployment/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/runtimespec"
)

type imagePullStub struct{}

func (imagePullStub) Read([]byte) (int, error) { return 0, io.EOF }
func (imagePullStub) Close() error             { return nil }
func (imagePullStub) JSONMessages(context.Context) iter.Seq2[jsonstream.Message, error] {
	return func(func(jsonstream.Message, error) bool) {}
}
func (imagePullStub) Wait(context.Context) error { return nil }

type dockerEngineProbe struct {
	inspect            mobyclient.ContainerInspectResult
	inspectErr         error
	created            bool
	started            bool
	removed            bool
	pulled             bool
	imagePresent       bool
	imageInspectErr    error
	pullAuth           string
	createdLabels      map[string]string
	createdConfig      *container.Config
	createdHostConfig  *container.HostConfig
	createdName        string
	createdInspect     mobyclient.ContainerInspectResult
	createdInspectErr  error
	renamed            bool
	renameCalls        []string
	candidateRenameErr error
	removedIDs         []string
	previousID         string
	previousInspect    mobyclient.ContainerInspectResult
	startHealth        container.HealthStatus
}

func (e *dockerEngineProbe) Ping(context.Context, mobyclient.PingOptions) (mobyclient.PingResult, error) {
	return mobyclient.PingResult{}, nil
}
func (e *dockerEngineProbe) ImageInspect(
	context.Context, string, ...mobyclient.ImageInspectOption,
) (mobyclient.ImageInspectResult, error) {
	if e.imageInspectErr != nil {
		return mobyclient.ImageInspectResult{}, e.imageInspectErr
	}
	if !e.imagePresent {
		return mobyclient.ImageInspectResult{}, cerrdefs.ErrNotFound
	}
	return mobyclient.ImageInspectResult{}, nil
}
func (e *dockerEngineProbe) ImagePull(
	_ context.Context, _ string, options mobyclient.ImagePullOptions,
) (mobyclient.ImagePullResponse, error) {
	e.pulled = true
	e.pullAuth = options.RegistryAuth
	return imagePullStub{}, nil
}
func (e *dockerEngineProbe) ContainerInspect(
	_ context.Context, name string, _ mobyclient.ContainerInspectOptions,
) (mobyclient.ContainerInspectResult, error) {
	if name == e.createdName || name == "created" {
		return e.createdInspect, e.createdInspectErr
	}
	if strings.Contains(name, "-candidate-") {
		return mobyclient.ContainerInspectResult{}, cerrdefs.ErrNotFound
	}
	if strings.Contains(name, "-previous-") {
		if e.previousID == "" {
			return mobyclient.ContainerInspectResult{}, cerrdefs.ErrNotFound
		}
		return e.previousInspect, nil
	}
	return e.inspect, e.inspectErr
}
func (e *dockerEngineProbe) ContainerCreate(
	_ context.Context, options mobyclient.ContainerCreateOptions,
) (mobyclient.ContainerCreateResult, error) {
	e.created = true
	e.createdLabels = options.Config.Labels
	e.createdConfig = options.Config
	e.createdHostConfig = options.HostConfig
	e.createdName = options.Name
	e.createdInspect = mobyclient.ContainerInspectResult{Container: container.InspectResponse{
		ID: "created", State: &container.State{Status: container.StateCreated},
		Config: options.Config,
	}}
	return mobyclient.ContainerCreateResult{ID: "created"}, nil
}

func TestDockerGatewayAppliesRuntimeSpecificationAndRegistryAuthorization(t *testing.T) {
	probe := &dockerEngineProbe{inspectErr: cerrdefs.ErrNotFound}
	gateway := &DockerGateway{newEngine: func(biz.ExecutionPlan, biz.RuntimeCredential) (dockerEngine, error) {
		return probe, nil
	}}
	plan := testExecutionPlan()
	plan.Environment = []string{"DATABASE_URL=mongodb://database"}
	plan.RuntimeSpec = runtimespec.Spec{
		Ports: []runtimespec.Port{{Name: "http", ContainerPort: 8080, Protocol: "tcp"}},
		Resources: runtimespec.Resources{
			CPUMilli: 750, MemoryBytes: 512 * 1024 * 1024,
		},
		HealthCheck: &runtimespec.HealthCheck{
			Command: []string{"/healthcheck"}, IntervalSeconds: 10,
			TimeoutSeconds: 2, Retries: 2,
		},
	}
	credential := biz.RuntimeCredential{RegistryAuthorization: []byte("encoded-auth")}
	if err := gateway.Prepare(t.Context(), plan, credential); err != nil {
		t.Fatal(err)
	}
	if err := gateway.Deploy(t.Context(), plan, credential); err != nil {
		t.Fatal(err)
	}
	if probe.pullAuth != "encoded-auth" ||
		len(probe.createdConfig.ExposedPorts) != 1 ||
		probe.createdConfig.Env[0] != plan.Environment[0] ||
		probe.createdConfig.Healthcheck == nil ||
		probe.createdHostConfig.Resources.NanoCPUs != 750_000_000 ||
		probe.createdHostConfig.Resources.Memory != 512*1024*1024 {
		t.Fatalf("probe = %+v", probe)
	}
}

func TestDockerGatewayReusesDigestAddressedLocalImage(t *testing.T) {
	probe := &dockerEngineProbe{imagePresent: true}
	gateway := &DockerGateway{newEngine: func(biz.ExecutionPlan, biz.RuntimeCredential) (dockerEngine, error) {
		return probe, nil
	}}
	if err := gateway.Prepare(
		t.Context(), testExecutionPlan(),
		biz.RuntimeCredential{RegistryAuthorization: []byte("encoded-auth")},
	); err != nil {
		t.Fatal(err)
	}
	if probe.pulled {
		t.Fatal("cached digest-addressed image was pulled again")
	}
}
func (e *dockerEngineProbe) ContainerStart(
	context.Context, string, mobyclient.ContainerStartOptions,
) (mobyclient.ContainerStartResult, error) {
	e.started = true
	state := &container.State{Status: container.StateRunning, Running: true}
	if e.createdConfig != nil && e.createdConfig.Healthcheck != nil {
		health := e.startHealth
		if health == "" {
			health = container.Healthy
		}
		state.Health = &container.Health{Status: health}
	}
	e.createdInspect.Container.State = state
	return mobyclient.ContainerStartResult{}, nil
}
func (e *dockerEngineProbe) ContainerRemove(
	_ context.Context, containerID string, _ mobyclient.ContainerRemoveOptions,
) (mobyclient.ContainerRemoveResult, error) {
	e.removed = true
	e.removedIDs = append(e.removedIDs, containerID)
	if containerID == e.previousID {
		e.previousID = ""
	}
	return mobyclient.ContainerRemoveResult{}, nil
}
func (e *dockerEngineProbe) ContainerRename(
	_ context.Context, containerID string, options mobyclient.ContainerRenameOptions,
) (mobyclient.ContainerRenameResult, error) {
	e.renamed = true
	e.renameCalls = append(e.renameCalls, containerID+"->"+options.NewName)
	if containerID == "created" {
		if e.candidateRenameErr != nil {
			return mobyclient.ContainerRenameResult{}, e.candidateRenameErr
		}
		e.inspect = e.createdInspect
		e.inspectErr = nil
		e.createdName = ""
		return mobyclient.ContainerRenameResult{}, nil
	}
	if containerID == e.previousID {
		e.inspect = e.previousInspect
		e.inspectErr = nil
		e.previousID = ""
		return mobyclient.ContainerRenameResult{}, nil
	}
	e.previousID = containerID
	e.previousInspect = e.inspect
	e.inspectErr = cerrdefs.ErrNotFound
	return mobyclient.ContainerRenameResult{}, nil
}
func (e *dockerEngineProbe) Close() error { return nil }

type fenceValidatorStub struct {
	err   error
	errs  []error
	calls int
}

func (f *fenceValidatorStub) ValidateFence(
	context.Context, string, string, string, uint64, time.Time,
) error {
	f.calls++
	if f.calls <= len(f.errs) {
		return f.errs[f.calls-1]
	}
	return f.err
}

func testExecutionPlan() biz.ExecutionPlan {
	connection, err := runtimeaccess.NewDirectDocker(
		"", "tcp://docker.example.com:2376", "docker.example.com", "secret://target",
	)
	if err != nil {
		panic(err)
	}
	return biz.ExecutionPlan{
		DeploymentID: "deployment", ProjectID: "project", ApplicationID: "application",
		EnvironmentID: "environment", RuntimeTargetID: "target",
		ImageDigest:      "registry.example.com/team/api@sha256:" + strings.Repeat("a", 64),
		ContainerName:    "owndock-scope",
		TargetConnection: connection,
	}
}

func TestDockerGatewayPreparesAndDeploysIdempotently(t *testing.T) {
	probe := &dockerEngineProbe{inspectErr: cerrdefs.ErrNotFound}
	gateway := &DockerGateway{newEngine: func(biz.ExecutionPlan, biz.RuntimeCredential) (dockerEngine, error) {
		return probe, nil
	}}
	plan := testExecutionPlan()
	if err := gateway.Prepare(t.Context(), plan, biz.RuntimeCredential{}); err != nil {
		t.Fatal(err)
	}
	if err := gateway.Deploy(t.Context(), plan, biz.RuntimeCredential{}); err != nil {
		t.Fatal(err)
	}
	if !probe.pulled || !probe.created || !probe.started ||
		probe.createdLabels[deploymentLabel] != plan.DeploymentID {
		t.Fatalf("probe = %+v", probe)
	}

	probe.inspectErr = nil
	probe.inspect = mobyclient.ContainerInspectResult{Container: container.InspectResponse{
		ID:     "existing",
		State:  &container.State{Running: true},
		Config: &container.Config{Labels: map[string]string{deploymentLabel: plan.DeploymentID}},
	}}
	probe.created, probe.started = false, false
	if err := gateway.Deploy(t.Context(), plan, biz.RuntimeCredential{}); err != nil {
		t.Fatal(err)
	}
	if probe.created || probe.started {
		t.Fatalf("idempotent deploy performed side effects: %+v", probe)
	}
}

func TestDockerGatewayCancelDoesNotRemoveNewerDeployment(t *testing.T) {
	plan := testExecutionPlan()
	probe := &dockerEngineProbe{inspect: mobyclient.ContainerInspectResult{Container: container.InspectResponse{
		ID:     "newer",
		Config: &container.Config{Labels: map[string]string{deploymentLabel: "newer-deployment"}},
	}}}
	gateway := &DockerGateway{newEngine: func(biz.ExecutionPlan, biz.RuntimeCredential) (dockerEngine, error) {
		return probe, nil
	}}
	if err := gateway.Cancel(t.Context(), plan, biz.RuntimeCredential{}); err != nil {
		t.Fatal(err)
	}
	if probe.removed {
		t.Fatal("cancel removed a newer deployment container")
	}
}

func TestDockerGatewayReplacesOlderDeploymentAndCancelsOwnedContainer(t *testing.T) {
	plan := testExecutionPlan()
	probe := &dockerEngineProbe{inspect: mobyclient.ContainerInspectResult{Container: container.InspectResponse{
		ID:     "older",
		Config: &container.Config{Labels: map[string]string{deploymentLabel: "older-deployment"}},
	}}}
	gateway := &DockerGateway{newEngine: func(biz.ExecutionPlan, biz.RuntimeCredential) (dockerEngine, error) {
		return probe, nil
	}}
	if err := gateway.Deploy(t.Context(), plan, biz.RuntimeCredential{}); err != nil {
		t.Fatal(err)
	}
	if !probe.removed || !probe.created || !probe.started || !probe.renamed {
		t.Fatalf("replacement probe = %+v", probe)
	}

	probe.removed = false
	probe.inspect = mobyclient.ContainerInspectResult{Container: container.InspectResponse{
		ID:     "current",
		Config: &container.Config{Labels: map[string]string{deploymentLabel: plan.DeploymentID}},
	}}
	if err := gateway.Cancel(t.Context(), plan, biz.RuntimeCredential{}); err != nil {
		t.Fatal(err)
	}
	if !probe.removed {
		t.Fatal("cancel did not remove the owned deployment container")
	}
}

func TestDockerGatewayKeepsCurrentContainerWhenCandidateIsUnhealthy(t *testing.T) {
	plan := testExecutionPlan()
	plan.FencingToken = 2
	plan.RuntimeSpec = runtimespec.Spec{HealthCheck: &runtimespec.HealthCheck{
		Command: []string{"/healthcheck"}, IntervalSeconds: 1,
		TimeoutSeconds: 1, Retries: 1,
	}}
	probe := &dockerEngineProbe{
		inspect: mobyclient.ContainerInspectResult{Container: container.InspectResponse{
			ID: "current", State: &container.State{Running: true},
			Config: &container.Config{Labels: map[string]string{
				deploymentLabel: "older", fencingLabel: "1",
			}},
		}},
		startHealth: container.Unhealthy,
	}
	gateway := NewDockerGateway()
	gateway.newEngine = func(biz.ExecutionPlan, biz.RuntimeCredential) (dockerEngine, error) {
		return probe, nil
	}
	err := gateway.Deploy(t.Context(), plan, biz.RuntimeCredential{})
	if err == nil || containsString(probe.removedIDs, "current") || probe.renamed {
		t.Fatalf("error = %v, probe = %+v", err, probe)
	}
	if !containsString(probe.removedIDs, "created") {
		t.Fatalf("unhealthy candidate was not cleaned up: %+v", probe.removedIDs)
	}
}

func TestDockerGatewayDoesNotStartCandidateAfterInspectFailure(t *testing.T) {
	plan := testExecutionPlan()
	probe := &dockerEngineProbe{
		inspectErr: cerrdefs.ErrNotFound, createdInspectErr: errors.New("inspect failed"),
	}
	gateway := NewDockerGateway()
	gateway.newEngine = func(biz.ExecutionPlan, biz.RuntimeCredential) (dockerEngine, error) {
		return probe, nil
	}
	err := gateway.Deploy(t.Context(), plan, biz.RuntimeCredential{})
	if err == nil || probe.started || !containsString(probe.removedIDs, "created") {
		t.Fatalf("error = %v, probe = %+v", err, probe)
	}
}

func TestDockerGatewayRejectsStaleFenceBeforeCutover(t *testing.T) {
	plan := testExecutionPlan()
	plan.WorkerID = "worker"
	plan.FencingToken = 2
	probe := &dockerEngineProbe{
		inspect: mobyclient.ContainerInspectResult{Container: container.InspectResponse{
			ID: "current", State: &container.State{Running: true},
			Config: &container.Config{Labels: map[string]string{
				deploymentLabel: "older", fencingLabel: "1",
			}},
		}},
	}
	fence := &fenceValidatorStub{err: biz.ErrStaleExecution}
	gateway := NewDockerGateway().WithFence(fence)
	gateway.newEngine = func(biz.ExecutionPlan, biz.RuntimeCredential) (dockerEngine, error) {
		return probe, nil
	}
	err := gateway.Deploy(t.Context(), plan, biz.RuntimeCredential{})
	if !errors.Is(err, biz.ErrStaleExecution) || fence.calls != 1 ||
		containsString(probe.removedIDs, "current") || probe.renamed {
		t.Fatalf("error = %v, fence calls = %d, probe = %+v", err, fence.calls, probe)
	}
}

func TestDockerGatewayRejectsContainerWithNewerFence(t *testing.T) {
	plan := testExecutionPlan()
	plan.FencingToken = 2
	probe := &dockerEngineProbe{inspect: mobyclient.ContainerInspectResult{Container: container.InspectResponse{
		ID: "newer", State: &container.State{Running: true},
		Config: &container.Config{Labels: map[string]string{
			deploymentLabel: plan.DeploymentID, fencingLabel: "3",
		}},
	}}}
	gateway := NewDockerGateway()
	gateway.newEngine = func(biz.ExecutionPlan, biz.RuntimeCredential) (dockerEngine, error) {
		return probe, nil
	}
	err := gateway.Deploy(t.Context(), plan, biz.RuntimeCredential{})
	if !errors.Is(err, biz.ErrStaleExecution) || probe.created || probe.removed {
		t.Fatalf("error = %v, probe = %+v", err, probe)
	}
}

func TestDockerGatewayDoesNotCompareFencesAcrossDeployments(t *testing.T) {
	plan := testExecutionPlan()
	plan.DeploymentID = "new-deployment"
	plan.FencingToken = 1
	probe := &dockerEngineProbe{inspect: mobyclient.ContainerInspectResult{Container: container.InspectResponse{
		ID: "older", State: &container.State{Running: true},
		Config: &container.Config{Labels: map[string]string{
			deploymentLabel: "old-deployment", fencingLabel: "7",
		}},
	}}}
	gateway := NewDockerGateway()
	gateway.newEngine = func(biz.ExecutionPlan, biz.RuntimeCredential) (dockerEngine, error) {
		return probe, nil
	}
	if err := gateway.Deploy(t.Context(), plan, biz.RuntimeCredential{}); err != nil {
		t.Fatal(err)
	}
	if !probe.created || !probe.renamed {
		t.Fatalf("new deployment did not replace older generation: %+v", probe)
	}
}

func TestDockerGatewayRestoresPreviousContainerWhenCandidateRenameFails(t *testing.T) {
	plan := testExecutionPlan()
	plan.WorkerID = "worker"
	plan.FencingToken = 2
	previous := mobyclient.ContainerInspectResult{Container: container.InspectResponse{
		ID: "previous", State: &container.State{Running: true},
		Config: &container.Config{Labels: map[string]string{
			deploymentLabel: "older-deployment", fencingLabel: "1",
		}},
	}}
	probe := &dockerEngineProbe{
		inspect: previous, candidateRenameErr: errors.New("rename candidate failed"),
	}
	gateway := NewDockerGateway().WithFence(&fenceValidatorStub{})
	gateway.newEngine = func(biz.ExecutionPlan, biz.RuntimeCredential) (dockerEngine, error) {
		return probe, nil
	}
	err := gateway.Deploy(t.Context(), plan, biz.RuntimeCredential{})
	if err == nil {
		t.Fatal("candidate rename failure was ignored")
	}
	if probe.inspectErr != nil || probe.inspect.Container.ID != previous.Container.ID {
		t.Fatalf("previous container was not restored: %+v", probe.inspect)
	}
	if probe.previousID != "" || !containsString(probe.removedIDs, "created") {
		t.Fatalf("cutover cleanup = previous %q removed %+v", probe.previousID, probe.removedIDs)
	}
}

func TestDockerGatewayRestoresPreviousContainerWhenFenceExpiresDuringCutover(t *testing.T) {
	plan := testExecutionPlan()
	plan.WorkerID = "worker"
	plan.FencingToken = 2
	previous := mobyclient.ContainerInspectResult{Container: container.InspectResponse{
		ID: "previous", State: &container.State{Running: true},
		Config: &container.Config{Labels: map[string]string{
			deploymentLabel: "older-deployment", fencingLabel: "1",
		}},
	}}
	probe := &dockerEngineProbe{inspect: previous}
	fence := &fenceValidatorStub{errs: []error{nil, biz.ErrStaleExecution}}
	gateway := NewDockerGateway().WithFence(fence)
	gateway.newEngine = func(biz.ExecutionPlan, biz.RuntimeCredential) (dockerEngine, error) {
		return probe, nil
	}
	err := gateway.Deploy(t.Context(), plan, biz.RuntimeCredential{})
	if !errors.Is(err, biz.ErrStaleExecution) || fence.calls != 2 {
		t.Fatalf("error = %v, fence calls = %d", err, fence.calls)
	}
	if probe.inspectErr != nil || probe.inspect.Container.ID != previous.Container.ID ||
		probe.previousID != "" || probe.renamed && !containsString(probe.removedIDs, "created") {
		t.Fatalf("previous container was not restored safely: %+v", probe)
	}
}

func TestDockerGatewayUsesDeploymentSpecificTemporaryNames(t *testing.T) {
	first := testExecutionPlan()
	first.DeploymentID = "deployment-one"
	first.FencingToken = 1
	second := first
	second.DeploymentID = "deployment-two"
	if candidateContainerName(first) == candidateContainerName(second) ||
		previousContainerName(first) == previousContainerName(second) {
		t.Fatalf(
			"temporary names collide: %q %q",
			candidateContainerName(first), candidateContainerName(second),
		)
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func TestDockerGatewayCategorizesConnectionFailure(t *testing.T) {
	gateway := &DockerGateway{newEngine: func(biz.ExecutionPlan, biz.RuntimeCredential) (dockerEngine, error) {
		return nil, errors.New("bad certificate")
	}}
	err := gateway.Prepare(t.Context(), testExecutionPlan(), biz.RuntimeCredential{})
	var executionError *biz.ExecutionError
	if !errors.As(err, &executionError) || executionError.Category != biz.FailureCredential {
		t.Fatalf("error = %v", err)
	}
}
