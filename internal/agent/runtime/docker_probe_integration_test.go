package agentruntime

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	mobyclient "github.com/moby/moby/client"

	"github.com/owndock/owndock/internal/shared/agentprotocol"
	"github.com/owndock/owndock/internal/shared/runtimespec"
)

const agentDockerIntegrationImage = "nginx@sha256:1eff5a5f3fcf8431a0abb7eddf5471fec24e5e1905a2581aeacdb07a4479b92b"

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
