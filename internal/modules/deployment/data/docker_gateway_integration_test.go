package data

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
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
