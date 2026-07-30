package agentruntime

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	mobyclient "github.com/moby/moby/client"

	"github.com/owndock/owndock/internal/shared/agentprotocol"
)

const (
	deploymentLabel      = "net.owndock.deployment_id"
	fencingLabel         = "net.owndock.fencing_token"
	cutoverSequenceLabel = "net.owndock.cutover_sequence"
	projectLabel         = "net.owndock.project_id"
	applicationLabel     = "net.owndock.application_id"
	environmentLabel     = "net.owndock.environment_id"
)

type dockerDeploymentEngine interface {
	Ping(context.Context, mobyclient.PingOptions) (mobyclient.PingResult, error)
	ImageInspect(
		context.Context,
		string,
		...mobyclient.ImageInspectOption,
	) (mobyclient.ImageInspectResult, error)
	ImagePull(
		context.Context,
		string,
		mobyclient.ImagePullOptions,
	) (mobyclient.ImagePullResponse, error)
	ContainerInspect(
		context.Context,
		string,
		mobyclient.ContainerInspectOptions,
	) (mobyclient.ContainerInspectResult, error)
	ContainerCreate(
		context.Context,
		mobyclient.ContainerCreateOptions,
	) (mobyclient.ContainerCreateResult, error)
	ContainerStart(
		context.Context,
		string,
		mobyclient.ContainerStartOptions,
	) (mobyclient.ContainerStartResult, error)
	ContainerRemove(
		context.Context,
		string,
		mobyclient.ContainerRemoveOptions,
	) (mobyclient.ContainerRemoveResult, error)
	ContainerRename(
		context.Context,
		string,
		mobyclient.ContainerRenameOptions,
	) (mobyclient.ContainerRenameResult, error)
	Close() error
}

type dockerDeploymentEngineFactory func(string) (dockerDeploymentEngine, error)

type deploymentExecutionError struct {
	code  string
	cause error
}

func (e *deploymentExecutionError) Error() string {
	return e.code
}

func (e *deploymentExecutionError) Unwrap() error {
	return e.cause
}

func (e *DockerExecutor) executeDeployment(
	ctx context.Context,
	command agentprotocol.AgentCommand,
) (agentprotocol.AgentCommandResult, error) {
	stale := false
	if command.Kind != agentprotocol.AgentCommandDeploymentCancel {
		var watermarkError error
		stale, watermarkError = e.cutovers.Observe(
			command.Deployment.ContainerName,
			command.Deployment.DeploymentID,
			command.Deployment.CutoverSequence,
		)
		if watermarkError != nil {
			return deploymentResult(
				command.ID,
				"runtime_configuration",
			), nil
		}
		if stale &&
			command.Kind ==
				agentprotocol.AgentCommandDeploymentPrepare {
			return deploymentResult(command.ID, "stale_execution"), nil
		}
	}
	engine, err := e.newDeploymentEngine(e.socketPath)
	if err != nil {
		return deploymentResult(command.ID, "runtime_configuration"), nil
	}
	defer func() { _ = engine.Close() }()
	if stale {
		removeNamedOwnedCandidate(*command.Deployment, engine)
		return deploymentResult(command.ID, "stale_execution"), nil
	}

	switch command.Kind {
	case agentprotocol.AgentCommandDeploymentPrepare:
		err = prepareDeployment(ctx, engine, *command.Deployment)
	case agentprotocol.AgentCommandDeploymentStage:
		err = e.stageDeployment(ctx, engine, *command.Deployment)
	case agentprotocol.AgentCommandDeploymentActivate:
		err = activateDeployment(ctx, engine, *command.Deployment)
	case agentprotocol.AgentCommandDeploymentCancel:
		err = cancelDeployment(ctx, engine, *command.Deployment)
	default:
		return agentprotocol.AgentCommandResult{}, agentprotocol.ErrCommandInvalid
	}
	if err == nil {
		return deploymentResult(command.ID, ""), nil
	}
	if contextError := ctx.Err(); contextError != nil {
		return agentprotocol.AgentCommandResult{}, contextError
	}
	var executionError *deploymentExecutionError
	if errors.As(err, &executionError) {
		return deploymentResult(command.ID, executionError.code), nil
	}
	return deploymentResult(command.ID, "runtime_error"), nil
}

func prepareDeployment(
	ctx context.Context,
	engine dockerDeploymentEngine,
	deployment agentprotocol.DeploymentCommand,
) error {
	if _, err := engine.Ping(ctx, mobyclient.PingOptions{}); err != nil {
		return deploymentError("target_unreachable", err)
	}
	if _, err := engine.ImageInspect(ctx, deployment.ImageDigest); err == nil {
		return nil
	} else if !cerrdefs.IsNotFound(err) {
		return deploymentError("runtime_error", err)
	}
	pull, err := engine.ImagePull(
		ctx,
		deployment.ImageDigest,
		mobyclient.ImagePullOptions{
			RegistryAuth: string(deployment.RegistryAuthorization),
		},
	)
	if err != nil {
		return deploymentError("image_pull", err)
	}
	if err := pull.Wait(ctx); err != nil {
		return deploymentError("image_pull", err)
	}
	return nil
}

func (e *DockerExecutor) stageDeployment(
	ctx context.Context,
	engine dockerDeploymentEngine,
	deployment agentprotocol.DeploymentCommand,
) error {
	current, err := inspectContainer(ctx, engine, deployment.ContainerName)
	switch {
	case err == nil && hasNewerFence(current, deployment):
		removeNamedOwnedCandidate(deployment, engine)
		return deploymentError("stale_execution", nil)
	case err == nil && ownsExecution(current, deployment):
		return e.waitUntilReady(
			ctx,
			engine,
			current.Container.ID,
			deployment,
		)
	case err != nil && !cerrdefs.IsNotFound(err):
		return deploymentError("runtime_error", err)
	}

	candidateName := candidateContainerName(deployment)
	candidate, err := inspectContainer(ctx, engine, candidateName)
	var candidateID string
	switch {
	case err == nil && hasNewerFence(candidate, deployment):
		return deploymentError("stale_execution", nil)
	case err == nil && ownsExecution(candidate, deployment):
		candidateID = candidate.Container.ID
	case err == nil:
		return deploymentError("runtime_conflict", nil)
	case !cerrdefs.IsNotFound(err):
		return deploymentError("runtime_error", err)
	}
	if candidateID == "" {
		created, createError := engine.ContainerCreate(
			ctx,
			dockerCreateOptions(deployment, candidateName),
		)
		if createError != nil {
			return deploymentError("runtime_error", createError)
		}
		candidateID = created.ID
	}

	candidate, err = inspectContainer(ctx, engine, candidateID)
	if err != nil {
		removeOwnedContainer(candidateID, deployment, engine)
		return deploymentError("runtime_error", err)
	}
	if candidate.Container.State == nil || !candidate.Container.State.Running {
		if _, err := engine.ContainerStart(
			ctx,
			candidateID,
			mobyclient.ContainerStartOptions{},
		); err != nil {
			removeOwnedContainer(candidateID, deployment, engine)
			return deploymentError("runtime_error", err)
		}
	}
	if err := e.waitUntilReady(ctx, engine, candidateID, deployment); err != nil {
		removeOwnedContainer(candidateID, deployment, engine)
		return deploymentError("runtime_error", err)
	}
	return nil
}

func activateDeployment(
	ctx context.Context,
	engine dockerDeploymentEngine,
	deployment agentprotocol.DeploymentCommand,
) error {
	current, currentError := inspectContainer(
		ctx,
		engine,
		deployment.ContainerName,
	)
	switch {
	case currentError == nil && hasNewerFence(current, deployment):
		removeNamedOwnedCandidate(deployment, engine)
		return deploymentError("stale_execution", nil)
	case currentError == nil && ownsExecution(current, deployment):
		removeNamedOwnedCandidate(deployment, engine)
		removeManagedContainer(previousContainerName(deployment), engine)
		return nil
	case currentError != nil && !cerrdefs.IsNotFound(currentError):
		return deploymentError("runtime_error", currentError)
	}

	candidateName := candidateContainerName(deployment)
	candidate, err := inspectContainer(ctx, engine, candidateName)
	switch {
	case cerrdefs.IsNotFound(err):
		return deploymentError("candidate_missing", nil)
	case err != nil:
		return deploymentError("runtime_error", err)
	case hasNewerFence(candidate, deployment):
		return deploymentError("stale_execution", nil)
	case !ownsExecution(candidate, deployment):
		return deploymentError("runtime_conflict", nil)
	}
	if candidate.Container.State == nil || !candidate.Container.State.Running {
		return deploymentError("candidate_not_ready", nil)
	}
	if candidate.Container.State.Health != nil &&
		candidate.Container.State.Health.Status != container.Healthy {
		return deploymentError("candidate_not_ready", nil)
	}

	previousName := previousContainerName(deployment)
	var previousID string
	if currentError == nil {
		if !managedContainer(current) {
			return deploymentError("runtime_conflict", nil)
		}
		if err := removeManagedContainerStrict(
			ctx,
			previousName,
			engine,
		); err != nil {
			return err
		}
		if _, err := engine.ContainerRename(
			ctx,
			current.Container.ID,
			mobyclient.ContainerRenameOptions{NewName: previousName},
		); err != nil {
			return deploymentError("runtime_error", err)
		}
		previousID = current.Container.ID
	} else {
		previous, previousError := inspectContainer(ctx, engine, previousName)
		switch {
		case previousError == nil && managedContainer(previous):
			previousID = previous.Container.ID
		case previousError == nil:
			return deploymentError("runtime_conflict", nil)
		case !cerrdefs.IsNotFound(previousError):
			return deploymentError("runtime_error", previousError)
		}
	}

	if _, err := engine.ContainerRename(
		ctx,
		candidate.Container.ID,
		mobyclient.ContainerRenameOptions{NewName: deployment.ContainerName},
	); err != nil {
		restorePrevious(previousID, deployment, engine)
		removeOwnedContainer(candidate.Container.ID, deployment, engine)
		return deploymentError("runtime_error", err)
	}
	if previousID != "" {
		removeManagedContainer(previousID, engine)
	}
	return nil
}

func cancelDeployment(
	ctx context.Context,
	engine dockerDeploymentEngine,
	deployment agentprotocol.DeploymentCommand,
) error {
	for _, name := range []string{
		candidateContainerName(deployment),
		previousContainerName(deployment),
		deployment.ContainerName,
	} {
		current, err := inspectContainer(ctx, engine, name)
		if cerrdefs.IsNotFound(err) {
			continue
		}
		if err != nil {
			return deploymentError("runtime_error", err)
		}
		if !ownsExecution(current, deployment) {
			continue
		}
		if _, err := engine.ContainerRemove(
			ctx,
			current.Container.ID,
			mobyclient.ContainerRemoveOptions{Force: true},
		); err != nil && !cerrdefs.IsNotFound(err) {
			return deploymentError("runtime_error", err)
		}
	}
	return nil
}

func inspectContainer(
	ctx context.Context,
	engine dockerDeploymentEngine,
	name string,
) (mobyclient.ContainerInspectResult, error) {
	return engine.ContainerInspect(
		ctx,
		name,
		mobyclient.ContainerInspectOptions{},
	)
}

func ownsExecution(
	result mobyclient.ContainerInspectResult,
	deployment agentprotocol.DeploymentCommand,
) bool {
	return managedContainer(result) &&
		result.Container.Config.Labels[deploymentLabel] ==
			deployment.DeploymentID &&
		fencingToken(result) == deployment.FencingToken &&
		cutoverSequence(result) == deployment.CutoverSequence
}

func hasNewerFence(
	result mobyclient.ContainerInspectResult,
	deployment agentprotocol.DeploymentCommand,
) bool {
	if !managedContainer(result) {
		return false
	}
	currentCutover := cutoverSequence(result)
	if currentCutover > deployment.CutoverSequence {
		return true
	}
	if currentCutover == deployment.CutoverSequence &&
		result.Container.Config.Labels[deploymentLabel] !=
			deployment.DeploymentID {
		return true
	}
	return currentCutover == deployment.CutoverSequence &&
		result.Container.Config.Labels[deploymentLabel] ==
			deployment.DeploymentID &&
		fencingToken(result) > deployment.FencingToken
}

func managedContainer(result mobyclient.ContainerInspectResult) bool {
	return result.Container.Config != nil &&
		result.Container.Config.Labels[deploymentLabel] != ""
}

func fencingToken(result mobyclient.ContainerInspectResult) uint64 {
	if result.Container.Config == nil {
		return 0
	}
	token, _ := strconv.ParseUint(
		result.Container.Config.Labels[fencingLabel],
		10,
		64,
	)
	return token
}

func cutoverSequence(result mobyclient.ContainerInspectResult) uint64 {
	if result.Container.Config == nil {
		return 0
	}
	sequence, _ := strconv.ParseUint(
		result.Container.Config.Labels[cutoverSequenceLabel],
		10,
		64,
	)
	return sequence
}

func candidateContainerName(
	deployment agentprotocol.DeploymentCommand,
) string {
	return fmt.Sprintf(
		"%s-candidate-%s-%d",
		deployment.ContainerName,
		executionNamePart(deployment.DeploymentID),
		deployment.FencingToken,
	)
}

func previousContainerName(
	deployment agentprotocol.DeploymentCommand,
) string {
	return fmt.Sprintf(
		"%s-previous-%s-%d",
		deployment.ContainerName,
		executionNamePart(deployment.DeploymentID),
		deployment.FencingToken,
	)
}

func executionNamePart(deploymentID string) string {
	sum := sha256.Sum256([]byte(deploymentID))
	return fmt.Sprintf("%x", sum[:6])
}

func dockerCreateOptions(
	deployment agentprotocol.DeploymentCommand,
	name string,
) mobyclient.ContainerCreateOptions {
	exposedPorts := make(
		network.PortSet,
		len(deployment.RuntimeSpec.Ports),
	)
	for _, port := range deployment.RuntimeSpec.Ports {
		exposedPorts[network.MustParsePort(
			fmt.Sprintf("%d/%s", port.ContainerPort, port.Protocol),
		)] = struct{}{}
	}
	config := &container.Config{
		Env:          append([]string(nil), deployment.Environment...),
		ExposedPorts: exposedPorts,
		Labels: map[string]string{
			deploymentLabel: deployment.DeploymentID,
			fencingLabel:    strconv.FormatUint(deployment.FencingToken, 10),
			cutoverSequenceLabel: strconv.FormatUint(
				deployment.CutoverSequence,
				10,
			),
			projectLabel:     deployment.ProjectID,
			applicationLabel: deployment.ApplicationID,
			environmentLabel: deployment.EnvironmentID,
		},
	}
	if health := deployment.RuntimeSpec.HealthCheck; health != nil {
		config.Healthcheck = &container.HealthConfig{
			Test: append(
				[]string{"CMD"},
				health.Command...,
			),
			Interval: time.Duration(health.IntervalSeconds) *
				time.Second,
			Timeout: time.Duration(health.TimeoutSeconds) *
				time.Second,
			Retries: health.Retries,
			StartPeriod: time.Duration(
				health.StartPeriodSeconds,
			) * time.Second,
		}
	}
	return mobyclient.ContainerCreateOptions{
		Name:   name,
		Image:  deployment.ImageDigest,
		Config: config,
		HostConfig: &container.HostConfig{
			Resources: container.Resources{
				NanoCPUs: deployment.RuntimeSpec.Resources.CPUMilli *
					1_000_000,
				Memory: deployment.RuntimeSpec.Resources.MemoryBytes,
			},
		},
	}
}

func (e *DockerExecutor) waitUntilReady(
	ctx context.Context,
	engine dockerDeploymentEngine,
	containerID string,
	deployment agentprotocol.DeploymentCommand,
) error {
	for {
		current, err := inspectContainer(ctx, engine, containerID)
		if err != nil {
			return err
		}
		state := current.Container.State
		if state == nil || state.Dead ||
			(!state.Running && state.Status != container.StateCreated) {
			return errors.New(
				"candidate container stopped before becoming ready",
			)
		}
		if state.Running {
			if deployment.RuntimeSpec.HealthCheck == nil {
				return nil
			}
			if state.Health != nil {
				switch state.Health.Status {
				case container.Healthy:
					return nil
				case container.Unhealthy:
					return errors.New("candidate container is unhealthy")
				}
			}
		}
		timer := time.NewTimer(e.pollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func removeNamedOwnedCandidate(
	deployment agentprotocol.DeploymentCommand,
	engine dockerDeploymentEngine,
) {
	candidate, err := inspectContainer(
		context.Background(),
		engine,
		candidateContainerName(deployment),
	)
	if err == nil && ownsExecution(candidate, deployment) {
		removeOwnedContainer(candidate.Container.ID, deployment, engine)
	}
}

func removeOwnedContainer(
	containerID string,
	deployment agentprotocol.DeploymentCommand,
	engine dockerDeploymentEngine,
) {
	cleanupContext, cancel := context.WithTimeout(
		context.Background(),
		10*time.Second,
	)
	defer cancel()
	current, err := inspectContainer(cleanupContext, engine, containerID)
	if err != nil || !ownsExecution(current, deployment) {
		return
	}
	_, _ = engine.ContainerRemove(
		cleanupContext,
		containerID,
		mobyclient.ContainerRemoveOptions{Force: true},
	)
}

func removeManagedContainer(
	containerName string,
	engine dockerDeploymentEngine,
) {
	cleanupContext, cancel := context.WithTimeout(
		context.Background(),
		10*time.Second,
	)
	defer cancel()
	current, err := inspectContainer(cleanupContext, engine, containerName)
	if err != nil || !managedContainer(current) {
		return
	}
	_, _ = engine.ContainerRemove(
		cleanupContext,
		current.Container.ID,
		mobyclient.ContainerRemoveOptions{Force: true},
	)
}

func removeManagedContainerStrict(
	ctx context.Context,
	containerName string,
	engine dockerDeploymentEngine,
) error {
	current, err := inspectContainer(ctx, engine, containerName)
	if cerrdefs.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return deploymentError("runtime_error", err)
	}
	if !managedContainer(current) {
		return deploymentError("runtime_conflict", nil)
	}
	if _, err := engine.ContainerRemove(
		ctx,
		current.Container.ID,
		mobyclient.ContainerRemoveOptions{Force: true},
	); err != nil && !cerrdefs.IsNotFound(err) {
		return deploymentError("runtime_error", err)
	}
	return nil
}

func restorePrevious(
	previousID string,
	deployment agentprotocol.DeploymentCommand,
	engine dockerDeploymentEngine,
) {
	if previousID == "" {
		return
	}
	cleanupContext, cancel := context.WithTimeout(
		context.Background(),
		10*time.Second,
	)
	defer cancel()
	_, _ = engine.ContainerRename(
		cleanupContext,
		previousID,
		mobyclient.ContainerRenameOptions{
			NewName: deployment.ContainerName,
		},
	)
}

func deploymentResult(
	commandID string,
	errorCode string,
) agentprotocol.AgentCommandResult {
	result := agentprotocol.AgentCommandResult{
		CommandID: commandID,
		Status:    agentprotocol.AgentCommandSucceeded,
	}
	if errorCode != "" {
		result.Status = agentprotocol.AgentCommandFailed
		result.ErrorCode = errorCode
	}
	return result
}

func deploymentError(code string, cause error) error {
	return &deploymentExecutionError{code: code, cause: cause}
}

func newLocalDockerDeploymentEngine(
	socketPath string,
) (dockerDeploymentEngine, error) {
	return mobyclient.New(
		mobyclient.WithHost("unix://" + socketPath),
	)
}
