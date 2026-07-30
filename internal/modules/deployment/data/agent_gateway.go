package data

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/owndock/owndock/internal/modules/deployment/biz"
	managedhostbiz "github.com/owndock/owndock/internal/modules/managedhost/biz"
	"github.com/owndock/owndock/internal/shared/agentprotocol"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
)

var ErrAgentDockerGatewayUnavailable = errors.New(
	"Agent Docker gateway is unavailable",
)

// AgentDockerGateway preserves the Deployment RuntimeGateway contract while
// splitting remote cutover around the authoritative MongoDB lease fence.
type AgentDockerGateway struct {
	dispatcher managedhostbiz.AgentCommandDispatcher
	fence      biz.FenceValidator
	newID      func() (string, error)
	now        func() time.Time
	timeout    time.Duration
}

func NewAgentDockerGateway(
	dispatcher managedhostbiz.AgentCommandDispatcher,
	fence biz.FenceValidator,
	newID func() (string, error),
	now func() time.Time,
	timeout time.Duration,
) (*AgentDockerGateway, error) {
	if dispatcher == nil || fence == nil || newID == nil || now == nil ||
		timeout <= 0 || timeout > 30*time.Minute {
		return nil, ErrAgentDockerGatewayUnavailable
	}
	return &AgentDockerGateway{
		dispatcher: dispatcher,
		fence:      fence,
		newID:      newID,
		now:        now,
		timeout:    timeout,
	}, nil
}

func (g *AgentDockerGateway) Prepare(
	ctx context.Context,
	plan biz.ExecutionPlan,
	credential biz.RuntimeCredential,
) error {
	deployment, err := agentDeploymentIdentity(plan)
	if err != nil {
		return err
	}
	deployment.ImageDigest = plan.ImageDigest
	deployment.RegistryAuthorization = append(
		[]byte(nil),
		credential.RegistryAuthorization...,
	)
	return g.dispatch(
		ctx,
		plan.TargetConnection.ManagedHostID,
		agentprotocol.AgentCommandDeploymentPrepare,
		deployment,
	)
}

func (g *AgentDockerGateway) Deploy(
	ctx context.Context,
	plan biz.ExecutionPlan,
	_ biz.RuntimeCredential,
) error {
	deployment, err := agentDeploymentIdentity(plan)
	if err != nil {
		return err
	}
	deployment.ProjectID = plan.ProjectID
	deployment.ApplicationID = plan.ApplicationID
	deployment.EnvironmentID = plan.EnvironmentID
	deployment.ImageDigest = plan.ImageDigest
	deployment.RuntimeSpec = plan.RuntimeSpec
	deployment.Environment = append([]string(nil), plan.Environment...)

	hostID := plan.TargetConnection.ManagedHostID
	if err := g.dispatch(
		ctx,
		hostID,
		agentprotocol.AgentCommandDeploymentStage,
		deployment,
	); err != nil {
		return err
	}
	if err := g.validateFence(ctx, plan); err != nil {
		g.cancelStagedCandidate(plan)
		return staleExecutionError()
	}
	activation, err := agentDeploymentIdentity(plan)
	if err != nil {
		return err
	}
	return g.dispatch(
		ctx,
		hostID,
		agentprotocol.AgentCommandDeploymentActivate,
		activation,
	)
}

func (g *AgentDockerGateway) Cancel(
	ctx context.Context,
	plan biz.ExecutionPlan,
	_ biz.RuntimeCredential,
) error {
	deployment, err := agentDeploymentIdentity(plan)
	if err != nil {
		return err
	}
	if err := g.validateFence(ctx, plan); err != nil {
		return staleExecutionError()
	}
	return g.dispatch(
		ctx,
		plan.TargetConnection.ManagedHostID,
		agentprotocol.AgentCommandDeploymentCancel,
		deployment,
	)
}

func (g *AgentDockerGateway) dispatch(
	ctx context.Context,
	hostID string,
	kind agentprotocol.AgentCommandKind,
	deployment agentprotocol.DeploymentCommand,
) error {
	commandID, err := g.newID()
	if err != nil {
		return executionError(
			biz.FailureRuntime,
			fmt.Errorf("generate Agent command ID: %w", err),
		)
	}
	deadline := g.now().UTC().Add(g.timeout)
	if contextDeadline, ok := ctx.Deadline(); ok &&
		contextDeadline.Before(deadline) {
		deadline = contextDeadline.UTC()
	}
	command := managedhostbiz.AgentCommand{
		ID:         commandID,
		Kind:       kind,
		Deadline:   deadline,
		Deployment: &deployment,
	}
	result, err := g.dispatcher.Dispatch(ctx, hostID, command)
	if err != nil {
		return g.dispatchError(ctx, err)
	}
	if err := result.Validate(command); err != nil {
		return executionError(biz.FailureRuntime, err)
	}
	if result.Status == agentprotocol.AgentCommandSucceeded {
		return nil
	}
	return agentResultError(result.ErrorCode)
}

func (g *AgentDockerGateway) dispatchError(
	ctx context.Context,
	err error,
) error {
	if contextError := ctx.Err(); contextError != nil {
		return executionError(biz.FailureRuntime, contextError)
	}
	switch {
	case errors.Is(err, managedhostbiz.ErrAgentNotConnected),
		errors.Is(err, managedhostbiz.ErrAgentDisconnected),
		errors.Is(err, managedhostbiz.ErrAgentCommandExpired),
		errors.Is(err, managedhostbiz.ErrAgentBackpressure),
		errors.Is(err, context.DeadlineExceeded):
		return executionError(biz.FailureTargetUnreachable, err)
	case errors.Is(err, managedhostbiz.ErrAgentCapabilityUnavailable):
		return executionError(biz.FailureUnsupportedTarget, err)
	default:
		return executionError(biz.FailureRuntime, err)
	}
}

func (g *AgentDockerGateway) validateFence(
	ctx context.Context,
	plan biz.ExecutionPlan,
) error {
	return g.fence.ValidateFence(
		ctx,
		plan.ProjectID,
		plan.DeploymentID,
		plan.WorkerID,
		plan.FencingToken,
		g.now().UTC(),
	)
}

func (g *AgentDockerGateway) cancelStagedCandidate(
	plan biz.ExecutionPlan,
) {
	ctx, cancel := context.WithTimeout(
		context.Background(),
		min(g.timeout, 10*time.Second),
	)
	defer cancel()
	deployment, err := agentDeploymentIdentity(plan)
	if err != nil {
		return
	}
	_ = g.dispatch(
		ctx,
		plan.TargetConnection.ManagedHostID,
		agentprotocol.AgentCommandDeploymentCancel,
		deployment,
	)
}

func agentDeploymentIdentity(
	plan biz.ExecutionPlan,
) (agentprotocol.DeploymentCommand, error) {
	if err := plan.TargetConnection.Validate(); err != nil ||
		plan.TargetConnection.Mode != runtimeaccess.ModeAgent {
		if err == nil {
			err = runtimeaccess.ErrUnsupportedMode
		}
		return agentprotocol.DeploymentCommand{}, executionError(
			biz.FailureConfiguration,
			err,
		)
	}
	return agentprotocol.DeploymentCommand{
		DeploymentID:    plan.DeploymentID,
		WorkerID:        plan.WorkerID,
		FencingToken:    plan.FencingToken,
		CutoverSequence: plan.CutoverSequence,
		RuntimeTargetID: plan.RuntimeTargetID,
		ContainerName:   plan.ContainerName,
	}, nil
}

func agentResultError(code string) error {
	switch code {
	case "runtime_configuration":
		return executionError(
			biz.FailureConfiguration,
			errors.New(code),
		)
	case "target_unreachable", "command_expired":
		return executionError(
			biz.FailureTargetUnreachable,
			errors.New(code),
		)
	case "image_pull":
		return executionError(
			biz.FailureImagePull,
			errors.New(code),
		)
	case "stale_execution":
		return staleExecutionError()
	default:
		return executionError(
			biz.FailureRuntime,
			errors.New(code),
		)
	}
}

func executionError(
	category biz.FailureCategory,
	cause error,
) error {
	return &biz.ExecutionError{
		Category: category,
		Cause:    cause,
	}
}
