package data

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/owndock/owndock/internal/modules/controlplane/biz"
	managedhostbiz "github.com/owndock/owndock/internal/modules/managedhost/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
)

type AgentRuntimeTargetProber struct {
	dispatcher managedhostbiz.AgentCommandDispatcher
	newID      func() (string, error)
	now        func() time.Time
	timeout    time.Duration
}

// NewAgentRuntimeTargetProber builds the authorized Server-side bridge from a
// Runtime Target to the Agent command stream. The composition root registers
// it only alongside the matching Agent executor and Deployment Gateway,
// because a ready probe also opens the Deployment ready gate.
func NewAgentRuntimeTargetProber(
	dispatcher managedhostbiz.AgentCommandDispatcher,
	newID func() (string, error),
	now func() time.Time,
	timeout time.Duration,
) (*AgentRuntimeTargetProber, error) {
	if dispatcher == nil || newID == nil || now == nil ||
		timeout <= 0 || timeout > time.Minute {
		return nil, biz.ErrRuntimeTargetProbeUnavailable
	}
	return &AgentRuntimeTargetProber{
		dispatcher: dispatcher,
		newID:      newID,
		now:        now,
		timeout:    timeout,
	}, nil
}

func (p *AgentRuntimeTargetProber) ProbeRuntimeTarget(
	ctx context.Context,
	target biz.RuntimeTarget,
) (biz.RuntimeTargetStatus, error) {
	if target.ConnectionMode != runtimeaccess.ModeAgent ||
		target.ID == "" || target.ManagedHostID == "" {
		return "", biz.ErrRuntimeTargetProbeUnavailable
	}
	commandID, err := p.newID()
	if err != nil {
		return "", fmt.Errorf("generate Agent runtime probe command ID: %w", err)
	}
	command := managedhostbiz.AgentCommand{
		ID:       commandID,
		Kind:     managedhostbiz.AgentCommandRuntimeProbe,
		Deadline: p.now().UTC().Add(p.timeout),
		RuntimeProbe: &managedhostbiz.RuntimeProbeCommand{
			RuntimeTargetID: target.ID,
		},
	}
	commandContext, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	result, err := p.dispatcher.Dispatch(
		commandContext, target.ManagedHostID, command,
	)
	if err != nil {
		return p.classifyDispatchError(ctx, err)
	}
	if err := result.Validate(command); err != nil {
		return "", biz.ErrRuntimeTargetProbeUnavailable
	}
	if result.Status == managedhostbiz.AgentCommandFailed {
		return biz.RuntimeTargetStatusUnreachable, nil
	}
	if result.Status != managedhostbiz.AgentCommandSucceeded ||
		result.RuntimeProbe == nil {
		return "", biz.ErrRuntimeTargetProbeUnavailable
	}
	switch result.RuntimeProbe.Status {
	case managedhostbiz.RuntimeProbeReady:
		return biz.RuntimeTargetStatusReady, nil
	case managedhostbiz.RuntimeProbeUnreachable,
		managedhostbiz.RuntimeProbeUnsupported:
		return biz.RuntimeTargetStatusUnreachable, nil
	default:
		return "", biz.ErrRuntimeTargetProbeUnavailable
	}
}

func (*AgentRuntimeTargetProber) classifyDispatchError(
	ctx context.Context,
	err error,
) (biz.RuntimeTargetStatus, error) {
	if contextErr := ctx.Err(); contextErr != nil {
		return "", contextErr
	}
	switch {
	case errors.Is(err, managedhostbiz.ErrAgentNotConnected),
		errors.Is(err, managedhostbiz.ErrAgentDisconnected),
		errors.Is(err, managedhostbiz.ErrAgentCapabilityUnavailable),
		errors.Is(err, managedhostbiz.ErrAgentCommandExpired),
		errors.Is(err, context.DeadlineExceeded):
		return biz.RuntimeTargetStatusUnreachable, nil
	default:
		return "", biz.ErrRuntimeTargetProbeUnavailable
	}
}
