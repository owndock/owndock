package data

import (
	"context"
	"errors"

	controlplanebiz "github.com/owndock/owndock/internal/modules/controlplane/biz"
	"github.com/owndock/owndock/internal/modules/deployment/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/security"
)

type RuntimeTargetRetirementAdapter struct {
	retirement *biz.RuntimeTargetRetirement
}

type retirementConnectionSource interface {
	GetRuntimeTarget(context.Context, string, string) (controlplanebiz.RuntimeTarget, error)
	RuntimeTargetCleanupExecution(context.Context, string, string) (runtimeaccess.Connection, error)
}

type RetirementConnectionResolver struct {
	source retirementConnectionSource
}

func NewRetirementConnectionResolver(source retirementConnectionSource) *RetirementConnectionResolver {
	return &RetirementConnectionResolver{source: source}
}

func (r *RetirementConnectionResolver) RuntimeTargetCleanupExecution(
	ctx context.Context,
	projectID, targetID string,
) (runtimeaccess.Connection, error) {
	if r == nil || r.source == nil {
		return runtimeaccess.Connection{}, biz.ErrRetirementUnavailable
	}
	if _, err := r.source.GetRuntimeTarget(ctx, projectID, targetID); errors.Is(err, controlplanebiz.ErrNotFound) {
		return runtimeaccess.Connection{}, biz.ErrRetirementTargetRemoved
	} else if err != nil {
		return runtimeaccess.Connection{}, err
	}
	return r.source.RuntimeTargetCleanupExecution(ctx, projectID, targetID)
}

func NewRuntimeTargetRetirementAdapter(
	retirement *biz.RuntimeTargetRetirement,
) *RuntimeTargetRetirementAdapter {
	return &RuntimeTargetRetirementAdapter{retirement: retirement}
}

func (a *RuntimeTargetRetirementAdapter) RetireProductResource(
	ctx context.Context,
	scope controlplanebiz.ProductResourceRetirementScope,
	principal security.Principal,
	requestID string,
) error {
	if a == nil || a.retirement == nil {
		return controlplanebiz.ErrResourceRetirementUnavailable
	}
	err := a.retirement.RetireScope(ctx, biz.RetirementScope{
		ProjectID: scope.ProjectID, ApplicationID: scope.ApplicationID,
		EnvironmentID: scope.EnvironmentID,
	}, principal, requestID)
	if errors.Is(err, biz.ErrRetirementPending) {
		return controlplanebiz.ErrResourceRetirementPending
	}
	if errors.Is(err, biz.ErrRetirementUnavailable) {
		return controlplanebiz.ErrResourceRetirementUnavailable
	}
	return err
}

func (a *RuntimeTargetRetirementAdapter) RetireRuntimeTarget(
	ctx context.Context,
	target controlplanebiz.RuntimeTarget,
	principal security.Principal,
	requestID string,
) error {
	if a == nil || a.retirement == nil {
		return controlplanebiz.ErrRuntimeTargetRetirementUnavailable
	}
	connection, err := retirementConnection(target)
	if err != nil {
		return controlplanebiz.ErrRuntimeTargetRetirementUnavailable
	}
	err = a.retirement.Retire(
		ctx,
		biz.RetirementTarget{
			ID: target.ID, ProjectID: target.ProjectID, Connection: connection,
		},
		principal,
		requestID,
	)
	if errors.Is(err, biz.ErrRetirementPending) {
		return controlplanebiz.ErrRuntimeTargetRetirementPending
	}
	if errors.Is(err, biz.ErrRetirementUnavailable) {
		return controlplanebiz.ErrRuntimeTargetRetirementUnavailable
	}
	return err
}

func retirementConnection(
	target controlplanebiz.RuntimeTarget,
) (runtimeaccess.Connection, error) {
	switch target.ConnectionMode {
	case runtimeaccess.ModeDirectDocker:
		return runtimeaccess.NewDirectDocker(
			target.ManagedHostID, target.Endpoint,
			target.TLSServerName, target.CredentialRef,
		)
	case runtimeaccess.ModeAgent:
		return runtimeaccess.NewAgent(target.ManagedHostID)
	default:
		return runtimeaccess.Connection{}, runtimeaccess.ErrUnsupportedMode
	}
}
