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

func NewRuntimeTargetRetirementAdapter(
	retirement *biz.RuntimeTargetRetirement,
) *RuntimeTargetRetirementAdapter {
	return &RuntimeTargetRetirementAdapter{retirement: retirement}
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
