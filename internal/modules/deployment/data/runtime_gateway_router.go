package data

import (
	"context"
	"errors"

	"github.com/owndock/owndock/internal/modules/deployment/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
)

var ErrRuntimeModeUnavailable = errors.New("runtime connection mode is unavailable")

// RuntimeGatewayRouter keeps Deployment independent from the target transport.
// A mode is registered only when its complete executor is available.
type RuntimeGatewayRouter struct {
	gateways map[runtimeaccess.Mode]biz.RuntimeGateway
}

func NewRuntimeGatewayRouter(
	gateways map[runtimeaccess.Mode]biz.RuntimeGateway,
) *RuntimeGatewayRouter {
	copied := make(map[runtimeaccess.Mode]biz.RuntimeGateway, len(gateways))
	for mode, gateway := range gateways {
		if mode.Valid() && gateway != nil {
			copied[mode] = gateway
		}
	}
	return &RuntimeGatewayRouter{gateways: copied}
}

func (r *RuntimeGatewayRouter) Prepare(
	ctx context.Context,
	plan biz.ExecutionPlan,
	credential biz.RuntimeCredential,
) error {
	gateway, err := r.gateway(plan)
	if err != nil {
		return err
	}
	return gateway.Prepare(ctx, plan, credential)
}

func (r *RuntimeGatewayRouter) Deploy(
	ctx context.Context,
	plan biz.ExecutionPlan,
	credential biz.RuntimeCredential,
) error {
	gateway, err := r.gateway(plan)
	if err != nil {
		return err
	}
	return gateway.Deploy(ctx, plan, credential)
}

func (r *RuntimeGatewayRouter) Cancel(
	ctx context.Context,
	plan biz.ExecutionPlan,
	credential biz.RuntimeCredential,
) error {
	gateway, err := r.gateway(plan)
	if err != nil {
		return err
	}
	return gateway.Cancel(ctx, plan, credential)
}

func (r *RuntimeGatewayRouter) gateway(
	plan biz.ExecutionPlan,
) (biz.RuntimeGateway, error) {
	if err := plan.TargetConnection.Validate(); err != nil {
		return nil, &biz.ExecutionError{
			Category: biz.FailureConfiguration,
			Cause:    err,
		}
	}
	gateway := r.gateways[plan.TargetConnection.Mode]
	if gateway == nil {
		return nil, &biz.ExecutionError{
			Category: biz.FailureUnsupportedTarget,
			Cause:    ErrRuntimeModeUnavailable,
		}
	}
	return gateway, nil
}
