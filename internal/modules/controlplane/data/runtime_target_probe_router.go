package data

import (
	"context"

	"github.com/owndock/owndock/internal/modules/controlplane/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
)

// RuntimeTargetProbeRouter keeps the control-plane use case independent from
// direct Docker and Agent transports. A mode is registered only when its
// complete probe path is available.
type RuntimeTargetProbeRouter struct {
	probers map[runtimeaccess.Mode]biz.RuntimeTargetProber
}

func NewRuntimeTargetProbeRouter(
	probers map[runtimeaccess.Mode]biz.RuntimeTargetProber,
) *RuntimeTargetProbeRouter {
	copied := make(map[runtimeaccess.Mode]biz.RuntimeTargetProber, len(probers))
	for mode, prober := range probers {
		if mode.Valid() && prober != nil {
			copied[mode] = prober
		}
	}
	return &RuntimeTargetProbeRouter{probers: copied}
}

func (r *RuntimeTargetProbeRouter) ProbeRuntimeTarget(
	ctx context.Context,
	target biz.RuntimeTarget,
) (biz.RuntimeTargetStatus, error) {
	prober := r.probers[target.ConnectionMode]
	if prober == nil {
		return "", biz.ErrRuntimeTargetProbeUnavailable
	}
	return prober.ProbeRuntimeTarget(ctx, target)
}
