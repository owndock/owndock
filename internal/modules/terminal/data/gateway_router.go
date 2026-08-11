package data

import (
	"context"

	terminalbiz "github.com/owndock/owndock/internal/modules/terminal/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
)

// ContainerGatewayRouter keeps connection-mode selection outside the domain
// use case. Unsupported modes fail closed instead of silently falling back to
// another path.
type ContainerGatewayRouter struct {
	gateways map[runtimeaccess.Mode]terminalbiz.ContainerGateway
}

func NewContainerGatewayRouter(
	gateways map[runtimeaccess.Mode]terminalbiz.ContainerGateway,
) *ContainerGatewayRouter {
	copyOfGateways := make(map[runtimeaccess.Mode]terminalbiz.ContainerGateway, len(gateways))
	for mode, gateway := range gateways {
		if mode.Valid() && gateway != nil {
			copyOfGateways[mode] = gateway
		}
	}
	return &ContainerGatewayRouter{gateways: copyOfGateways}
}

func (r *ContainerGatewayRouter) OpenContainer(
	ctx context.Context,
	sessionID string,
	target terminalbiz.Target,
	size terminalbiz.TerminalSize,
) (terminalbiz.TerminalStream, error) {
	gateway := r.gateways[target.ConnectionMode]
	if gateway == nil || target.Connection.Mode != target.ConnectionMode {
		return nil, terminalbiz.ErrStreamUnavailable
	}
	return gateway.OpenContainer(ctx, sessionID, target, size)
}

var _ terminalbiz.ContainerGateway = (*ContainerGatewayRouter)(nil)
