package data

import (
	"context"
	"errors"

	terminalbiz "github.com/owndock/owndock/internal/modules/terminal/biz"
	"github.com/owndock/owndock/internal/shared/agentprotocol"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
)

var ErrInvalidAgentHostGateway = errors.New("Agent host terminal gateway is invalid")

// AgentHostGateway opens a PTY on the authenticated Agent already bound to
// the Managed Host. The frame intentionally contains no user, shell, command,
// environment, directory, endpoint, or privilege selection.
type AgentHostGateway struct {
	opener agentTerminalOpener
}

func NewAgentHostGateway(opener agentTerminalOpener) (*AgentHostGateway, error) {
	if opener == nil {
		return nil, ErrInvalidAgentHostGateway
	}
	return &AgentHostGateway{opener: opener}, nil
}

func (g *AgentHostGateway) OpenHost(
	ctx context.Context,
	sessionID string,
	target terminalbiz.Target,
	size terminalbiz.TerminalSize,
) (terminalbiz.TerminalStream, error) {
	if target.Kind != terminalbiz.KindHost || sessionID == "" ||
		target.OrganizationID == "" || target.ManagedHostID == "" ||
		target.ProjectID != "" || target.RuntimeTargetID != "" ||
		target.DeploymentID != "" || target.RunningInstanceID != "" ||
		target.ConnectionMode != runtimeaccess.ModeAgent || size.Validate() != nil {
		return nil, terminalbiz.ErrTargetUnavailable
	}
	stream, err := g.opener.OpenTerminal(
		ctx,
		target.ManagedHostID,
		sessionID,
		agentprotocol.TerminalOpen{
			Kind:    agentprotocol.TerminalKindHost,
			Columns: size.Columns, Rows: size.Rows,
		},
	)
	if err != nil {
		return nil, terminalbiz.ErrStreamUnavailable
	}
	return &agentContainerStream{TerminalStream: stream}, nil
}

type HostGatewayRouter struct {
	gateways map[runtimeaccess.Mode]terminalbiz.HostGateway
}

func NewHostGatewayRouter(
	gateways map[runtimeaccess.Mode]terminalbiz.HostGateway,
) *HostGatewayRouter {
	copyOfGateways := make(map[runtimeaccess.Mode]terminalbiz.HostGateway, len(gateways))
	for mode, gateway := range gateways {
		if mode.Valid() && gateway != nil {
			copyOfGateways[mode] = gateway
		}
	}
	return &HostGatewayRouter{gateways: copyOfGateways}
}

func (r *HostGatewayRouter) OpenHost(
	ctx context.Context,
	sessionID string,
	target terminalbiz.Target,
	size terminalbiz.TerminalSize,
) (terminalbiz.TerminalStream, error) {
	gateway := r.gateways[target.ConnectionMode]
	if gateway == nil {
		return nil, terminalbiz.ErrStreamUnavailable
	}
	return gateway.OpenHost(ctx, sessionID, target, size)
}

var _ terminalbiz.HostGateway = (*AgentHostGateway)(nil)
var _ terminalbiz.HostGateway = (*HostGatewayRouter)(nil)
