package data

import (
	"context"
	"errors"

	terminalbiz "github.com/owndock/owndock/internal/modules/terminal/biz"
	"github.com/owndock/owndock/internal/shared/agentprotocol"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
)

var ErrInvalidAgentContainerGateway = errors.New("Agent container terminal gateway is invalid")

type agentTerminalOpener interface {
	OpenTerminal(
		context.Context,
		string,
		string,
		agentprotocol.TerminalOpen,
	) (agentprotocol.TerminalStream, error)
}

// AgentContainerGateway maps the already-authorized product target to the
// constrained Agent terminal protocol. It does not accept arbitrary runtime
// endpoints, container names, commands, users, environments, or privileges.
type AgentContainerGateway struct {
	opener agentTerminalOpener
}

func NewAgentContainerGateway(opener agentTerminalOpener) (*AgentContainerGateway, error) {
	if opener == nil {
		return nil, ErrInvalidAgentContainerGateway
	}
	return &AgentContainerGateway{opener: opener}, nil
}

func (g *AgentContainerGateway) OpenContainer(
	ctx context.Context,
	sessionID string,
	target terminalbiz.Target,
	size terminalbiz.TerminalSize,
) (terminalbiz.TerminalStream, error) {
	if target.Kind != terminalbiz.KindContainer || sessionID == "" ||
		target.OrganizationID == "" || target.ProjectID == "" ||
		target.ApplicationID == "" || target.EnvironmentID == "" ||
		target.ManagedHostID == "" || target.RuntimeTargetID == "" ||
		target.DeploymentID == "" || target.ContainerName == "" ||
		target.InstanceGeneration == 0 ||
		target.ConnectionMode != runtimeaccess.ModeAgent ||
		target.Connection.Mode != runtimeaccess.ModeAgent ||
		target.Connection.ManagedHostID != target.ManagedHostID ||
		target.Connection.Validate() != nil || size.Validate() != nil {
		return nil, terminalbiz.ErrTargetUnavailable
	}
	stream, err := g.opener.OpenTerminal(
		ctx,
		target.ManagedHostID,
		sessionID,
		agentprotocol.TerminalOpen{
			Kind:         agentprotocol.TerminalKindContainer,
			DeploymentID: target.DeploymentID, ProjectID: target.ProjectID,
			ApplicationID: target.ApplicationID, EnvironmentID: target.EnvironmentID,
			RuntimeTargetID: target.RuntimeTargetID, ContainerName: target.ContainerName,
			CutoverSequence: target.InstanceGeneration,
			Columns:         size.Columns, Rows: size.Rows,
		},
	)
	if err != nil {
		return nil, terminalbiz.ErrStreamUnavailable
	}
	return &agentContainerStream{TerminalStream: stream}, nil
}

type agentContainerStream struct {
	agentprotocol.TerminalStream
}

func (s *agentContainerStream) Resize(
	ctx context.Context,
	size terminalbiz.TerminalSize,
) error {
	if err := size.Validate(); err != nil {
		return err
	}
	return s.TerminalStream.Resize(ctx, size.Columns, size.Rows)
}

var _ terminalbiz.ContainerGateway = (*AgentContainerGateway)(nil)
var _ terminalbiz.TerminalStream = (*agentContainerStream)(nil)
