package data

import (
	"bytes"
	"context"
	"testing"

	terminalbiz "github.com/owndock/owndock/internal/modules/terminal/biz"
	"github.com/owndock/owndock/internal/shared/agentprotocol"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
)

type agentTerminalOpenerStub struct {
	hostID, sessionID string
	open              agentprotocol.TerminalOpen
	stream            *agentProtocolStreamStub
}

func (o *agentTerminalOpenerStub) OpenTerminal(
	_ context.Context,
	hostID, sessionID string,
	open agentprotocol.TerminalOpen,
) (agentprotocol.TerminalStream, error) {
	o.hostID, o.sessionID, o.open = hostID, sessionID, open
	return o.stream, nil
}

type agentProtocolStreamStub struct {
	bytes.Buffer
	columns, rows uint16
}

func (*agentProtocolStreamStub) Close() error { return nil }
func (s *agentProtocolStreamStub) Resize(
	_ context.Context,
	columns, rows uint16,
) error {
	s.columns, s.rows = columns, rows
	return nil
}

func TestAgentContainerGatewayMapsAuthorizedTarget(t *testing.T) {
	connection, err := runtimeaccess.NewAgent("host-1")
	if err != nil {
		t.Fatal(err)
	}
	stream := &agentProtocolStreamStub{}
	opener := &agentTerminalOpenerStub{stream: stream}
	gateway, err := NewAgentContainerGateway(opener)
	if err != nil {
		t.Fatal(err)
	}
	target := terminalbiz.Target{
		Kind: terminalbiz.KindContainer, OrganizationID: "organization-1",
		ProjectID: "project-1", ApplicationID: "application-1",
		EnvironmentID: "environment-1", ManagedHostID: "host-1",
		RuntimeTargetID: "target-1", DeploymentID: "deployment-1",
		ContainerName: "owndock-container-1", InstanceGeneration: 7,
		ConnectionMode: runtimeaccess.ModeAgent, Connection: connection,
	}
	opened, err := gateway.OpenContainer(
		t.Context(),
		"terminal-session-1",
		target,
		terminalbiz.TerminalSize{Columns: 120, Rows: 30},
	)
	if err != nil {
		t.Fatal(err)
	}
	if opener.hostID != "host-1" || opener.sessionID != "terminal-session-1" ||
		opener.open.DeploymentID != "deployment-1" ||
		opener.open.ProjectID != "project-1" ||
		opener.open.ApplicationID != "application-1" ||
		opener.open.EnvironmentID != "environment-1" ||
		opener.open.RuntimeTargetID != "target-1" ||
		opener.open.ContainerName != "owndock-container-1" ||
		opener.open.CutoverSequence != 7 ||
		opener.open.Columns != 120 || opener.open.Rows != 30 {
		t.Fatalf("Agent terminal route = %+v", opener)
	}
	if err := opened.Resize(
		t.Context(), terminalbiz.TerminalSize{Columns: 132, Rows: 43},
	); err != nil {
		t.Fatal(err)
	}
	if stream.columns != 132 || stream.rows != 43 {
		t.Fatalf("Agent terminal resize = %dx%d", stream.columns, stream.rows)
	}
}

func TestAgentContainerGatewayRejectsDirectTarget(t *testing.T) {
	gateway, err := NewAgentContainerGateway(&agentTerminalOpenerStub{
		stream: &agentProtocolStreamStub{},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = gateway.OpenContainer(
		t.Context(),
		"terminal-session-1",
		terminalbiz.Target{
			Kind: terminalbiz.KindContainer, OrganizationID: "organization-1",
			ProjectID: "project-1", ManagedHostID: "host-1",
			ConnectionMode: runtimeaccess.ModeDirectDocker,
		},
		terminalbiz.DefaultTerminalSize(),
	)
	if err != terminalbiz.ErrTargetUnavailable {
		t.Fatalf("OpenContainer() error = %v", err)
	}
}
