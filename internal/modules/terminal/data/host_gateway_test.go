package data

import (
	"testing"

	terminalbiz "github.com/owndock/owndock/internal/modules/terminal/biz"
	"github.com/owndock/owndock/internal/shared/agentprotocol"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
)

func TestAgentHostGatewaySendsOnlyConstrainedHostOpen(t *testing.T) {
	stream := &agentProtocolStreamStub{}
	opener := &agentTerminalOpenerStub{stream: stream}
	gateway, err := NewAgentHostGateway(opener)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := gateway.OpenHost(
		t.Context(),
		"terminal-session-1",
		terminalbiz.Target{
			Kind: terminalbiz.KindHost, OrganizationID: "organization-1",
			ManagedHostID: "host-1", ConnectionMode: runtimeaccess.ModeAgent,
		},
		terminalbiz.TerminalSize{Columns: 100, Rows: 40},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if opener.hostID != "host-1" || opener.sessionID != "terminal-session-1" ||
		opener.open.Kind != agentprotocol.TerminalKindHost ||
		opener.open.Columns != 100 || opener.open.Rows != 40 ||
		opener.open.DeploymentID != "" || opener.open.ProjectID != "" ||
		opener.open.ContainerName != "" || opener.open.CutoverSequence != 0 {
		t.Fatalf("Agent host open = %+v", opener)
	}
}

func TestAgentHostGatewayRejectsContainerFieldsAndDirectMode(t *testing.T) {
	gateway, err := NewAgentHostGateway(&agentTerminalOpenerStub{
		stream: &agentProtocolStreamStub{},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []terminalbiz.Target{
		{
			Kind: terminalbiz.KindHost, OrganizationID: "organization-1",
			ManagedHostID: "host-1", ConnectionMode: runtimeaccess.ModeDirectDocker,
		},
		{
			Kind: terminalbiz.KindHost, OrganizationID: "organization-1",
			ManagedHostID: "host-1", ProjectID: "injected-project",
			ConnectionMode: runtimeaccess.ModeAgent,
		},
	} {
		if _, err := gateway.OpenHost(
			t.Context(), "terminal-session-1", target,
			terminalbiz.DefaultTerminalSize(),
		); err != terminalbiz.ErrTargetUnavailable {
			t.Fatalf("target %+v error = %v", target, err)
		}
	}
}
