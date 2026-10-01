package data

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	applicationroutebiz "github.com/owndock/owndock/internal/modules/applicationroute/biz"
	managedhostbiz "github.com/owndock/owndock/internal/modules/managedhost/biz"
	"github.com/owndock/owndock/internal/shared/agentprotocol"
)

func TestAgentGatewayBuildsCanonicalTypedCommand(t *testing.T) {
	aliasA, err := agentprotocol.DeploymentBackendAlias("deployment-a")
	if err != nil {
		t.Fatal(err)
	}
	aliasB, err := agentprotocol.DeploymentBackendAlias("deployment-b")
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := &ingressDispatcherStub{}
	gateway, err := NewAgentGateway(dispatcher, func() (string, error) { return "command-1", nil },
		func() time.Time { return time.Unix(100, 0).UTC() }, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	desired := applicationroutebiz.HostDesiredConfig{ManagedHostID: "host-1", HostRevision: 3,
		ProbeRouteIDs: []string{"route-b", "route-a"},
		Routes: []applicationroutebiz.GatewayRoute{
			{RouteID: "route-b", Revision: 1, DeploymentID: "deployment-b", CutoverSequence: 2,
				RuntimeTargetID: "target-1", Hostname: "b.example.com", BackendAlias: aliasB,
				BackendPort: 8080, TLSMode: applicationroutebiz.TLSModeAutomatic},
			{RouteID: "route-a", Revision: 1, DeploymentID: "deployment-a", CutoverSequence: 1,
				RuntimeTargetID: "target-1", Hostname: "a.example.com", BackendAlias: aliasA,
				BackendPort: 8080, TLSMode: applicationroutebiz.TLSModeAutomatic},
		}}
	dispatcher.result = func(command managedhostbiz.AgentCommand) managedhostbiz.AgentCommandResult {
		return managedhostbiz.AgentCommandResult{CommandID: command.ID,
			Status: agentprotocol.AgentCommandSucceeded, Ingress: &agentprotocol.IngressResult{
				HostRevision: command.Ingress.HostRevision, ConfigDigest: command.Ingress.ConfigDigest}}
	}
	observation, err := gateway.Prepare(context.Background(), desired)
	if err != nil || observation.HostRevision != 3 || observation.ConfigDigest == "" {
		t.Fatalf("Prepare() = %#v, %v", observation, err)
	}
	if dispatcher.hostID != "host-1" || dispatcher.command.Ingress == nil ||
		dispatcher.command.Ingress.Routes[0].RouteID != "route-a" ||
		dispatcher.command.Ingress.ProbeRouteIDs[0] != "route-a" ||
		dispatcher.command.Kind != agentprotocol.AgentCommandIngressPrepare {
		t.Fatalf("dispatch = %q/%+v", dispatcher.hostID, dispatcher.command)
	}
}

func TestAgentGatewayMapsSafeFenceErrors(t *testing.T) {
	dispatcher := &ingressDispatcherStub{result: func(command managedhostbiz.AgentCommand) managedhostbiz.AgentCommandResult {
		return managedhostbiz.AgentCommandResult{CommandID: command.ID,
			Status: agentprotocol.AgentCommandFailed, ErrorCode: "ingress_fence_stale"}
	}}
	gateway, _ := NewAgentGateway(dispatcher, func() (string, error) { return "command-1", nil },
		func() time.Time { return time.Unix(100, 0).UTC() }, time.Minute)
	desired := applicationroutebiz.HostDesiredConfig{ManagedHostID: "host-1", HostRevision: 1}
	if _, err := gateway.Prepare(context.Background(), desired); !errors.Is(err, applicationroutebiz.ErrGatewayFenceStale) {
		t.Fatalf("stale result error = %v", err)
	}
}

func TestAgentGatewayMapsCertificateFailure(t *testing.T) {
	dispatcher := &ingressDispatcherStub{result: func(command managedhostbiz.AgentCommand) managedhostbiz.AgentCommandResult {
		return managedhostbiz.AgentCommandResult{CommandID: command.ID,
			Status: agentprotocol.AgentCommandFailed, ErrorCode: "ingress_certificate_unavailable"}
	}}
	gateway, _ := NewAgentGateway(dispatcher, func() (string, error) { return "command-1", nil },
		func() time.Time { return time.Unix(100, 0).UTC() }, time.Minute)
	desired := applicationroutebiz.HostDesiredConfig{ManagedHostID: "host-1", HostRevision: 1}
	if _, err := gateway.Prepare(context.Background(), desired); !errors.Is(err, applicationroutebiz.ErrGatewayCertificateUnavailable) {
		t.Fatalf("certificate result error = %v", err)
	}
}

func TestAgentGatewayDispatchesCommitAndAbort(t *testing.T) {
	dispatcher := &ingressDispatcherStub{}
	dispatcher.result = func(command managedhostbiz.AgentCommand) managedhostbiz.AgentCommandResult {
		return managedhostbiz.AgentCommandResult{CommandID: command.ID,
			Status: agentprotocol.AgentCommandSucceeded, Ingress: &agentprotocol.IngressResult{
				HostRevision: command.Ingress.HostRevision, ConfigDigest: command.Ingress.ConfigDigest}}
	}
	nextID := 0
	gateway, err := NewAgentGateway(dispatcher, func() (string, error) {
		nextID++
		return fmt.Sprintf("command-%d", nextID), nil
	}, func() time.Time { return time.Unix(100, 0).UTC() }, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	desired := applicationroutebiz.HostDesiredConfig{ManagedHostID: "host-1", HostRevision: 1}
	if _, err := gateway.Commit(context.Background(), desired); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	if dispatcher.command.Kind != agentprotocol.AgentCommandIngressCommit {
		t.Fatalf("commit kind = %q", dispatcher.command.Kind)
	}
	if _, err := gateway.Abort(context.Background(), desired); err != nil {
		t.Fatalf("Abort() error = %v", err)
	}
	if dispatcher.command.Kind != agentprotocol.AgentCommandIngressAbort {
		t.Fatalf("abort kind = %q", dispatcher.command.Kind)
	}
}

type ingressDispatcherStub struct {
	hostID  string
	command managedhostbiz.AgentCommand
	result  func(managedhostbiz.AgentCommand) managedhostbiz.AgentCommandResult
	err     error
}

func (d *ingressDispatcherStub) Dispatch(_ context.Context, hostID string, command managedhostbiz.AgentCommand) (managedhostbiz.AgentCommandResult, error) {
	d.hostID, d.command = hostID, command
	if d.err != nil {
		return managedhostbiz.AgentCommandResult{}, d.err
	}
	return d.result(command), nil
}
