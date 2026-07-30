package data

import (
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/controlplane/biz"
	managedhostbiz "github.com/owndock/owndock/internal/modules/managedhost/biz"
	managedhostdata "github.com/owndock/owndock/internal/modules/managedhost/data"
	"github.com/owndock/owndock/internal/shared/agentprotocol"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
)

func TestAgentRuntimeTargetProberUsesConnectedHostRegistry(t *testing.T) {
	registry, err := managedhostdata.NewConnectionRegistry(2, 4)
	if err != nil {
		t.Fatal(err)
	}
	commands := registry.Register(
		"host-1",
		"session-1",
		agentprotocol.SupportedCapabilities(),
		func() {},
	)
	prober, err := NewAgentRuntimeTargetProber(
		registry,
		func() (string, error) { return "command-1", nil },
		time.Now,
		time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}

	statusChannel := make(chan biz.RuntimeTargetStatus, 1)
	errorChannel := make(chan error, 1)
	go func() {
		status, probeErr := prober.ProbeRuntimeTarget(
			t.Context(),
			biz.RuntimeTarget{
				ID: "target-1", ManagedHostID: "host-1",
				ConnectionMode: runtimeaccess.ModeAgent,
			},
		)
		statusChannel <- status
		errorChannel <- probeErr
	}()

	command := <-commands
	if command.RuntimeProbe == nil ||
		command.RuntimeProbe.RuntimeTargetID != "target-1" {
		t.Fatalf("command = %+v", command)
	}
	if err := registry.Complete(
		"host-1", "session-1",
		managedhostbiz.AgentCommandResult{
			CommandID: command.ID,
			Status:    managedhostbiz.AgentCommandSucceeded,
			RuntimeProbe: &managedhostbiz.RuntimeProbeResult{
				Status: managedhostbiz.RuntimeProbeReady,
			},
		},
	); err != nil {
		t.Fatal(err)
	}
	if err := <-errorChannel; err != nil {
		t.Fatal(err)
	}
	if status := <-statusChannel; status != biz.RuntimeTargetStatusReady {
		t.Fatalf("status = %s", status)
	}
}

func TestAgentRuntimeTargetProberDoesNotCrossHostBoundary(t *testing.T) {
	registry, err := managedhostdata.NewConnectionRegistry(1, 2)
	if err != nil {
		t.Fatal(err)
	}
	otherHostCommands := registry.Register(
		"host-2",
		"session-2",
		agentprotocol.SupportedCapabilities(),
		func() {},
	)
	prober, err := NewAgentRuntimeTargetProber(
		registry,
		func() (string, error) { return "command-1", nil },
		time.Now,
		time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	status, err := prober.ProbeRuntimeTarget(
		t.Context(),
		biz.RuntimeTarget{
			ID: "target-1", ManagedHostID: "host-1",
			ConnectionMode: runtimeaccess.ModeAgent,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if status != biz.RuntimeTargetStatusUnreachable {
		t.Fatalf("status = %s", status)
	}
	select {
	case command := <-otherHostCommands:
		t.Fatalf("command crossed Host boundary: %+v", command)
	default:
	}
}

func TestAgentRuntimeTargetProberBoundsCommandWait(t *testing.T) {
	registry, err := managedhostdata.NewConnectionRegistry(1, 2)
	if err != nil {
		t.Fatal(err)
	}
	commands := registry.Register(
		"host-1",
		"session-1",
		agentprotocol.SupportedCapabilities(),
		func() {},
	)
	prober, err := NewAgentRuntimeTargetProber(
		registry,
		func() (string, error) { return "command-1", nil },
		time.Now,
		20*time.Millisecond,
	)
	if err != nil {
		t.Fatal(err)
	}
	statusChannel := make(chan biz.RuntimeTargetStatus, 1)
	errorChannel := make(chan error, 1)
	go func() {
		status, probeErr := prober.ProbeRuntimeTarget(
			t.Context(),
			biz.RuntimeTarget{
				ID: "target-1", ManagedHostID: "host-1",
				ConnectionMode: runtimeaccess.ModeAgent,
			},
		)
		statusChannel <- status
		errorChannel <- probeErr
	}()
	<-commands
	if err := <-errorChannel; err != nil {
		t.Fatal(err)
	}
	if status := <-statusChannel; status != biz.RuntimeTargetStatusUnreachable {
		t.Fatalf("status = %s", status)
	}
}
