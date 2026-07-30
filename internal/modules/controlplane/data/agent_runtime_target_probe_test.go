package data

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/controlplane/biz"
	managedhostbiz "github.com/owndock/owndock/internal/modules/managedhost/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
)

type agentCommandDispatcherStub struct {
	hostID  string
	command managedhostbiz.AgentCommand
	result  managedhostbiz.AgentCommandResult
	err     error
}

func (d *agentCommandDispatcherStub) Dispatch(
	_ context.Context,
	hostID string,
	command managedhostbiz.AgentCommand,
) (managedhostbiz.AgentCommandResult, error) {
	d.hostID = hostID
	d.command = command
	return d.result, d.err
}

func TestAgentRuntimeTargetProberDispatchesBackendResolvedTarget(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	dispatcher := &agentCommandDispatcherStub{
		result: managedhostbiz.AgentCommandResult{
			CommandID: "command-1",
			Status:    managedhostbiz.AgentCommandSucceeded,
			RuntimeProbe: &managedhostbiz.RuntimeProbeResult{
				Status: managedhostbiz.RuntimeProbeReady,
			},
		},
	}
	prober, err := NewAgentRuntimeTargetProber(
		dispatcher,
		func() (string, error) { return "command-1", nil },
		func() time.Time { return now },
		10*time.Second,
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
	if status != biz.RuntimeTargetStatusReady ||
		dispatcher.hostID != "host-1" ||
		dispatcher.command.Kind != managedhostbiz.AgentCommandRuntimeProbe ||
		!dispatcher.command.Deadline.Equal(now.Add(10*time.Second)) ||
		dispatcher.command.RuntimeProbe == nil ||
		dispatcher.command.RuntimeProbe.RuntimeTargetID != "target-1" {
		t.Fatalf(
			"status = %s, host = %q, command = %+v",
			status, dispatcher.hostID, dispatcher.command,
		)
	}
}

func TestAgentRuntimeTargetProberClassifiesSafeResults(t *testing.T) {
	tests := []struct {
		name    string
		result  managedhostbiz.AgentCommandResult
		err     error
		want    biz.RuntimeTargetStatus
		wantErr error
	}{
		{
			name: "unreachable result",
			result: managedhostbiz.AgentCommandResult{
				CommandID: "command-1",
				Status:    managedhostbiz.AgentCommandSucceeded,
				RuntimeProbe: &managedhostbiz.RuntimeProbeResult{
					Status: managedhostbiz.RuntimeProbeUnreachable,
				},
			},
			want: biz.RuntimeTargetStatusUnreachable,
		},
		{
			name: "unsupported result",
			result: managedhostbiz.AgentCommandResult{
				CommandID: "command-1",
				Status:    managedhostbiz.AgentCommandSucceeded,
				RuntimeProbe: &managedhostbiz.RuntimeProbeResult{
					Status: managedhostbiz.RuntimeProbeUnsupported,
				},
			},
			want: biz.RuntimeTargetStatusUnreachable,
		},
		{
			name: "safe Agent failure",
			result: managedhostbiz.AgentCommandResult{
				CommandID: "command-1",
				Status:    managedhostbiz.AgentCommandFailed,
				ErrorCode: "runtime_unavailable",
			},
			want: biz.RuntimeTargetStatusUnreachable,
		},
		{
			name: "Agent offline",
			err:  managedhostbiz.ErrAgentNotConnected,
			want: biz.RuntimeTargetStatusUnreachable,
		},
		{
			name: "Agent disconnected",
			err:  managedhostbiz.ErrAgentDisconnected,
			want: biz.RuntimeTargetStatusUnreachable,
		},
		{
			name: "probe capability unavailable",
			err:  managedhostbiz.ErrAgentCapabilityUnavailable,
			want: biz.RuntimeTargetStatusUnreachable,
		},
		{
			name:    "queue full",
			err:     managedhostbiz.ErrAgentBackpressure,
			wantErr: biz.ErrRuntimeTargetProbeUnavailable,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dispatcher := &agentCommandDispatcherStub{
				result: test.result,
				err:    test.err,
			}
			prober, err := NewAgentRuntimeTargetProber(
				dispatcher,
				func() (string, error) { return "command-1", nil },
				time.Now,
				10*time.Second,
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
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
			if status != test.want {
				t.Fatalf("status = %s, want %s", status, test.want)
			}
		})
	}
}
