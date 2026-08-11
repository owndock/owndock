package agentprotocol

import (
	"errors"
	"testing"
)

func TestTerminalFrameValidatesDirectionAndConstrainedOpen(t *testing.T) {
	open := TerminalFrame{
		SessionID: "terminal-session-1", Sequence: 1, Type: TerminalFrameOpen,
		Open: &TerminalOpen{
			Kind:         TerminalKindContainer,
			DeploymentID: "deployment-1", ProjectID: "project-1",
			ApplicationID: "application-1", EnvironmentID: "environment-1",
			RuntimeTargetID: "target-1", ContainerName: "owndock-container-1",
			CutoverSequence: 7, Columns: 120, Rows: 30,
		},
	}
	if err := open.Validate(TerminalServerToAgent); err != nil {
		t.Fatalf("open.Validate() error = %v", err)
	}
	if err := open.Validate(TerminalAgentToServer); !errors.Is(err, ErrTerminalFrameInvalid) {
		t.Fatalf("wrong direction error = %v", err)
	}
	host := TerminalFrame{
		SessionID: "host-session-1", Sequence: 1, Type: TerminalFrameOpen,
		Open: &TerminalOpen{
			Kind: TerminalKindHost, Columns: 100, Rows: 40,
		},
	}
	if err := host.Validate(TerminalServerToAgent); err != nil {
		t.Fatalf("host.Validate() error = %v", err)
	}
	host.Open.ProjectID = "injected-project"
	if err := host.Validate(TerminalServerToAgent); !errors.Is(err, ErrTerminalFrameInvalid) {
		t.Fatalf("host with container selector error = %v", err)
	}
}

func TestTerminalFrameRejectsOversizedDataAndUnsafeCode(t *testing.T) {
	invalid := []struct {
		frame     TerminalFrame
		direction TerminalDirection
	}{
		{TerminalFrame{SessionID: "session-1", Sequence: 1, Type: TerminalFrameStdin,
			Data: make([]byte, MaximumTerminalDataBytes+1)}, TerminalServerToAgent},
		{TerminalFrame{SessionID: "session-1", Sequence: 1, Type: TerminalFrameError,
			Code: "raw error: token=secret"}, TerminalAgentToServer},
		{TerminalFrame{SessionID: "session-1", Sequence: 1, Type: TerminalFrameResize,
			Columns: MaximumTerminalColumns + 1, Rows: 30}, TerminalServerToAgent},
	}
	for _, test := range invalid {
		if err := test.frame.Validate(test.direction); !errors.Is(err, ErrTerminalFrameInvalid) {
			t.Fatalf("Validate(%+v) error = %v", test.frame, err)
		}
	}
}
