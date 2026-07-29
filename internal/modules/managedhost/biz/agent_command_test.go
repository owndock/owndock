package biz

import (
	"errors"
	"testing"
	"time"
)

func TestAgentRuntimeProbeCommandAndResultValidation(t *testing.T) {
	command := AgentCommand{
		ID: "command-1", Kind: AgentCommandRuntimeProbe,
		Deadline:     time.Unix(1000, 0).UTC(),
		RuntimeProbe: &RuntimeProbeCommand{RuntimeTargetID: "target-1"},
	}
	if err := command.Validate(); err != nil {
		t.Fatalf("valid command error = %v", err)
	}
	result := AgentCommandResult{
		CommandID: command.ID, Status: AgentCommandSucceeded,
		RuntimeProbe: &RuntimeProbeResult{Status: RuntimeProbeReady},
	}
	if err := result.Validate(command); err != nil {
		t.Fatalf("valid result error = %v", err)
	}
	if !command.Equivalent(command) || !result.Equivalent(result) {
		t.Fatal("values must be equivalent to themselves")
	}
}

func TestAgentCommandRejectsUntypedOrUnsafePayload(t *testing.T) {
	deadline := time.Unix(1000, 0).UTC()
	tests := []AgentCommand{
		{ID: "command-1", Kind: AgentCommandRuntimeProbe, Deadline: deadline},
		{
			ID: "command-1", Kind: AgentCommandRuntimeProbe, Deadline: deadline,
			RuntimeProbe: &RuntimeProbeCommand{
				RuntimeTargetID: "unix:///var/run/docker.sock",
			},
		},
		{
			ID: "command-1", Kind: "shell.exec", Deadline: deadline,
			RuntimeProbe: &RuntimeProbeCommand{RuntimeTargetID: "target-1"},
		},
	}
	for _, command := range tests {
		if !errors.Is(command.Validate(), ErrAgentCommandInvalid) {
			t.Fatalf("unsafe command accepted: %+v", command)
		}
	}
}

func TestAgentResultRejectsMismatchedAndFreeFormValues(t *testing.T) {
	command := AgentCommand{
		ID: "command-1", Kind: AgentCommandRuntimeProbe,
		Deadline:     time.Unix(1000, 0).UTC(),
		RuntimeProbe: &RuntimeProbeCommand{RuntimeTargetID: "target-1"},
	}
	tests := []AgentCommandResult{
		{
			CommandID: "different", Status: AgentCommandSucceeded,
			RuntimeProbe: &RuntimeProbeResult{Status: RuntimeProbeReady},
		},
		{
			CommandID: command.ID, Status: AgentCommandSucceeded,
			ErrorCode:    "unexpected",
			RuntimeProbe: &RuntimeProbeResult{Status: RuntimeProbeReady},
		},
		{
			CommandID: command.ID, Status: AgentCommandFailed,
			ErrorCode: "unsafe error message",
		},
	}
	for _, result := range tests {
		if !errors.Is(result.Validate(command), ErrAgentResultInvalid) {
			t.Fatalf("invalid result accepted: %+v", result)
		}
	}
}
