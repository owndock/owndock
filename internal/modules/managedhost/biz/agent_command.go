package biz

import (
	"errors"
	"strings"
	"time"
)

var (
	ErrAgentBackpressure      = errors.New("agent command queue is full")
	ErrAgentCommandExpired    = errors.New("agent command deadline has expired")
	ErrAgentCommandInvalid    = errors.New("agent command is invalid")
	ErrAgentDisconnected      = errors.New("agent disconnected before completing the command")
	ErrAgentNotConnected      = errors.New("agent is not connected")
	ErrAgentResultInvalid     = errors.New("agent command result is invalid")
	ErrAgentResultUnavailable = errors.New("agent command result is unavailable")
)

type AgentCommandKind string

const (
	AgentCommandRuntimeProbe AgentCommandKind = "runtime.probe"
)

type AgentCommand struct {
	ID           string
	Kind         AgentCommandKind
	Deadline     time.Time
	RuntimeProbe *RuntimeProbeCommand
}

type RuntimeProbeCommand struct {
	RuntimeTargetID string
}

func (c AgentCommand) Validate() error {
	if !validIdentitySegment(c.ID) || c.Deadline.IsZero() {
		return ErrAgentCommandInvalid
	}
	switch c.Kind {
	case AgentCommandRuntimeProbe:
		if c.RuntimeProbe == nil ||
			!validIdentitySegment(c.RuntimeProbe.RuntimeTargetID) {
			return ErrAgentCommandInvalid
		}
	default:
		return ErrAgentCommandInvalid
	}
	return nil
}

func (c AgentCommand) Equivalent(other AgentCommand) bool {
	if c.ID != other.ID || c.Kind != other.Kind ||
		!c.Deadline.Equal(other.Deadline) {
		return false
	}
	switch {
	case c.RuntimeProbe == nil && other.RuntimeProbe == nil:
		return true
	case c.RuntimeProbe == nil || other.RuntimeProbe == nil:
		return false
	default:
		return c.RuntimeProbe.RuntimeTargetID == other.RuntimeProbe.RuntimeTargetID
	}
}

type AgentCommandStatus string

const (
	AgentCommandSucceeded AgentCommandStatus = "succeeded"
	AgentCommandFailed    AgentCommandStatus = "failed"
)

type RuntimeProbeStatus string

const (
	RuntimeProbeReady       RuntimeProbeStatus = "ready"
	RuntimeProbeUnreachable RuntimeProbeStatus = "unreachable"
	RuntimeProbeUnsupported RuntimeProbeStatus = "unsupported"
)

func (s RuntimeProbeStatus) Valid() bool {
	switch s {
	case RuntimeProbeReady, RuntimeProbeUnreachable, RuntimeProbeUnsupported:
		return true
	default:
		return false
	}
}

type AgentCommandResult struct {
	CommandID    string
	Status       AgentCommandStatus
	ErrorCode    string
	RuntimeProbe *RuntimeProbeResult
}

type RuntimeProbeResult struct {
	Status RuntimeProbeStatus
}

func (r AgentCommandResult) Validate(command AgentCommand) error {
	if command.Validate() != nil || r.CommandID != command.ID {
		return ErrAgentResultInvalid
	}
	switch r.Status {
	case AgentCommandSucceeded:
		if r.ErrorCode != "" {
			return ErrAgentResultInvalid
		}
		switch command.Kind {
		case AgentCommandRuntimeProbe:
			if r.RuntimeProbe == nil || !r.RuntimeProbe.Status.Valid() {
				return ErrAgentResultInvalid
			}
		default:
			return ErrAgentResultInvalid
		}
	case AgentCommandFailed:
		if !validAgentErrorCode(r.ErrorCode) || r.RuntimeProbe != nil {
			return ErrAgentResultInvalid
		}
	default:
		return ErrAgentResultInvalid
	}
	return nil
}

func (r AgentCommandResult) Equivalent(other AgentCommandResult) bool {
	if r.CommandID != other.CommandID || r.Status != other.Status ||
		r.ErrorCode != other.ErrorCode {
		return false
	}
	switch {
	case r.RuntimeProbe == nil && other.RuntimeProbe == nil:
		return true
	case r.RuntimeProbe == nil || other.RuntimeProbe == nil:
		return false
	default:
		return r.RuntimeProbe.Status == other.RuntimeProbe.Status
	}
}

func validAgentErrorCode(value string) bool {
	if value == "" || len(value) > 64 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			character == '_' {
			continue
		}
		return false
	}
	return true
}
