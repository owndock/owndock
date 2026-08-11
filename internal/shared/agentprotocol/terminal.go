package agentprotocol

import (
	"context"
	"errors"
	"io"
	"strings"
)

const (
	MaximumTerminalDataBytes  = 32 * 1024
	MaximumTerminalColumns    = 1000
	MaximumTerminalRows       = 500
	MinimumTerminalFrameBytes = 64 * 1024
)

var ErrTerminalFrameInvalid = errors.New("agent terminal frame is invalid")

type TerminalKind string

const (
	TerminalKindContainer TerminalKind = "container"
	TerminalKindHost      TerminalKind = "host"
)

type TerminalStream interface {
	io.Reader
	io.Writer
	io.Closer
	Resize(context.Context, uint16, uint16) error
}

type TerminalDirection uint8

const (
	TerminalServerToAgent TerminalDirection = iota + 1
	TerminalAgentToServer
)

type TerminalFrameType string

const (
	TerminalFrameOpen   TerminalFrameType = "open"
	TerminalFrameReady  TerminalFrameType = "ready"
	TerminalFrameStdin  TerminalFrameType = "stdin"
	TerminalFrameStdout TerminalFrameType = "stdout"
	TerminalFrameResize TerminalFrameType = "resize"
	TerminalFrameClose  TerminalFrameType = "close"
	TerminalFrameError  TerminalFrameType = "error"
)

// TerminalOpen is derived entirely by the Server from the authorized current
// Deployment. It deliberately has no command, shell, user, environment,
// working-directory, endpoint, socket, or privileged fields.
type TerminalOpen struct {
	Kind            TerminalKind `json:"kind"`
	DeploymentID    string       `json:"deployment_id"`
	ProjectID       string       `json:"project_id"`
	ApplicationID   string       `json:"application_id"`
	EnvironmentID   string       `json:"environment_id"`
	RuntimeTargetID string       `json:"runtime_target_id"`
	ContainerName   string       `json:"container_name"`
	CutoverSequence uint64       `json:"cutover_sequence"`
	Columns         uint16       `json:"columns"`
	Rows            uint16       `json:"rows"`
}

type TerminalFrame struct {
	SessionID string            `json:"session_id"`
	Sequence  uint64            `json:"sequence"`
	Type      TerminalFrameType `json:"type"`
	Open      *TerminalOpen     `json:"open,omitempty"`
	Columns   uint16            `json:"columns,omitempty"`
	Rows      uint16            `json:"rows,omitempty"`
	Data      []byte            `json:"data,omitempty"`
	Code      string            `json:"code,omitempty"`
}

func (open TerminalOpen) Validate() error {
	if !validTerminalOpen(open) {
		return ErrTerminalFrameInvalid
	}
	return nil
}

func (frame TerminalFrame) Validate(direction TerminalDirection) error {
	if !validIdentifier(frame.SessionID) || frame.Sequence == 0 ||
		!terminalDirectionAllows(direction, frame.Type) {
		return ErrTerminalFrameInvalid
	}
	switch frame.Type {
	case TerminalFrameOpen:
		if frame.Open == nil || frame.Columns != 0 || frame.Rows != 0 ||
			len(frame.Data) != 0 || frame.Code != "" || !validTerminalOpen(*frame.Open) {
			return ErrTerminalFrameInvalid
		}
	case TerminalFrameStdin, TerminalFrameStdout:
		if frame.Open != nil || frame.Columns != 0 || frame.Rows != 0 ||
			frame.Code != "" || len(frame.Data) < 1 || len(frame.Data) > MaximumTerminalDataBytes {
			return ErrTerminalFrameInvalid
		}
	case TerminalFrameResize:
		if frame.Open != nil || len(frame.Data) != 0 || frame.Code != "" ||
			!validTerminalSize(frame.Columns, frame.Rows) {
			return ErrTerminalFrameInvalid
		}
	case TerminalFrameError:
		if frame.Open != nil || frame.Columns != 0 || frame.Rows != 0 ||
			len(frame.Data) != 0 || !validTerminalCode(frame.Code) {
			return ErrTerminalFrameInvalid
		}
	case TerminalFrameClose:
		if frame.Open != nil || frame.Columns != 0 || frame.Rows != 0 ||
			len(frame.Data) != 0 || frame.Code != "" && !validTerminalCode(frame.Code) {
			return ErrTerminalFrameInvalid
		}
	case TerminalFrameReady:
		if frame.Open != nil || frame.Columns != 0 || frame.Rows != 0 ||
			len(frame.Data) != 0 || frame.Code != "" {
			return ErrTerminalFrameInvalid
		}
	default:
		return ErrTerminalFrameInvalid
	}
	return nil
}

func validTerminalOpen(open TerminalOpen) bool {
	if !validTerminalSize(open.Columns, open.Rows) {
		return false
	}
	switch open.Kind {
	case TerminalKindContainer:
		return validIdentifier(open.DeploymentID) && validIdentifier(open.ProjectID) &&
			validIdentifier(open.ApplicationID) && validIdentifier(open.EnvironmentID) &&
			validIdentifier(open.RuntimeTargetID) && containerNameRule.MatchString(open.ContainerName) &&
			open.CutoverSequence > 0
	case TerminalKindHost:
		return open.DeploymentID == "" && open.ProjectID == "" &&
			open.ApplicationID == "" && open.EnvironmentID == "" &&
			open.RuntimeTargetID == "" && open.ContainerName == "" &&
			open.CutoverSequence == 0
	default:
		return false
	}
}

func validTerminalSize(columns, rows uint16) bool {
	return columns > 0 && rows > 0 && columns <= MaximumTerminalColumns && rows <= MaximumTerminalRows
}

func terminalDirectionAllows(direction TerminalDirection, frameType TerminalFrameType) bool {
	switch direction {
	case TerminalServerToAgent:
		return frameType == TerminalFrameOpen || frameType == TerminalFrameStdin ||
			frameType == TerminalFrameResize || frameType == TerminalFrameClose
	case TerminalAgentToServer:
		return frameType == TerminalFrameReady || frameType == TerminalFrameStdout ||
			frameType == TerminalFrameClose || frameType == TerminalFrameError
	default:
		return false
	}
}

func validTerminalCode(value string) bool {
	if value == "" || len(value) > 64 || value != strings.TrimSpace(value) {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' || character == '_' {
			continue
		}
		return false
	}
	return true
}
