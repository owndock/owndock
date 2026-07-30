package biz

import (
	"errors"

	"github.com/owndock/owndock/internal/shared/agentprotocol"
)

var (
	ErrAgentBackpressure          = errors.New("agent command queue is full")
	ErrAgentCapabilityUnavailable = errors.New(
		"agent command capability is unavailable",
	)
	ErrAgentCommandExpired    = errors.New("agent command deadline has expired")
	ErrAgentCommandInvalid    = agentprotocol.ErrCommandInvalid
	ErrAgentDisconnected      = errors.New("agent disconnected before completing the command")
	ErrAgentNotConnected      = errors.New("agent is not connected")
	ErrAgentResultInvalid     = agentprotocol.ErrResultInvalid
	ErrAgentResultUnavailable = errors.New("agent command result is unavailable")
)

// Aliases keep the Managed Host ports source-compatible while the canonical
// wire contract lives in shared/agentprotocol for both Server and Agent code.
type AgentCommandKind = agentprotocol.AgentCommandKind
type AgentCommand = agentprotocol.AgentCommand
type RuntimeProbeCommand = agentprotocol.RuntimeProbeCommand
type DeploymentCommand = agentprotocol.DeploymentCommand
type RuntimeInventoryCommand = agentprotocol.RuntimeInventoryCommand
type AgentCommandStatus = agentprotocol.AgentCommandStatus
type RuntimeProbeStatus = agentprotocol.RuntimeProbeStatus
type AgentCommandResult = agentprotocol.AgentCommandResult
type RuntimeProbeResult = agentprotocol.RuntimeProbeResult
type RuntimeInventoryResult = agentprotocol.RuntimeInventoryResult
type RuntimeInventoryManifest = agentprotocol.RuntimeInventoryManifest

const (
	AgentCommandRuntimeProbe       = agentprotocol.AgentCommandRuntimeProbe
	AgentCommandDeploymentPrepare  = agentprotocol.AgentCommandDeploymentPrepare
	AgentCommandDeploymentStage    = agentprotocol.AgentCommandDeploymentStage
	AgentCommandDeploymentActivate = agentprotocol.AgentCommandDeploymentActivate
	AgentCommandDeploymentCancel   = agentprotocol.AgentCommandDeploymentCancel
	AgentCommandInventoryPrepare   = agentprotocol.AgentCommandInventoryPrepare
	AgentCommandInventoryChunk     = agentprotocol.AgentCommandInventoryChunk
	AgentCommandInventoryRelease   = agentprotocol.AgentCommandInventoryRelease
	AgentCommandSucceeded          = agentprotocol.AgentCommandSucceeded
	AgentCommandFailed             = agentprotocol.AgentCommandFailed
	RuntimeProbeReady              = agentprotocol.RuntimeProbeReady
	RuntimeProbeUnreachable        = agentprotocol.RuntimeProbeUnreachable
	RuntimeProbeUnsupported        = agentprotocol.RuntimeProbeUnsupported
)
