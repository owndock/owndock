package agentcontrol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/shared/agentprotocol"
	"github.com/owndock/owndock/internal/shared/runtimeinventory"
)

const (
	contentType     = "application/x-ndjson"
	protocolVersion = "v1"
)

type agentFrame struct {
	Type          string              `json:"type"`
	Sequence      uint64              `json:"sequence"`
	Hello         *agentHello         `json:"hello,omitempty"`
	CommandResult *agentCommandResult `json:"command_result,omitempty"`
}

type agentHello struct {
	OrganizationID  string   `json:"organization_id"`
	ManagedHostID   string   `json:"managed_host_id"`
	AgentIdentityID string   `json:"agent_identity_id"`
	InstanceID      string   `json:"instance_id"`
	BootID          string   `json:"boot_id"`
	AgentVersion    string   `json:"agent_version"`
	ProtocolVersion string   `json:"protocol_version"`
	Capabilities    []string `json:"capabilities"`
}

type agentCommandResult struct {
	CommandID    string                           `json:"command_id"`
	Status       agentprotocol.AgentCommandStatus `json:"status"`
	ErrorCode    string                           `json:"error_code,omitempty"`
	RuntimeProbe *agentRuntimeProbeResult         `json:"runtime_probe,omitempty"`
	Inventory    *agentRuntimeInventoryResult     `json:"runtime_inventory,omitempty"`
}

type agentRuntimeProbeResult struct {
	Status agentprotocol.RuntimeProbeStatus `json:"status"`
}

type agentRuntimeInventoryResult struct {
	Manifest *agentRuntimeInventoryManifest `json:"manifest,omitempty"`
	Chunk    *runtimeinventory.Chunk        `json:"chunk,omitempty"`
	Events   *runtimeinventory.EventBatch   `json:"events,omitempty"`
}

type agentRuntimeInventoryManifest struct {
	ObservationID     string                   `json:"observation_id"`
	SchemaVersion     int                      `json:"schema_version"`
	ExpectedChunks    int                      `json:"expected_chunks"`
	ExpectedResources int                      `json:"expected_resources"`
	RetentionSeconds  int                      `json:"retention_seconds"`
	Events            []runtimeinventory.Event `json:"events,omitempty"`
	EventsTruncated   bool                     `json:"events_truncated,omitempty"`
}

func newAgentResult(result agentprotocol.AgentCommandResult) *agentCommandResult {
	document := &agentCommandResult{
		CommandID: result.CommandID,
		Status:    result.Status,
		ErrorCode: result.ErrorCode,
	}
	if result.RuntimeProbe != nil {
		document.RuntimeProbe = &agentRuntimeProbeResult{
			Status: result.RuntimeProbe.Status,
		}
	}
	if result.Inventory != nil {
		document.Inventory = &agentRuntimeInventoryResult{
			Chunk: result.Inventory.Chunk, Events: result.Inventory.Events,
		}
		if result.Inventory.Manifest != nil {
			manifest := result.Inventory.Manifest
			document.Inventory.Manifest = &agentRuntimeInventoryManifest{
				ObservationID:     manifest.ObservationID,
				SchemaVersion:     manifest.SchemaVersion,
				ExpectedChunks:    manifest.ExpectedChunks,
				ExpectedResources: manifest.ExpectedResources,
				RetentionSeconds:  manifest.RetentionSeconds,
				Events:            append([]runtimeinventory.Event(nil), manifest.Events...),
				EventsTruncated:   manifest.EventsTruncated,
			}
		}
	}
	return document
}

type serverFrame struct {
	Type                     string                         `json:"type"`
	Sequence                 uint64                         `json:"sequence"`
	SessionID                string                         `json:"session_id,omitempty"`
	ProtocolVersion          string                         `json:"protocol_version,omitempty"`
	HeartbeatIntervalSeconds int64                          `json:"heartbeat_interval_seconds,omitempty"`
	MaxFrameBytes            int                            `json:"max_frame_bytes,omitempty"`
	AcknowledgedSequence     uint64                         `json:"acknowledged_sequence,omitempty"`
	ServerTime               time.Time                      `json:"server_time,omitzero"`
	Code                     string                         `json:"code,omitempty"`
	CommandID                string                         `json:"command_id,omitempty"`
	Command                  *agentprotocol.CommandDocument `json:"command,omitempty"`
}

func decodeServerFrame(value []byte, target *serverFrame) error {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("server frame must contain one JSON value")
	}
	return nil
}

func validSafeCode(value string) bool {
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

func validIdentity(value string) bool {
	if value == "" || len(value) > 128 ||
		value == "." || value == ".." || value[0] == '.' {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}
