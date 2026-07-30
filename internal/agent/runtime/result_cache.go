package agentruntime

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sync"
	"time"

	"github.com/owndock/owndock/internal/shared/agentprotocol"
)

const resultCacheVersion = 2
const maximumResultCacheBytes = 4 * 1024 * 1024

var ErrInvalidResultCache = errors.New("agent result cache is invalid")

type ResultCache interface {
	Lookup(
		agentprotocol.AgentCommand,
	) (agentprotocol.AgentCommandResult, bool, error)
	Store(
		agentprotocol.AgentCommand,
		agentprotocol.AgentCommandResult,
	) error
}

type resultCacheEntry struct {
	fingerprint [sha256.Size]byte
	kind        agentprotocol.AgentCommandKind
	result      agentprotocol.AgentCommandResult
}

// FileResultCache persists only a one-way command fingerprint, command kind,
// and bounded safe result fields. Secret-bearing command payloads, runtime
// secrets, and raw engine errors never enter this file.
type FileResultCache struct {
	mu sync.Mutex

	directory string
	path      string
	maximum   int
	entries   map[string]resultCacheEntry
	order     []string
}

func NewFileResultCache(
	directory string,
	maximum int,
) (*FileResultCache, error) {
	if maximum < 1 || maximum > 4096 {
		return nil, ErrInvalidResultCache
	}
	directory, err := prepareStateDirectory(
		directory,
		ErrInvalidResultCache,
	)
	if err != nil {
		return nil, err
	}
	cache := &FileResultCache{
		directory: directory,
		path:      filepath.Join(directory, "command-results.json"),
		maximum:   maximum,
		entries:   make(map[string]resultCacheEntry),
	}
	if err := cache.load(); err != nil {
		return nil, err
	}
	return cache, nil
}

func (c *FileResultCache) Lookup(
	command agentprotocol.AgentCommand,
) (agentprotocol.AgentCommandResult, bool, error) {
	if !command.Kind.DurableResult() {
		if err := command.Validate(); err != nil {
			return agentprotocol.AgentCommandResult{}, false, err
		}
		return agentprotocol.AgentCommandResult{}, false, nil
	}
	fingerprint, err := command.Fingerprint()
	if err != nil {
		return agentprotocol.AgentCommandResult{}, false, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, exists := c.entries[command.ID]
	if !exists {
		return agentprotocol.AgentCommandResult{}, false, nil
	}
	if entry.kind != command.Kind || entry.fingerprint != fingerprint {
		return agentprotocol.AgentCommandResult{}, false,
			agentprotocol.ErrCommandInvalid
	}
	return entry.result, true, nil
}

func (c *FileResultCache) Store(
	command agentprotocol.AgentCommand,
	result agentprotocol.AgentCommandResult,
) error {
	if !command.Kind.DurableResult() {
		return ErrInvalidResultCache
	}
	if err := result.Validate(command); err != nil {
		return err
	}
	fingerprint, err := command.Fingerprint()
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, exists := c.entries[command.ID]; exists {
		if entry.kind != command.Kind ||
			entry.fingerprint != fingerprint {
			return agentprotocol.ErrCommandInvalid
		}
		if !entry.result.Equivalent(result) {
			return agentprotocol.ErrResultInvalid
		}
		return nil
	}

	c.entries[command.ID] = resultCacheEntry{
		fingerprint: fingerprint,
		kind:        command.Kind,
		result:      result,
	}
	c.order = append(c.order, command.ID)
	var evicted *resultCacheEntry
	var evictedID string
	if len(c.order) > c.maximum {
		evictedID = c.order[0]
		c.order = c.order[1:]
		entry := c.entries[evictedID]
		evicted = &entry
		delete(c.entries, evictedID)
	}
	if err := c.persistLocked(); err != nil {
		delete(c.entries, command.ID)
		c.order = c.order[:len(c.order)-1]
		if evicted != nil {
			c.entries[evictedID] = *evicted
			c.order = append([]string{evictedID}, c.order...)
		}
		return err
	}
	return nil
}

func (c *FileResultCache) load() error {
	value, exists, err := readRestrictedStateFile(
		c.path,
		maximumResultCacheBytes,
		ErrInvalidResultCache,
	)
	if err != nil || !exists {
		return err
	}
	var header struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(value, &header); err != nil {
		return ErrInvalidResultCache
	}
	switch header.Version {
	case 1:
		return c.loadVersionOne(value)
	case resultCacheVersion:
		return c.loadVersionTwo(value)
	default:
		return ErrInvalidResultCache
	}
}

func (c *FileResultCache) loadVersionTwo(value []byte) error {
	var document resultCacheDocument
	if decodeStrictJSON(value, &document) != nil ||
		document.Version != resultCacheVersion ||
		len(document.Entries) > c.maximum {
		return ErrInvalidResultCache
	}
	for _, encoded := range document.Entries {
		result := encoded.Result.domain()
		if !encoded.Kind.Valid() ||
			result.ValidateShape(encoded.Kind) != nil {
			return ErrInvalidResultCache
		}
		fingerprintValue, err := hex.DecodeString(
			encoded.CommandFingerprint,
		)
		if err != nil || len(fingerprintValue) != sha256.Size {
			return ErrInvalidResultCache
		}
		var fingerprint [sha256.Size]byte
		copy(fingerprint[:], fingerprintValue)
		if _, exists := c.entries[result.CommandID]; exists {
			return ErrInvalidResultCache
		}
		c.entries[result.CommandID] = resultCacheEntry{
			fingerprint: fingerprint,
			kind:        encoded.Kind,
			result:      result,
		}
		c.order = append(c.order, result.CommandID)
	}
	return nil
}

// Version 1 stored only runtime.probe fields and never contained deployment
// secrets. Loading it preserves pre-release probe replay; the next Store writes
// the complete cache back in the secret-safe version 2 shape.
func (c *FileResultCache) loadVersionOne(value []byte) error {
	var document resultCacheDocumentV1
	if decodeStrictJSON(value, &document) != nil ||
		document.Version != 1 ||
		len(document.Entries) > c.maximum {
		return ErrInvalidResultCache
	}
	for _, encoded := range document.Entries {
		command, result := encoded.domain()
		fingerprint, err := command.Fingerprint()
		if err != nil || result.Validate(command) != nil {
			return ErrInvalidResultCache
		}
		if _, exists := c.entries[command.ID]; exists {
			return ErrInvalidResultCache
		}
		c.entries[command.ID] = resultCacheEntry{
			fingerprint: fingerprint,
			kind:        command.Kind,
			result:      result,
		}
		c.order = append(c.order, command.ID)
	}
	return nil
}

func decodeStrictJSON(value []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalidResultCache
	}
	return nil
}

func (c *FileResultCache) persistLocked() error {
	document := resultCacheDocument{
		Version: resultCacheVersion,
		Entries: make([]resultCacheEntryDocument, 0, len(c.order)),
	}
	for _, commandID := range c.order {
		entry := c.entries[commandID]
		document.Entries = append(
			document.Entries,
			resultCacheEntryDocument{
				Kind: entry.kind,
				CommandFingerprint: hex.EncodeToString(
					entry.fingerprint[:],
				),
				Result: newResultCacheResultDocument(entry.result),
			},
		)
	}
	value, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("encode Agent result cache: %w", err)
	}
	return replaceRestrictedStateFile(
		c.directory,
		c.path,
		".command-results-*",
		value,
	)
}

type resultCacheDocument struct {
	Version int                        `json:"version"`
	Entries []resultCacheEntryDocument `json:"entries"`
}

type resultCacheEntryDocument struct {
	Kind               agentprotocol.AgentCommandKind `json:"kind"`
	CommandFingerprint string                         `json:"command_fingerprint"`
	Result             resultCacheResultDocument      `json:"result"`
}

type resultCacheResultDocument struct {
	CommandID    string                           `json:"command_id"`
	Status       agentprotocol.AgentCommandStatus `json:"status"`
	ErrorCode    string                           `json:"error_code,omitempty"`
	RuntimeProbe *resultCacheRuntimeProbeDocument `json:"runtime_probe,omitempty"`
}

type resultCacheRuntimeProbeDocument struct {
	Status agentprotocol.RuntimeProbeStatus `json:"status"`
}

func newResultCacheResultDocument(
	result agentprotocol.AgentCommandResult,
) resultCacheResultDocument {
	document := resultCacheResultDocument{
		CommandID: result.CommandID,
		Status:    result.Status,
		ErrorCode: result.ErrorCode,
	}
	if result.RuntimeProbe != nil {
		document.RuntimeProbe = &resultCacheRuntimeProbeDocument{
			Status: result.RuntimeProbe.Status,
		}
	}
	return document
}

func (d resultCacheResultDocument) domain() agentprotocol.AgentCommandResult {
	result := agentprotocol.AgentCommandResult{
		CommandID: d.CommandID,
		Status:    d.Status,
		ErrorCode: d.ErrorCode,
	}
	if d.RuntimeProbe != nil {
		result.RuntimeProbe = &agentprotocol.RuntimeProbeResult{
			Status: d.RuntimeProbe.Status,
		}
	}
	return result
}

type resultCacheDocumentV1 struct {
	Version int                          `json:"version"`
	Entries []resultCacheEntryDocumentV1 `json:"entries"`
}

type resultCacheEntryDocumentV1 struct {
	CommandID       string                           `json:"command_id"`
	Kind            agentprotocol.AgentCommandKind   `json:"kind"`
	Deadline        time.Time                        `json:"deadline"`
	RuntimeTargetID string                           `json:"runtime_target_id"`
	Status          agentprotocol.AgentCommandStatus `json:"status"`
	ErrorCode       string                           `json:"error_code,omitempty"`
	RuntimeStatus   agentprotocol.RuntimeProbeStatus `json:"runtime_status,omitempty"`
}

func (d resultCacheEntryDocumentV1) domain() (
	agentprotocol.AgentCommand,
	agentprotocol.AgentCommandResult,
) {
	command := agentprotocol.AgentCommand{
		ID: d.CommandID, Kind: d.Kind, Deadline: d.Deadline.UTC(),
	}
	if d.RuntimeTargetID != "" {
		command.RuntimeProbe = &agentprotocol.RuntimeProbeCommand{
			RuntimeTargetID: d.RuntimeTargetID,
		}
	}
	result := agentprotocol.AgentCommandResult{
		CommandID: d.CommandID,
		Status:    d.Status,
		ErrorCode: d.ErrorCode,
	}
	if d.RuntimeStatus != "" {
		result.RuntimeProbe = &agentprotocol.RuntimeProbeResult{
			Status: d.RuntimeStatus,
		}
	}
	return command, result
}
