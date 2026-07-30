package agentruntime

import (
	"context"
	"encoding/json"
	"time"

	"github.com/moby/moby/client"

	"github.com/owndock/owndock/internal/adapters/dockerinventory"
	"github.com/owndock/owndock/internal/shared/agentprotocol"
	inventory "github.com/owndock/owndock/internal/shared/runtimeinventory"
)

const (
	inventorySnapshotTTL          = 10 * time.Minute
	maximumInventorySnapshots     = 2
	maximumInventorySnapshotBytes = 32 * 1024 * 1024
)

type dockerInventoryEngine interface {
	dockerinventory.Engine
	Close() error
}

type dockerInventoryEngineFactory func(string) (dockerInventoryEngine, error)

type inventorySnapshot struct {
	runtimeTargetID string
	observationID   string
	maxChunkBytes   int
	resourceCount   int
	chunks          []inventory.Chunk
	expiresAt       time.Time
	expirationTimer *time.Timer
}

func (e *DockerExecutor) executeInventory(
	ctx context.Context,
	command agentprotocol.AgentCommand,
) (agentprotocol.AgentCommandResult, error) {
	switch command.Kind {
	case agentprotocol.AgentCommandInventoryPrepare:
		return e.prepareInventory(ctx, command)
	case agentprotocol.AgentCommandInventoryChunk:
		return e.inventoryChunk(command), nil
	case agentprotocol.AgentCommandInventoryRelease:
		return e.releaseInventory(command), nil
	default:
		return agentprotocol.AgentCommandResult{},
			agentprotocol.ErrCommandInvalid
	}
}

func (e *DockerExecutor) prepareInventory(
	ctx context.Context,
	command agentprotocol.AgentCommand,
) (agentprotocol.AgentCommandResult, error) {
	request := command.Inventory
	if snapshot, found := e.findInventorySnapshot(
		request.ObservationID,
		request.RuntimeTargetID,
		request.MaxChunkBytes,
	); found {
		return inventoryManifestResult(command.ID, snapshot), nil
	}

	engine, err := e.newInventoryEngine(e.socketPath)
	if err != nil {
		return inventoryFailure(command.ID, "inventory_configuration"), nil
	}
	resources, collectErr := dockerinventory.NewReader(engine).Collect(ctx)
	_ = engine.Close()
	if collectErr != nil {
		if contextError := ctx.Err(); contextError != nil {
			return agentprotocol.AgentCommandResult{}, contextError
		}
		return inventoryFailure(command.ID, "inventory_unavailable"), nil
	}
	chunks, err := inventory.Split(
		resources,
		request.MaxChunkBytes,
		inventory.MaxResourcesPerChunk,
	)
	if err != nil || inventoryChunksBytes(chunks) > maximumInventorySnapshotBytes {
		return inventoryFailure(command.ID, "inventory_capacity"), nil
	}
	snapshot := &inventorySnapshot{
		runtimeTargetID: request.RuntimeTargetID,
		observationID:   request.ObservationID,
		maxChunkBytes:   request.MaxChunkBytes,
		resourceCount:   len(resources),
		chunks:          chunks,
		expiresAt:       e.now().UTC().Add(inventorySnapshotTTL),
	}
	stored, code := e.storeInventorySnapshot(snapshot)
	if code != "" {
		return inventoryFailure(command.ID, code), nil
	}
	return inventoryManifestResult(command.ID, stored), nil
}

func (e *DockerExecutor) inventoryChunk(
	command agentprotocol.AgentCommand,
) agentprotocol.AgentCommandResult {
	request := command.Inventory
	snapshot, found := e.findInventorySnapshot(
		request.ObservationID,
		request.RuntimeTargetID,
		request.MaxChunkBytes,
	)
	if !found {
		return inventoryFailure(command.ID, "inventory_snapshot_missing")
	}
	if request.ChunkIndex >= len(snapshot.chunks) {
		return inventoryFailure(command.ID, "inventory_chunk_invalid")
	}
	chunk := snapshot.chunks[request.ChunkIndex]
	chunk.Resources = append([]inventory.Resource{}, chunk.Resources...)
	return agentprotocol.AgentCommandResult{
		CommandID: command.ID,
		Status:    agentprotocol.AgentCommandSucceeded,
		Inventory: &agentprotocol.RuntimeInventoryResult{Chunk: &chunk},
	}
}

func (e *DockerExecutor) releaseInventory(
	command agentprotocol.AgentCommand,
) agentprotocol.AgentCommandResult {
	request := command.Inventory
	e.mu.Lock()
	e.removeExpiredInventorySnapshotsLocked()
	snapshot := e.inventorySnapshots[request.ObservationID]
	if snapshot != nil && snapshot.runtimeTargetID != request.RuntimeTargetID {
		e.mu.Unlock()
		return inventoryFailure(command.ID, "inventory_snapshot_mismatch")
	}
	delete(e.inventorySnapshots, request.ObservationID)
	if snapshot != nil && snapshot.expirationTimer != nil {
		snapshot.expirationTimer.Stop()
	}
	e.mu.Unlock()
	return agentprotocol.AgentCommandResult{
		CommandID: command.ID,
		Status:    agentprotocol.AgentCommandSucceeded,
	}
}

func (e *DockerExecutor) findInventorySnapshot(
	observationID, runtimeTargetID string,
	maxChunkBytes int,
) (*inventorySnapshot, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.removeExpiredInventorySnapshotsLocked()
	snapshot := e.inventorySnapshots[observationID]
	if snapshot == nil ||
		snapshot.runtimeTargetID != runtimeTargetID ||
		snapshot.maxChunkBytes != maxChunkBytes {
		return nil, false
	}
	return snapshot, true
}

func (e *DockerExecutor) storeInventorySnapshot(
	snapshot *inventorySnapshot,
) (*inventorySnapshot, string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.removeExpiredInventorySnapshotsLocked()
	if existing := e.inventorySnapshots[snapshot.observationID]; existing != nil {
		if existing.runtimeTargetID != snapshot.runtimeTargetID ||
			existing.maxChunkBytes != snapshot.maxChunkBytes {
			return nil, "inventory_snapshot_mismatch"
		}
		return existing, ""
	}
	if len(e.inventorySnapshots) >= maximumInventorySnapshots {
		return nil, "inventory_capacity"
	}
	e.inventorySnapshots[snapshot.observationID] = snapshot
	snapshot.expirationTimer = time.AfterFunc(
		inventorySnapshotTTL,
		func() {
			e.mu.Lock()
			if e.inventorySnapshots[snapshot.observationID] == snapshot {
				delete(e.inventorySnapshots, snapshot.observationID)
			}
			e.mu.Unlock()
		},
	)
	return snapshot, ""
}

func (e *DockerExecutor) removeExpiredInventorySnapshotsLocked() {
	now := e.now().UTC()
	for observationID, snapshot := range e.inventorySnapshots {
		if !snapshot.expiresAt.After(now) {
			delete(e.inventorySnapshots, observationID)
			if snapshot.expirationTimer != nil {
				snapshot.expirationTimer.Stop()
			}
		}
	}
}

func inventoryManifestResult(
	commandID string,
	snapshot *inventorySnapshot,
) agentprotocol.AgentCommandResult {
	return agentprotocol.AgentCommandResult{
		CommandID: commandID,
		Status:    agentprotocol.AgentCommandSucceeded,
		Inventory: &agentprotocol.RuntimeInventoryResult{
			Manifest: &agentprotocol.RuntimeInventoryManifest{
				ObservationID:     snapshot.observationID,
				SchemaVersion:     inventory.SchemaVersion,
				ExpectedChunks:    len(snapshot.chunks),
				ExpectedResources: snapshot.resourceCount,
				RetentionSeconds:  int(inventorySnapshotTTL / time.Second),
			},
		},
	}
}

func inventoryFailure(
	commandID, code string,
) agentprotocol.AgentCommandResult {
	return agentprotocol.AgentCommandResult{
		CommandID: commandID,
		Status:    agentprotocol.AgentCommandFailed,
		ErrorCode: code,
	}
}

func inventoryChunksBytes(chunks []inventory.Chunk) int {
	total := 0
	for _, chunk := range chunks {
		payload, err := json.Marshal(chunk)
		if err != nil {
			return maximumInventorySnapshotBytes + 1
		}
		total += len(payload)
		if total > maximumInventorySnapshotBytes {
			return total
		}
	}
	return total
}

func newLocalDockerInventoryEngine(
	socketPath string,
) (dockerInventoryEngine, error) {
	return client.New(client.WithHost("unix://" + socketPath))
}
