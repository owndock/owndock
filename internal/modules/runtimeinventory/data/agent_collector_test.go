package data

import (
	"context"
	"fmt"
	"testing"
	"time"

	managedhostbiz "github.com/owndock/owndock/internal/modules/managedhost/biz"
	inventorybiz "github.com/owndock/owndock/internal/modules/runtimeinventory/biz"
	"github.com/owndock/owndock/internal/shared/agentprotocol"
	transport "github.com/owndock/owndock/internal/shared/runtimeinventory"
)

type inventoryDispatcherStub struct {
	now            time.Time
	commands       []managedhostbiz.AgentCommand
	chunks         []transport.Chunk
	failChunkIndex *int
}

func (s *inventoryDispatcherStub) Dispatch(
	_ context.Context,
	hostID string,
	command managedhostbiz.AgentCommand,
) (managedhostbiz.AgentCommandResult, error) {
	if hostID != "host-1" {
		return managedhostbiz.AgentCommandResult{},
			fmt.Errorf("unexpected host %q", hostID)
	}
	s.commands = append(s.commands, command)
	switch command.Kind {
	case managedhostbiz.AgentCommandInventoryPrepare:
		return managedhostbiz.AgentCommandResult{
			CommandID: command.ID,
			Status:    managedhostbiz.AgentCommandSucceeded,
			Inventory: &managedhostbiz.RuntimeInventoryResult{
				Manifest: &managedhostbiz.RuntimeInventoryManifest{
					ObservationID:     command.Inventory.ObservationID,
					SchemaVersion:     transport.SchemaVersion,
					ExpectedChunks:    len(s.chunks),
					ExpectedResources: inventoryChunkResources(s.chunks),
					RetentionSeconds:  600,
				},
			},
		}, nil
	case managedhostbiz.AgentCommandInventoryChunk:
		index := command.Inventory.ChunkIndex
		if s.failChunkIndex != nil && index == *s.failChunkIndex {
			return managedhostbiz.AgentCommandResult{
				CommandID: command.ID,
				Status:    managedhostbiz.AgentCommandFailed,
				ErrorCode: "inventory_unavailable",
			}, nil
		}
		if index < 0 || index >= len(s.chunks) {
			return managedhostbiz.AgentCommandResult{}, fmt.Errorf("invalid chunk")
		}
		chunk := s.chunks[index]
		return managedhostbiz.AgentCommandResult{
			CommandID: command.ID,
			Status:    managedhostbiz.AgentCommandSucceeded,
			Inventory: &managedhostbiz.RuntimeInventoryResult{Chunk: &chunk},
		}, nil
	case managedhostbiz.AgentCommandInventoryRelease:
		return managedhostbiz.AgentCommandResult{
			CommandID: command.ID,
			Status:    managedhostbiz.AgentCommandSucceeded,
		}, nil
	default:
		return managedhostbiz.AgentCommandResult{}, fmt.Errorf("unexpected kind")
	}
}

func TestAgentCollectorReleasesPartialSnapshotWithoutCompleting(t *testing.T) {
	now := time.Unix(2000, 0).UTC()
	failedIndex := 1
	dispatcher := &inventoryDispatcherStub{
		now: now,
		chunks: []transport.Chunk{
			inventoryTransportChunk(0, "container-1", now),
			inventoryTransportChunk(1, "container-2", now),
		},
		failChunkIndex: &failedIndex,
	}
	repository := &inventoryRepositoryStub{}
	idSequence := 0
	collector, err := NewAgentCollector(
		dispatcher,
		repository,
		func() (string, error) {
			idSequence++
			return fmt.Sprintf("generated-%d", idSequence), nil
		},
		func() time.Time { return now },
		30*time.Second,
		transport.DefaultChunkBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := collector.Synchronize(
		t.Context(),
		"organization-1",
		"host-1",
		"target-1",
	); err == nil {
		t.Fatal("partial Agent snapshot unexpectedly completed")
	}
	if repository.completed || len(repository.chunks) != 1 {
		t.Fatalf(
			"completed/chunks = %v/%d",
			repository.completed,
			len(repository.chunks),
		)
	}
	if got := dispatcher.commands[len(dispatcher.commands)-1].Kind; got != agentprotocol.AgentCommandInventoryRelease {
		t.Fatalf("last command = %s, want release", got)
	}
}

type inventoryRepositoryStub struct {
	observation inventorybiz.Observation
	chunks      []inventorybiz.Chunk
	completed   bool
}

func (r *inventoryRepositoryStub) Begin(
	_ context.Context,
	observation inventorybiz.Observation,
) error {
	r.observation = observation
	return nil
}

func (r *inventoryRepositoryStub) Append(
	_ context.Context,
	chunk inventorybiz.Chunk,
) error {
	r.chunks = append(r.chunks, chunk)
	return nil
}

func (r *inventoryRepositoryStub) Complete(
	_ context.Context,
	observationID, runtimeTargetID string,
	_ time.Time,
) error {
	if observationID != r.observation.ID ||
		runtimeTargetID != r.observation.RuntimeTargetID {
		return inventorybiz.ErrConflict
	}
	r.completed = true
	return nil
}

func (*inventoryRepositoryStub) Current(
	context.Context,
	inventorybiz.Query,
) ([]inventorybiz.Resource, error) {
	return nil, inventorybiz.ErrNotFound
}

func TestAgentCollectorPullsBoundedChunksAndCompletes(t *testing.T) {
	now := time.Unix(2000, 0).UTC()
	dispatcher := &inventoryDispatcherStub{
		now: now,
		chunks: []transport.Chunk{
			inventoryTransportChunk(0, "container-1", now),
			inventoryTransportChunk(1, "container-2", now),
		},
	}
	repository := &inventoryRepositoryStub{}
	idSequence := 0
	collector, err := NewAgentCollector(
		dispatcher,
		repository,
		func() (string, error) {
			idSequence++
			return fmt.Sprintf("generated-%d", idSequence), nil
		},
		func() time.Time { return now },
		30*time.Second,
		transport.DefaultChunkBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := collector.Synchronize(
		t.Context(),
		"organization-1",
		"host-1",
		"target-1",
	); err != nil {
		t.Fatal(err)
	}
	if !repository.completed || len(repository.chunks) != 2 {
		t.Fatalf(
			"completed/chunks = %v/%d",
			repository.completed,
			len(repository.chunks),
		)
	}
	kinds := make([]agentprotocol.AgentCommandKind, len(dispatcher.commands))
	for index, command := range dispatcher.commands {
		kinds[index] = command.Kind
	}
	want := []agentprotocol.AgentCommandKind{
		agentprotocol.AgentCommandInventoryPrepare,
		agentprotocol.AgentCommandInventoryChunk,
		agentprotocol.AgentCommandInventoryChunk,
		agentprotocol.AgentCommandInventoryRelease,
	}
	if fmt.Sprint(kinds) != fmt.Sprint(want) {
		t.Fatalf("command sequence = %v, want %v", kinds, want)
	}
	for _, chunk := range repository.chunks {
		for _, resource := range chunk.Resources {
			if resource.Managed || resource.ProjectID != "" ||
				resource.DeploymentID != "" {
				t.Fatalf("unverified ownership was trusted: %+v", resource)
			}
		}
	}
}

func inventoryTransportChunk(
	index int,
	runtimeID string,
	observedAt time.Time,
) transport.Chunk {
	return transport.Chunk{
		SchemaVersion: transport.SchemaVersion,
		Index:         index,
		Resources: []transport.Resource{{
			Kind:      transport.KindContainer,
			RuntimeID: runtimeID,
			Name:      runtimeID,
			Container: &transport.ContainerSummary{State: "running"},
			Labels: map[string]string{
				"net.owndock.deployment_id": "deployment-1",
			},
			ObservedAt:    observedAt,
			SchemaVersion: transport.SchemaVersion,
		}},
	}
}

func inventoryChunkResources(chunks []transport.Chunk) int {
	total := 0
	for _, chunk := range chunks {
		total += len(chunk.Resources)
	}
	return total
}
