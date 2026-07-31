package data

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	managedhostbiz "github.com/owndock/owndock/internal/modules/managedhost/biz"
	managedhostdata "github.com/owndock/owndock/internal/modules/managedhost/data"
	inventorybiz "github.com/owndock/owndock/internal/modules/runtimeinventory/biz"
	"github.com/owndock/owndock/internal/shared/agentprotocol"
	transport "github.com/owndock/owndock/internal/shared/runtimeinventory"
)

type inventoryDispatcherStub struct {
	now            time.Time
	commands       []managedhostbiz.AgentCommand
	chunks         []transport.Chunk
	failChunkIndex *int
	failChunkCode  string
	events         []transport.Event
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
					Events:            append([]transport.Event(nil), s.events...),
				},
			},
		}, nil
	case managedhostbiz.AgentCommandInventoryChunk:
		index := command.Inventory.ChunkIndex
		if s.failChunkIndex != nil && index == *s.failChunkIndex {
			code := s.failChunkCode
			if code == "" {
				code = "inventory_unavailable"
			}
			return managedhostbiz.AgentCommandResult{
				CommandID: command.ID,
				Status:    managedhostbiz.AgentCommandFailed,
				ErrorCode: code,
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

type transientInventoryDispatcher struct {
	inner    *inventoryDispatcherStub
	failures map[agentprotocol.AgentCommandKind]int
	failure  error
	attempts map[agentprotocol.AgentCommandKind]int
}

type observedInventoryDispatcher struct {
	inner        managedhostbiz.AgentCommandDispatcher
	backpressure chan struct{}
}

func (d observedInventoryDispatcher) Dispatch(
	ctx context.Context,
	hostID string,
	command managedhostbiz.AgentCommand,
) (managedhostbiz.AgentCommandResult, error) {
	result, err := d.inner.Dispatch(ctx, hostID, command)
	if errors.Is(err, managedhostbiz.ErrAgentBackpressure) {
		select {
		case d.backpressure <- struct{}{}:
		default:
		}
	}
	return result, err
}

func (d *transientInventoryDispatcher) Dispatch(
	ctx context.Context,
	hostID string,
	command managedhostbiz.AgentCommand,
) (managedhostbiz.AgentCommandResult, error) {
	if d.attempts == nil {
		d.attempts = make(map[agentprotocol.AgentCommandKind]int)
	}
	d.attempts[command.Kind]++
	if d.failures[command.Kind] > 0 {
		d.failures[command.Kind]--
		return managedhostbiz.AgentCommandResult{}, d.failure
	}
	return d.inner.Dispatch(ctx, hostID, command)
}

func TestAgentCollectorRetriesTransientReconnectAndBackpressure(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		name    string
		kind    agentprotocol.AgentCommandKind
		failure error
	}{
		{
			name:    "reconnect while pulling chunk",
			kind:    agentprotocol.AgentCommandInventoryChunk,
			failure: managedhostbiz.ErrAgentDisconnected,
		},
		{
			name:    "backpressure while preparing",
			kind:    agentprotocol.AgentCommandInventoryPrepare,
			failure: managedhostbiz.ErrAgentBackpressure,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			base := &inventoryDispatcherStub{
				now: now,
				chunks: []transport.Chunk{
					inventoryTransportChunk(0, "container-1", now),
				},
			}
			dispatcher := &transientInventoryDispatcher{
				inner:    base,
				failures: map[agentprotocol.AgentCommandKind]int{test.kind: 1},
				failure:  test.failure,
			}
			repository := &inventoryRepositoryStub{}
			identifier := 0
			collector, err := NewAgentCollector(
				dispatcher,
				repository,
				func() (string, error) {
					identifier++
					return fmt.Sprintf("retry-%d", identifier), nil
				},
				time.Now,
				time.Second,
				transport.DefaultChunkBytes,
			)
			if err != nil {
				t.Fatal(err)
			}
			collector.retryDelay = time.Millisecond
			if err := collector.Synchronize(
				t.Context(),
				"organization-1",
				"host-1",
				"target-1",
			); err != nil {
				t.Fatal(err)
			}
			if !repository.completed || dispatcher.attempts[test.kind] != 2 {
				t.Fatalf(
					"completed / attempts = %v / %d",
					repository.completed,
					dispatcher.attempts[test.kind],
				)
			}
		})
	}
}

func TestAgentCollectorStartsNewObservationAfterAgentSnapshotLoss(t *testing.T) {
	now := time.Now().UTC()
	failedIndex := 0
	dispatcher := &inventoryDispatcherStub{
		now: now,
		chunks: []transport.Chunk{
			inventoryTransportChunk(0, "container-1", now),
		},
		failChunkIndex: &failedIndex,
		failChunkCode:  "inventory_snapshot_missing",
	}
	repository := &inventoryRepositoryStub{}
	identifier := 0
	collector, err := NewAgentCollector(
		dispatcher,
		repository,
		func() (string, error) {
			identifier++
			return fmt.Sprintf("restart-%d", identifier), nil
		},
		time.Now,
		time.Second,
		transport.DefaultChunkBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := collector.Synchronize(
		t.Context(), "organization-1", "host-1", "target-1",
	); err == nil || repository.completed {
		t.Fatalf("snapshot loss error / completed = %v / %v", err, repository.completed)
	}
	firstObservation := dispatcher.commands[0].Inventory.ObservationID
	dispatcher.failChunkIndex = nil
	if err := collector.Synchronize(
		t.Context(), "organization-1", "host-1", "target-1",
	); err != nil {
		t.Fatal(err)
	}
	var secondObservation string
	for _, command := range dispatcher.commands {
		if command.Kind == agentprotocol.AgentCommandInventoryPrepare &&
			command.Inventory.ObservationID != firstObservation {
			secondObservation = command.Inventory.ObservationID
			break
		}
	}
	if secondObservation == "" || secondObservation == firstObservation ||
		!repository.completed {
		t.Fatalf(
			"first / second / completed = %q / %q / %v",
			firstObservation,
			secondObservation,
			repository.completed,
		)
	}
}

func TestAgentCollectorRecoversFromRealRegistryBackpressure(t *testing.T) {
	now := time.Now().UTC()
	registry, err := managedhostdata.NewConnectionRegistry(1, 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(registry.Close)
	commands := registry.Register(
		"host-1",
		"session-1",
		agentprotocol.SupportedCapabilities(),
		func() {},
	)
	filler := managedhostbiz.AgentCommand{
		ID:       "backpressure-filler",
		Kind:     agentprotocol.AgentCommandRuntimeProbe,
		Deadline: time.Now().Add(5 * time.Second).UTC(),
		RuntimeProbe: &agentprotocol.RuntimeProbeCommand{
			RuntimeTargetID: "target-1",
		},
	}
	fillerDone := make(chan error, 1)
	go func() {
		_, dispatchErr := registry.Dispatch(t.Context(), "host-1", filler)
		fillerDone <- dispatchErr
	}()
	deadline := time.Now().Add(time.Second)
	for len(commands) != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(commands) != 1 {
		t.Fatal("filler command did not saturate the Agent queue")
	}

	backpressure := make(chan struct{}, 1)
	repository := &inventoryRepositoryStub{}
	identifier := 0
	collector, err := NewAgentCollector(
		observedInventoryDispatcher{inner: registry, backpressure: backpressure},
		repository,
		func() (string, error) {
			identifier++
			return fmt.Sprintf("registry-backpressure-%d", identifier), nil
		},
		time.Now,
		time.Second,
		transport.DefaultChunkBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	collector.retryDelay = time.Millisecond
	collectionDone := make(chan error, 1)
	go func() {
		collectionDone <- collector.Synchronize(
			t.Context(), "organization-1", "host-1", "target-1",
		)
	}()
	select {
	case <-backpressure:
	case <-time.After(time.Second):
		t.Fatal("collector did not observe real registry backpressure")
	}
	if command := <-commands; !command.Equivalent(filler) {
		t.Fatalf("filler command = %+v", command)
	}
	if err := registry.Complete(
		"host-1",
		"session-1",
		managedhostbiz.AgentCommandResult{
			CommandID: filler.ID,
			Status:    agentprotocol.AgentCommandSucceeded,
			RuntimeProbe: &agentprotocol.RuntimeProbeResult{
				Status: agentprotocol.RuntimeProbeReady,
			},
		},
	); err != nil {
		t.Fatal(err)
	}
	if err := <-fillerDone; err != nil {
		t.Fatal(err)
	}

	responderDone := make(chan error, 1)
	go func() {
		for command := range commands {
			result := managedhostbiz.AgentCommandResult{
				CommandID: command.ID,
				Status:    agentprotocol.AgentCommandSucceeded,
			}
			switch command.Kind {
			case agentprotocol.AgentCommandInventoryPrepare:
				result.Inventory = &agentprotocol.RuntimeInventoryResult{
					Manifest: &agentprotocol.RuntimeInventoryManifest{
						ObservationID:     command.Inventory.ObservationID,
						SchemaVersion:     transport.SchemaVersion,
						ExpectedChunks:    1,
						ExpectedResources: 1,
						RetentionSeconds:  600,
					},
				}
			case agentprotocol.AgentCommandInventoryChunk:
				result.Inventory = &agentprotocol.RuntimeInventoryResult{
					Chunk: &transport.Chunk{
						SchemaVersion: transport.SchemaVersion,
						Index:         command.Inventory.ChunkIndex,
						Resources: []transport.Resource{{
							Kind:          transport.KindContainer,
							RuntimeID:     "container-after-backpressure",
							Name:          "api",
							Container:     &transport.ContainerSummary{State: "running"},
							ObservedAt:    now,
							SchemaVersion: transport.SchemaVersion,
						}},
					},
				}
			case agentprotocol.AgentCommandInventoryRelease:
			default:
				responderDone <- fmt.Errorf("unexpected command %s", command.Kind)
				return
			}
			if completeErr := registry.Complete(
				"host-1", "session-1", result,
			); completeErr != nil {
				responderDone <- completeErr
				return
			}
			if command.Kind == agentprotocol.AgentCommandInventoryRelease {
				responderDone <- nil
				return
			}
		}
		responderDone <- managedhostbiz.ErrAgentDisconnected
	}()
	select {
	case err := <-collectionDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("collector did not recover after queue capacity was released")
	}
	if err := <-responderDone; err != nil {
		t.Fatal(err)
	}
	if !repository.completed || len(repository.chunks) != 1 {
		t.Fatalf(
			"completed / chunks = %v / %d",
			repository.completed,
			len(repository.chunks),
		)
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
		events: []transport.Event{{
			Kind: transport.KindContainer, RuntimeID: "container-removed-in-window",
			Action: transport.EventActionDestroy, OccurredAt: now.Add(time.Second),
		}},
	}
	repository := &inventoryRepositoryStub{}
	hints := &eventHintRepositoryStub{}
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
	collector.WithEventHints(hints)
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
	if len(hints.hints) != 1 ||
		hints.hints[0].RuntimeID != "container-removed-in-window" ||
		hints.hints[0].Action != inventorybiz.EventActionDestroy {
		t.Fatalf("Agent snapshot event hints = %#v", hints.hints)
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
