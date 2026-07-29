package data

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/managedhost/biz"
)

func TestConnectionRegistryReplacesAndConditionallyUnregisters(t *testing.T) {
	registry := newTestConnectionRegistry(t, 2, 4)
	firstContext, firstCancel := context.WithCancel(t.Context())
	firstCommands := registry.Register("host-1", "session-1", firstCancel)
	secondContext, secondCancel := context.WithCancel(t.Context())
	registry.Register("host-1", "session-2", secondCancel)
	if firstContext.Err() != context.Canceled {
		t.Fatal("replaced connection was not canceled")
	}
	if _, open := <-firstCommands; open {
		t.Fatal("replaced connection command channel remained open")
	}
	registry.Unregister("host-1", "session-1")
	if secondContext.Err() != nil {
		t.Fatal("stale unregister canceled the current connection")
	}
	registry.DisconnectHost("host-1")
	if secondContext.Err() != context.Canceled {
		t.Fatal("host disconnect did not cancel the current connection")
	}
}

func TestConnectionRegistryDispatchCompletesAndCachesResult(t *testing.T) {
	registry := newTestConnectionRegistry(t, 2, 4)
	commands := registry.Register("host-1", "session-1", func() {})
	command := testAgentCommand("command-1")
	result := biz.AgentCommandResult{
		CommandID: command.ID, Status: biz.AgentCommandSucceeded,
		RuntimeProbe: &biz.RuntimeProbeResult{Status: biz.RuntimeProbeReady},
	}

	firstResult := make(chan biz.AgentCommandResult, 1)
	firstError := make(chan error, 1)
	go func() {
		value, err := registry.Dispatch(t.Context(), "host-1", command)
		firstResult <- value
		firstError <- err
	}()
	if got := <-commands; !got.Equivalent(command) {
		t.Fatalf("command = %+v, want %+v", got, command)
	}

	secondResult := make(chan biz.AgentCommandResult, 1)
	go func() {
		value, _ := registry.Dispatch(t.Context(), "host-1", command)
		secondResult <- value
	}()
	if err := registry.Complete("host-1", "session-1", result); err != nil {
		t.Fatal(err)
	}
	if err := <-firstError; err != nil {
		t.Fatal(err)
	}
	if got := <-firstResult; !got.Equivalent(result) {
		t.Fatalf("first result = %+v, want %+v", got, result)
	}
	if got := <-secondResult; !got.Equivalent(result) {
		t.Fatalf("second result = %+v, want %+v", got, result)
	}

	cached, err := registry.Dispatch(t.Context(), "host-1", command)
	if err != nil || !cached.Equivalent(result) {
		t.Fatalf("cached result = %+v, error = %v", cached, err)
	}
	if err := registry.Complete("host-1", "session-1", result); err != nil {
		t.Fatalf("duplicate result error = %v", err)
	}
	registry.DisconnectHost("host-1")
	registry.Register("host-1", "session-2", func() {})
	cached, err = registry.Dispatch(t.Context(), "host-1", command)
	if err != nil || !cached.Equivalent(result) {
		t.Fatalf("cached result after reconnect = %+v, error = %v", cached, err)
	}
}

func TestConnectionRegistryBoundsCompletedResultCache(t *testing.T) {
	registry := newTestConnectionRegistry(t, 1, 1)
	commands := registry.Register("host-1", "session-1", func() {})
	first := testAgentCommand("command-1")
	second := testAgentCommand("command-2")
	dispatchAndCompleteAgentCommand(t, registry, commands, first)
	dispatchAndCompleteAgentCommand(t, registry, commands, second)

	retryContext, cancel := context.WithCancel(t.Context())
	retry := make(chan error, 1)
	go func() {
		_, err := registry.Dispatch(retryContext, "host-1", first)
		retry <- err
	}()
	if got := <-commands; !got.Equivalent(first) {
		t.Fatalf("evicted command was not queued again: %+v", got)
	}
	cancel()
	if err := <-retry; !errors.Is(err, context.Canceled) {
		t.Fatalf("retried command error = %v", err)
	}
	registry.DisconnectHost("host-1")
}

func TestConnectionRegistryAppliesBackpressure(t *testing.T) {
	registry := newTestConnectionRegistry(t, 1, 4)
	registry.Register("host-1", "session-1", func() {})
	first := testAgentCommand("command-1")
	second := testAgentCommand("command-2")

	firstContext, cancel := context.WithCancel(t.Context())
	defer cancel()
	firstDone := make(chan error, 1)
	go func() {
		_, err := registry.Dispatch(firstContext, "host-1", first)
		firstDone <- err
	}()
	waitForPendingCommand(t, registry, "host-1", first.ID)

	_, err := registry.Dispatch(t.Context(), "host-1", second)
	if !errors.Is(err, biz.ErrAgentBackpressure) {
		t.Fatalf("Dispatch() error = %v, want backpressure", err)
	}
	cancel()
	if err := <-firstDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("first Dispatch() error = %v", err)
	}
}

func TestConnectionRegistryFailsPendingCommandOnReconnect(t *testing.T) {
	registry := newTestConnectionRegistry(t, 1, 4)
	commands := registry.Register("host-1", "session-1", func() {})
	result := make(chan error, 1)
	go func() {
		_, err := registry.Dispatch(
			t.Context(), "host-1", testAgentCommand("command-1"),
		)
		result <- err
	}()
	<-commands
	registry.Register("host-1", "session-2", func() {})
	if err := <-result; !errors.Is(err, biz.ErrAgentDisconnected) {
		t.Fatalf("Dispatch() error = %v, want disconnected", err)
	}
}

func TestConnectionRegistryRejectsConflictingCommandAndResult(t *testing.T) {
	registry := newTestConnectionRegistry(t, 2, 4)
	commands := registry.Register("host-1", "session-1", func() {})
	command := testAgentCommand("command-1")
	dispatchError := make(chan error, 1)
	go func() {
		_, err := registry.Dispatch(t.Context(), "host-1", command)
		dispatchError <- err
	}()
	<-commands

	conflicting := command
	conflicting.RuntimeProbe = &biz.RuntimeProbeCommand{RuntimeTargetID: "target-2"}
	if _, err := registry.Dispatch(
		t.Context(), "host-1", conflicting,
	); !errors.Is(err, biz.ErrAgentCommandInvalid) {
		t.Fatalf("conflicting Dispatch() error = %v", err)
	}
	if err := registry.Complete(
		"host-1", "session-1",
		biz.AgentCommandResult{
			CommandID: command.ID, Status: biz.AgentCommandSucceeded,
			RuntimeProbe: &biz.RuntimeProbeResult{Status: "unexpected"},
		},
	); !errors.Is(err, biz.ErrAgentResultInvalid) {
		t.Fatalf("invalid Complete() error = %v", err)
	}
	registry.DisconnectHost("host-1")
	if err := <-dispatchError; !errors.Is(err, biz.ErrAgentDisconnected) {
		t.Fatalf("Dispatch() error = %v", err)
	}
}

func TestConnectionRegistryExpiresPendingCommand(t *testing.T) {
	registry := newTestConnectionRegistry(t, 1, 4)
	commands := registry.Register("host-1", "session-1", func() {})
	command := testAgentCommand("command-1")
	command.Deadline = time.Now().Add(20 * time.Millisecond)
	result := make(chan error, 1)
	go func() {
		_, err := registry.Dispatch(t.Context(), "host-1", command)
		result <- err
	}()
	<-commands
	if err := <-result; !errors.Is(err, biz.ErrAgentCommandExpired) {
		t.Fatalf("Dispatch() error = %v, want expired", err)
	}
}

func TestConnectionRegistryCloseCancelsAllConnections(t *testing.T) {
	registry := newTestConnectionRegistry(t, 2, 4)
	firstContext, firstCancel := context.WithCancel(t.Context())
	secondContext, secondCancel := context.WithCancel(t.Context())
	registry.Register("host-1", "session-1", firstCancel)
	registry.Register("host-2", "session-2", secondCancel)
	registry.Close()
	if firstContext.Err() != context.Canceled ||
		secondContext.Err() != context.Canceled {
		t.Fatal("registry close did not cancel every connection")
	}
}

func newTestConnectionRegistry(
	t *testing.T,
	outboundBuffer, completedCacheSize int,
) *ConnectionRegistry {
	t.Helper()
	registry, err := NewConnectionRegistry(outboundBuffer, completedCacheSize)
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func testAgentCommand(id string) biz.AgentCommand {
	return biz.AgentCommand{
		ID: id, Kind: biz.AgentCommandRuntimeProbe,
		Deadline:     time.Now().Add(time.Minute).UTC(),
		RuntimeProbe: &biz.RuntimeProbeCommand{RuntimeTargetID: "target-1"},
	}
}

func waitForPendingCommand(
	t *testing.T,
	registry *ConnectionRegistry,
	hostID, commandID string,
) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		registry.mu.Lock()
		connection := registry.connections[hostID]
		pending := connection != nil && connection.pending[commandID] != nil
		registry.mu.Unlock()
		if pending {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("command was not queued")
}

func dispatchAndCompleteAgentCommand(
	t *testing.T,
	registry *ConnectionRegistry,
	commands <-chan biz.AgentCommand,
	command biz.AgentCommand,
) {
	t.Helper()
	completed := make(chan error, 1)
	go func() {
		_, err := registry.Dispatch(t.Context(), "host-1", command)
		completed <- err
	}()
	if got := <-commands; !got.Equivalent(command) {
		t.Fatalf("command = %+v, want %+v", got, command)
	}
	if err := registry.Complete(
		"host-1", "session-1",
		biz.AgentCommandResult{
			CommandID: command.ID,
			Status:    biz.AgentCommandSucceeded,
			RuntimeProbe: &biz.RuntimeProbeResult{
				Status: biz.RuntimeProbeReady,
			},
		},
	); err != nil {
		t.Fatal(err)
	}
	if err := <-completed; err != nil {
		t.Fatal(err)
	}
}
