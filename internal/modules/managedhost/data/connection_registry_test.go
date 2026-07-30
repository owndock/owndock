package data

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/managedhost/biz"
	"github.com/owndock/owndock/internal/shared/agentprotocol"
)

func TestConnectionRegistryReplacesAndConditionallyUnregisters(t *testing.T) {
	registry := newTestConnectionRegistry(t, 2, 4)
	firstContext, firstCancel := context.WithCancel(t.Context())
	firstCommands := registerTestAgent(registry, "host-1", "session-1", firstCancel)
	secondContext, secondCancel := context.WithCancel(t.Context())
	registerTestAgent(registry, "host-1", "session-2", secondCancel)
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
	commands := registerTestAgent(registry, "host-1", "session-1", func() {})
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
	registerTestAgent(registry, "host-1", "session-2", func() {})
	cached, err = registry.Dispatch(t.Context(), "host-1", command)
	if err != nil || !cached.Equivalent(result) {
		t.Fatalf("cached result after reconnect = %+v, error = %v", cached, err)
	}
}

func TestConnectionRegistryBoundsCompletedResultCache(t *testing.T) {
	registry := newTestConnectionRegistry(t, 1, 1)
	commands := registerTestAgent(registry, "host-1", "session-1", func() {})
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

func TestConnectionRegistryCompletedCacheDoesNotRetainCommandSecrets(
	t *testing.T,
) {
	registry := newTestConnectionRegistry(t, 1, 4)
	commands := registerTestAgent(registry, "host-1", "session-1", func() {})
	command := biz.AgentCommand{
		ID:       "deployment-prepare-1",
		Kind:     biz.AgentCommandDeploymentPrepare,
		Deadline: time.Now().Add(time.Minute).UTC(),
		Deployment: &biz.DeploymentCommand{
			DeploymentID:    "deployment-1",
			WorkerID:        "worker-1",
			FencingToken:    1,
			CutoverSequence: 1,
			RuntimeTargetID: "target-secret-value",
			ContainerName:   "owndock-runtime",
			ImageDigest: "registry.example/team/api@sha256:" +
				strings.Repeat("a", 64),
			RegistryAuthorization: []byte("registry-secret-value"),
		},
	}
	completed := make(chan error, 1)
	go func() {
		_, err := registry.Dispatch(t.Context(), "host-1", command)
		completed <- err
	}()
	<-commands
	if err := registry.Complete(
		"host-1",
		"session-1",
		biz.AgentCommandResult{
			CommandID: command.ID,
			Status:    biz.AgentCommandSucceeded,
		},
	); err != nil {
		t.Fatal(err)
	}
	if err := <-completed; err != nil {
		t.Fatal(err)
	}

	key := completedCommandKey{
		hostID:    "host-1",
		commandID: command.ID,
	}
	registry.mu.Lock()
	cached := registry.completed[key]
	registry.mu.Unlock()
	if cached.kind != command.Kind ||
		cached.fingerprint == ([32]byte{}) ||
		!cached.result.Equivalent(biz.AgentCommandResult{
			CommandID: command.ID,
			Status:    biz.AgentCommandSucceeded,
		}) {
		t.Fatalf("cached metadata = %+v", cached)
	}
}

func TestConnectionRegistryAppliesBackpressure(t *testing.T) {
	registry := newTestConnectionRegistry(t, 1, 4)
	registerTestAgent(registry, "host-1", "session-1", func() {})
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

func TestConnectionRegistryEnforcesAuthenticatedCapabilities(
	t *testing.T,
) {
	registry := newTestConnectionRegistry(t, 2, 4)
	commands := registry.Register(
		"host-1",
		"session-1",
		[]string{agentprotocol.CapabilityRuntimeProbe},
		func() {},
	)
	deployment := biz.AgentCommand{
		ID:       "deployment-activate-1",
		Kind:     biz.AgentCommandDeploymentActivate,
		Deadline: time.Now().Add(time.Minute),
		Deployment: &biz.DeploymentCommand{
			DeploymentID:    "deployment-1",
			WorkerID:        "worker-1",
			FencingToken:    1,
			CutoverSequence: 1,
			RuntimeTargetID: "target-1",
			ContainerName:   "owndock-runtime",
		},
	}
	if _, err := registry.Dispatch(
		t.Context(),
		"host-1",
		deployment,
	); !errors.Is(err, biz.ErrAgentCapabilityUnavailable) {
		t.Fatalf("deployment capability error = %v", err)
	}
	select {
	case command := <-commands:
		t.Fatalf("unsupported command was queued: %+v", command)
	default:
	}

	probe := testAgentCommand("probe-1")
	done := make(chan error, 1)
	go func() {
		_, err := registry.Dispatch(t.Context(), "host-1", probe)
		done <- err
	}()
	if command := <-commands; !command.Equivalent(probe) {
		t.Fatalf("probe command = %+v", command)
	}
	if err := registry.Complete(
		"host-1",
		"session-1",
		biz.AgentCommandResult{
			CommandID: probe.ID,
			Status:    biz.AgentCommandSucceeded,
			RuntimeProbe: &biz.RuntimeProbeResult{
				Status: biz.RuntimeProbeReady,
			},
		},
	); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestConnectionRegistryFailsPendingCommandOnReconnect(t *testing.T) {
	registry := newTestConnectionRegistry(t, 1, 4)
	commands := registerTestAgent(registry, "host-1", "session-1", func() {})
	result := make(chan error, 1)
	go func() {
		_, err := registry.Dispatch(
			t.Context(), "host-1", testAgentCommand("command-1"),
		)
		result <- err
	}()
	<-commands
	registerTestAgent(registry, "host-1", "session-2", func() {})
	if err := <-result; !errors.Is(err, biz.ErrAgentDisconnected) {
		t.Fatalf("Dispatch() error = %v, want disconnected", err)
	}
}

func TestConnectionRegistryRejectsConflictingCommandAndResult(t *testing.T) {
	registry := newTestConnectionRegistry(t, 2, 4)
	commands := registerTestAgent(registry, "host-1", "session-1", func() {})
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
	commands := registerTestAgent(registry, "host-1", "session-1", func() {})
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
	registerTestAgent(registry, "host-1", "session-1", firstCancel)
	registerTestAgent(registry, "host-2", "session-2", secondCancel)
	registry.Close()
	if firstContext.Err() != context.Canceled ||
		secondContext.Err() != context.Canceled {
		t.Fatal("registry close did not cancel every connection")
	}
}

func TestConnectionRegistryDoesNotRetainInventoryResults(t *testing.T) {
	registry := newTestConnectionRegistry(t, 2, 4)
	commands := registerTestAgent(
		registry,
		"host-1",
		"session-1",
		func() {},
	)
	command := biz.AgentCommand{
		ID:       "inventory-release-1",
		Kind:     biz.AgentCommandInventoryRelease,
		Deadline: time.Now().Add(time.Minute).UTC(),
		Inventory: &biz.RuntimeInventoryCommand{
			RuntimeTargetID: "target-1",
			ObservationID:   "observation-1",
		},
	}
	for attempt := 0; attempt < 2; attempt++ {
		completed := make(chan error, 1)
		go func() {
			_, err := registry.Dispatch(t.Context(), "host-1", command)
			completed <- err
		}()
		if got := <-commands; !got.Equivalent(command) {
			t.Fatalf("attempt %d command = %+v", attempt, got)
		}
		if err := registry.Complete(
			"host-1",
			"session-1",
			biz.AgentCommandResult{
				CommandID: command.ID,
				Status:    biz.AgentCommandSucceeded,
			},
		); err != nil {
			t.Fatal(err)
		}
		if err := <-completed; err != nil {
			t.Fatal(err)
		}
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if len(registry.completed) != 0 {
		t.Fatalf("inventory results retained in Server cache: %+v", registry.completed)
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

func registerTestAgent(
	registry *ConnectionRegistry,
	hostID, sessionID string,
	cancel context.CancelFunc,
) <-chan biz.AgentCommand {
	return registry.Register(
		hostID,
		sessionID,
		agentprotocol.SupportedCapabilities(),
		cancel,
	)
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
