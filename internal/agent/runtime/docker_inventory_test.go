package agentruntime

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"

	"github.com/owndock/owndock/internal/shared/agentprotocol"
	inventory "github.com/owndock/owndock/internal/shared/runtimeinventory"
)

type inventoryEngineStub struct {
	containers client.ContainerListResult
	events     []events.Message
}

func (s *inventoryEngineStub) Events(
	_ context.Context,
	_ client.EventsListOptions,
) client.EventsResult {
	messages := make(chan events.Message, len(s.events))
	errorsChannel := make(chan error, 1)
	for _, event := range s.events {
		messages <- event
	}
	close(messages)
	errorsChannel <- io.EOF
	close(errorsChannel)
	return client.EventsResult{Messages: messages, Err: errorsChannel}
}

func (s *inventoryEngineStub) ContainerList(
	context.Context,
	client.ContainerListOptions,
) (client.ContainerListResult, error) {
	return s.containers, nil
}

func (*inventoryEngineStub) ImageList(
	context.Context,
	client.ImageListOptions,
) (client.ImageListResult, error) {
	return client.ImageListResult{}, nil
}

func (*inventoryEngineStub) NetworkList(
	context.Context,
	client.NetworkListOptions,
) (client.NetworkListResult, error) {
	return client.NetworkListResult{}, nil
}

func (*inventoryEngineStub) VolumeList(
	context.Context,
	client.VolumeListOptions,
) (client.VolumeListResult, error) {
	return client.VolumeListResult{}, nil
}

func (*inventoryEngineStub) Close() error { return nil }

func TestDockerInventoryPreparePullReleaseStaysInMemory(t *testing.T) {
	stateDirectory := filepath.Join(t.TempDir(), "state")
	cache, err := NewFileResultCache(stateDirectory, 8)
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewDockerExecutor(
		"/var/run/docker.sock",
		cache,
		noopCutoverStore{},
	)
	if err != nil {
		t.Fatal(err)
	}
	executor.now = func() time.Time { return time.Unix(1000, 0).UTC() }
	engineCalls := 0
	executor.newInventoryEngine = func(string) (dockerInventoryEngine, error) {
		engineCalls++
		return &inventoryEngineStub{
			containers: client.ContainerListResult{Items: []container.Summary{{
				ID:    strings.Repeat("a", 64),
				Names: []string{"/api"},
				State: container.StateRunning,
				Labels: map[string]string{
					"net.owndock.deployment_id": "deployment-1",
					"com.example.password":      "must-not-leak",
				},
				Mounts: []container.MountPoint{{
					Type: "bind", Source: "/srv/private",
					Destination: "/data", RW: true,
				}},
			}}},
		}, nil
	}

	prepare := inventoryCommand(
		"inventory-prepare-1",
		agentprotocol.AgentCommandInventoryPrepare,
		0,
	)
	result, err := executor.Execute(t.Context(), prepare)
	if err != nil {
		t.Fatal(err)
	}
	if result.Inventory == nil || result.Inventory.Manifest == nil ||
		result.Inventory.Manifest.ExpectedChunks != 1 ||
		result.Inventory.Manifest.ExpectedResources != 1 {
		t.Fatalf("prepare result = %+v", result)
	}
	if result.Inventory.Manifest.RetentionSeconds != 600 {
		t.Fatalf(
			"snapshot retention = %d",
			result.Inventory.Manifest.RetentionSeconds,
		)
	}

	repeated := prepare
	repeated.ID = "inventory-prepare-2"
	if _, err := executor.Execute(t.Context(), repeated); err != nil {
		t.Fatal(err)
	}
	if engineCalls != 1 {
		t.Fatalf("engine calls = %d, want 1", engineCalls)
	}

	chunkCommand := inventoryCommand(
		"inventory-chunk-1",
		agentprotocol.AgentCommandInventoryChunk,
		0,
	)
	chunkResult, err := executor.Execute(t.Context(), chunkCommand)
	if err != nil {
		t.Fatal(err)
	}
	if chunkResult.Inventory == nil || chunkResult.Inventory.Chunk == nil ||
		chunkResult.Inventory.Chunk.Validate(inventory.DefaultChunkBytes) != nil {
		t.Fatalf("chunk result = %+v", chunkResult)
	}
	text := testJSON(t, chunkResult.Inventory)
	for _, forbidden := range []string{
		"must-not-leak", "/srv/private", "com.example.password",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("inventory frame leaked %q: %s", forbidden, text)
		}
	}

	cacheFile, err := os.ReadFile(filepath.Join(stateDirectory, "command-results.json"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if strings.Contains(string(cacheFile), prepare.Inventory.ObservationID) ||
		strings.Contains(string(cacheFile), chunkResult.Inventory.Chunk.Resources[0].RuntimeID) {
		t.Fatalf("inventory entered durable result cache: %s", cacheFile)
	}
	restartedExecutor, err := NewDockerExecutor(
		"/var/run/docker.sock",
		cache,
		noopCutoverStore{},
	)
	if err != nil {
		t.Fatal(err)
	}
	restartedResult, err := restartedExecutor.Execute(t.Context(), chunkCommand)
	if err != nil || restartedResult.ErrorCode != "inventory_snapshot_missing" {
		t.Fatalf(
			"chunk after Agent restart result/error = %+v/%v",
			restartedResult,
			err,
		)
	}

	release := inventoryCommand(
		"inventory-release-1",
		agentprotocol.AgentCommandInventoryRelease,
		0,
	)
	if result, err := executor.Execute(t.Context(), release); err != nil ||
		result.Status != agentprotocol.AgentCommandSucceeded {
		t.Fatalf("release result/error = %+v/%v", result, err)
	}
	missing := chunkCommand
	missing.ID = "inventory-chunk-2"
	result, err = executor.Execute(t.Context(), missing)
	if err != nil || result.ErrorCode != "inventory_snapshot_missing" {
		t.Fatalf("missing chunk result/error = %+v/%v", result, err)
	}
}

func TestDockerInventorySnapshotExpiresWithoutDiskFallback(t *testing.T) {
	cache, err := NewFileResultCache(
		filepath.Join(t.TempDir(), "state"),
		8,
	)
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewDockerExecutor(
		"/var/run/docker.sock",
		cache,
		noopCutoverStore{},
	)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0).UTC()
	executor.now = func() time.Time { return now }
	executor.newInventoryEngine = func(string) (dockerInventoryEngine, error) {
		return &inventoryEngineStub{}, nil
	}
	prepare := inventoryCommand(
		"inventory-prepare-expiring",
		agentprotocol.AgentCommandInventoryPrepare,
		0,
	)
	result, err := executor.Execute(t.Context(), prepare)
	if err != nil || result.Status != agentprotocol.AgentCommandSucceeded {
		t.Fatalf("prepare result/error = %+v/%v", result, err)
	}
	now = now.Add(11 * time.Minute)
	chunk := inventoryCommand(
		"inventory-chunk-expired",
		agentprotocol.AgentCommandInventoryChunk,
		0,
	)
	result, err = executor.Execute(t.Context(), chunk)
	if err != nil || result.ErrorCode != "inventory_snapshot_missing" {
		t.Fatalf("expired chunk result/error = %+v/%v", result, err)
	}
}

func TestDockerInventoryPrepareReportsEventsDuringSnapshotWindow(t *testing.T) {
	cache, err := NewFileResultCache(filepath.Join(t.TempDir(), "state"), 8)
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewDockerExecutor(
		"/var/run/docker.sock",
		cache,
		noopCutoverStore{},
	)
	if err != nil {
		t.Fatal(err)
	}
	current := time.Unix(3000, 0).UTC()
	executor.now = func() time.Time {
		current = current.Add(100 * time.Millisecond)
		return current
	}
	executor.newInventoryEngine = func(string) (dockerInventoryEngine, error) {
		return &inventoryEngineStub{events: []events.Message{{
			Type: events.ContainerEventType, Action: events.ActionDestroy,
			Actor:    events.Actor{ID: "container-removed-during-agent-snapshot"},
			TimeNano: time.Unix(3000, 250*int64(time.Millisecond)).UnixNano(),
		}}}, nil
	}
	result, err := executor.Execute(t.Context(), inventoryCommand(
		"inventory-prepare-event-window",
		agentprotocol.AgentCommandInventoryPrepare,
		0,
	))
	if err != nil {
		t.Fatal(err)
	}
	manifest := result.Inventory.Manifest
	if len(manifest.Events) != 1 || manifest.EventsTruncated ||
		manifest.Events[0].RuntimeID != "container-removed-during-agent-snapshot" ||
		manifest.Events[0].Action != inventory.EventActionDestroy {
		t.Fatalf("Agent snapshot events = %#v", manifest)
	}
}

func inventoryCommand(
	id string,
	kind agentprotocol.AgentCommandKind,
	index int,
) agentprotocol.AgentCommand {
	request := &agentprotocol.RuntimeInventoryCommand{
		RuntimeTargetID: "target-1",
		ObservationID:   "observation-1",
	}
	if kind != agentprotocol.AgentCommandInventoryRelease {
		request.MaxChunkBytes = inventory.DefaultChunkBytes
		request.ChunkIndex = index
	}
	return agentprotocol.AgentCommand{
		ID:        id,
		Kind:      kind,
		Deadline:  time.Now().Add(time.Minute).UTC(),
		Inventory: request,
	}
}

func testJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
