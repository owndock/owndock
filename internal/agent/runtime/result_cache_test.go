package agentruntime

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/shared/agentprotocol"
)

func TestFileResultCachePersistsSafeResultAcrossRestart(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	cache, err := NewFileResultCache(directory, 2)
	if err != nil {
		t.Fatal(err)
	}
	command := runtimeProbeCommand("command-1", "target-1")
	result := runtimeProbeResult(command.ID, agentprotocol.RuntimeProbeReady)
	if err := cache.Store(command, result); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewFileResultCache(directory, 2)
	if err != nil {
		t.Fatal(err)
	}
	cached, exists, err := reopened.Lookup(command)
	if err != nil || !exists || !cached.Equivalent(result) {
		t.Fatalf("cached = %+v, exists = %v, error = %v", cached, exists, err)
	}
	info, err := os.Stat(filepath.Join(directory, "command-results.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("cache permissions = %o", info.Mode().Perm())
	}
}

func TestFileResultCacheLoadsVersionOneAndUpgradesWithoutPayload(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	command := runtimeProbeCommand("legacy-command", "legacy-target")
	document := resultCacheDocumentV1{
		Version: 1,
		Entries: []resultCacheEntryDocumentV1{{
			CommandID:       command.ID,
			Kind:            command.Kind,
			Deadline:        command.Deadline,
			RuntimeTargetID: command.RuntimeProbe.RuntimeTargetID,
			Status:          agentprotocol.AgentCommandSucceeded,
			RuntimeStatus:   agentprotocol.RuntimeProbeReady,
		}},
	}
	value, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "command-results.json")
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatal(err)
	}
	cache, err := NewFileResultCache(directory, 4)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists, err := cache.Lookup(command); err != nil || !exists {
		t.Fatalf("legacy lookup exists = %v, error = %v", exists, err)
	}
	second := runtimeProbeCommand("new-command", "new-target")
	if err := cache.Store(
		second,
		runtimeProbeResult(second.ID, agentprotocol.RuntimeProbeReady),
	); err != nil {
		t.Fatal(err)
	}
	upgraded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(upgraded), "legacy-target") ||
		!strings.Contains(string(upgraded), `"version":2`) {
		t.Fatalf("upgraded cache = %s", upgraded)
	}
}

func TestFileResultCachePersistsOnlyDeploymentFingerprint(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	cache, err := NewFileResultCache(directory, 2)
	if err != nil {
		t.Fatal(err)
	}
	command := agentprotocol.AgentCommand{
		ID:       "command-deploy",
		Kind:     agentprotocol.AgentCommandDeploymentPrepare,
		Deadline: time.Now().Add(time.Minute).UTC(),
		Deployment: &agentprotocol.DeploymentCommand{
			DeploymentID:    "deployment-1",
			WorkerID:        "worker-1",
			FencingToken:    1,
			CutoverSequence: 1,
			RuntimeTargetID: "target-1",
			ContainerName:   "owndock-container",
			ImageDigest: "registry.example.com/team/app@sha256:" +
				strings.Repeat("a", 64),
			RegistryAuthorization: []byte(
				"top-secret-registry-authorization",
			),
		},
	}
	result := agentprotocol.AgentCommandResult{
		CommandID: command.ID,
		Status:    agentprotocol.AgentCommandSucceeded,
	}
	if err := cache.Store(command, result); err != nil {
		t.Fatal(err)
	}
	value, err := os.ReadFile(
		filepath.Join(directory, "command-results.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"top-secret-registry-authorization",
		"registry.example.com",
		"deployment-1",
		"target-1",
	} {
		if strings.Contains(string(value), forbidden) {
			t.Fatalf("cache persisted command payload %q: %s", forbidden, value)
		}
	}
	reopened, err := NewFileResultCache(directory, 2)
	if err != nil {
		t.Fatal(err)
	}
	cached, exists, err := reopened.Lookup(command)
	if err != nil || !exists || !cached.Equivalent(result) {
		t.Fatalf(
			"cached = %+v, exists = %v, error = %v",
			cached,
			exists,
			err,
		)
	}
}

func TestFileResultCacheBoundsAndRejectsConflictingCommand(t *testing.T) {
	cache, err := NewFileResultCache(
		filepath.Join(t.TempDir(), "state"),
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	first := runtimeProbeCommand("command-1", "target-1")
	second := runtimeProbeCommand("command-2", "target-2")
	if err := cache.Store(
		first,
		runtimeProbeResult(first.ID, agentprotocol.RuntimeProbeReady),
	); err != nil {
		t.Fatal(err)
	}
	if err := cache.Store(
		second,
		runtimeProbeResult(second.ID, agentprotocol.RuntimeProbeUnreachable),
	); err != nil {
		t.Fatal(err)
	}
	if _, exists, err := cache.Lookup(first); err != nil || exists {
		t.Fatalf("evicted lookup exists = %v, error = %v", exists, err)
	}

	conflicting := second
	conflicting.RuntimeProbe = &agentprotocol.RuntimeProbeCommand{
		RuntimeTargetID: "different-target",
	}
	if _, _, err := cache.Lookup(conflicting); !errors.Is(
		err, agentprotocol.ErrCommandInvalid,
	) {
		t.Fatalf("conflicting lookup error = %v", err)
	}
}

func TestFileResultCacheRejectsLooseDirectoryAndSymlink(t *testing.T) {
	parent := t.TempDir()
	loose := filepath.Join(parent, "loose")
	if err := os.Mkdir(loose, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileResultCache(loose, 2); !errors.Is(
		err, ErrInvalidResultCache,
	) {
		t.Fatalf("loose directory error = %v", err)
	}

	state := filepath.Join(parent, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(parent, "outside.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(
		target,
		filepath.Join(state, "command-results.json"),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileResultCache(state, 2); !errors.Is(
		err, ErrInvalidResultCache,
	) {
		t.Fatalf("symlink cache error = %v", err)
	}
}

func runtimeProbeCommand(
	commandID, targetID string,
) agentprotocol.AgentCommand {
	return agentprotocol.AgentCommand{
		ID: commandID, Kind: agentprotocol.AgentCommandRuntimeProbe,
		Deadline: time.Now().Add(time.Minute).UTC(),
		RuntimeProbe: &agentprotocol.RuntimeProbeCommand{
			RuntimeTargetID: targetID,
		},
	}
}

func runtimeProbeResult(
	commandID string,
	status agentprotocol.RuntimeProbeStatus,
) agentprotocol.AgentCommandResult {
	return agentprotocol.AgentCommandResult{
		CommandID: commandID,
		Status:    agentprotocol.AgentCommandSucceeded,
		RuntimeProbe: &agentprotocol.RuntimeProbeResult{
			Status: status,
		},
	}
}
