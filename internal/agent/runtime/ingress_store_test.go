package agentruntime

import (
	"errors"
	"os"
	"testing"

	"github.com/owndock/owndock/internal/shared/agentprotocol"
)

func TestFileIngressFenceStorePersistsPreparedCommittedAndAbortedState(t *testing.T) {
	directory := restrictedTempDirectory(t)
	store, err := NewFileIngressFenceStore(directory, 4)
	if err != nil {
		t.Fatal(err)
	}
	first := ingressCommand(t, 1, []agentprotocol.IngressRoute{
		ingressRoute("route-1", 1, "deployment-1", 1),
	})
	first.ProbeRouteIDs = []string{"route-1"}
	state, err := store.Begin(first)
	if err != nil || state != IngressPrepareNew {
		t.Fatalf("first Begin() = %d, %v", state, err)
	}
	reloaded, err := NewFileIngressFenceStore(directory, 4)
	if err != nil {
		t.Fatal(err)
	}
	state, err = reloaded.Begin(first)
	if err != nil || state != IngressPreparePending {
		t.Fatalf("reloaded Begin() = %d, %v", state, err)
	}
	if err := reloaded.Commit(first); err != nil {
		t.Fatal(err)
	}
	state, err = reloaded.Begin(first)
	if err != nil || state != IngressPrepareCommitted {
		t.Fatalf("committed Begin() = %d, %v", state, err)
	}
	committed, exists := reloaded.Committed()
	if !exists || !sameIngressConfig(committed, first) {
		t.Fatalf("committed = %#v, %t", committed, exists)
	}

	second := ingressCommand(t, 2, []agentprotocol.IngressRoute{
		ingressRoute("route-1", 2, "deployment-2", 2),
	})
	if state, err := reloaded.Begin(second); err != nil || state != IngressPrepareNew {
		t.Fatalf("second Begin() = %d, %v", state, err)
	}
	if err := reloaded.Abort(second); err != nil {
		t.Fatal(err)
	}
	if already, err := reloaded.CanAbort(second); err != nil || !already {
		t.Fatalf("abort replay = %t, %v", already, err)
	}
	committed, exists = reloaded.Committed()
	if !exists || !sameIngressConfig(committed, first) {
		t.Fatalf("abort changed committed config = %#v, %t", committed, exists)
	}
}

func TestFileIngressFenceStoreRejectsStaleConflictingAndConcurrentPrepare(t *testing.T) {
	store, err := NewFileIngressFenceStore(restrictedTempDirectory(t), 2)
	if err != nil {
		t.Fatal(err)
	}
	first := ingressCommand(t, 5, []agentprotocol.IngressRoute{
		ingressRoute("route-1", 2, "deployment-2", 8),
	})
	if _, err := store.Begin(first); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(first); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Begin(ingressCommand(t, 4, first.Routes)); !errors.Is(err, ErrIngressFenceStale) {
		t.Fatalf("old host revision error = %v", err)
	}
	oldRoute := ingressRoute("route-1", 1, "deployment-3", 9)
	if _, err := store.Begin(ingressCommand(t, 6, []agentprotocol.IngressRoute{oldRoute})); !errors.Is(err, ErrIngressFenceStale) {
		t.Fatalf("old route revision error = %v", err)
	}
	conflicting := ingressRoute("route-1", 2, "other-deployment", 8)
	if _, err := store.Begin(ingressCommand(t, 6, []agentprotocol.IngressRoute{conflicting})); !errors.Is(err, ErrIngressFenceConflict) {
		t.Fatalf("same cutover conflict error = %v", err)
	}
	valid := ingressRoute("route-1", 3, "deployment-3", 9)
	prepared := ingressCommand(t, 6, []agentprotocol.IngressRoute{valid})
	if _, err := store.Begin(prepared); err != nil {
		t.Fatal(err)
	}
	other := ingressCommand(t, 7, []agentprotocol.IngressRoute{valid})
	if _, err := store.Begin(other); !errors.Is(err, ErrIngressFenceConflict) {
		t.Fatalf("concurrent prepare error = %v", err)
	}
	if _, err := store.CanCommit(other); !errors.Is(err, ErrIngressFenceConflict) {
		t.Fatalf("mismatched commit error = %v", err)
	}
	if _, err := store.CanAbort(other); !errors.Is(err, ErrIngressFenceConflict) {
		t.Fatalf("mismatched abort error = %v", err)
	}
	if err := store.Abort(prepared); err != nil {
		t.Fatal(err)
	}
	full := []agentprotocol.IngressRoute{valid,
		ingressRoute("route-2", 1, "deployment-4", 1),
		ingressRoute("route-3", 1, "deployment-5", 1)}
	if _, err := store.Begin(ingressCommand(t, 7, full)); !errors.Is(err, ErrIngressStoreFull) {
		t.Fatalf("capacity error = %v", err)
	}
}

func TestFileIngressFenceStoreRejectsLegacyOrInconsistentState(t *testing.T) {
	directory := restrictedTempDirectory(t)
	path := directory + "/ingress-fences.json"
	if err := os.WriteFile(path, []byte(`{"version":1,"host_revision":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileIngressFenceStore(directory, 4); !errors.Is(err, ErrInvalidIngressStore) {
		t.Fatalf("legacy state error = %v", err)
	}
}

func restrictedTempDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func ingressRoute(routeID string, revision uint64, deploymentID string, cutover uint64) agentprotocol.IngressRoute {
	alias, _ := agentprotocol.DeploymentBackendAlias(deploymentID)
	return agentprotocol.IngressRoute{RouteID: routeID, Revision: revision,
		DeploymentID: deploymentID, CutoverSequence: cutover, RuntimeTargetID: "target-1",
		Hostname: routeID + ".example.com", BackendAlias: alias, BackendPort: 8080,
		TLSMode: agentprotocol.IngressTLSAutomatic}
}

func ingressCommand(t *testing.T, hostRevision uint64, routes []agentprotocol.IngressRoute) agentprotocol.IngressCommand {
	t.Helper()
	digest, err := agentprotocol.IngressConfigDigest(hostRevision, routes)
	if err != nil {
		t.Fatal(err)
	}
	return agentprotocol.IngressCommand{HostRevision: hostRevision, ConfigDigest: digest, Routes: routes}
}
