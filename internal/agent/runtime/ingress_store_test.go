package agentruntime

import (
	"errors"
	"os"
	"testing"

	"github.com/owndock/owndock/internal/shared/agentprotocol"
)

func TestFileIngressFenceStorePersistsHostAndRouteFences(t *testing.T) {
	directory := restrictedTempDirectory(t)
	store, err := NewFileIngressFenceStore(directory, 4)
	if err != nil {
		t.Fatal(err)
	}
	first := ingressCommand(t, 1, []agentprotocol.IngressRoute{ingressRoute("route-1", 1, "deployment-1", 1)})
	if idempotent, err := store.Check(first); err != nil || idempotent {
		t.Fatalf("first Check() = %t, %v", idempotent, err)
	}
	if err := store.Commit(first); err != nil {
		t.Fatal(err)
	}
	if idempotent, err := store.Check(first); err != nil || !idempotent {
		t.Fatalf("replay Check() = %t, %v", idempotent, err)
	}

	reloaded, err := NewFileIngressFenceStore(directory, 4)
	if err != nil {
		t.Fatal(err)
	}
	if idempotent, err := reloaded.Check(first); err != nil || !idempotent {
		t.Fatalf("reloaded Check() = %t, %v", idempotent, err)
	}
	removed := ingressCommand(t, 2, nil)
	if err := reloaded.Commit(removed); err != nil {
		t.Fatal(err)
	}
	delayed := ingressCommand(t, 3, []agentprotocol.IngressRoute{ingressRoute("route-1", 1, "deployment-1", 1)})
	if _, err := reloaded.Check(delayed); !errors.Is(err, ErrIngressFenceConflict) {
		t.Fatalf("delayed removed route error = %v", err)
	}
}

func TestFileIngressFenceStoreRejectsStaleAndConflictingUpdates(t *testing.T) {
	store, err := NewFileIngressFenceStore(restrictedTempDirectory(t), 2)
	if err != nil {
		t.Fatal(err)
	}
	first := ingressCommand(t, 5, []agentprotocol.IngressRoute{ingressRoute("route-1", 2, "deployment-2", 8)})
	if err := store.Commit(first); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Check(ingressCommand(t, 4, first.Routes)); !errors.Is(err, ErrIngressFenceStale) {
		t.Fatalf("old host revision error = %v", err)
	}
	oldRoute := ingressRoute("route-1", 1, "deployment-3", 9)
	if _, err := store.Check(ingressCommand(t, 6, []agentprotocol.IngressRoute{oldRoute})); !errors.Is(err, ErrIngressFenceStale) {
		t.Fatalf("old route revision error = %v", err)
	}
	conflictingDeployment := ingressRoute("route-1", 2, "other-deployment", 8)
	if _, err := store.Check(ingressCommand(t, 6, []agentprotocol.IngressRoute{conflictingDeployment})); !errors.Is(err, ErrIngressFenceConflict) {
		t.Fatalf("same cutover conflict error = %v", err)
	}
	changedSpec := ingressRoute("route-1", 2, "deployment-3", 9)
	changedSpec.Hostname = "changed.example.com"
	if _, err := store.Check(ingressCommand(t, 6, []agentprotocol.IngressRoute{changedSpec})); !errors.Is(err, ErrIngressFenceConflict) {
		t.Fatalf("same revision spec conflict error = %v", err)
	}
	valid := ingressRoute("route-1", 3, "deployment-3", 9)
	if err := store.Commit(ingressCommand(t, 6, []agentprotocol.IngressRoute{valid})); err != nil {
		t.Fatalf("new revision and cutover rejected: %v", err)
	}
	full := []agentprotocol.IngressRoute{valid, ingressRoute("route-2", 1, "deployment-4", 1),
		ingressRoute("route-3", 1, "deployment-5", 1)}
	if _, err := store.Check(ingressCommand(t, 7, full)); !errors.Is(err, ErrIngressStoreFull) {
		t.Fatalf("capacity error = %v", err)
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
	return agentprotocol.IngressRoute{RouteID: routeID, Revision: revision,
		DeploymentID: deploymentID, CutoverSequence: cutover, RuntimeTargetID: "target-1",
		Hostname: routeID + ".example.com", BackendAlias: deploymentID, BackendPort: 8080,
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
