package agentruntime

import (
	"context"
	"errors"
	"testing"

	"github.com/owndock/owndock/internal/shared/agentprotocol"
)

func TestIngressExecutorPreparesCommitsAndReplaysActualGateway(t *testing.T) {
	store, err := NewFileIngressFenceStore(restrictedTempDirectory(t), 4)
	if err != nil {
		t.Fatal(err)
	}
	command := ingressCommand(t, 1, []agentprotocol.IngressRoute{
		ingressRoute("route-1", 1, "deployment-1", 1),
	})
	gateway := &ingressGatewayStub{digest: command.ConfigDigest}
	executor, err := NewIngressExecutor(store, gateway)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := executor.Prepare(t.Context(), command)
	if err != nil || prepared.HostRevision != 1 {
		t.Fatalf("Prepare() = %#v, %v", prepared, err)
	}
	if _, exists := store.Committed(); exists {
		t.Fatal("prepare advanced committed fence")
	}
	committed, err := executor.Commit(t.Context(), command)
	if err != nil || committed.ConfigDigest != command.ConfigDigest {
		t.Fatalf("Commit() = %#v, %v", committed, err)
	}
	if _, err := executor.Commit(t.Context(), command); err != nil {
		t.Fatal(err)
	}
	if gateway.calls != 3 {
		t.Fatalf("gateway calls = %d, want prepare + commit + replay", gateway.calls)
	}
}

func TestIngressExecutorRestoresCommittedConfigOnAbortAndPrepareFailure(t *testing.T) {
	store, err := NewFileIngressFenceStore(restrictedTempDirectory(t), 4)
	if err != nil {
		t.Fatal(err)
	}
	first := ingressCommand(t, 1, []agentprotocol.IngressRoute{
		ingressRoute("route-1", 1, "deployment-1", 1),
	})
	gateway := &ingressGatewayStub{digest: first.ConfigDigest}
	executor, err := NewIngressExecutor(store, gateway)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Prepare(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Commit(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	second := ingressCommand(t, 2, []agentprotocol.IngressRoute{
		ingressRoute("route-1", 2, "deployment-2", 2),
	})
	gateway.digest = second.ConfigDigest
	if _, err := executor.Prepare(t.Context(), second); err != nil {
		t.Fatal(err)
	}
	gateway.digestByRevision = map[uint64]string{1: first.ConfigDigest}
	if _, err := executor.Abort(t.Context(), second); err != nil {
		t.Fatal(err)
	}
	if gateway.last.HostRevision != first.HostRevision {
		t.Fatalf("abort restored revision %d", gateway.last.HostRevision)
	}

	third := ingressCommand(t, 3, []agentprotocol.IngressRoute{
		ingressRoute("route-1", 3, "deployment-3", 3),
	})
	gateway.errByRevision = map[uint64]error{3: ErrIngressGatewayUnavailable}
	if _, err := executor.Prepare(t.Context(), third); !errors.Is(err, ErrIngressGatewayUnavailable) {
		t.Fatalf("prepare failure = %v", err)
	}
	if already, err := store.CanAbort(third); err != nil || !already {
		t.Fatalf("failed prepare pending state = %t, %v", already, err)
	}
	fourth := ingressCommand(t, 4, []agentprotocol.IngressRoute{
		ingressRoute("route-1", 4, "deployment-4", 4),
	})
	fourth.ProbeRouteIDs = []string{"route-1"}
	gateway.errByRevision = nil
	gateway.digestByRevision[4] = fourth.ConfigDigest
	gateway.probeErr = ErrIngressBackendUnhealthy
	if _, err := executor.Prepare(t.Context(), fourth); !errors.Is(err, ErrIngressBackendUnhealthy) {
		t.Fatalf("private probe failure = %v", err)
	}
	committed, exists := store.Committed()
	if !exists || !sameIngressConfig(committed, first) {
		t.Fatalf("private probe failure changed committed config = %#v, %t", committed, exists)
	}
}

func TestIngressExecutorClearsGatewayWhenFirstPrepareIsAborted(t *testing.T) {
	store, err := NewFileIngressFenceStore(restrictedTempDirectory(t), 4)
	if err != nil {
		t.Fatal(err)
	}
	command := ingressCommand(t, 1, []agentprotocol.IngressRoute{
		ingressRoute("route-1", 1, "deployment-1", 1),
	})
	gateway := &ingressGatewayStub{digest: command.ConfigDigest}
	executor, err := NewIngressExecutor(store, gateway)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Prepare(t.Context(), command); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Abort(t.Context(), command); err != nil || gateway.clears != 1 {
		t.Fatalf("Abort() error/clears = %v/%d", err, gateway.clears)
	}
}

type ingressGatewayStub struct {
	digest           string
	digestByRevision map[uint64]string
	errByRevision    map[uint64]error
	calls            int
	clears           int
	last             agentprotocol.IngressCommand
	probeErr         error
	probes           int
}

func (g *ingressGatewayStub) Probe(context.Context, agentprotocol.IngressCommand) error {
	g.probes++
	return g.probeErr
}

func (g *ingressGatewayStub) Apply(_ context.Context, command agentprotocol.IngressCommand) (string, error) {
	g.calls++
	g.last = command
	if err := g.errByRevision[command.HostRevision]; err != nil {
		return "", err
	}
	if digest := g.digestByRevision[command.HostRevision]; digest != "" {
		return digest, nil
	}
	return g.digest, nil
}

func (g *ingressGatewayStub) Clear(context.Context) error {
	g.clears++
	return nil
}
