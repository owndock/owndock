package agentruntime

import (
	"context"
	"errors"
	"testing"

	"github.com/owndock/owndock/internal/shared/agentprotocol"
)

func TestIngressExecutorCommitsOnlyMatchingAppliedConfig(t *testing.T) {
	store, err := NewFileIngressFenceStore(restrictedTempDirectory(t), 4)
	if err != nil {
		t.Fatal(err)
	}
	command := ingressCommand(t, 1, []agentprotocol.IngressRoute{ingressRoute("route-1", 1, "deployment-1", 1)})
	gateway := &ingressGatewayStub{digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	executor, err := NewIngressExecutor(store, gateway)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Reconcile(context.Background(), command); !errors.Is(err, ErrIngressConfiguration) {
		t.Fatalf("mismatched digest error = %v", err)
	}
	gateway.digest = command.ConfigDigest
	result, err := executor.Reconcile(context.Background(), command)
	if err != nil || result.HostRevision != 1 || result.ConfigDigest != command.ConfigDigest {
		t.Fatalf("Reconcile() = %#v, %v", result, err)
	}
	if _, err := executor.Reconcile(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	if gateway.calls != 3 {
		t.Fatalf("gateway calls = %d, want mismatch + committed apply + reconciliation", gateway.calls)
	}
}

type ingressGatewayStub struct {
	digest string
	err    error
	calls  int
}

func (g *ingressGatewayStub) Apply(context.Context, agentprotocol.IngressCommand) (string, error) {
	g.calls++
	return g.digest, g.err
}
