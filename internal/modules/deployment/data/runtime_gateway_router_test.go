package data

import (
	"context"
	"errors"
	"testing"

	"github.com/owndock/owndock/internal/modules/deployment/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
)

type gatewayProbe struct {
	called string
}

func (g *gatewayProbe) Prepare(context.Context, biz.ExecutionPlan, biz.RuntimeCredential) error {
	g.called = "prepare"
	return nil
}

func (g *gatewayProbe) Deploy(context.Context, biz.ExecutionPlan, biz.RuntimeCredential) error {
	g.called = "deploy"
	return nil
}

func (g *gatewayProbe) Cancel(context.Context, biz.ExecutionPlan, biz.RuntimeCredential) error {
	g.called = "cancel"
	return nil
}

func (g *gatewayProbe) RemoveRuntime(context.Context, biz.ExecutionPlan, biz.RuntimeCredential) error {
	g.called = "remove"
	return nil
}

func (g *gatewayProbe) ReleaseCutoverWatermark(context.Context, biz.ExecutionPlan) error {
	g.called = "release"
	return nil
}

func TestRuntimeGatewayRouterDispatchesByConnectionMode(t *testing.T) {
	direct := &gatewayProbe{}
	router := NewRuntimeGatewayRouter(map[runtimeaccess.Mode]biz.RuntimeGateway{
		runtimeaccess.ModeDirectDocker: direct,
	})
	connection, err := runtimeaccess.NewDirectDocker(
		"", "tcp://docker.example.com:2376", "docker.example.com", "secret://runtime",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := router.Deploy(
		t.Context(),
		biz.ExecutionPlan{TargetConnection: connection},
		biz.RuntimeCredential{},
	); err != nil {
		t.Fatal(err)
	}
	if direct.called != "deploy" {
		t.Fatalf("called = %q", direct.called)
	}
}

func TestRuntimeGatewayRouterDispatchesLifecycleOperations(t *testing.T) {
	agent := &gatewayProbe{}
	router := NewRuntimeGatewayRouter(map[runtimeaccess.Mode]biz.RuntimeGateway{
		runtimeaccess.ModeAgent: agent,
	})
	connection, err := runtimeaccess.NewAgent("host-1")
	if err != nil {
		t.Fatal(err)
	}
	plan := biz.ExecutionPlan{TargetConnection: connection}
	if err := router.RemoveRuntime(
		t.Context(), plan, biz.RuntimeCredential{},
	); err != nil || agent.called != "remove" {
		t.Fatalf("remove = %q, %v", agent.called, err)
	}
	if err := router.ReleaseCutoverWatermark(
		t.Context(), plan,
	); err != nil || agent.called != "release" {
		t.Fatalf("release = %q, %v", agent.called, err)
	}
}

func TestRuntimeGatewayRouterRejectsMissingLifecycleGateway(t *testing.T) {
	connection, _ := runtimeaccess.NewAgent("host-1")
	router := NewRuntimeGatewayRouter(map[runtimeaccess.Mode]biz.RuntimeGateway{
		runtimeaccess.ModeAgent: runtimeOnlyGateway{},
	})
	err := router.RemoveRuntime(
		t.Context(), biz.ExecutionPlan{TargetConnection: connection},
		biz.RuntimeCredential{},
	)
	var executionError *biz.ExecutionError
	if !errors.As(err, &executionError) ||
		executionError.Category != biz.FailureUnsupportedTarget {
		t.Fatalf("error = %v", err)
	}
}

type runtimeOnlyGateway struct{}

func (runtimeOnlyGateway) Prepare(context.Context, biz.ExecutionPlan, biz.RuntimeCredential) error {
	return nil
}
func (runtimeOnlyGateway) Deploy(context.Context, biz.ExecutionPlan, biz.RuntimeCredential) error {
	return nil
}
func (runtimeOnlyGateway) Cancel(context.Context, biz.ExecutionPlan, biz.RuntimeCredential) error {
	return nil
}

func TestRuntimeGatewayRouterRejectsUnavailableMode(t *testing.T) {
	router := NewRuntimeGatewayRouter(nil)
	connection, err := runtimeaccess.NewAgent("host-1")
	if err != nil {
		t.Fatal(err)
	}
	err = router.Prepare(
		t.Context(),
		biz.ExecutionPlan{TargetConnection: connection},
		biz.RuntimeCredential{},
	)
	var executionError *biz.ExecutionError
	if !errors.As(err, &executionError) ||
		executionError.Category != biz.FailureUnsupportedTarget {
		t.Fatalf("error = %v", err)
	}
}
