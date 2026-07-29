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
