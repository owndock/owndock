package data

import (
	"context"
	"errors"
	"testing"

	"github.com/owndock/owndock/internal/modules/controlplane/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
)

type runtimeTargetProbeStub struct {
	status biz.RuntimeTargetStatus
	called bool
}

func (p *runtimeTargetProbeStub) ProbeRuntimeTarget(
	context.Context,
	biz.RuntimeTarget,
) (biz.RuntimeTargetStatus, error) {
	p.called = true
	return p.status, nil
}

func TestRuntimeTargetProbeRouterDispatchesByConnectionMode(t *testing.T) {
	direct := &runtimeTargetProbeStub{status: biz.RuntimeTargetStatusReady}
	agent := &runtimeTargetProbeStub{status: biz.RuntimeTargetStatusUnreachable}
	router := NewRuntimeTargetProbeRouter(
		map[runtimeaccess.Mode]biz.RuntimeTargetProber{
			runtimeaccess.ModeDirectDocker: direct,
			runtimeaccess.ModeAgent:        agent,
		},
	)

	status, err := router.ProbeRuntimeTarget(
		t.Context(),
		biz.RuntimeTarget{ConnectionMode: runtimeaccess.ModeAgent},
	)
	if err != nil {
		t.Fatal(err)
	}
	if status != biz.RuntimeTargetStatusUnreachable ||
		!agent.called || direct.called {
		t.Fatalf(
			"status = %s, direct called = %v, Agent called = %v",
			status, direct.called, agent.called,
		)
	}
}

func TestRuntimeTargetProbeRouterRejectsUnavailableMode(t *testing.T) {
	router := NewRuntimeTargetProbeRouter(nil)
	_, err := router.ProbeRuntimeTarget(
		t.Context(),
		biz.RuntimeTarget{ConnectionMode: runtimeaccess.ModeAgent},
	)
	if !errors.Is(err, biz.ErrRuntimeTargetProbeUnavailable) {
		t.Fatalf("error = %v", err)
	}
}
