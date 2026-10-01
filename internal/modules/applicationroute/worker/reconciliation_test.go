package worker

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type reconciliationProbe struct {
	calls atomic.Int32
	err   error
}

func (p *reconciliationProbe) ContinueRouteReconciliations(context.Context, int64) (int, error) {
	p.calls.Add(1)
	return 0, p.err
}

func TestReconciliationLoopRunsImmediatelyAndReportsErrors(t *testing.T) {
	probe := &reconciliationProbe{err: errors.New("probe")}
	reported := make(chan error, 1)
	loop, err := NewReconciliationLoop(probe, 16, time.Hour, time.Second,
		func(err error) { reported <- err })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- loop.Run(ctx) }()
	select {
	case err := <-reported:
		if err == nil || probe.calls.Load() != 1 {
			t.Fatalf("reported error = %v, calls = %d", err, probe.calls.Load())
		}
	case <-time.After(time.Second):
		t.Fatal("reconciliation loop did not run immediately")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestReconciliationLoopValidatesConfiguration(t *testing.T) {
	if _, err := NewReconciliationLoop(nil, 0, 0, 0, nil); !errors.Is(err, ErrInvalidReconciliationWorker) {
		t.Fatalf("NewReconciliationLoop() error = %v", err)
	}
}
