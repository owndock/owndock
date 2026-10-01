package worker

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type retirementProbe struct {
	calls atomic.Int32
	err   error
}

func (p *retirementProbe) ContinueRouteRetirements(context.Context, int64) (int, error) {
	p.calls.Add(1)
	return 0, p.err
}

func TestRetirementLoopRunsImmediatelyAndReportsErrors(t *testing.T) {
	probe := &retirementProbe{err: errors.New("probe")}
	reported := make(chan error, 1)
	loop, err := NewRetirementLoop(probe, 16, time.Hour, time.Second,
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
		t.Fatal("retirement loop did not run immediately")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRetirementLoopValidatesConfiguration(t *testing.T) {
	if _, err := NewRetirementLoop(nil, 0, 0, 0, nil); !errors.Is(err, ErrInvalidRetirementWorker) {
		t.Fatalf("NewRetirementLoop() error = %v", err)
	}
}
