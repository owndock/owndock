package worker

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type productResourceRetirementLoopProbe struct {
	calls atomic.Int64
	err   error
}

func (p *productResourceRetirementLoopProbe) ContinueProductResourceRetirements(
	context.Context, int64,
) (int, error) {
	p.calls.Add(1)
	return 0, p.err
}

func TestProductResourceRetirementLoopRunsImmediately(t *testing.T) {
	probe := &productResourceRetirementLoopProbe{}
	loop, err := NewProductResourceRetirementLoop(
		probe, 10, time.Hour, time.Second, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- loop.Run(ctx) }()
	deadline := time.Now().Add(time.Second)
	for probe.calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v", err)
	}
	if probe.calls.Load() == 0 {
		t.Fatal("worker did not poll immediately")
	}
}

func TestProductResourceRetirementLoopValidatesInputAndReportsErrors(t *testing.T) {
	if _, err := NewProductResourceRetirementLoop(nil, 0, 0, 0, nil); !errors.Is(err, ErrInvalidProductResourceRetirementWorker) {
		t.Fatalf("constructor error = %v", err)
	}
	probeError := errors.New("poll failed")
	probe := &productResourceRetirementLoopProbe{err: probeError}
	reported := make(chan error, 1)
	loop, err := NewProductResourceRetirementLoop(
		probe, 1, time.Hour, time.Second,
		func(err error) { reported <- err },
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- loop.Run(ctx) }()
	select {
	case err := <-reported:
		if !errors.Is(err, probeError) {
			t.Fatalf("reported error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("worker error was not reported")
	}
	cancel()
	<-done
}
