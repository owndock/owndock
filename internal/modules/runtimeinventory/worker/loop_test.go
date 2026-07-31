package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/runtimeinventory/biz"
)

func TestLoopReportsCollectionFailureAndStops(t *testing.T) {
	repository := &scheduleRepositoryStub{
		targets:   []biz.Target{testTarget(t)},
		available: true,
	}
	runner, err := NewRunner(
		repository,
		collectorStub{err: errors.New("unavailable")},
		"worker-1",
		time.Minute,
		time.Minute,
		time.Second,
		10,
		time.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	failures := make(chan error, 1)
	loop, err := NewLoop(
		runner,
		time.Millisecond,
		time.Second,
		2,
		func(err error) { failures <- err },
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- loop.Run(ctx) }()
	select {
	case err := <-failures:
		if err == nil {
			t.Fatal("error handler received nil")
		}
	case <-time.After(time.Second):
		t.Fatal("loop did not report collection failure")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("loop did not stop after cancellation")
	}
}

func TestNewLoopValidatesConcurrency(t *testing.T) {
	if _, err := NewLoop(nil, time.Second, time.Second, 1, nil); !errors.Is(
		err,
		ErrInvalidLoop,
	) {
		t.Fatalf("NewLoop(nil) error = %v", err)
	}
}
