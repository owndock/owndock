package worker

import (
	"context"
	"errors"
	"testing"
	"time"
)

type retirementUseCaseStub struct {
	called chan int64
	err    error
}

func (s retirementUseCaseStub) ContinueRuntimeTargetRetirements(
	_ context.Context,
	limit int64,
) (int, error) {
	s.called <- limit
	return 0, s.err
}

func TestRuntimeTargetRetirementLoopRunsImmediatelyAndStops(t *testing.T) {
	called := make(chan int64, 1)
	observed := make(chan string, 1)
	loop, err := NewRuntimeTargetRetirementLoop(
		retirementUseCaseStub{called: called}, 16,
		time.Hour, time.Second, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	loop.WithObservability(func(result string, _ time.Duration) {
		observed <- result
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- loop.Run(ctx) }()
	select {
	case limit := <-called:
		if limit != 16 {
			t.Fatalf("limit = %d, want 16", limit)
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not run immediately")
	}
	select {
	case result := <-observed:
		if result != "success" {
			t.Fatalf("result = %q", result)
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not record poll")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not stop")
	}
}

func TestRuntimeTargetRetirementLoopReportsErrorsAndValidatesInput(t *testing.T) {
	failure := errors.New("failure")
	called := make(chan int64, 1)
	reported := make(chan error, 1)
	loop, err := NewRuntimeTargetRetirementLoop(
		retirementUseCaseStub{called: called, err: failure}, 1,
		time.Hour, time.Second, func(err error) { reported <- err },
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- loop.Run(ctx) }()
	<-called
	if err := <-reported; !errors.Is(err, failure) {
		t.Fatalf("reported error = %v", err)
	}
	cancel()
	<-done

	if _, err := NewRuntimeTargetRetirementLoop(
		nil, 0, 0, 0, nil,
	); !errors.Is(err, ErrInvalidRuntimeTargetRetirementWorker) {
		t.Fatalf("invalid input error = %v", err)
	}
}

func TestRuntimeTargetRetirementResultClassifiesFailures(t *testing.T) {
	for _, test := range []struct {
		err  error
		want string
	}{
		{err: context.DeadlineExceeded, want: "timeout"},
		{err: context.Canceled, want: "canceled"},
		{err: errors.New("failure"), want: "error"},
	} {
		if got := runtimeTargetRetirementResult(test.err); got != test.want {
			t.Fatalf("result for %v = %q, want %q", test.err, got, test.want)
		}
	}
}
