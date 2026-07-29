package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/deployment/biz"
	"github.com/owndock/owndock/internal/modules/deployment/data"
)

func TestLoopRunsUntilCanceledAndReportsSafeExecutionError(t *testing.T) {
	repository := data.NewMemoryRepository()
	item, err := biz.New("app", "env", "", "deployment", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Create(t.Context(), item); err != nil {
		t.Fatal(err)
	}
	runner, err := NewRunner(
		repository,
		failingExecutor{},
		"worker",
		time.Second,
		time.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	reported := make(chan error, 1)
	loop, err := NewLoop(runner, 5*time.Millisecond, time.Second, func(err error) {
		select {
		case reported <- err:
		default:
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- loop.Run(ctx) }()
	select {
	case err := <-reported:
		var executionError *biz.ExecutionError
		if !errors.As(err, &executionError) || executionError.Category != biz.FailureConfiguration {
			t.Fatalf("reported error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("worker error was not reported")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestNewLoopValidatesConfiguration(t *testing.T) {
	if _, err := NewLoop(nil, time.Second, time.Second, nil); !errors.Is(err, ErrMissingRunner) {
		t.Fatalf("missing runner error = %v", err)
	}
}
