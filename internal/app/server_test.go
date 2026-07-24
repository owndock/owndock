package app

import (
	"context"
	"testing"
	"time"
)

func TestCleanupAfterStopUsesIndependentBoundedContext(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	cancel()

	called := false
	hook := cleanupAfterStop(time.Second, func(ctx context.Context) error {
		called = true
		if err := ctx.Err(); err != nil {
			t.Fatalf("cleanup context error = %v", err)
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("cleanup context has no deadline")
		}
		return nil
	})

	if err := hook(parent); err != nil {
		t.Fatalf("cleanup hook error = %v", err)
	}
	if !called {
		t.Fatal("cleanup was not called")
	}
}
