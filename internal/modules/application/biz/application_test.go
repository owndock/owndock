package biz

import (
	"testing"
	"time"
)

func TestApplicationLifecycle(t *testing.T) {
	item, err := New("demo", "app-1", time.Unix(0, 0))
	if err != nil || item.Status != StatusPending {
		t.Fatalf("new application = %+v, err = %v", item, err)
	}
	if err := item.Transition(StatusReady); err != nil {
		t.Fatalf("transition to ready: %v", err)
	}
	if err := item.Transition(StatusPending); err != ErrInvalidStatusTransition {
		t.Fatalf("transition from ready error = %v", err)
	}
}
