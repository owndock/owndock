package biz

import (
	"testing"
	"time"
)

func TestEnvironmentLifecycle(t *testing.T) {
	e, err := New("production", "docker", "env-1", time.Unix(0, 0))
	if err != nil || e.Status != StatusActive {
		t.Fatalf("environment = %+v, err = %v", e, err)
	}
	if err := e.Transition(StatusDraining); err != nil {
		t.Fatal(err)
	}
	if err := e.Transition(StatusDeleted); err != nil {
		t.Fatal(err)
	}
}
