package biz

import (
	"testing"
	"time"
)

func TestDeploymentLifecycle(t *testing.T) {
	d, err := New("app-1", "env-1", "main@abc", "dep-1", time.Unix(0, 0))
	if err != nil || d.Status != StatusQueued {
		t.Fatalf("deployment = %+v, err = %v", d, err)
	}
	for _, next := range []Status{StatusBuilding, StatusDeploying, StatusSucceeded} {
		if err := d.Transition(next); err != nil {
			t.Fatalf("transition to %s: %v", next, err)
		}
	}
}
