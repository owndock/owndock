package biz

import (
	"errors"
	"testing"
	"time"
)

func TestDeploymentLifecycle(t *testing.T) {
	d, err := New("app-1", "env-1", "main@abc", "dep-1", time.Unix(0, 0))
	if err != nil || d.Status != StatusQueued {
		t.Fatalf("deployment = %+v, err = %v", d, err)
	}
	for _, next := range []Status{StatusBuilding, StatusDeploying, StatusSucceeded} {
		if err := d.Transition(next, time.Unix(1, 0)); err != nil {
			t.Fatalf("transition to %s: %v", next, err)
		}
	}
}

func TestDeploymentLease(t *testing.T) {
	now := time.Unix(10, 0)
	d, err := New(" app-1 ", " env-1 ", "main@abc", "dep-1", now)
	if err != nil {
		t.Fatal(err)
	}
	claim := Claim{WorkerID: "worker-1", Now: now, ExpiresAt: now.Add(time.Minute)}
	if err := d.Acquire(claim); err != nil {
		t.Fatal(err)
	}
	if d.Status != StatusBuilding || d.Lease.Owner != "worker-1" {
		t.Fatalf("claimed deployment = %+v", d)
	}
	if err := d.Acquire(Claim{WorkerID: "worker-2", Now: now.Add(time.Second), ExpiresAt: now.Add(time.Minute)}); !errors.Is(err, ErrNotClaimable) {
		t.Fatalf("active lease acquire error = %v", err)
	}
	if err := d.Acquire(Claim{WorkerID: "worker-2", Now: now.Add(2 * time.Minute), ExpiresAt: now.Add(3 * time.Minute)}); err != nil {
		t.Fatalf("expired lease acquire: %v", err)
	}
	if d.Lease.Owner != "worker-2" {
		t.Fatalf("lease owner = %q", d.Lease.Owner)
	}
}
