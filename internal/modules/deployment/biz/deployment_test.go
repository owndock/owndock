package biz

import (
	"errors"
	"strings"
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

func TestDeploymentCancelingLifecycle(t *testing.T) {
	d, err := New("app-1", "env-1", "main@abc", "dep-1", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Cancel(time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if d.Terminal() {
		t.Fatal("canceling deployment must not be terminal")
	}
	if err := d.Transition(StatusCanceled, time.Unix(2, 0)); err != nil {
		t.Fatal(err)
	}
	if !d.Terminal() {
		t.Fatal("canceled deployment must be terminal")
	}
}

func TestTerminalDeploymentCannotBeCanceled(t *testing.T) {
	d, err := New("app", "env", "rev", "dep", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Transition(StatusBuilding, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if err := d.Transition(StatusDeploying, time.Unix(2, 0)); err != nil {
		t.Fatal(err)
	}
	if err := d.Transition(StatusSucceeded, time.Unix(3, 0)); err != nil {
		t.Fatal(err)
	}
	if err := d.Cancel(time.Unix(4, 0)); err != ErrInvalidTransition {
		t.Fatalf("cancel terminal error = %v", err)
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

func TestFormalDeploymentPinsReferencesAndIdempotency(t *testing.T) {
	d, err := NewFormal("dep-1", "release-1", "app-1", "env-1", "target-1", "request-123", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if d.ReleaseID != "release-1" || d.RuntimeTargetID != "target-1" || d.IdempotencyKey != "request-123" {
		t.Fatalf("deployment references = %+v", d)
	}
	for _, invalid := range [][6]string{
		{"dep", "", "app", "env", "target", "key"},
		{"dep", "rel", "app", "env", "", "key"},
		{"dep", "rel", "app", "env", "target", ""},
	} {
		if _, err := NewFormal(invalid[0], invalid[1], invalid[2], invalid[3], invalid[4], invalid[5], time.Now()); err == nil {
			t.Errorf("invalid formal deployment %+v accepted", invalid)
		}
	}
	longKey := strings.Repeat("k", 129)
	if _, err := NewFormal("dep", "rel", "app", "env", "target", longKey, time.Now()); err != ErrInvalidIdempotencyKey {
		t.Fatalf("long idempotency key error = %v", err)
	}
}
