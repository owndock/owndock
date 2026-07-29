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
	for _, next := range []Status{StatusPreparing, StatusDeploying, StatusSucceeded} {
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
	if err := d.Transition(StatusPreparing, time.Unix(1, 0)); err != nil {
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

func TestDeploymentFailureStoresOnlyCategory(t *testing.T) {
	deployment, err := New("app", "env", "", "deployment", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := deployment.Transition(StatusPreparing, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if err := deployment.Fail(FailureImagePull, time.Unix(2, 0)); err != nil {
		t.Fatal(err)
	}
	if deployment.Status != StatusFailed || deployment.FailureCategory != FailureImagePull {
		t.Fatalf("deployment = %+v", deployment)
	}
}

func TestDeploymentRetryCreatesNewOperation(t *testing.T) {
	d, err := NewFormal("dep-1", "project-1", "rel-1", "app-1", "env-1", "target-1", "key-1", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Transition(StatusPreparing, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if err := d.Transition(StatusFailed, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	retry, err := d.Retry("dep-2", "key-2", time.Unix(2, 0))
	if err != nil {
		t.Fatal(err)
	}
	if retry.ID == d.ID || retry.Status != StatusQueued || retry.ReleaseID != d.ReleaseID ||
		retry.IdempotencyKey == d.IdempotencyKey || retry.Operation != OperationRetry ||
		retry.SourceDeploymentID != d.ID {
		t.Fatalf("retry = %+v", retry)
	}
}

func TestDeploymentRollbackTargetsNewRelease(t *testing.T) {
	d, err := NewFormal("dep-1", "project-1", "rel-current", "app-1", "env-1", "target-1", "key-1", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Transition(StatusPreparing, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if err := d.Transition(StatusDeploying, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if err := d.Transition(StatusSucceeded, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	rollback, err := d.Rollback("dep-2", "rel-known-good", "key-2", time.Unix(2, 0))
	if err != nil {
		t.Fatal(err)
	}
	if rollback.ReleaseID != "rel-known-good" || rollback.Status != StatusQueued ||
		rollback.ApplicationID != d.ApplicationID || rollback.Operation != OperationRollback ||
		rollback.SourceDeploymentID != d.ID {
		t.Fatalf("rollback = %+v", rollback)
	}
}

func TestDeploymentDerivedOperationsRequireValidSourceState(t *testing.T) {
	d, err := NewFormal("dep", "project", "rel", "app", "env", "target", "key", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Retry("retry", "retry-key", time.Unix(2, 0)); err != ErrRetryRequiresFailed {
		t.Fatalf("queued retry error = %v", err)
	}
	if _, err := d.Rollback("rollback", "old-rel", "rollback-key", time.Unix(2, 0)); err != ErrRollbackRequiresFinal {
		t.Fatalf("queued rollback error = %v", err)
	}
	if err := d.Transition(StatusPreparing, time.Unix(2, 0)); err != nil {
		t.Fatal(err)
	}
	if err := d.Transition(StatusDeploying, time.Unix(3, 0)); err != nil {
		t.Fatal(err)
	}
	if err := d.Transition(StatusSucceeded, time.Unix(4, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Rollback("rollback", "rel", "rollback-key", time.Unix(5, 0)); err != ErrRollbackSameRelease {
		t.Fatalf("same-release rollback error = %v", err)
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
	if d.Status != StatusQueued || d.Lease.Owner != "worker-1" || d.Lease.Generation != 1 {
		t.Fatalf("claimed deployment = %+v", d)
	}
	if err := d.Acquire(Claim{WorkerID: "worker-2", Now: now.Add(time.Second), ExpiresAt: now.Add(time.Minute)}); !errors.Is(err, ErrNotClaimable) {
		t.Fatalf("active lease acquire error = %v", err)
	}
	if err := d.Acquire(Claim{WorkerID: "worker-2", Now: now.Add(2 * time.Minute), ExpiresAt: now.Add(3 * time.Minute)}); err != nil {
		t.Fatalf("expired lease acquire: %v", err)
	}
	if d.Lease.Owner != "worker-2" || d.Lease.Generation != 2 {
		t.Fatalf("lease = %+v", d.Lease)
	}
}

func TestFormalDeploymentPinsReferencesAndIdempotency(t *testing.T) {
	d, err := NewFormal("dep-1", "project-1", "release-1", "app-1", "env-1", "target-1", "request-123", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if d.ReleaseID != "release-1" || d.RuntimeTargetID != "target-1" ||
		d.IdempotencyKey != "request-123" || d.Operation != OperationDeploy {
		t.Fatalf("deployment references = %+v", d)
	}
	for _, invalid := range [][7]string{
		{"dep", "", "rel", "app", "env", "target", "key"},
		{"dep", "project", "", "app", "env", "target", "key"},
		{"dep", "project", "rel", "app", "env", "", "key"},
		{"dep", "project", "rel", "app", "env", "target", ""},
	} {
		if _, err := NewFormal(invalid[0], invalid[1], invalid[2], invalid[3], invalid[4], invalid[5], invalid[6], time.Now()); err == nil {
			t.Errorf("invalid formal deployment %+v accepted", invalid)
		}
	}
	longKey := strings.Repeat("k", 129)
	if _, err := NewFormal("dep", "project", "rel", "app", "env", "target", longKey, time.Now()); err != ErrInvalidIdempotencyKey {
		t.Fatalf("long idempotency key error = %v", err)
	}
}
