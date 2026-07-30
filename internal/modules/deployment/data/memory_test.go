package data

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/deployment/biz"
)

func createDeployment(t *testing.T, repo *MemoryRepository) biz.Deployment {
	t.Helper()
	item, err := biz.New("app-1", "env-1", "main@abc", "dep-1", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	item, err = repo.Create(t.Context(), item)
	if err != nil {
		t.Fatal(err)
	}
	return item
}

func TestClaimNextIsAtomic(t *testing.T) {
	repo := NewMemoryRepository()
	createDeployment(t, repo)

	now := time.Unix(10, 0)
	var claimed int
	var mu sync.Mutex
	var wait sync.WaitGroup
	for _, workerID := range []string{"worker-1", "worker-2"} {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, ok, err := repo.ClaimNext(t.Context(), biz.Claim{
				WorkerID: workerID, Now: now, ExpiresAt: now.Add(time.Minute),
			})
			if err != nil {
				t.Errorf("ClaimNext() error = %v", err)
				return
			}
			if ok {
				mu.Lock()
				claimed++
				mu.Unlock()
			}
		}()
	}
	wait.Wait()
	if claimed != 1 {
		t.Fatalf("claimed = %d, want 1", claimed)
	}
}

func TestExpiredLeaseCanBeReclaimedAndRejectsStaleSave(t *testing.T) {
	repo := NewMemoryRepository()
	createDeployment(t, repo)
	firstNow := time.Unix(10, 0)
	first, ok, err := repo.ClaimNext(t.Context(), biz.Claim{
		WorkerID: "worker-1", Now: firstNow, ExpiresAt: firstNow.Add(time.Minute),
	})
	if err != nil || !ok {
		t.Fatalf("first claim = %+v, %v, %v", first, ok, err)
	}

	secondNow := firstNow.Add(2 * time.Minute)
	second, ok, err := repo.ClaimNext(t.Context(), biz.Claim{
		WorkerID: "worker-2", Now: secondNow, ExpiresAt: secondNow.Add(time.Minute),
	})
	if err != nil || !ok {
		t.Fatalf("second claim = %+v, %v, %v", second, ok, err)
	}
	if second.Lease.Owner != "worker-2" || second.Lease.Generation != first.Lease.Generation+1 {
		t.Fatalf("first lease = %+v, second lease = %+v", first.Lease, second.Lease)
	}
	if err := repo.ValidateFence(
		t.Context(), second.ProjectID, second.ID, "worker-2",
		second.Lease.Generation, secondNow,
	); err != nil {
		t.Fatalf("validate current fence: %v", err)
	}
	if err := repo.ValidateFence(
		t.Context(), first.ProjectID, first.ID, "worker-1",
		first.Lease.Generation, secondNow,
	); !errors.Is(err, biz.ErrStaleExecution) {
		t.Fatalf("validate stale fence error = %v", err)
	}

	if _, err := repo.SaveClaimed(t.Context(), first, first.Version, "worker-1", secondNow); !errors.Is(err, biz.ErrConflict) {
		t.Fatalf("stale save error = %v, want conflict", err)
	}
}

func TestSaveClaimedRejectsExpiredLease(t *testing.T) {
	repo := NewMemoryRepository()
	createDeployment(t, repo)
	now := time.Unix(10, 0)
	item, _, err := repo.ClaimNext(t.Context(), biz.Claim{
		WorkerID: "worker-1", Now: now, ExpiresAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.SaveClaimed(t.Context(), item, item.Version, "worker-1", now.Add(2*time.Minute)); !errors.Is(err, biz.ErrLeaseExpired) {
		t.Fatalf("expired save error = %v", err)
	}
}

func TestFormalIdempotencyKeyIsUnique(t *testing.T) {
	repo := NewMemoryRepository()
	item, err := biz.NewFormal("dep-1", "project-1", "rel-1", "app-1", "env-1", "target-1", "request-1", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Create(t.Context(), item); err != nil {
		t.Fatal(err)
	}
	duplicate := item
	duplicate.ID = "dep-2"
	if _, err := repo.Create(t.Context(), duplicate); !errors.Is(err, biz.ErrDuplicateIdempotency) {
		t.Fatalf("duplicate key error = %v", err)
	}
	found, err := repo.GetByIdempotency(t.Context(), "project-1", "request-1")
	if err != nil || found.ID != "dep-1" {
		t.Fatalf("found = %+v, err = %v", found, err)
	}
	otherProject, err := biz.NewFormal(
		"dep-3", "project-2", "rel-1", "app-1", "env-1", "target-1", "request-1", time.Unix(1, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Create(t.Context(), otherProject); err != nil {
		t.Fatalf("same key in another project: %v", err)
	}
}

func TestCutoverSequenceIsMonotonicWithinDeploymentScope(t *testing.T) {
	repo := NewMemoryRepository()
	create := func(
		id, projectID, applicationID, environmentID, targetID string,
	) biz.Deployment {
		t.Helper()
		item, err := biz.NewFormal(
			id,
			projectID,
			"release-"+id,
			applicationID,
			environmentID,
			targetID,
			"request-"+id,
			time.Unix(1, 0),
		)
		if err != nil {
			t.Fatal(err)
		}
		item, err = repo.Create(t.Context(), item)
		if err != nil {
			t.Fatal(err)
		}
		return item
	}

	first := create("one", "project", "application", "environment", "target")
	second := create("two", "project", "application", "environment", "target")
	otherTarget := create(
		"other",
		"project",
		"application",
		"environment",
		"other-target",
	)
	if first.CutoverSequence != 1 || second.CutoverSequence != 2 {
		t.Fatalf(
			"same-scope sequences = %d, %d",
			first.CutoverSequence,
			second.CutoverSequence,
		)
	}
	if otherTarget.CutoverSequence != 1 {
		t.Fatalf(
			"independent target sequence = %d",
			otherTarget.CutoverSequence,
		)
	}
	now := time.Unix(2, 0)
	claimed, ok, err := repo.ClaimNext(t.Context(), biz.Claim{
		WorkerID:  "worker",
		Now:       now,
		ExpiresAt: now.Add(time.Minute),
	})
	if err != nil || !ok || claimed.ID != first.ID {
		t.Fatalf("claim first deployment = %+v, %t, %v", claimed, ok, err)
	}
	if err := repo.ValidateFence(
		t.Context(),
		claimed.ProjectID,
		claimed.ID,
		"worker",
		claimed.Lease.Generation,
		now,
	); !errors.Is(err, biz.ErrStaleExecution) {
		t.Fatalf("superseded deployment fence error = %v", err)
	}
}

func TestHasSucceededUsesCompleteDeploymentScope(t *testing.T) {
	repo := NewMemoryRepository()
	item, err := biz.NewFormal(
		"dep", "project", "release", "app", "env", "target", "key", time.Unix(1, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := item.Transition(biz.StatusPreparing, time.Unix(2, 0)); err != nil {
		t.Fatal(err)
	}
	if err := item.Transition(biz.StatusDeploying, time.Unix(3, 0)); err != nil {
		t.Fatal(err)
	}
	if err := item.Transition(biz.StatusSucceeded, time.Unix(4, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Create(t.Context(), item); err != nil {
		t.Fatal(err)
	}
	found, err := repo.HasSucceeded(t.Context(), "project", "release", "app", "env", "target")
	if err != nil || !found {
		t.Fatalf("exact successful deployment = %t, %v", found, err)
	}
	for name, values := range map[string][5]string{
		"project":     {"other", "release", "app", "env", "target"},
		"release":     {"project", "other", "app", "env", "target"},
		"application": {"project", "release", "other", "env", "target"},
		"environment": {"project", "release", "app", "other", "target"},
		"target":      {"project", "release", "app", "env", "other"},
	} {
		found, err := repo.HasSucceeded(
			t.Context(), values[0], values[1], values[2], values[3], values[4],
		)
		if err != nil || found {
			t.Errorf("%s mismatch result = %t, %v", name, found, err)
		}
	}
}
