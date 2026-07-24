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
	if second.Lease.Owner != "worker-2" {
		t.Fatalf("lease owner = %q", second.Lease.Owner)
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
	item, err := biz.NewFormal("dep-1", "rel-1", "app-1", "env-1", "target-1", "request-1", time.Unix(1, 0))
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
	found, err := repo.GetByIdempotency(t.Context(), "request-1")
	if err != nil || found.ID != "dep-1" {
		t.Fatalf("found = %+v, err = %v", found, err)
	}
}
