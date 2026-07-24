package data

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/owndock/owndock/internal/modules/deployment/biz"
)

type MemoryRepository struct {
	mu    sync.RWMutex
	items []biz.Deployment
}

func NewMemoryRepository() *MemoryRepository { return &MemoryRepository{} }

func (r *MemoryRepository) List(ctx context.Context, applicationID, environmentID string) ([]biz.Deployment, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	items := make([]biz.Deployment, 0, len(r.items))
	for _, item := range r.items {
		if (applicationID == "" || item.ApplicationID == applicationID) && (environmentID == "" || item.EnvironmentID == environmentID) {
			items = append(items, item)
		}
	}
	return items, nil
}

func (r *MemoryRepository) Create(ctx context.Context, item biz.Deployment) (biz.Deployment, error) {
	if err := ctx.Err(); err != nil {
		return biz.Deployment{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.items {
		if existing.ID == item.ID {
			return biz.Deployment{}, biz.ErrConflict
		}
	}
	if item.Version == 0 {
		item.Version = 1
	}
	r.items = append(r.items, item)
	return item, nil
}

func (r *MemoryRepository) ClaimNext(ctx context.Context, claim biz.Claim) (biz.Deployment, bool, error) {
	if err := ctx.Err(); err != nil {
		return biz.Deployment{}, false, err
	}
	if err := claim.Validate(); err != nil {
		return biz.Deployment{}, false, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.items {
		item := r.items[i]
		if item.Status != biz.StatusQueued &&
			(item.Status != biz.StatusBuilding && item.Status != biz.StatusDeploying) {
			continue
		}
		if err := item.Acquire(claim); err != nil {
			if err == biz.ErrNotClaimable {
				continue
			}
			return biz.Deployment{}, false, err
		}
		item.Version = r.items[i].Version + 1
		r.items[i] = item
		return item, true, nil
	}
	return biz.Deployment{}, false, nil
}

func (r *MemoryRepository) SaveClaimed(
	ctx context.Context,
	item biz.Deployment,
	expectedVersion uint64,
	workerID string,
	now time.Time,
) (biz.Deployment, error) {
	if err := ctx.Err(); err != nil {
		return biz.Deployment{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.items {
		current := r.items[i]
		if current.ID != item.ID {
			continue
		}
		if current.Version != expectedVersion {
			return biz.Deployment{}, biz.ErrConflict
		}
		if strings.TrimSpace(workerID) == "" || current.Lease.Owner != workerID {
			return biz.Deployment{}, biz.ErrConflict
		}
		if !current.Lease.Active(now) {
			return biz.Deployment{}, biz.ErrLeaseExpired
		}
		if !item.Terminal() && item.Lease.Owner != workerID {
			return biz.Deployment{}, biz.ErrConflict
		}
		item.Version = current.Version + 1
		r.items[i] = item
		return item, nil
	}
	return biz.Deployment{}, biz.ErrNotFound
}
