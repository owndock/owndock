package data

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/owndock/owndock/internal/modules/deployment/biz"
)

type MemoryRepository struct {
	mu               sync.RWMutex
	items            []biz.Deployment
	cutoverSequences map[string]uint64
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{
		cutoverSequences: make(map[string]uint64),
	}
}

func (r *MemoryRepository) List(ctx context.Context, projectID, applicationID, environmentID string) ([]biz.Deployment, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	items := make([]biz.Deployment, 0, len(r.items))
	for _, item := range r.items {
		if (projectID == "" || item.ProjectID == projectID) &&
			(applicationID == "" || item.ApplicationID == applicationID) &&
			(environmentID == "" || item.EnvironmentID == environmentID) {
			items = append(items, item)
		}
	}
	return items, nil
}

func (r *MemoryRepository) GetByIdempotency(ctx context.Context, projectID, key string) (biz.Deployment, error) {
	if err := ctx.Err(); err != nil {
		return biz.Deployment{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, item := range r.items {
		if item.ProjectID == projectID && item.IdempotencyKey == key {
			return item, nil
		}
	}
	return biz.Deployment{}, biz.ErrNotFound
}

func (r *MemoryRepository) Get(ctx context.Context, projectID, deploymentID string) (biz.Deployment, error) {
	if err := ctx.Err(); err != nil {
		return biz.Deployment{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, item := range r.items {
		if item.ProjectID == projectID && item.ID == deploymentID {
			return item, nil
		}
	}
	return biz.Deployment{}, biz.ErrNotFound
}

func (r *MemoryRepository) HasSucceeded(
	ctx context.Context,
	projectID, releaseID, applicationID, environmentID, runtimeTargetID string,
) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, item := range r.items {
		if item.ProjectID == projectID && item.ReleaseID == releaseID &&
			item.ApplicationID == applicationID && item.EnvironmentID == environmentID &&
			item.RuntimeTargetID == runtimeTargetID && item.Status == biz.StatusSucceeded {
			return true, nil
		}
	}
	return false, nil
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
		if item.IdempotencyKey != "" && existing.ProjectID == item.ProjectID && existing.IdempotencyKey == item.IdempotencyKey {
			return biz.Deployment{}, biz.ErrDuplicateIdempotency
		}
	}
	if item.Version == 0 {
		item.Version = 1
	}
	scope := item.CutoverScope()
	r.cutoverSequences[scope]++
	item.CutoverSequence = r.cutoverSequences[scope]
	r.items = append(r.items, item)
	return item, nil
}

func (r *MemoryRepository) Save(ctx context.Context, item biz.Deployment, expectedVersion uint64) (biz.Deployment, error) {
	if err := ctx.Err(); err != nil {
		return biz.Deployment{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.items {
		if r.items[i].ID != item.ID || r.items[i].ProjectID != item.ProjectID {
			continue
		}
		if r.items[i].Version != expectedVersion {
			return biz.Deployment{}, biz.ErrConflict
		}
		item.Version = expectedVersion + 1
		r.items[i] = item
		return item, nil
	}
	return biz.Deployment{}, biz.ErrNotFound
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
		if item.Status != biz.StatusQueued && item.Status != biz.StatusPreparing &&
			item.Status != biz.StatusDeploying && item.Status != biz.StatusCanceling {
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

func (r *MemoryRepository) RenewLease(ctx context.Context, deploymentID, workerID string, expectedVersion uint64, now, expiresAt time.Time) (biz.Deployment, error) {
	if err := ctx.Err(); err != nil {
		return biz.Deployment{}, err
	}
	if workerID == "" || !expiresAt.After(now) {
		return biz.Deployment{}, biz.ErrInvalidLease
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.items {
		item := &r.items[i]
		if item.ID != deploymentID {
			continue
		}
		if item.Version != expectedVersion || item.Lease.Owner != workerID || !item.Lease.Active(now) {
			return biz.Deployment{}, biz.ErrConflict
		}
		item.Lease.ExpiresAt = expiresAt.UTC()
		item.UpdatedAt = now.UTC()
		item.Version++
		return *item, nil
	}
	return biz.Deployment{}, biz.ErrNotFound
}

func (r *MemoryRepository) ValidateFence(
	ctx context.Context,
	projectID, deploymentID, workerID string,
	generation uint64,
	now time.Time,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, item := range r.items {
		if item.ID != deploymentID || item.ProjectID != projectID {
			continue
		}
		if item.Lease.Owner != workerID || item.Lease.Generation != generation ||
			!item.Lease.Active(now) || item.Terminal() ||
			r.cutoverSequences[item.CutoverScope()] != item.CutoverSequence {
			return biz.ErrStaleExecution
		}
		return nil
	}
	return biz.ErrStaleExecution
}
