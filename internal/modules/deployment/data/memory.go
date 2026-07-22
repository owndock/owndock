package data

import (
	"context"
	"errors"
	"sync"

	"github.com/owndock/owndock/internal/modules/deployment/biz"
)

var ErrNotFound = errors.New("deployment not found")

type MemoryRepository struct {
	mu    sync.RWMutex
	items []biz.Deployment
}

func NewMemoryRepository() *MemoryRepository { return &MemoryRepository{} }

func (r *MemoryRepository) List(_ context.Context, applicationID, environmentID string) ([]biz.Deployment, error) {
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

func (r *MemoryRepository) Create(_ context.Context, item biz.Deployment) (biz.Deployment, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.items = append(r.items, item)
	return item, nil
}

func (r *MemoryRepository) Update(_ context.Context, item biz.Deployment) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.items {
		if r.items[i].ID == item.ID {
			r.items[i] = item
			return nil
		}
	}
	return ErrNotFound
}
