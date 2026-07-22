package data

import (
	"context"
	"strings"
	"sync"

	"github.com/owndock/owndock/internal/modules/environment/biz"
)

type MemoryRepository struct {
	mu    sync.RWMutex
	items []biz.Environment
}

func NewMemoryRepository() *MemoryRepository { return &MemoryRepository{} }

func (r *MemoryRepository) List(context.Context) ([]biz.Environment, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	items := make([]biz.Environment, len(r.items))
	copy(items, r.items)
	return items, nil
}

func (r *MemoryRepository) Create(_ context.Context, item biz.Environment) (biz.Environment, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.items {
		if strings.EqualFold(existing.Name, item.Name) {
			return biz.Environment{}, biz.ErrDuplicateName
		}
	}
	r.items = append(r.items, item)
	return item, nil
}

func (r *MemoryRepository) Find(_ context.Context, id string) (biz.Environment, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, item := range r.items {
		if item.ID == id {
			return item, nil
		}
	}
	return biz.Environment{}, biz.ErrNotFound
}
