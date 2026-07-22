package data

import (
	"context"
	"sync"

	"github.com/owndock/owndock/internal/modules/application/biz"
)

type MemoryRepository struct {
	mu    sync.RWMutex
	items []biz.Application
}

func NewMemoryRepository() *MemoryRepository { return &MemoryRepository{} }

func (r *MemoryRepository) List(context.Context) ([]biz.Application, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	items := make([]biz.Application, len(r.items))
	copy(items, r.items)
	return items, nil
}

func (r *MemoryRepository) Create(_ context.Context, item biz.Application) (biz.Application, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.items = append(r.items, item)
	return item, nil
}
