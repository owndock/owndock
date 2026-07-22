package biz

import (
	"context"
	"time"
)

type IDGenerator func() (string, error)

type Clock func() time.Time

type UseCase struct {
	repo  Repository
	newID IDGenerator
	now   Clock
}

func NewUseCase(repo Repository, newID IDGenerator, now Clock) *UseCase {
	return &UseCase{repo: repo, newID: newID, now: now}
}

func (u *UseCase) List(ctx context.Context) ([]Application, error) {
	return u.repo.List(ctx)
}

func (u *UseCase) Create(ctx context.Context, name string) (Application, error) {
	id, err := u.newID()
	if err != nil {
		return Application{}, err
	}
	item, err := New(name, id, u.now())
	if err != nil {
		return Application{}, err
	}
	return u.repo.Create(ctx, item)
}
