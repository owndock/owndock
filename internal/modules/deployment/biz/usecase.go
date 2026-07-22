package biz

import (
	"context"
	"time"
)

type IDGenerator func() (string, error)

type Clock func() time.Time

type UseCase struct {
	repo         Repository
	applications ApplicationLookup
	environments EnvironmentLookup
	newID        IDGenerator
	now          Clock
}

func NewUseCase(
	repo Repository,
	applications ApplicationLookup,
	environments EnvironmentLookup,
	newID IDGenerator,
	now Clock,
) *UseCase {
	return &UseCase{
		repo: repo, applications: applications, environments: environments,
		newID: newID, now: now,
	}
}

func (u *UseCase) List(ctx context.Context, applicationID, environmentID string) ([]Deployment, error) {
	return u.repo.List(ctx, applicationID, environmentID)
}

func (u *UseCase) Create(ctx context.Context, applicationID, environmentID, revision string) (Deployment, error) {
	id, err := u.newID()
	if err != nil {
		return Deployment{}, err
	}
	item, err := New(applicationID, environmentID, revision, id, u.now())
	if err != nil {
		return Deployment{}, err
	}

	exists, err := u.applications.Exists(ctx, item.ApplicationID)
	if err != nil {
		return Deployment{}, err
	}
	if !exists {
		return Deployment{}, ErrApplicationNotFound
	}
	exists, err = u.environments.Exists(ctx, item.EnvironmentID)
	if err != nil {
		return Deployment{}, err
	}
	if !exists {
		return Deployment{}, ErrEnvironmentNotFound
	}
	return u.repo.Create(ctx, item)
}
