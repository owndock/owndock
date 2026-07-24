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
	releases     ReleaseLookup
	targets      RuntimeTargetLookup
	newID        IDGenerator
	now          Clock
}

type ReleaseLookup interface {
	Exists(context.Context, string) (bool, error)
}
type RuntimeTargetLookup interface {
	Exists(context.Context, string) (bool, error)
}

func (u *UseCase) WithFormalLookups(releases ReleaseLookup, targets RuntimeTargetLookup) *UseCase {
	u.releases, u.targets = releases, targets
	return u
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
	if u.releases != nil {
		exists, err = u.releases.Exists(ctx, item.ReleaseID)
		if err != nil {
			return Deployment{}, err
		}
		if !exists {
			return Deployment{}, ErrNotFound
		}
	}
	if u.targets != nil {
		exists, err = u.targets.Exists(ctx, item.RuntimeTargetID)
		if err != nil {
			return Deployment{}, err
		}
		if !exists {
			return Deployment{}, ErrNotFound
		}
	}
	created, err := u.repo.Create(ctx, item)
	if err == ErrDuplicateIdempotency {
		return u.repo.GetByIdempotency(ctx, item.IdempotencyKey)
	}
	return created, err
}

// CreateFormal persists a product deployment with immutable release and target
// references. The repository enforces idempotency uniqueness; execution is
// deliberately handled by the worker layer.
func (u *UseCase) CreateFormal(ctx context.Context, releaseID, applicationID, environmentID, runtimeTargetID, idempotencyKey string) (Deployment, error) {
	id, err := u.newID()
	if err != nil {
		return Deployment{}, err
	}
	item, err := NewFormal(id, releaseID, applicationID, environmentID, runtimeTargetID, idempotencyKey, u.now())
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
