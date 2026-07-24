package worker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/modules/deployment/biz"
)

var (
	ErrMissingRepository   = errors.New("deployment repository is required")
	ErrMissingExecutor     = errors.New("deployment executor is required")
	ErrInvalidWorkerID     = errors.New("worker id is required")
	ErrInvalidLeaseTimeout = errors.New("lease duration must be greater than zero")
	ErrMissingClock        = errors.New("worker clock is required")
)

// Runner claims one deployment atomically and executes its current delivery
// step. Executor operations must be idempotent for a deployment ID because an
// expired lease can be reclaimed after an interrupted process.
type Runner struct {
	repo          biz.Repository
	executor      Executor
	workerID      string
	leaseDuration time.Duration
	now           func() time.Time
}

type Executor interface {
	Build(context.Context, biz.Deployment) error
	Deploy(context.Context, biz.Deployment) error
}

func NewRunner(
	repo biz.Repository,
	executor Executor,
	workerID string,
	leaseDuration time.Duration,
	now func() time.Time,
) (*Runner, error) {
	if repo == nil {
		return nil, ErrMissingRepository
	}
	if executor == nil {
		return nil, ErrMissingExecutor
	}
	if strings.TrimSpace(workerID) == "" {
		return nil, ErrInvalidWorkerID
	}
	if leaseDuration <= 0 {
		return nil, ErrInvalidLeaseTimeout
	}
	if now == nil {
		return nil, ErrMissingClock
	}
	return &Runner{
		repo:          repo,
		executor:      executor,
		workerID:      strings.TrimSpace(workerID),
		leaseDuration: leaseDuration,
		now:           now,
	}, nil
}

func (r *Runner) RunOnce(ctx context.Context) error {
	now := r.now().UTC()
	item, claimed, err := r.repo.ClaimNext(ctx, biz.Claim{
		WorkerID:  r.workerID,
		Now:       now,
		ExpiresAt: now.Add(r.leaseDuration),
	})
	if err != nil || !claimed {
		return err
	}

	if item.Status == biz.StatusBuilding {
		if err := r.executor.Build(ctx, item); err != nil {
			return r.fail(ctx, item, "build", err)
		}
		item, err = r.advance(ctx, item, biz.StatusDeploying)
		if err != nil {
			return err
		}
	}

	if item.Status == biz.StatusDeploying {
		if err := r.executor.Deploy(ctx, item); err != nil {
			return r.fail(ctx, item, "deploy", err)
		}
		if _, err := r.advance(ctx, item, biz.StatusSucceeded); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runner) advance(ctx context.Context, item biz.Deployment, next biz.Status) (biz.Deployment, error) {
	now := r.now().UTC()
	expectedVersion := item.Version
	if next != biz.StatusSucceeded {
		if err := item.Renew(r.workerID, now, now.Add(r.leaseDuration)); err != nil {
			return biz.Deployment{}, err
		}
	}
	if err := item.Transition(next, now); err != nil {
		return biz.Deployment{}, err
	}
	saved, err := r.repo.SaveClaimed(ctx, item, expectedVersion, r.workerID, now)
	if err != nil {
		return biz.Deployment{}, err
	}
	return saved, nil
}

func (r *Runner) fail(ctx context.Context, item biz.Deployment, step string, cause error) error {
	now := r.now().UTC()
	expectedVersion := item.Version
	if err := item.Transition(biz.StatusFailed, now); err != nil {
		return errors.Join(fmt.Errorf("%s deployment %s: %w", step, item.ID, cause), err)
	}
	if _, err := r.repo.SaveClaimed(ctx, item, expectedVersion, r.workerID, now); err != nil {
		return errors.Join(fmt.Errorf("%s deployment %s: %w", step, item.ID, cause), err)
	}
	return fmt.Errorf("%s deployment %s: %w", step, item.ID, cause)
}
