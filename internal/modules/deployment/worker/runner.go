package worker

import (
	"context"

	"github.com/owndock/owndock/internal/modules/deployment/biz"
)

// Runner executes one deterministic delivery step. Infrastructure adapters are
// deliberately injected later; the worker owns orchestration, not Docker/K8s APIs.
type Runner struct {
	repo     biz.Repository
	executor Executor
}

type Executor interface {
	Build(context.Context, biz.Deployment) error
	Deploy(context.Context, biz.Deployment) error
}

func NewRunner(repo biz.Repository, executor Executor) *Runner {
	return &Runner{repo: repo, executor: executor}
}

func (r *Runner) RunOnce(ctx context.Context) error {
	items, err := r.repo.List(ctx, "", "")
	if err != nil {
		return err
	}
	for _, item := range items {
		if item.Status != biz.StatusQueued {
			continue
		}
		if err := item.Transition(biz.StatusBuilding); err != nil {
			return err
		}
		if err := r.repo.Update(ctx, item); err != nil {
			return err
		}
		if err := r.executor.Build(ctx, item); err != nil {
			return r.fail(ctx, item)
		}
		if err := item.Transition(biz.StatusDeploying); err != nil {
			return err
		}
		if err := r.repo.Update(ctx, item); err != nil {
			return err
		}
		if err := r.executor.Deploy(ctx, item); err != nil {
			return r.fail(ctx, item)
		}
		if err := item.Transition(biz.StatusSucceeded); err != nil {
			return err
		}
		if err := r.repo.Update(ctx, item); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runner) fail(ctx context.Context, item biz.Deployment) error {
	if err := item.Transition(biz.StatusFailed); err != nil {
		return err
	}
	return r.repo.Update(ctx, item)
}
