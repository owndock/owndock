package worker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/modules/deployment/biz"
	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/transaction"
)

var (
	ErrMissingRepository   = errors.New("deployment repository is required")
	ErrMissingExecutor     = errors.New("deployment executor is required")
	ErrInvalidWorkerID     = errors.New("worker id is required")
	ErrInvalidLeaseTimeout = errors.New("lease duration must be greater than zero")
	ErrMissingClock        = errors.New("worker clock is required")
	ErrLeaseRenewal        = errors.New("deployment lease renewal failed")
	ErrIncompleteAudit     = errors.New("deployment worker audit configuration is incomplete")
)

// Runner claims one deployment atomically and executes its current delivery
// step. Executor operations must be idempotent for a deployment ID because an
// expired lease can be reclaimed after an interrupted process.
type Runner struct {
	repo          biz.Repository
	executor      biz.Executor
	workerID      string
	leaseDuration time.Duration
	now           func() time.Time
	transaction   transaction.Manager
	audit         sharedaudit.Recorder
	newID         biz.IDGenerator
}

func NewRunner(
	repo biz.Repository,
	executor biz.Executor,
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

func (r *Runner) WithAudit(
	manager transaction.Manager,
	recorder sharedaudit.Recorder,
	newID biz.IDGenerator,
) *Runner {
	r.transaction = manager
	r.audit = recorder
	r.newID = newID
	return r
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

	if item.Status == biz.StatusQueued {
		item, err = r.advance(ctx, item, biz.StatusPreparing)
		if err != nil {
			return err
		}
	}
	if item.Status == biz.StatusPreparing {
		item, err = r.runStep(ctx, item, r.executor.Prepare)
		if err != nil {
			if errors.Is(err, ErrLeaseRenewal) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return r.fail(ctx, item, "prepare", err)
		}
		item, err = r.advance(ctx, item, biz.StatusDeploying)
		if err != nil {
			return err
		}
	}

	if item.Status == biz.StatusDeploying {
		item, err = r.runStep(ctx, item, r.executor.Deploy)
		if err != nil {
			if errors.Is(err, ErrLeaseRenewal) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return r.fail(ctx, item, "deploy", err)
		}
		if _, err := r.advance(ctx, item, biz.StatusSucceeded); err != nil {
			return err
		}
	}
	if item.Status == biz.StatusCanceling {
		item, err = r.runStep(ctx, item, r.executor.Cancel)
		if err != nil {
			if errors.Is(err, ErrLeaseRenewal) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return fmt.Errorf("cancel deployment %s: %w", item.ID, err)
		}
		if _, err := r.advance(ctx, item, biz.StatusCanceled); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runner) renew(ctx context.Context, item biz.Deployment) (biz.Deployment, error) {
	now := r.now().UTC()
	return r.repo.RenewLease(ctx, item.ID, r.workerID, item.Version, now, now.Add(r.leaseDuration))
}

func (r *Runner) runStep(
	ctx context.Context,
	item biz.Deployment,
	execute func(context.Context, biz.Deployment) error,
) (biz.Deployment, error) {
	item, err := r.renew(ctx, item)
	if err != nil {
		return item, errors.Join(ErrLeaseRenewal, err)
	}
	stepContext, cancel := context.WithCancel(ctx)
	defer cancel()
	result := make(chan error, 1)
	executionItem := item
	go func() {
		result <- execute(stepContext, executionItem)
	}()

	heartbeatInterval := r.leaseDuration / 3
	if heartbeatInterval <= 0 {
		heartbeatInterval = time.Nanosecond
	}
	heartbeat := time.NewTicker(heartbeatInterval)
	defer heartbeat.Stop()
	for {
		select {
		case err := <-result:
			return item, err
		case <-heartbeat.C:
			item, err = r.renew(ctx, item)
			if err != nil {
				cancel()
				return item, errors.Join(ErrLeaseRenewal, err)
			}
		case <-ctx.Done():
			return item, ctx.Err()
		}
	}
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
	return r.saveState(ctx, item, expectedVersion, now, auditAction(next))
}

func (r *Runner) fail(ctx context.Context, item biz.Deployment, step string, cause error) error {
	now := r.now().UTC()
	expectedVersion := item.Version
	category := biz.CategorizeExecutionError(cause, failureFallback(step))
	safeError := &biz.ExecutionError{Category: category, Cause: cause}
	if err := item.Fail(category, now); err != nil {
		return errors.Join(fmt.Errorf("%s deployment %s: %w", step, item.ID, safeError), err)
	}
	if _, err := r.saveState(ctx, item, expectedVersion, now, biz.AuditActionFailed); err != nil {
		return errors.Join(fmt.Errorf("%s deployment %s: %w", step, item.ID, safeError), err)
	}
	return fmt.Errorf("%s deployment %s: %w", step, item.ID, safeError)
}

func (r *Runner) saveState(
	ctx context.Context,
	item biz.Deployment,
	expectedVersion uint64,
	now time.Time,
	action string,
) (biz.Deployment, error) {
	auditDependencies := 0
	for _, configured := range []bool{r.transaction != nil, r.audit != nil, r.newID != nil} {
		if configured {
			auditDependencies++
		}
	}
	if auditDependencies == 0 {
		return r.repo.SaveClaimed(ctx, item, expectedVersion, r.workerID, now)
	}
	if auditDependencies != 3 {
		return biz.Deployment{}, ErrIncompleteAudit
	}
	auditID, err := r.newID()
	if err != nil {
		return biz.Deployment{}, err
	}
	var saved biz.Deployment
	err = r.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		var saveErr error
		saved, saveErr = r.repo.SaveClaimed(
			transactionContext, item, expectedVersion, r.workerID, now,
		)
		if saveErr != nil {
			return saveErr
		}
		return r.audit.Record(transactionContext, sharedaudit.Event{
			ID: auditID, OrganizationID: item.OrganizationID, ProjectID: item.ProjectID,
			ActorID: "system:" + r.workerID, Action: action,
			ResourceType: "deployment", ResourceID: item.ID, CreatedAt: now,
		})
	})
	return saved, err
}

func auditAction(status biz.Status) string {
	switch status {
	case biz.StatusPreparing:
		return biz.AuditActionPreparing
	case biz.StatusDeploying:
		return biz.AuditActionDeploying
	case biz.StatusSucceeded:
		return biz.AuditActionSucceeded
	case biz.StatusCanceled:
		return biz.AuditActionCanceled
	default:
		return "deployment.status_changed"
	}
}

func failureFallback(step string) biz.FailureCategory {
	if step == "prepare" {
		return biz.FailureConfiguration
	}
	return biz.FailureRuntime
}
