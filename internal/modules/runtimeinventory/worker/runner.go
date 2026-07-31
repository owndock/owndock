package worker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/modules/runtimeinventory/biz"
)

var (
	ErrMissingScheduleRepository = errors.New("runtime inventory schedule repository is required")
	ErrMissingCollector          = errors.New("runtime inventory collector is required")
	ErrInvalidWorkerID           = errors.New("runtime inventory worker ID is required")
	ErrInvalidSchedule           = errors.New("runtime inventory schedule is invalid")
)

type Runner struct {
	repository     biz.ScheduleRepository
	collector      biz.Collector
	workerID       string
	leaseDuration  time.Duration
	syncInterval   time.Duration
	retryInterval  time.Duration
	candidateLimit int
	now            func() time.Time
}

func NewRunner(
	repository biz.ScheduleRepository,
	collector biz.Collector,
	workerID string,
	leaseDuration, syncInterval, retryInterval time.Duration,
	candidateLimit int,
	now func() time.Time,
) (*Runner, error) {
	if repository == nil {
		return nil, ErrMissingScheduleRepository
	}
	if collector == nil {
		return nil, ErrMissingCollector
	}
	workerID = strings.TrimSpace(workerID)
	if workerID == "" {
		return nil, ErrInvalidWorkerID
	}
	if leaseDuration <= 0 || syncInterval <= 0 || retryInterval <= 0 ||
		candidateLimit < 1 || candidateLimit > 1000 || now == nil {
		return nil, ErrInvalidSchedule
	}
	return &Runner{
		repository: repository, collector: collector, workerID: workerID,
		leaseDuration: leaseDuration, syncInterval: syncInterval,
		retryInterval: retryInterval, candidateLimit: candidateLimit, now: now,
	}, nil
}

// RunOnce claims at most one target. A Mongo lease is the cross-process
// non-overlap guard; callers can safely run several Runner loops concurrently.
func (r *Runner) RunOnce(ctx context.Context) error {
	targets, err := r.repository.ListReadyTargets(
		ctx,
		r.candidateLimit,
		r.now().UTC(),
	)
	if err != nil {
		return err
	}
	for _, target := range targets {
		now := r.now().UTC()
		lease, acquired, acquireErr := r.repository.TryAcquire(
			ctx,
			target,
			r.workerID,
			now,
			now.Add(r.leaseDuration),
		)
		if acquireErr != nil {
			return acquireErr
		}
		if !acquired {
			continue
		}
		collectErr := r.collector.Collect(ctx, target)
		finishedAt := r.now().UTC()
		nextDueAt := finishedAt.Add(r.syncInterval)
		if collectErr != nil {
			nextDueAt = finishedAt.Add(r.retryInterval)
		}
		settleContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		finishErr := r.repository.Finish(
			settleContext,
			lease,
			finishedAt,
			nextDueAt,
			collectErr == nil,
		)
		cancel()
		if collectErr != nil {
			collectErr = fmt.Errorf(
				"collect runtime inventory target %s: %w",
				target.RuntimeTargetID,
				collectErr,
			)
		}
		if collectErr != nil || finishErr != nil {
			return errors.Join(collectErr, finishErr)
		}
		return nil
	}
	return nil
}
