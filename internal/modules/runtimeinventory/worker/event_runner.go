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
	ErrMissingEventScheduleRepository = errors.New(
		"runtime inventory event schedule repository is required",
	)
	ErrMissingEventCollector = errors.New(
		"runtime inventory event collector is required",
	)
)

type EventRunner struct {
	repository     biz.EventScheduleRepository
	collector      biz.EventCollector
	workerID       string
	leaseDuration  time.Duration
	pollInterval   time.Duration
	retryInterval  time.Duration
	candidateLimit int
	now            func() time.Time
}

func NewEventRunner(
	repository biz.EventScheduleRepository,
	collector biz.EventCollector,
	workerID string,
	leaseDuration, pollInterval, retryInterval time.Duration,
	candidateLimit int,
	now func() time.Time,
) (*EventRunner, error) {
	if repository == nil {
		return nil, ErrMissingEventScheduleRepository
	}
	if collector == nil {
		return nil, ErrMissingEventCollector
	}
	workerID = strings.TrimSpace(workerID)
	if workerID == "" {
		return nil, ErrInvalidWorkerID
	}
	if leaseDuration <= 0 || pollInterval <= 0 || retryInterval <= 0 ||
		candidateLimit < 1 || candidateLimit > 1000 || now == nil {
		return nil, ErrInvalidSchedule
	}
	return &EventRunner{
		repository: repository, collector: collector, workerID: workerID,
		leaseDuration: leaseDuration, pollInterval: pollInterval,
		retryInterval: retryInterval, candidateLimit: candidateLimit, now: now,
	}, nil
}

// RunOnce holds one fenced event-subscription lease and advances its cursor
// only after every event hint in the bounded batch has been safely recorded.
func (r *EventRunner) RunOnce(ctx context.Context) error {
	targets, err := r.repository.ListEventTargets(
		ctx,
		r.candidateLimit,
		r.now().UTC(),
	)
	if err != nil {
		return err
	}
	for _, target := range targets {
		now := r.now().UTC()
		lease, acquired, acquireErr := r.repository.TryAcquireEvents(
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
		cursorAt, collectErr := r.collector.CollectEvents(
			ctx,
			target,
			lease.CursorAt,
		)
		finishedAt := r.now().UTC()
		nextPollAt := finishedAt.Add(r.pollInterval)
		if collectErr != nil {
			cursorAt = lease.CursorAt
			nextPollAt = finishedAt.Add(r.retryInterval)
		}
		settleContext, cancel := context.WithTimeout(
			context.Background(),
			5*time.Second,
		)
		finishErr := r.repository.FinishEvents(
			settleContext,
			lease,
			finishedAt,
			cursorAt,
			nextPollAt,
			collectErr == nil,
		)
		cancel()
		if collectErr != nil {
			collectErr = fmt.Errorf(
				"collect runtime inventory events for target %s: %w",
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

var _ OnceRunner = (*EventRunner)(nil)
