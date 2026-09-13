package worker

import (
	"context"
	"errors"
	"time"
)

var ErrInvalidRuntimeTargetRetirementWorker = errors.New("runtime target retirement worker is invalid")

type RuntimeTargetRetirementUseCase interface {
	ContinueRuntimeTargetRetirements(context.Context, int64) (int, error)
}

type ErrorHandler func(error)

// RuntimeTargetRetirementLoop resumes durable target retirement records at a
// bounded interval. A record remains discoverable until its metadata deletion
// transaction commits, so process restarts do not lose accepted work.
type RuntimeTargetRetirementLoop struct {
	useCase          RuntimeTargetRetirementUseCase
	batchSize        int64
	pollInterval     time.Duration
	operationTimeout time.Duration
	onError          ErrorHandler
	observePoll      func(string, time.Duration)
}

func NewRuntimeTargetRetirementLoop(
	useCase RuntimeTargetRetirementUseCase,
	batchSize int64,
	pollInterval, operationTimeout time.Duration,
	onError ErrorHandler,
) (*RuntimeTargetRetirementLoop, error) {
	if useCase == nil || batchSize < 1 || batchSize > 100 ||
		pollInterval <= 0 || operationTimeout <= 0 {
		return nil, ErrInvalidRuntimeTargetRetirementWorker
	}
	return &RuntimeTargetRetirementLoop{
		useCase: useCase, batchSize: batchSize,
		pollInterval: pollInterval, operationTimeout: operationTimeout,
		onError: onError,
	}, nil
}

func (l *RuntimeTargetRetirementLoop) WithObservability(
	observe func(string, time.Duration),
) *RuntimeTargetRetirementLoop {
	l.observePoll = observe
	return l
}

func (l *RuntimeTargetRetirementLoop) Run(ctx context.Context) error {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			startedAt := time.Now()
			operationContext, cancel := context.WithTimeout(ctx, l.operationTimeout)
			_, err := l.useCase.ContinueRuntimeTargetRetirements(
				operationContext, l.batchSize,
			)
			cancel()
			if l.observePoll != nil {
				l.observePoll(runtimeTargetRetirementResult(err), time.Since(startedAt))
			}
			if err != nil && !errors.Is(err, context.Canceled) && l.onError != nil {
				l.onError(err)
			}
			timer.Reset(l.pollInterval)
		}
	}
}

func runtimeTargetRetirementResult(err error) string {
	switch {
	case err == nil:
		return "success"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	default:
		return "error"
	}
}
