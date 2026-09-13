package worker

import (
	"context"
	"errors"
	"time"
)

var ErrInvalidProductResourceRetirementWorker = errors.New("product resource retirement worker is invalid")

type ProductResourceRetirementUseCase interface {
	ContinueProductResourceRetirements(context.Context, int64) (int, error)
}

// ProductResourceRetirementLoop resumes durable Application and Environment
// retirements independently from request lifetimes.
type ProductResourceRetirementLoop struct {
	useCase          ProductResourceRetirementUseCase
	batchSize        int64
	pollInterval     time.Duration
	operationTimeout time.Duration
	onError          ErrorHandler
	observePoll      func(string, time.Duration)
}

func NewProductResourceRetirementLoop(
	useCase ProductResourceRetirementUseCase,
	batchSize int64,
	pollInterval, operationTimeout time.Duration,
	onError ErrorHandler,
) (*ProductResourceRetirementLoop, error) {
	if useCase == nil || batchSize < 1 || batchSize > 100 ||
		pollInterval <= 0 || operationTimeout <= 0 {
		return nil, ErrInvalidProductResourceRetirementWorker
	}
	return &ProductResourceRetirementLoop{
		useCase: useCase, batchSize: batchSize,
		pollInterval: pollInterval, operationTimeout: operationTimeout,
		onError: onError,
	}, nil
}

func (l *ProductResourceRetirementLoop) WithObservability(
	observe func(string, time.Duration),
) *ProductResourceRetirementLoop {
	l.observePoll = observe
	return l
}

func (l *ProductResourceRetirementLoop) Run(ctx context.Context) error {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			startedAt := time.Now()
			operationContext, cancel := context.WithTimeout(ctx, l.operationTimeout)
			_, err := l.useCase.ContinueProductResourceRetirements(operationContext, l.batchSize)
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
