package worker

import (
	"context"
	"errors"
	"time"
)

var ErrInvalidRetirementWorker = errors.New("application route retirement worker is invalid")

type RetirementUseCase interface {
	ContinueRouteRetirements(context.Context, int64) (int, error)
}

type RetirementLoop struct {
	useCase          RetirementUseCase
	batchSize        int64
	pollInterval     time.Duration
	operationTimeout time.Duration
	onError          func(error)
	observe          func(string, time.Duration)
}

func NewRetirementLoop(
	useCase RetirementUseCase,
	batchSize int64,
	pollInterval, operationTimeout time.Duration,
	onError func(error),
) (*RetirementLoop, error) {
	if useCase == nil || batchSize < 1 || batchSize > 100 || pollInterval <= 0 ||
		operationTimeout <= 0 || onError == nil {
		return nil, ErrInvalidRetirementWorker
	}
	return &RetirementLoop{useCase: useCase, batchSize: batchSize,
		pollInterval: pollInterval, operationTimeout: operationTimeout,
		onError: onError}, nil
}

func (l *RetirementLoop) WithObservability(
	observe func(string, time.Duration),
) *RetirementLoop {
	l.observe = observe
	return l
}

func (l *RetirementLoop) Run(ctx context.Context) error {
	ticker := time.NewTicker(l.pollInterval)
	defer ticker.Stop()
	for {
		startedAt := time.Now()
		operationContext, cancel := context.WithTimeout(ctx, l.operationTimeout)
		_, err := l.useCase.ContinueRouteRetirements(operationContext, l.batchSize)
		cancel()
		result := "success"
		if err != nil {
			result = "error"
			l.onError(err)
		}
		if l.observe != nil {
			l.observe(result, time.Since(startedAt))
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
