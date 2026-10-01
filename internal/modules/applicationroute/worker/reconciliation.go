package worker

import (
	"context"
	"errors"
	"time"
)

var ErrInvalidReconciliationWorker = errors.New("application route reconciliation worker is invalid")

type ReconciliationUseCase interface {
	ContinueRouteReconciliations(context.Context, int64) (int, error)
}

type ReconciliationLoop struct {
	useCase          ReconciliationUseCase
	batchSize        int64
	pollInterval     time.Duration
	operationTimeout time.Duration
	onError          func(error)
	observe          func(string, time.Duration)
}

func NewReconciliationLoop(
	useCase ReconciliationUseCase,
	batchSize int64,
	pollInterval, operationTimeout time.Duration,
	onError func(error),
) (*ReconciliationLoop, error) {
	if useCase == nil || batchSize < 1 || batchSize > 100 || pollInterval <= 0 ||
		operationTimeout <= 0 || onError == nil {
		return nil, ErrInvalidReconciliationWorker
	}
	return &ReconciliationLoop{useCase: useCase, batchSize: batchSize,
		pollInterval: pollInterval, operationTimeout: operationTimeout, onError: onError}, nil
}

func (l *ReconciliationLoop) WithObservability(
	observe func(string, time.Duration),
) *ReconciliationLoop {
	l.observe = observe
	return l
}

func (l *ReconciliationLoop) Run(ctx context.Context) error {
	ticker := time.NewTicker(l.pollInterval)
	defer ticker.Stop()
	for {
		startedAt := time.Now()
		operationContext, cancel := context.WithTimeout(ctx, l.operationTimeout)
		_, err := l.useCase.ContinueRouteReconciliations(operationContext, l.batchSize)
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
