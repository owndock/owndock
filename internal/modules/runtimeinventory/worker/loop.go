package worker

import (
	"context"
	"errors"
	"sync"
	"time"
)

var ErrInvalidLoop = errors.New("runtime inventory worker loop is invalid")

type ErrorHandler func(error)

type Loop struct {
	runner           *Runner
	pollInterval     time.Duration
	operationTimeout time.Duration
	concurrency      int
	onError          ErrorHandler
}

func NewLoop(
	runner *Runner,
	pollInterval, operationTimeout time.Duration,
	concurrency int,
	onError ErrorHandler,
) (*Loop, error) {
	if runner == nil || pollInterval <= 0 || operationTimeout <= 0 ||
		concurrency < 1 || concurrency > 32 {
		return nil, ErrInvalidLoop
	}
	return &Loop{
		runner: runner, pollInterval: pollInterval,
		operationTimeout: operationTimeout, concurrency: concurrency,
		onError: onError,
	}, nil
}

func (l *Loop) Run(ctx context.Context) error {
	var workers sync.WaitGroup
	workers.Add(l.concurrency)
	for index := 0; index < l.concurrency; index++ {
		go func() {
			defer workers.Done()
			l.runWorker(ctx)
		}()
	}
	workers.Wait()
	return ctx.Err()
}

func (l *Loop) runWorker(ctx context.Context) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			operationContext, cancel := context.WithTimeout(
				ctx,
				l.operationTimeout,
			)
			err := l.runner.RunOnce(operationContext)
			cancel()
			if err != nil && !errors.Is(err, context.Canceled) &&
				l.onError != nil {
				l.onError(err)
			}
			timer.Reset(l.pollInterval)
		}
	}
}
