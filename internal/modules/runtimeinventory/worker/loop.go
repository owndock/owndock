package worker

import (
	"context"
	"errors"
	"sync"
	"time"
)

var ErrInvalidLoop = errors.New("runtime inventory worker loop is invalid")

type ErrorHandler func(error)

type OnceRunner interface {
	RunOnce(context.Context) error
}

type Loop struct {
	runner           OnceRunner
	pollInterval     time.Duration
	operationTimeout time.Duration
	concurrency      int
	onError          ErrorHandler
	observePoll      func(string, time.Duration)
}

func (l *Loop) WithObservability(observe func(string, time.Duration)) *Loop {
	l.observePoll = observe
	return l
}

func NewLoop(
	runner OnceRunner,
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
			startedAt := time.Now()
			operationContext, cancel := context.WithTimeout(
				ctx,
				l.operationTimeout,
			)
			err := l.runner.RunOnce(operationContext)
			cancel()
			if l.observePoll != nil {
				l.observePoll(loopResult(err), time.Since(startedAt))
			}
			if err != nil && !errors.Is(err, context.Canceled) &&
				l.onError != nil {
				l.onError(err)
			}
			timer.Reset(l.pollInterval)
		}
	}
}

func loopResult(err error) string {
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
