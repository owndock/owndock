package worker

import (
	"context"
	"errors"
	"time"
)

type ErrorHandler func(error)

type Loop struct {
	runner           *Runner
	pollInterval     time.Duration
	operationTimeout time.Duration
	onError          ErrorHandler
	observePoll      func(string, time.Duration)
}

func NewLoop(
	runner *Runner,
	pollInterval, operationTimeout time.Duration,
	onError ErrorHandler,
) (*Loop, error) {
	if runner == nil || pollInterval <= 0 || operationTimeout <= 0 {
		return nil, errors.New("evidence worker loop configuration is invalid")
	}
	return &Loop{
		runner: runner, pollInterval: pollInterval,
		operationTimeout: operationTimeout, onError: onError,
	}, nil
}

func (l *Loop) WithObservability(observe func(string, time.Duration)) *Loop {
	l.observePoll = observe
	return l
}

func (l *Loop) Run(ctx context.Context) error {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			startedAt := time.Now()
			operationContext, cancel := context.WithTimeout(ctx, l.operationTimeout)
			err := l.runner.RunOnce(operationContext)
			cancel()
			if l.observePoll != nil {
				l.observePoll(evidenceLoopResult(err), time.Since(startedAt))
			}
			if err != nil && !errors.Is(err, context.Canceled) && l.onError != nil {
				l.onError(err)
			}
			timer.Reset(l.pollInterval)
		}
	}
}

func evidenceLoopResult(err error) string {
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
