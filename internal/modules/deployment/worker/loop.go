package worker

import (
	"context"
	"errors"
	"time"
)

var (
	ErrMissingRunner       = errors.New("deployment runner is required")
	ErrInvalidPollInterval = errors.New("poll interval must be greater than zero")
)

type ErrorHandler func(error)

// Loop adapts RunOnce to the application lifecycle. It intentionally polls at
// a bounded interval so an empty queue cannot become a busy loop.
type Loop struct {
	runner           *Runner
	pollInterval     time.Duration
	operationTimeout time.Duration
	onError          ErrorHandler
}

func NewLoop(
	runner *Runner,
	pollInterval, operationTimeout time.Duration,
	onError ErrorHandler,
) (*Loop, error) {
	if runner == nil {
		return nil, ErrMissingRunner
	}
	if pollInterval <= 0 {
		return nil, ErrInvalidPollInterval
	}
	if operationTimeout <= 0 {
		return nil, errors.New("operation timeout must be greater than zero")
	}
	return &Loop{
		runner: runner, pollInterval: pollInterval,
		operationTimeout: operationTimeout, onError: onError,
	}, nil
}

func (l *Loop) Run(ctx context.Context) error {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			operationContext, cancel := context.WithTimeout(ctx, l.operationTimeout)
			err := l.runner.RunOnce(operationContext)
			cancel()
			if err != nil && !errors.Is(err, context.Canceled) && l.onError != nil {
				l.onError(err)
			}
			timer.Reset(l.pollInterval)
		}
	}
}
