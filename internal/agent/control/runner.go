package agentcontrol

import (
	"context"
	"math/rand/v2"
	"time"
)

type Session interface {
	Run(context.Context) error
}

type RunnerConfig struct {
	MinimumDelay time.Duration
	MaximumDelay time.Duration
	StableAfter  time.Duration
}

type ReconnectEvent struct {
	Attempt int
	Delay   time.Duration
	Code    string
}

type Runner struct {
	session Session
	config  RunnerConfig
	now     func() time.Time
	wait    func(context.Context, time.Duration) bool
	jitter  func(time.Duration) time.Duration
	notify  func(ReconnectEvent)
}

func NewRunner(
	session Session,
	config RunnerConfig,
	notify func(ReconnectEvent),
) (*Runner, error) {
	if session == nil ||
		config.MinimumDelay <= 0 ||
		config.MaximumDelay < config.MinimumDelay ||
		config.MaximumDelay > 10*time.Minute ||
		config.StableAfter <= 0 {
		return nil, ErrConfigurationInvalid
	}
	if notify == nil {
		notify = func(ReconnectEvent) {}
	}
	return &Runner{
		session: session,
		config:  config,
		now:     time.Now,
		wait:    waitForReconnect,
		jitter:  jitterDuration,
		notify:  notify,
	}, nil
}

func (r *Runner) Run(ctx context.Context) error {
	delay := r.config.MinimumDelay
	attempt := 0
	for {
		startedAt := r.now()
		err := r.session.Run(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if IsPermanent(err) {
			return err
		}
		attempt++
		if r.now().Sub(startedAt) >= r.config.StableAfter {
			delay = r.config.MinimumDelay
			attempt = 1
		}
		wait := r.jitter(delay)
		r.notify(ReconnectEvent{
			Attempt: attempt,
			Delay:   wait,
			Code:    reconnectErrorCode(err),
		})
		if !r.wait(ctx, wait) {
			return nil
		}
		delay = nextDelay(delay, r.config.MaximumDelay)
	}
}

func reconnectErrorCode(err error) string {
	if err == nil {
		return "connection_closed"
	}
	return "connection_unavailable"
}

func nextDelay(current, maximum time.Duration) time.Duration {
	if current >= maximum/2 {
		return maximum
	}
	return current * 2
}

func jitterDuration(value time.Duration) time.Duration {
	// Full jitter in [50%, 100%] avoids synchronized reconnect waves while
	// retaining a useful lower bound for repeated failures.
	half := value / 2
	if half <= 0 {
		return value
	}
	return half + time.Duration(rand.Int64N(int64(value-half)+1))
}

func waitForReconnect(
	ctx context.Context,
	delay time.Duration,
) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}
