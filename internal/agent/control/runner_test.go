package agentcontrol

import (
	"context"
	"errors"
	"testing"
	"time"
)

type sessionStub struct {
	errors []error
	calls  int
}

func (s *sessionStub) Run(context.Context) error {
	s.calls++
	if len(s.errors) == 0 {
		return nil
	}
	err := s.errors[0]
	s.errors = s.errors[1:]
	return err
}

func TestRunnerReconnectsWithBoundedExponentialDelay(t *testing.T) {
	session := &sessionStub{
		errors: []error{
			ErrConnectionUnavailable,
			ErrConnectionUnavailable,
			&PermanentError{Code: "identity_revoked"},
		},
	}
	var events []ReconnectEvent
	runner, err := NewRunner(
		session,
		RunnerConfig{
			MinimumDelay: time.Second,
			MaximumDelay: 4 * time.Second,
			StableAfter:  time.Minute,
		},
		func(event ReconnectEvent) { events = append(events, event) },
	)
	if err != nil {
		t.Fatal(err)
	}
	runner.jitter = func(value time.Duration) time.Duration { return value }
	runner.wait = func(context.Context, time.Duration) bool { return true }
	now := time.Unix(1, 0)
	runner.now = func() time.Time {
		now = now.Add(time.Second)
		return now
	}
	err = runner.Run(t.Context())
	if !IsPermanent(err) || session.calls != 3 {
		t.Fatalf("error = %v, calls = %d", err, session.calls)
	}
	if len(events) != 2 ||
		events[0].Delay != time.Second ||
		events[1].Delay != 2*time.Second {
		t.Fatalf("events = %#v", events)
	}
}

func TestRunnerStopsDuringReconnectWait(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	session := &sessionStub{
		errors: []error{ErrConnectionUnavailable},
	}
	runner, err := NewRunner(
		session,
		RunnerConfig{
			MinimumDelay: time.Second,
			MaximumDelay: 2 * time.Second,
			StableAfter:  time.Minute,
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	runner.wait = func(context.Context, time.Duration) bool {
		cancel()
		return false
	}
	if err := runner.Run(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestJitterAndDelayRemainBounded(t *testing.T) {
	for range 100 {
		value := jitterDuration(10 * time.Second)
		if value < 5*time.Second || value > 10*time.Second {
			t.Fatalf("jitter = %s", value)
		}
	}
	if value := nextDelay(8*time.Second, 10*time.Second); value != 10*time.Second {
		t.Fatalf("next delay = %s", value)
	}
	if _, err := NewRunner(
		nil,
		RunnerConfig{},
		nil,
	); !errors.Is(err, ErrConfigurationInvalid) {
		t.Fatalf("error = %v", err)
	}
}
