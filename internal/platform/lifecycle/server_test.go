package lifecycle

import (
	"context"
	"errors"
	"testing"
	"time"
)

type runnerFunc func(context.Context) error

func (f runnerFunc) Run(ctx context.Context) error { return f(ctx) }

func TestServerStopsRunner(t *testing.T) {
	started := make(chan struct{})
	server := NewServer(runnerFunc(func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}))
	errCh := make(chan error, 1)
	go func() { errCh <- server.Start(context.Background()) }()
	<-started

	stopContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Stop(stopContext); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("Start() error = %v", err)
	}
}

func TestServerPropagatesRunnerFailure(t *testing.T) {
	want := errors.New("runner failed")
	server := NewServer(runnerFunc(func(context.Context) error { return want }))
	if err := server.Start(context.Background()); !errors.Is(err, want) {
		t.Fatalf("Start() error = %v, want %v", err, want)
	}
}

func TestServerStopHonorsDeadline(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server := NewServer(runnerFunc(func(context.Context) error {
		close(started)
		<-release
		return nil
	}))
	errCh := make(chan error, 1)
	go func() { errCh <- server.Start(context.Background()) }()
	<-started

	stopContext, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if err := server.Stop(stopContext); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Stop() error = %v", err)
	}
	close(release)
	if err := <-errCh; err != nil {
		t.Fatalf("Start() error = %v", err)
	}
}
