package lifecycle

import (
	"context"
	"errors"
	"sync"
)

var ErrAlreadyStarted = errors.New("runner server already started")

type Runner interface {
	Run(context.Context) error
}

// Server adapts a long-running task to the lifecycle used by the application.
// Constructors remain side-effect free: the runner starts only from Start.
type Server struct {
	runner Runner

	mu      sync.Mutex
	started bool
	cancel  context.CancelFunc
	done    chan struct{}
}

func NewServer(runner Runner) *Server {
	return &Server{runner: runner}
}

func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return ErrAlreadyStarted
	}
	runContext, cancel := context.WithCancel(ctx)
	s.started = true
	s.cancel = cancel
	s.done = make(chan struct{})
	done := s.done
	s.mu.Unlock()

	err := s.runner.Run(runContext)
	close(done)
	if runContext.Err() != nil && errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	if !s.started {
		s.mu.Unlock()
		return nil
	}
	cancel := s.cancel
	done := s.done
	s.mu.Unlock()

	cancel()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
