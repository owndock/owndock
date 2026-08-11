package biz

import (
	"context"
	"errors"
	"io"
	"time"
)

var (
	ErrInvalidTerminalSize = errors.New("terminal size is invalid")
	ErrStreamUnavailable   = errors.New("terminal stream is unavailable")
)

const (
	DefaultTerminalColumns = 120
	DefaultTerminalRows    = 30
	MaximumTerminalColumns = 1000
	MaximumTerminalRows    = 500
)

type TerminalSize struct {
	Columns uint16
	Rows    uint16
}

func DefaultTerminalSize() TerminalSize {
	return TerminalSize{Columns: DefaultTerminalColumns, Rows: DefaultTerminalRows}
}

func (s TerminalSize) Validate() error {
	if s.Columns < 1 || s.Rows < 1 || s.Columns > MaximumTerminalColumns ||
		s.Rows > MaximumTerminalRows {
		return ErrInvalidTerminalSize
	}
	return nil
}

// TerminalStream is an already authenticated byte stream. Implementations
// must support one reader and one writer concurrently and make Close
// idempotent. Payload bytes must never be logged or persisted.
type TerminalStream interface {
	io.Reader
	io.Writer
	io.Closer
	Resize(context.Context, TerminalSize) error
}

type ContainerGateway interface {
	OpenContainer(context.Context, string, Target, TerminalSize) (TerminalStream, error)
}

type HostGateway interface {
	OpenHost(context.Context, string, Target, TerminalSize) (TerminalStream, error)
}

// ConnectionReview is the current database-backed authorization decision for
// an already-open terminal. Permission revocation can use the policy grace
// period; explicit termination and target replacement are immediate.
type ConnectionReview struct {
	Terminate   bool
	Reason      CloseReason
	GracePeriod time.Duration
}
