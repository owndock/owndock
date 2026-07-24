package transaction

import "context"

type Manager interface {
	WithinTransaction(context.Context, func(context.Context) error) error
}

type Passthrough struct{}

func (Passthrough) WithinTransaction(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}
