package app

import (
	"context"
	"time"

	"github.com/go-kratos/kratos/v2"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/transport"

	"github.com/owndock/owndock/internal/platform/health"
)

func NewServer(
	name string,
	version string,
	instanceID string,
	healthChecker *health.Checker,
	shutdownTimeout time.Duration,
	logger log.Logger,
	cleanup func(context.Context) error,
	servers ...transport.Server,
) *kratos.App {
	options := []kratos.Option{
		kratos.Name(name),
		kratos.Version(version),
		kratos.ID(instanceID),
		kratos.Logger(logger),
		kratos.Server(servers...),
		kratos.StopTimeout(shutdownTimeout),
		kratos.AfterStart(func(context.Context) error {
			healthChecker.SetReady(true)
			return nil
		}),
		kratos.BeforeStop(func(context.Context) error {
			healthChecker.SetReady(false)
			return nil
		}),
	}
	if cleanup != nil {
		options = append(options, kratos.AfterStop(cleanupAfterStop(shutdownTimeout, cleanup)))
	}
	return kratos.New(options...)
}

func cleanupAfterStop(timeout time.Duration, cleanup func(context.Context) error) func(context.Context) error {
	return func(ctx context.Context) error {
		shutdownContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
		defer cancel()
		return cleanup(shutdownContext)
	}
}
