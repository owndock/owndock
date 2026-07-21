package app

import (
	"context"
	"time"

	"github.com/go-kratos/kratos/v2"
	"github.com/go-kratos/kratos/v2/log"
	kratoshttp "github.com/go-kratos/kratos/v2/transport/http"

	"github.com/owndock/owndock/internal/platform/health"
)

func NewServer(
	name string,
	version string,
	instanceID string,
	server *kratoshttp.Server,
	healthChecker *health.Checker,
	shutdownTimeout time.Duration,
	logger log.Logger,
) *kratos.App {
	return kratos.New(
		kratos.Name(name),
		kratos.Version(version),
		kratos.ID(instanceID),
		kratos.Logger(logger),
		kratos.Server(server),
		kratos.StopTimeout(shutdownTimeout),
		kratos.AfterStart(func(context.Context) error {
			healthChecker.SetReady(true)
			return nil
		}),
		kratos.BeforeStop(func(context.Context) error {
			healthChecker.SetReady(false)
			return nil
		}),
	)
}
