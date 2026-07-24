package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/go-kratos/kratos/v2/log"

	serverapp "github.com/owndock/owndock/internal/app"
	applicationbiz "github.com/owndock/owndock/internal/modules/application/biz"
	applicationdata "github.com/owndock/owndock/internal/modules/application/data"
	applicationservice "github.com/owndock/owndock/internal/modules/application/service"
	deploymentbiz "github.com/owndock/owndock/internal/modules/deployment/biz"
	deploymentdata "github.com/owndock/owndock/internal/modules/deployment/data"
	deploymentservice "github.com/owndock/owndock/internal/modules/deployment/service"
	environmentbiz "github.com/owndock/owndock/internal/modules/environment/biz"
	environmentdata "github.com/owndock/owndock/internal/modules/environment/data"
	environmentservice "github.com/owndock/owndock/internal/modules/environment/service"
	"github.com/owndock/owndock/internal/modules/meta"
	platformconfig "github.com/owndock/owndock/internal/platform/config"
	"github.com/owndock/owndock/internal/platform/health"
	"github.com/owndock/owndock/internal/platform/id"
	platformmongo "github.com/owndock/owndock/internal/platform/mongo"
	"github.com/owndock/owndock/internal/platform/observability"
	"github.com/owndock/owndock/internal/server"
)

const serviceName = "owndock"

var (
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
)

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	var configPath string
	flag.StringVar(&configPath, "conf", "configs/config.yaml", "configuration file or directory")
	flag.Parse()

	cfg, err := platformconfig.Load(configPath)
	if err != nil {
		return err
	}
	shutdownTimeout, err := cfg.Server.HTTP.ShutdownTimeoutDuration()
	if err != nil {
		return err
	}

	instanceID, err := os.Hostname()
	if err != nil || instanceID == "" {
		instanceID = "unknown"
	}
	logger := log.With(
		log.NewStdLogger(os.Stdout),
		"ts", log.DefaultTimestamp,
		"caller", log.DefaultCaller,
		"service.name", serviceName,
		"service.version", version,
		"instance.id", instanceID,
	)

	healthChecker := health.NewChecker()
	metaService := meta.NewService(meta.BuildInfo{
		Service:   serviceName,
		Version:   version,
		Commit:    commit,
		BuildTime: buildTime,
	})
	var engineeringSamples *server.EngineeringSamples
	if cfg.Development.EnableEngineeringSamples {
		applicationRepository := applicationdata.NewMemoryRepository()
		environmentRepository := environmentdata.NewMemoryRepository()
		engineeringSamples = &server.EngineeringSamples{
			Application: applicationservice.NewHTTP(applicationbiz.NewUseCase(applicationRepository, id.New, time.Now)),
			Environment: environmentservice.NewHTTP(environmentbiz.NewUseCase(environmentRepository, id.New, time.Now)),
			Deployment: deploymentservice.NewHTTP(deploymentbiz.NewUseCase(
				deploymentdata.NewMemoryRepository(),
				deploymentdata.NewApplicationLookup(applicationRepository),
				deploymentdata.NewEnvironmentLookup(environmentRepository),
				id.New,
				time.Now,
			)),
		}
	}
	metrics := observability.NewMetrics()
	tracing, err := observability.NewTracing(context.Background(), cfg.Observability.Tracing, serviceName, version, instanceID)
	if err != nil {
		return fmt.Errorf("create tracing: %w", err)
	}
	var mongoClient *platformmongo.Client
	if cfg.Database.Mongo.Enabled {
		mongoClient, err = platformmongo.Open(context.Background(), cfg.Database.Mongo)
		if err != nil {
			shutdownContext, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
			defer cancel()
			return errors.Join(fmt.Errorf("open MongoDB: %w", err), tracing.Shutdown(shutdownContext))
		}
		healthChecker.AddReadinessCheck("mongo", mongoClient.Ping)
	}
	cleanup := func(ctx context.Context) error {
		var mongoErr error
		if mongoClient != nil {
			mongoErr = mongoClient.Close(ctx)
		}
		return errors.Join(mongoErr, tracing.Shutdown(ctx))
	}
	defer func() {
		shutdownContext, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		_ = cleanup(shutdownContext)
	}()

	httpServer, err := server.NewHTTPServer(cfg.Server.HTTP, healthChecker, metaService, engineeringSamples, metrics, tracing, logger)
	if err != nil {
		return fmt.Errorf("create HTTP server: %w", err)
	}

	application := serverapp.NewServer(
		serviceName,
		version,
		instanceID,
		healthChecker,
		shutdownTimeout,
		logger,
		cleanup,
		httpServer,
	)
	return application.Run()
}
