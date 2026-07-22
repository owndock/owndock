package main

import (
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
	applicationRepository := applicationdata.NewMemoryRepository()
	environmentRepository := environmentdata.NewMemoryRepository()
	applicationUseCase := applicationbiz.NewUseCase(applicationRepository, id.New, time.Now)
	environmentUseCase := environmentbiz.NewUseCase(environmentRepository, id.New, time.Now)
	deploymentUseCase := deploymentbiz.NewUseCase(
		deploymentdata.NewMemoryRepository(),
		deploymentdata.NewApplicationLookup(applicationRepository),
		deploymentdata.NewEnvironmentLookup(environmentRepository),
		id.New,
		time.Now,
	)
	applicationService := applicationservice.NewHTTP(applicationUseCase)
	environmentService := environmentservice.NewHTTP(environmentUseCase)
	deploymentService := deploymentservice.NewHTTP(deploymentUseCase)
	metrics := observability.NewMetrics()
	httpServer, err := server.NewHTTPServer(cfg.Server.HTTP, healthChecker, metaService, applicationService, environmentService, deploymentService, metrics, logger)
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
		httpServer,
	)
	return application.Run()
}
