package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/go-kratos/kratos/v2/log"

	serverapp "github.com/owndock/owndock/internal/app"
	applicationmodule "github.com/owndock/owndock/internal/modules/application"
	applicationdata "github.com/owndock/owndock/internal/modules/application/data"
	"github.com/owndock/owndock/internal/modules/meta"
	platformconfig "github.com/owndock/owndock/internal/platform/config"
	"github.com/owndock/owndock/internal/platform/health"
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
	applicationService := applicationmodule.NewService(applicationdata.NewMemoryRepository())
	httpServer, err := server.NewHTTPServer(cfg.Server.HTTP, healthChecker, metaService, applicationService, logger)
	if err != nil {
		return fmt.Errorf("create HTTP server: %w", err)
	}

	application := serverapp.NewServer(
		serviceName,
		version,
		instanceID,
		httpServer,
		healthChecker,
		shutdownTimeout,
		logger,
	)
	return application.Run()
}
