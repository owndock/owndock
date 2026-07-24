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
	controlplanebiz "github.com/owndock/owndock/internal/modules/controlplane/biz"
	controlplanedata "github.com/owndock/owndock/internal/modules/controlplane/data"
	controlplaneservice "github.com/owndock/owndock/internal/modules/controlplane/service"
	deploymentbiz "github.com/owndock/owndock/internal/modules/deployment/biz"
	deploymentdata "github.com/owndock/owndock/internal/modules/deployment/data"
	deploymentservice "github.com/owndock/owndock/internal/modules/deployment/service"
	environmentbiz "github.com/owndock/owndock/internal/modules/environment/biz"
	environmentdata "github.com/owndock/owndock/internal/modules/environment/data"
	environmentservice "github.com/owndock/owndock/internal/modules/environment/service"
	identitybiz "github.com/owndock/owndock/internal/modules/identity/biz"
	identitydata "github.com/owndock/owndock/internal/modules/identity/data"
	identityservice "github.com/owndock/owndock/internal/modules/identity/service"
	"github.com/owndock/owndock/internal/modules/meta"
	platformaudit "github.com/owndock/owndock/internal/platform/audit"
	platformconfig "github.com/owndock/owndock/internal/platform/config"
	"github.com/owndock/owndock/internal/platform/health"
	"github.com/owndock/owndock/internal/platform/id"
	"github.com/owndock/owndock/internal/platform/migration"
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
	var productAPI *server.ProductAPI
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
	if cfg.Database.Mongo.Enabled {
		mongoClient, err = platformmongo.Open(context.Background(), cfg.Database.Mongo)
		if err != nil {
			return fmt.Errorf("open MongoDB: %w", err)
		}
		healthChecker.AddReadinessCheck("mongo", mongoClient.Ping)
		if err := migration.NewRunner(mongoClient.Database(), instanceID).Run(context.Background(), migration.Default()); err != nil {
			return fmt.Errorf("run MongoDB migrations: %w", err)
		}
	}
	if cfg.Product.Enabled {
		sessionTTL, err := cfg.Security.SessionTTLDuration()
		if err != nil {
			return err
		}
		passwords, err := identitydata.NewPasswordHasher()
		if err != nil {
			return fmt.Errorf("create password hasher: %w", err)
		}
		auditStore := platformaudit.NewMongoStore(mongoClient.Database())
		identityUseCase := identitybiz.NewUseCase(
			identitydata.NewMongoRepository(mongoClient.Database()),
			mongoClient,
			auditStore,
			passwords,
			identitydata.SessionTokens{},
			id.New,
			time.Now,
			sessionTTL,
		)
		identityHTTP := identityservice.NewHTTP(identityUseCase, cfg.Security.BootstrapToken)
		controlPlaneStore := controlplanedata.NewMongoStore(mongoClient.Database())
		controlPlaneHTTP := controlplaneservice.NewHTTP(controlplanebiz.NewUseCase(
			controlPlaneStore,
			controlPlaneStore,
			controlPlaneStore,
			controlPlaneStore,
			mongoClient,
			auditStore,
			auditStore,
			id.New,
			time.Now,
		))
		productAPI, err = server.NewProductAPI(identityHTTP, controlPlaneHTTP, identityHTTP.Authenticate)
		if err != nil {
			return fmt.Errorf("create product API: %w", err)
		}
	}
	httpServer, err := server.NewHTTPServer(
		cfg.Server.HTTP,
		healthChecker,
		metaService,
		engineeringSamples,
		productAPI,
		metrics,
		tracing,
		logger,
	)
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
