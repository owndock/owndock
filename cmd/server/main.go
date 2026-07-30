package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/transport"

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
	deploymentworker "github.com/owndock/owndock/internal/modules/deployment/worker"
	environmentbiz "github.com/owndock/owndock/internal/modules/environment/biz"
	environmentdata "github.com/owndock/owndock/internal/modules/environment/data"
	environmentservice "github.com/owndock/owndock/internal/modules/environment/service"
	identitybiz "github.com/owndock/owndock/internal/modules/identity/biz"
	identitydata "github.com/owndock/owndock/internal/modules/identity/data"
	identityservice "github.com/owndock/owndock/internal/modules/identity/service"
	managedhostbiz "github.com/owndock/owndock/internal/modules/managedhost/biz"
	managedhostdata "github.com/owndock/owndock/internal/modules/managedhost/data"
	managedhostservice "github.com/owndock/owndock/internal/modules/managedhost/service"
	"github.com/owndock/owndock/internal/modules/meta"
	platformaudit "github.com/owndock/owndock/internal/platform/audit"
	platformconfig "github.com/owndock/owndock/internal/platform/config"
	"github.com/owndock/owndock/internal/platform/health"
	"github.com/owndock/owndock/internal/platform/httpx"
	"github.com/owndock/owndock/internal/platform/id"
	"github.com/owndock/owndock/internal/platform/lifecycle"
	"github.com/owndock/owndock/internal/platform/migration"
	platformmongo "github.com/owndock/owndock/internal/platform/mongo"
	"github.com/owndock/owndock/internal/platform/observability"
	"github.com/owndock/owndock/internal/server"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
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
	var deploymentWorkerServer *lifecycle.Server
	var agentControlServer *server.AgentServer
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
		loginAttemptWindow, err :=
			cfg.Security.LoginAttemptWindowDuration()
		if err != nil {
			return err
		}
		passwords, err := identitydata.NewPasswordHasher()
		if err != nil {
			return fmt.Errorf("create password hasher: %w", err)
		}
		auditStore := platformaudit.NewMongoStore(mongoClient.Database())
		identityRepository := identitydata.NewMongoRepository(
			mongoClient.Database(),
		)
		identityUseCase := identitybiz.NewUseCase(
			identityRepository,
			mongoClient,
			auditStore,
			passwords,
			identitydata.SessionTokens{},
			id.New,
			time.Now,
			sessionTTL,
		).WithLoginProtection(
			identityRepository,
			cfg.Security.LoginAttemptLimitValue(),
			loginAttemptWindow,
		).WithSessionPolicy(
			cfg.Security.MaxActiveSessionsValue(),
		)
		identityHTTP := identityservice.NewHTTP(identityUseCase, cfg.Security.BootstrapToken)
		controlPlaneStore := controlplanedata.NewMongoStore(mongoClient.Database())
		managedHostStore := managedhostdata.NewMongoRepository(mongoClient.Database())
		managedHostUseCase := managedhostbiz.NewUseCase(
			managedHostStore,
			mongoClient,
			auditStore,
			id.New,
			time.Now,
		)
		runtimeTargetProbers := map[runtimeaccess.Mode]controlplanebiz.RuntimeTargetProber{
			runtimeaccess.ModeDirectDocker: controlplanedata.
				NewDockerRuntimeTargetProber(),
		}
		var agentCommandDispatcher managedhostbiz.AgentCommandDispatcher
		if cfg.Security.AgentPKI.Enabled {
			enrollmentTTL, err := cfg.Security.AgentPKI.EnrollmentTTLDuration()
			if err != nil {
				return err
			}
			certificateTTL, err := cfg.Security.AgentPKI.CertificateTTLDuration()
			if err != nil {
				return err
			}
			caCertificate, caPrivateKey, err := cfg.Security.AgentPKI.Materials()
			if err != nil {
				return fmt.Errorf("load Agent PKI material: %w", err)
			}
			issuer, issuerErr := managedhostdata.NewCertificateIssuer(
				caCertificate, caPrivateKey, certificateTTL,
			)
			for index := range caPrivateKey {
				caPrivateKey[index] = 0
			}
			if issuerErr != nil {
				return fmt.Errorf("create Agent certificate issuer: %w", issuerErr)
			}
			managedHostUseCase.WithEnrollment(
				managedHostStore,
				managedhostdata.EnrollmentTokens{},
				issuer,
				enrollmentTTL,
			)
			if cfg.Server.Agent.Enabled {
				handshakeTimeout, durationErr :=
					cfg.Server.Agent.HandshakeTimeoutDuration()
				if durationErr != nil {
					return durationErr
				}
				heartbeatInterval, durationErr :=
					cfg.Server.Agent.HeartbeatIntervalDuration()
				if durationErr != nil {
					return durationErr
				}
				heartbeatTimeout, durationErr :=
					cfg.Server.Agent.HeartbeatTimeoutDuration()
				if durationErr != nil {
					return durationErr
				}
				connectionRegistry, registryErr :=
					managedhostdata.NewConnectionRegistry(
						cfg.Server.Agent.OutboundBuffer,
						cfg.Server.Agent.CompletedCommandCache,
					)
				if registryErr != nil {
					return fmt.Errorf(
						"create Agent connection registry: %w",
						registryErr,
					)
				}
				agentCommandDispatcher = connectionRegistry
				managedHostUseCase.WithAgentControl(
					managedHostStore,
					connectionRegistry,
					cfg.Server.Agent.ProtocolVersions,
				)
				agentStream, streamErr := managedhostservice.NewAgentStream(
					managedHostUseCase,
					connectionRegistry,
					handshakeTimeout,
					heartbeatInterval,
					heartbeatTimeout,
					cfg.Server.Agent.MaxFrameBytes,
				)
				if streamErr != nil {
					return fmt.Errorf("create Agent stream: %w", streamErr)
				}
				serverCertificate, serverPrivateKey, materialErr :=
					cfg.Server.Agent.Materials()
				if materialErr != nil {
					return fmt.Errorf("load Agent server material: %w", materialErr)
				}
				agentHandler := httpx.RequestID(id.New)(
					httpx.AccessLog(logger)(
						httpx.Recovery(logger)(agentStream),
					),
				)
				agentControlServer, materialErr = server.NewAgentServer(
					cfg.Server.Agent,
					agentHandler,
					caCertificate,
					serverCertificate,
					serverPrivateKey,
					connectionRegistry,
				)
				for index := range serverPrivateKey {
					serverPrivateKey[index] = 0
				}
				if materialErr != nil {
					return fmt.Errorf("create Agent server: %w", materialErr)
				}
				agentProber, proberErr :=
					controlplanedata.NewAgentRuntimeTargetProber(
						connectionRegistry,
						id.New,
						time.Now,
						min(heartbeatTimeout, time.Minute),
					)
				if proberErr != nil {
					return fmt.Errorf(
						"create Agent runtime target prober: %w",
						proberErr,
					)
				}
				runtimeTargetProbers[runtimeaccess.ModeAgent] =
					agentProber
			}
		}
		managedHostHTTP := managedhostservice.NewHTTP(managedHostUseCase)
		controlPlaneUseCase := controlplanebiz.NewUseCaseWithResources(
			controlPlaneStore,
			controlPlaneStore,
			controlPlaneStore,
			controlPlaneStore,
			controlPlaneStore,
			controlPlaneStore,
			mongoClient,
			auditStore,
			auditStore,
			id.New,
			time.Now,
		).WithManagedHosts(managedHostStore).
			WithRuntimeTargetProbe(
				controlPlaneStore,
				controlplanedata.NewRuntimeTargetProbeRouter(
					runtimeTargetProbers,
				),
			)
		controlPlaneHTTP := controlplaneservice.NewHTTP(controlPlaneUseCase)
		deploymentStore := deploymentdata.NewMongoRepository(mongoClient.Database())
		deploymentHTTP := deploymentservice.NewHTTP(
			deploymentbiz.NewUseCase(deploymentStore, nil, nil, id.New, time.Now).
				WithFormalReferences(deploymentdata.NewFormalReferenceLookup(controlPlaneStore)).
				WithFormalSecurity(mongoClient, auditStore),
		)
		productAPI, err = server.NewProductAPIWithDeploymentAndManagedHost(
			identityHTTP,
			controlPlaneHTTP,
			http.HandlerFunc(deploymentHTTP.HandleFormal),
			managedHostHTTP,
			identityHTTP.Authenticate,
		)
		if err != nil {
			return fmt.Errorf("create product API: %w", err)
		}
		if cfg.Runtime.DeploymentWorker.Enabled {
			pollInterval, err := cfg.Runtime.DeploymentWorker.PollIntervalDuration()
			if err != nil {
				return err
			}
			leaseDuration, err := cfg.Runtime.DeploymentWorker.LeaseDurationValue()
			if err != nil {
				return err
			}
			operationTimeout, err := cfg.Runtime.DeploymentWorker.OperationTimeoutDuration()
			if err != nil {
				return err
			}
			runtimeGateways := map[runtimeaccess.Mode]deploymentbiz.RuntimeGateway{
				runtimeaccess.ModeDirectDocker: deploymentdata.
					NewDockerGateway().
					WithFence(deploymentStore),
			}
			if agentCommandDispatcher != nil {
				agentGateway, gatewayErr :=
					deploymentdata.NewAgentDockerGateway(
						agentCommandDispatcher,
						deploymentStore,
						id.New,
						time.Now,
						operationTimeout,
					)
				if gatewayErr != nil {
					return fmt.Errorf(
						"create Agent deployment gateway: %w",
						gatewayErr,
					)
				}
				runtimeGateways[runtimeaccess.ModeAgent] =
					agentGateway
			}
			executor, err := deploymentworker.NewRuntimeExecutor(
				deploymentdata.NewExecutionResolver(controlPlaneStore),
				deploymentdata.NewEnvironmentSecretResolver(),
				deploymentdata.NewRuntimeGatewayRouter(
					runtimeGateways,
				),
			)
			if err != nil {
				return fmt.Errorf("create deployment executor: %w", err)
			}
			executor.
				WithRegistryCredentials(deploymentdata.NewEnvironmentSecretResolver()).
				WithConfiguration(deploymentdata.NewEnvironmentSecretResolver())
			runner, err := deploymentworker.NewRunner(
				deploymentStore, executor, instanceID, leaseDuration, time.Now,
			)
			if err != nil {
				return fmt.Errorf("create deployment runner: %w", err)
			}
			runner.WithAudit(mongoClient, auditStore, id.New)
			loop, err := deploymentworker.NewLoop(
				runner, pollInterval, operationTimeout,
				func(workerErr error) {
					category := deploymentbiz.CategorizeExecutionError(
						workerErr, deploymentbiz.FailureUnknown,
					)
					_ = logger.Log(
						log.LevelError,
						"component", "deployment_worker",
						"failure.category", category,
					)
				},
			)
			if err != nil {
				return fmt.Errorf("create deployment worker loop: %w", err)
			}
			deploymentWorkerServer = lifecycle.NewServer(loop)
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

	managedServers := []transport.Server{httpServer}
	if deploymentWorkerServer != nil {
		managedServers = append(managedServers, deploymentWorkerServer)
	}
	if agentControlServer != nil {
		managedServers = append(managedServers, agentControlServer)
	}
	application := serverapp.NewServer(
		serviceName,
		version,
		instanceID,
		healthChecker,
		shutdownTimeout,
		logger,
		cleanup,
		managedServers...,
	)
	return application.Run()
}
