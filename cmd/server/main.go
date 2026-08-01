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
	buildbiz "github.com/owndock/owndock/internal/modules/build/biz"
	builddata "github.com/owndock/owndock/internal/modules/build/data"
	buildservice "github.com/owndock/owndock/internal/modules/build/service"
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
	runtimeinventorybiz "github.com/owndock/owndock/internal/modules/runtimeinventory/biz"
	runtimeinventorydata "github.com/owndock/owndock/internal/modules/runtimeinventory/data"
	runtimeinventoryservice "github.com/owndock/owndock/internal/modules/runtimeinventory/service"
	runtimeinventoryworker "github.com/owndock/owndock/internal/modules/runtimeinventory/worker"
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
	var inventoryWorkerServer *lifecycle.Server
	var inventoryEventWorkerServer *lifecycle.Server
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
		runtimeInventoryViewUseCase, err := runtimeinventorybiz.NewViewUseCase(
			runtimeinventorydata.NewMongoViewRepository(mongoClient.Database()),
			auditStore,
			id.New,
			time.Now,
		)
		if err != nil {
			return fmt.Errorf("create runtime inventory view use case: %w", err)
		}
		if err := productAPI.WithRuntimeInventory(
			runtimeinventoryservice.NewHTTP(runtimeInventoryViewUseCase),
			identityHTTP.Authenticate,
		); err != nil {
			return fmt.Errorf("mount runtime inventory API: %w", err)
		}
		buildRepository := builddata.NewMongoRepository(mongoClient.Database())
		sourceProbeTimeout, err := cfg.Product.SourceProbeTimeoutDuration()
		if err != nil {
			return fmt.Errorf("parse source repository probe timeout: %w", err)
		}
		buildUseCase := buildbiz.NewUseCase(
			controlPlaneStore,
			buildRepository,
			mongoClient,
			auditStore,
			id.New,
			time.Now,
		).WithSourceProber(builddata.NewGitSourceProber(
			builddata.NewEnvironmentRepositorySecretResolver(),
		).WithTimeout(sourceProbeTimeout))
		if err := productAPI.WithBuild(
			buildservice.NewHTTP(buildUseCase),
			identityHTTP.Authenticate,
		); err != nil {
			return fmt.Errorf("mount build API: %w", err)
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
		if cfg.Runtime.InventoryWorker.Enabled {
			pollInterval, durationErr :=
				cfg.Runtime.InventoryWorker.PollIntervalDuration()
			if durationErr != nil {
				return durationErr
			}
			syncInterval, durationErr :=
				cfg.Runtime.InventoryWorker.SyncIntervalDuration()
			if durationErr != nil {
				return durationErr
			}
			retryInterval, durationErr :=
				cfg.Runtime.InventoryWorker.RetryIntervalDuration()
			if durationErr != nil {
				return durationErr
			}
			leaseDuration, durationErr :=
				cfg.Runtime.InventoryWorker.LeaseDurationValue()
			if durationErr != nil {
				return durationErr
			}
			operationTimeout, durationErr :=
				cfg.Runtime.InventoryWorker.OperationTimeoutDuration()
			if durationErr != nil {
				return durationErr
			}
			commandTimeout, durationErr :=
				cfg.Runtime.InventoryWorker.CommandTimeoutDuration()
			if durationErr != nil {
				return durationErr
			}
			eventPollInterval, durationErr :=
				cfg.Runtime.InventoryWorker.EventPollIntervalDuration()
			if durationErr != nil {
				return durationErr
			}
			eventWait, durationErr :=
				cfg.Runtime.InventoryWorker.EventWaitDuration()
			if durationErr != nil {
				return durationErr
			}
			inventoryRepository := runtimeinventorydata.NewMongoRepository(
				mongoClient.Database(),
			).WithOwnershipVerifier(
				runtimeinventorydata.NewMongoOwnershipVerifier(mongoClient.Database()),
			)
			scheduleRepository :=
				runtimeinventorydata.NewMongoScheduleRepository(
					mongoClient.Database(),
				)
			directCredentials :=
				runtimeinventorydata.NewEnvironmentDirectCredentialResolver()
			directCollector, collectorErr :=
				runtimeinventorydata.NewDirectTargetCollector(
					directCredentials,
					inventoryRepository,
					id.New,
					time.Now,
					cfg.Runtime.InventoryWorker.MaxChunkBytesValue(),
				)
			if collectorErr != nil {
				return fmt.Errorf(
					"create direct runtime inventory collector: %w",
					collectorErr,
				)
			}
			directCollector.WithEventHints(scheduleRepository)
			collectors := map[runtimeaccess.Mode]runtimeinventorybiz.Collector{
				runtimeaccess.ModeDirectDocker: directCollector,
			}
			directEventCollector, eventCollectorErr :=
				runtimeinventorydata.NewDirectEventCollector(
					directCredentials,
					scheduleRepository,
					eventWait,
					time.Now,
				)
			if eventCollectorErr != nil {
				return fmt.Errorf(
					"create direct runtime inventory event collector: %w",
					eventCollectorErr,
				)
			}
			eventCollectors :=
				map[runtimeaccess.Mode]runtimeinventorybiz.EventCollector{
					runtimeaccess.ModeDirectDocker: directEventCollector,
				}
			if agentCommandDispatcher != nil {
				agentCollector, agentCollectorErr :=
					runtimeinventorydata.NewAgentCollector(
						agentCommandDispatcher,
						inventoryRepository,
						id.New,
						time.Now,
						commandTimeout,
						cfg.Runtime.InventoryWorker.MaxChunkBytesValue(),
					)
				if agentCollectorErr != nil {
					return fmt.Errorf(
						"create Agent runtime inventory collector: %w",
						agentCollectorErr,
					)
				}
				agentCollector.WithEventHints(scheduleRepository)
				collectors[runtimeaccess.ModeAgent] = agentCollector
				agentEventCollector, agentEventCollectorErr :=
					runtimeinventorydata.NewAgentEventCollector(
						agentCommandDispatcher,
						scheduleRepository,
						id.New,
						time.Now,
						commandTimeout,
						eventWait,
					)
				if agentEventCollectorErr != nil {
					return fmt.Errorf(
						"create Agent runtime inventory event collector: %w",
						agentEventCollectorErr,
					)
				}
				eventCollectors[runtimeaccess.ModeAgent] = agentEventCollector
			}
			inventoryRunner, runnerErr := runtimeinventoryworker.NewRunner(
				scheduleRepository,
				runtimeinventorydata.NewCollectorRouter(collectors),
				instanceID,
				leaseDuration,
				syncInterval,
				retryInterval,
				cfg.Runtime.InventoryWorker.CandidateLimitValue(),
				time.Now,
			)
			if runnerErr != nil {
				return fmt.Errorf("create runtime inventory runner: %w", runnerErr)
			}
			inventoryLoop, loopErr := runtimeinventoryworker.NewLoop(
				inventoryRunner,
				pollInterval,
				operationTimeout,
				cfg.Runtime.InventoryWorker.ConcurrencyValue(),
				func(error) {
					_ = logger.Log(
						log.LevelError,
						"component", "runtime_inventory_worker",
						"failure.category", "collection_failed",
					)
				},
			)
			if loopErr != nil {
				return fmt.Errorf("create runtime inventory worker loop: %w", loopErr)
			}
			inventoryWorkerServer = lifecycle.NewServer(inventoryLoop)
			inventoryEventRunner, eventRunnerErr :=
				runtimeinventoryworker.NewEventRunner(
					scheduleRepository,
					runtimeinventorydata.NewEventCollectorRouter(eventCollectors),
					instanceID+"-inventory-events",
					leaseDuration,
					eventPollInterval,
					retryInterval,
					cfg.Runtime.InventoryWorker.CandidateLimitValue(),
					time.Now,
				)
			if eventRunnerErr != nil {
				return fmt.Errorf(
					"create runtime inventory event runner: %w",
					eventRunnerErr,
				)
			}
			inventoryEventLoop, eventLoopErr :=
				runtimeinventoryworker.NewLoop(
					inventoryEventRunner,
					eventPollInterval,
					operationTimeout,
					cfg.Runtime.InventoryWorker.EventConcurrencyValue(),
					func(error) {
						_ = logger.Log(
							log.LevelError,
							"component", "runtime_inventory_event_worker",
							"failure.category", "event_collection_failed",
						)
					},
				)
			if eventLoopErr != nil {
				return fmt.Errorf(
					"create runtime inventory event worker loop: %w",
					eventLoopErr,
				)
			}
			inventoryEventWorkerServer = lifecycle.NewServer(inventoryEventLoop)
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
	if inventoryWorkerServer != nil {
		managedServers = append(managedServers, inventoryWorkerServer)
	}
	if inventoryEventWorkerServer != nil {
		managedServers = append(managedServers, inventoryEventWorkerServer)
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
