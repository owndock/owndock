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
	buildbiz "github.com/owndock/owndock/internal/modules/build/biz"
	builddata "github.com/owndock/owndock/internal/modules/build/data"
	buildservice "github.com/owndock/owndock/internal/modules/build/service"
	controlplanebiz "github.com/owndock/owndock/internal/modules/controlplane/biz"
	controlplanedata "github.com/owndock/owndock/internal/modules/controlplane/data"
	controlplaneservice "github.com/owndock/owndock/internal/modules/controlplane/service"
	controlplaneworker "github.com/owndock/owndock/internal/modules/controlplane/worker"
	deploymentbiz "github.com/owndock/owndock/internal/modules/deployment/biz"
	deploymentdata "github.com/owndock/owndock/internal/modules/deployment/data"
	deploymentservice "github.com/owndock/owndock/internal/modules/deployment/service"
	deploymentworker "github.com/owndock/owndock/internal/modules/deployment/worker"
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
	supplychainbiz "github.com/owndock/owndock/internal/modules/supplychain/biz"
	supplychaindata "github.com/owndock/owndock/internal/modules/supplychain/data"
	supplychainservice "github.com/owndock/owndock/internal/modules/supplychain/service"
	supplychainworker "github.com/owndock/owndock/internal/modules/supplychain/worker"
	terminalbiz "github.com/owndock/owndock/internal/modules/terminal/biz"
	terminaldata "github.com/owndock/owndock/internal/modules/terminal/data"
	terminalservice "github.com/owndock/owndock/internal/modules/terminal/service"
	platformaudit "github.com/owndock/owndock/internal/platform/audit"
	platformconfig "github.com/owndock/owndock/internal/platform/config"
	"github.com/owndock/owndock/internal/platform/health"
	"github.com/owndock/owndock/internal/platform/httpx"
	"github.com/owndock/owndock/internal/platform/id"
	"github.com/owndock/owndock/internal/platform/ingress"
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
	metrics := observability.NewMetrics()
	tracing, err := observability.NewTracing(context.Background(), cfg.Observability.Tracing, serviceName, version, instanceID)
	if err != nil {
		return fmt.Errorf("create tracing: %w", err)
	}
	var mongoClient *platformmongo.Client
	var productAPI *server.ProductAPI
	var deploymentWorkerServer *lifecycle.Server
	var runtimeTargetRetirementWorkerServer *lifecycle.Server
	var productResourceRetirementWorkerServer *lifecycle.Server
	var inventoryWorkerServer *lifecycle.Server
	var inventoryEventWorkerServer *lifecycle.Server
	var vulnerabilityRescanWorkerServer *lifecycle.Server
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
		invitationTTL, err := cfg.Security.UserInvitationTTLDuration()
		if err != nil {
			return fmt.Errorf("parse user invitation TTL: %w", err)
		}
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
		).WithInvitationPolicy(
			identityRepository, invitationTTL,
		).WithAdministrativeSessions(
			identityRepository,
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
		var agentConnectionRegistry *managedhostdata.ConnectionRegistry
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
				agentConnectionRegistry = connectionRegistry
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
				agentRoutes := http.NewServeMux()
				agentRoutes.Handle("/api/v1/agent/connect", agentStream)
				agentRoutes.Handle(
					"/api/v1/agent/certificate:rotate",
					managedhostservice.NewAgentCertificateRotationHTTP(managedHostUseCase),
				)
				serverCertificate, serverPrivateKey, materialErr :=
					cfg.Server.Agent.Materials()
				if materialErr != nil {
					return fmt.Errorf("load Agent server material: %w", materialErr)
				}
				agentHandler := httpx.RequestID(id.New)(
					httpx.AccessLog(logger)(
						httpx.Recovery(logger)(agentRoutes),
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
			WithProjectMembers(controlPlaneStore).
			WithTemplates(controlplanedata.NewBuiltInTemplateCatalog()).
			WithArtifactReleases(controlPlaneStore).
			WithRuntimeTargetProbe(
				controlPlaneStore,
				controlplanedata.NewRuntimeTargetProbeRouter(
					runtimeTargetProbers,
				),
			)
		controlPlaneHTTP := controlplaneservice.NewHTTP(controlPlaneUseCase)
		projectAccess := controlplaneservice.NewProjectAccess(controlPlaneStore)
		authenticateProject := func(next http.Handler) http.Handler {
			return identityHTTP.Authenticate(projectAccess.Authorize(next))
		}
		deploymentStore := deploymentdata.NewMongoRepository(mongoClient.Database())
		deploymentReferences := deploymentdata.NewFormalReferenceLookup(controlPlaneStore)
		deploymentUseCase := deploymentbiz.NewUseCase(deploymentStore, id.New, time.Now).
			WithFormalReferences(deploymentReferences).
			WithAutomaticReferences(deploymentReferences).
			WithFormalSecurity(mongoClient, auditStore)
		deploymentHTTP := deploymentservice.NewHTTP(deploymentUseCase)
		productAPI, err = server.NewProductAPIWithDeploymentAndManagedHost(
			identityHTTP,
			controlPlaneHTTP,
			http.HandlerFunc(deploymentHTTP.HandleFormal),
			managedHostHTTP,
			authenticateProject,
		)
		if err != nil {
			return fmt.Errorf("create product API: %w", err)
		}
		terminalStore := terminaldata.NewMongoRepository(mongoClient.Database())
		runtimeTargetInventoryConvergence :=
			runtimeinventorydata.NewRuntimeTargetConvergence(
				mongoClient.Database(),
			)
		terminalUseCase, err := terminalbiz.NewUseCase(
			terminalStore,
			terminalStore,
			terminaldata.NewTargetResolver(controlPlaneStore, deploymentStore, managedHostStore),
			terminaldata.NewProjectRoleResolver(controlPlaneStore),
			mongoClient,
			auditStore,
			terminaldata.TicketTokens{},
			id.New,
			time.Now,
		)
		if err != nil {
			return fmt.Errorf("create terminal use case: %w", err)
		}
		directContainerGateway, err := terminaldata.NewDirectContainerGateway(
			runtimeinventorydata.NewEnvironmentDirectCredentialResolver(),
		)
		if err != nil {
			return fmt.Errorf("create direct container terminal gateway: %w", err)
		}
		containerGateways := map[runtimeaccess.Mode]terminalbiz.ContainerGateway{
			runtimeaccess.ModeDirectDocker: directContainerGateway,
		}
		directSSHGateway, err := terminaldata.NewDirectSSHGateway(
			terminaldata.NewEnvironmentSSHPrivateKeyResolver(),
		)
		if err != nil {
			return fmt.Errorf("create direct SSH terminal gateway: %w", err)
		}
		hostGateways := map[runtimeaccess.Mode]terminalbiz.HostGateway{
			runtimeaccess.ModeDirectDocker: directSSHGateway,
		}
		if agentConnectionRegistry != nil {
			agentContainerGateway, gatewayErr :=
				terminaldata.NewAgentContainerGateway(agentConnectionRegistry)
			if gatewayErr != nil {
				return fmt.Errorf("create Agent container terminal gateway: %w", gatewayErr)
			}
			containerGateways[runtimeaccess.ModeAgent] = agentContainerGateway
			agentHostGateway, gatewayErr :=
				terminaldata.NewAgentHostGateway(agentConnectionRegistry)
			if gatewayErr != nil {
				return fmt.Errorf("create Agent host terminal gateway: %w", gatewayErr)
			}
			hostGateways[runtimeaccess.ModeAgent] = agentHostGateway
		}
		terminalUseCase.WithContainerGateway(
			terminaldata.NewContainerGatewayRouter(containerGateways),
		).WithHostGateway(
			terminaldata.NewHostGatewayRouter(hostGateways),
		).WithPrincipalResolver(identityUseCase)
		if err := productAPI.WithTerminal(
			terminalservice.NewHTTP(terminalUseCase, metrics), authenticateProject,
		); err != nil {
			return fmt.Errorf("mount terminal API: %w", err)
		}
		ingressWindow, err := cfg.Security.IngressRateWindowDuration()
		if err != nil {
			return fmt.Errorf("parse ingress rate window: %w", err)
		}
		clientIPs, err := ingress.NewClientIPResolver(cfg.Security.TrustedProxyCIDRs)
		if err != nil {
			return fmt.Errorf("create client IP resolver: %w", err)
		}
		ingressLimiter, err := ingress.NewLimiter(
			ingress.NewMongoGuard(mongoClient.Database()), clientIPs,
			cfg.Security.IngressSourceLimitValue(), cfg.Security.IngressGlobalLimitValue(),
			ingressWindow, time.Now,
		)
		if err != nil {
			return fmt.Errorf("create ingress limiter: %w", err)
		}
		if err := productAPI.WithIngressProtection(ingressLimiter.Protect); err != nil {
			return fmt.Errorf("mount ingress protection: %w", err)
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
			authenticateProject,
		); err != nil {
			return fmt.Errorf("mount runtime inventory API: %w", err)
		}
		buildLogRetention, err := cfg.Runtime.BuildWorker.BuildLogRetentionDuration()
		if err != nil {
			return fmt.Errorf("parse Build log retention: %w", err)
		}
		buildRepository := builddata.NewMongoRepository(mongoClient.Database()).WithBuildLogLimits(
			buildLogRetention, cfg.Runtime.BuildWorker.BuildLogMaxBytesValue(),
			cfg.Runtime.BuildWorker.BuildLogChunkBytesValue(),
		)
		buildReferences := builddata.NewConfigurationReferenceLookup(controlPlaneStore)
		sourceProbeTimeout, err := cfg.Product.SourceProbeTimeoutDuration()
		if err != nil {
			return fmt.Errorf("parse source repository probe timeout: %w", err)
		}
		gitSourceGateway, err := builddata.NewGitSourceProberWithNetwork(
			builddata.NewEnvironmentRepositorySecretResolver(),
			builddata.GitNetworkOptions{
				CACertFile: cfg.Product.SourceGitCACertFile, HTTPSProxyURL: cfg.Product.SourceGitHTTPSProxy,
			},
		)
		if err != nil {
			return fmt.Errorf("create Git source prober: %w", err)
		}
		gitSourceGateway.WithTimeout(sourceProbeTimeout)
		buildTriggerWindow, err := cfg.Product.BuildTriggerRateWindowDuration()
		if err != nil {
			return fmt.Errorf("parse build trigger rate window: %w", err)
		}
		buildWebhookWindow, err := cfg.Product.BuildWebhookRateWindowDuration()
		if err != nil {
			return fmt.Errorf("parse build webhook rate window: %w", err)
		}
		buildUseCase := buildbiz.NewUseCase(
			controlPlaneStore,
			buildRepository,
			mongoClient,
			auditStore,
			id.New,
			time.Now,
		).WithSourceProber(gitSourceGateway).
			WithSourceRevisionResolver(gitSourceGateway).
			WithWebhookVerifier(builddata.NewWebhookVerifier(
				builddata.NewEnvironmentWebhookSecretResolver(),
			)).WithWebhookAdmission(
			buildRepository, cfg.Product.BuildWebhookRateLimitValue(), buildWebhookWindow,
		).
			WithBuildTriggerAutomation(
				builddata.BuildTriggerTokens{}, buildRepository,
				cfg.Product.BuildTriggerRateLimitValue(), buildTriggerWindow,
			).WithConfigurationReferences(
			buildReferences,
			buildReferences,
		).WithAutomaticDeploymentReferences(buildReferences).
			WithArtifactReleases(buildRepository, builddata.NewArtifactReleaseAdapter(controlPlaneUseCase).
				WithAutomaticDeployments(deploymentUseCase)).
			WithBuildLogs(buildRepository)
		buildRetirement, err := buildbiz.NewProductResourceRetirement(
			buildRepository, mongoClient, auditStore, id.New, time.Now, 100,
		)
		if err != nil {
			return fmt.Errorf("create build retirement dependency: %w", err)
		}
		buildRetirement.WithArtifactReleaseResolver(
			builddata.NewArtifactReleaseRetirementResolver(controlPlaneStore),
		)
		if err := productAPI.WithBuild(
			buildservice.NewHTTP(buildUseCase).
				WithWebhookMaxBodyBytes(cfg.Product.BuildWebhookMaxBodyBytesValue()),
			authenticateProject,
		); err != nil {
			return fmt.Errorf("mount build API: %w", err)
		}
		supplyChainRepository := supplychaindata.NewMongoRepository(mongoClient.Database())
		registryCredentialProvider :=
			supplychaindata.NewEnvironmentRegistryCredentialProvider(controlPlaneStore)
		registryCABundle, err := supplychaindata.LoadRegistryCABundle(cfg.Product.RegistryCACertFile)
		if err != nil {
			return fmt.Errorf("load Registry CA bundle: %w", err)
		}
		artifactProber, err := supplychaindata.NewOCIArtifactProber(
			supplychaindata.OCIArtifactProberOptions{
				Credentials: registryCredentialProvider, RegistryCABundle: registryCABundle,
				RegistryHTTPSProxy: cfg.Product.RegistryHTTPSProxy,
			},
		)
		if err != nil {
			return fmt.Errorf("create OCI Artifact prober: %w", err)
		}
		buildUseCase.WithExternalArtifactRegistration(
			supplychaindata.NewArtifactEvidenceScheduler(
				supplyChainRepository, id.New, time.Now,
			).WithSignatureTrustPolicies(supplyChainRepository).
				WithVulnerabilityScanning(),
			artifactProber,
		)
		supplyChainUseCase, err := supplychainbiz.NewUseCase(
			controlPlaneStore,
			supplychaindata.NewArtifactLookupAdapter(buildRepository),
			supplyChainRepository,
		)
		if err != nil {
			return fmt.Errorf("create supply-chain use case: %w", err)
		}
		evidenceContentReader, err := supplychaindata.NewOCIContentReader(
			supplychaindata.OCIContentReaderOptions{
				Credentials:        registryCredentialProvider,
				MaxDocumentBytes:   cfg.Runtime.EvidenceWorker.MaxDocumentBytesValue(),
				RegistryCABundle:   registryCABundle,
				RegistryHTTPSProxy: cfg.Product.RegistryHTTPSProxy,
			},
		)
		if err != nil {
			return fmt.Errorf("create OCI Evidence content reader: %w", err)
		}
		supplyChainUseCase.WithContentReader(evidenceContentReader)
		supplyChainUseCase.WithVerificationRepository(supplyChainRepository)
		supplyChainUseCase.WithVulnerabilityObservations(supplyChainRepository, time.Now)
		deploymentAdmission, err := supplychaindata.NewDeploymentAdmissionEvaluator(
			supplychaindata.DeploymentAdmissionOptions{
				Releases: controlPlaneStore, Artifacts: supplychaindata.NewArtifactLookupAdapter(buildRepository),
				Policies: supplyChainRepository, Evidence: supplyChainRepository, Content: evidenceContentReader,
				Verifications: supplyChainRepository, TrustPolicies: supplyChainRepository,
				Vulnerabilities: supplyChainRepository, Waivers: supplyChainRepository, Now: time.Now,
			},
		)
		if err != nil {
			return fmt.Errorf("create deployment admission evaluator: %w", err)
		}
		deploymentUseCase.WithAdmissionEvaluator(deploymentAdmission)
		signatureTrustPolicies, err := supplychainbiz.NewSignatureTrustPolicyUseCase(
			controlPlaneStore, supplyChainRepository, id.New, time.Now,
		)
		if err != nil {
			return fmt.Errorf("create signature trust policy use case: %w", err)
		}
		signatureTrustPolicies.WithAudit(mongoClient, auditStore)
		signatureSigningProfiles, err := supplychainbiz.NewSignatureSigningProfileUseCase(
			controlPlaneStore, supplyChainRepository, supplyChainRepository, id.New, time.Now,
		)
		if err != nil {
			return fmt.Errorf("create signature signing profile use case: %w", err)
		}
		signatureSigningProfiles.WithAudit(mongoClient, auditStore)
		signatureVerifications, err := supplychainbiz.NewSignatureVerificationUseCase(
			supplychaindata.NewArtifactLookupAdapter(buildRepository), supplyChainRepository,
			supplyChainRepository, id.New, time.Now,
		)
		if err != nil {
			return fmt.Errorf("create signature verification use case: %w", err)
		}
		signatureVerifications.WithAudit(mongoClient, auditStore)
		vulnerabilityScans, err := supplychainbiz.NewVulnerabilityScanUseCase(
			supplychaindata.NewArtifactLookupAdapter(buildRepository), supplyChainRepository, id.New, time.Now,
		)
		if err != nil {
			return fmt.Errorf("create vulnerability scan use case: %w", err)
		}
		vulnerabilityScans.WithAudit(mongoClient, auditStore)
		vulnerabilityWaivers, err := supplychainbiz.NewVulnerabilityWaiverUseCase(
			controlPlaneStore, supplychaindata.NewArtifactLookupAdapter(buildRepository),
			supplyChainRepository, id.New, time.Now,
		)
		if err != nil {
			return fmt.Errorf("create vulnerability waiver use case: %w", err)
		}
		vulnerabilityWaivers.WithAudit(mongoClient, auditStore)
		deploymentPolicies, err := supplychainbiz.NewDeploymentPolicyUseCase(
			controlPlaneStore, controlPlaneStore, supplyChainRepository, id.New, time.Now,
		)
		if err != nil {
			return fmt.Errorf("create deployment policy use case: %w", err)
		}
		deploymentPolicies.WithAudit(mongoClient, auditStore)
		if err := productAPI.WithSupplyChain(
			supplychainservice.NewHTTP(supplyChainUseCase).
				WithSignatureTrustPolicies(signatureTrustPolicies).
				WithSignatureSigningProfiles(signatureSigningProfiles).
				WithSignatureVerifications(signatureVerifications).
				WithVulnerabilityScans(vulnerabilityScans).
				WithVulnerabilityWaivers(vulnerabilityWaivers).
				WithDeploymentPolicies(deploymentPolicies), authenticateProject,
		); err != nil {
			return fmt.Errorf("mount supply-chain API: %w", err)
		}
		if cfg.Product.VulnerabilityRescanEnabled {
			pollInterval, durationErr := cfg.Product.VulnerabilityRescanPollIntervalDuration()
			if durationErr != nil {
				return durationErr
			}
			retryInterval, durationErr := cfg.Product.VulnerabilityRescanRetryIntervalDuration()
			if durationErr != nil {
				return durationErr
			}
			operationTimeout, durationErr := cfg.Product.VulnerabilityRescanOperationTimeoutDuration()
			if durationErr != nil {
				return durationErr
			}
			scheduler, schedulerErr := supplychainbiz.NewVulnerabilityRescanScheduler(
				supplyChainRepository,
				supplychaindata.NewArtifactLookupAdapter(buildRepository),
				supplyChainRepository,
				time.Now,
				retryInterval,
				cfg.Product.VulnerabilityRescanCandidateLimitValue(),
			)
			if schedulerErr != nil {
				return fmt.Errorf("create vulnerability rescan scheduler: %w", schedulerErr)
			}
			rescanLoop, loopErr := supplychainworker.NewLoop(
				scheduler, pollInterval, operationTimeout,
				func(workerErr error) {
					_ = logger.Log(
						log.LevelError,
						"component", "vulnerability_rescan_worker",
						"error", workerErr,
					)
				},
			)
			if loopErr != nil {
				return fmt.Errorf("create vulnerability rescan worker loop: %w", loopErr)
			}
			rescanLoop.WithObservability(func(result string, duration time.Duration) {
				metrics.RecordWorkerPoll("vulnerability_rescan", result, duration)
			})
			vulnerabilityRescanWorkerServer = lifecycle.NewServer(rescanLoop)
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
			runtimeGateway := deploymentdata.NewRuntimeGatewayRouter(
				runtimeGateways,
			)
			secretResolver := deploymentdata.NewEnvironmentSecretResolver()
			executor, err := deploymentworker.NewRuntimeExecutor(
				deploymentdata.NewExecutionResolver(controlPlaneStore),
				secretResolver,
				runtimeGateway,
			)
			if err != nil {
				return fmt.Errorf("create deployment executor: %w", err)
			}
			executor.WithRegistryCredentials(secretResolver).
				WithConfiguration(secretResolver)
			retirement, retirementErr := deploymentbiz.NewRuntimeTargetRetirement(
				deploymentStore, secretResolver, runtimeGateway,
				mongoClient, auditStore, id.New, time.Now,
			)
			if retirementErr != nil {
				return fmt.Errorf("create runtime target retirement: %w", retirementErr)
			}
			retirement.WithConnectionResolver(
				deploymentdata.NewRetirementConnectionResolver(controlPlaneStore),
			)
			retirementAdapter := deploymentdata.NewRuntimeTargetRetirementAdapter(retirement)
			controlPlaneUseCase.WithRuntimeTargetRetirement(
				controlPlaneStore,
				retirementAdapter,
			).WithRuntimeTargetDependencies(
				terminalUseCase,
				runtimeTargetInventoryConvergence,
			).WithProductResourceRetirement(controlPlaneStore, retirementAdapter).
				WithProductResourceDependencies(buildRetirement, terminalUseCase)
			retirementLoop, retirementLoopErr :=
				controlplaneworker.NewRuntimeTargetRetirementLoop(
					controlPlaneUseCase, 16, pollInterval, operationTimeout,
					func(workerErr error) {
						_ = logger.Log(
							log.LevelError,
							"component", "runtime_target_retirement_worker",
							"error", workerErr,
						)
					},
				)
			if retirementLoopErr != nil {
				return fmt.Errorf(
					"create runtime target retirement worker loop: %w",
					retirementLoopErr,
				)
			}
			retirementLoop.WithObservability(
				func(result string, duration time.Duration) {
					metrics.RecordWorkerPoll(
						"runtime_target_retirement", result, duration,
					)
				},
			)
			runtimeTargetRetirementWorkerServer = lifecycle.NewServer(retirementLoop)
			resourceRetirementLoop, resourceRetirementLoopErr :=
				controlplaneworker.NewProductResourceRetirementLoop(
					controlPlaneUseCase, 16, pollInterval, operationTimeout,
					func(workerErr error) {
						_ = logger.Log(
							log.LevelError,
							"component", "product_resource_retirement_worker",
							"error", workerErr,
						)
					},
				)
			if resourceRetirementLoopErr != nil {
				return fmt.Errorf("create product resource retirement worker loop: %w", resourceRetirementLoopErr)
			}
			resourceRetirementLoop.WithObservability(
				func(result string, duration time.Duration) {
					metrics.RecordWorkerPoll("product_resource_retirement", result, duration)
				},
			)
			productResourceRetirementWorkerServer = lifecycle.NewServer(resourceRetirementLoop)
			runner, err := deploymentworker.NewRunner(
				deploymentStore, executor, instanceID, leaseDuration, time.Now,
			)
			if err != nil {
				return fmt.Errorf("create deployment runner: %w", err)
			}
			runner.WithAudit(mongoClient, auditStore, id.New)
			runner.WithObservability(tracing.Tracer(serviceName + ".deployment_worker"))
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
			loop.WithObservability(func(result string, duration time.Duration) {
				metrics.RecordWorkerPoll("deployment", result, duration)
			})
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
			inventoryRunner.WithObservability(
				tracing.Tracer(serviceName + ".runtime_inventory_worker"),
			)
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
			inventoryLoop.WithObservability(func(result string, duration time.Duration) {
				metrics.RecordWorkerPoll("runtime_inventory", result, duration)
			})
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
			inventoryEventRunner.WithObservability(
				tracing.Tracer(serviceName + ".runtime_inventory_event_worker"),
			)
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
			inventoryEventLoop.WithObservability(func(result string, duration time.Duration) {
				metrics.RecordWorkerPoll("runtime_inventory_events", result, duration)
			})
			inventoryEventWorkerServer = lifecycle.NewServer(inventoryEventLoop)
		}
	}
	httpServer, err := server.NewHTTPServer(
		cfg.Server.HTTP,
		healthChecker,
		metaService,
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
	if runtimeTargetRetirementWorkerServer != nil {
		managedServers = append(managedServers, runtimeTargetRetirementWorkerServer)
	}
	if productResourceRetirementWorkerServer != nil {
		managedServers = append(managedServers, productResourceRetirementWorkerServer)
	}
	if inventoryWorkerServer != nil {
		managedServers = append(managedServers, inventoryWorkerServer)
	}
	if inventoryEventWorkerServer != nil {
		managedServers = append(managedServers, inventoryEventWorkerServer)
	}
	if vulnerabilityRescanWorkerServer != nil {
		managedServers = append(managedServers, vulnerabilityRescanWorkerServer)
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
