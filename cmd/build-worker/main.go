package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	builddata "github.com/owndock/owndock/internal/modules/build/data"
	buildworker "github.com/owndock/owndock/internal/modules/build/worker"
	controlplanebiz "github.com/owndock/owndock/internal/modules/controlplane/biz"
	controlplanedata "github.com/owndock/owndock/internal/modules/controlplane/data"
	deploymentbiz "github.com/owndock/owndock/internal/modules/deployment/biz"
	deploymentdata "github.com/owndock/owndock/internal/modules/deployment/data"
	supplychainbiz "github.com/owndock/owndock/internal/modules/supplychain/biz"
	supplychaindata "github.com/owndock/owndock/internal/modules/supplychain/data"
	platformaudit "github.com/owndock/owndock/internal/platform/audit"
	platformconfig "github.com/owndock/owndock/internal/platform/config"
	"github.com/owndock/owndock/internal/platform/id"
	"github.com/owndock/owndock/internal/platform/migration"
	platformmongo "github.com/owndock/owndock/internal/platform/mongo"
	platformobservability "github.com/owndock/owndock/internal/platform/observability"
)

const serviceName = "owndock-build-worker"

var (
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string) error {
	flags := flag.NewFlagSet(serviceName, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var configPath string
	var showVersion bool
	var storageRoot string
	var storageHardQuotaBytes int64
	flags.StringVar(&configPath, "conf", "configs/config.yaml", "Build Worker configuration file or directory")
	flags.BoolVar(&showVersion, "version", false, "print version and exit")
	flags.StringVar(&storageRoot, "check-storage-root", "", "verify one independent hard-quota filesystem and exit")
	flags.Int64Var(&storageHardQuotaBytes, "check-storage-hard-quota-bytes", 0, "maximum advertised filesystem capacity for storage preflight")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if showVersion {
		_, err := fmt.Fprintf(os.Stdout, "%s %s (%s, %s)\n", serviceName, version, commit, buildTime)
		return err
	}
	if storageRoot != "" || storageHardQuotaBytes != 0 {
		if storageRoot == "" || storageHardQuotaBytes <= 0 {
			return errors.New("check-storage-root and check-storage-hard-quota-bytes must be provided together")
		}
		if err := buildworker.ValidateHardQuotaFilesystem(storageRoot, storageHardQuotaBytes); err != nil {
			return fmt.Errorf("storage hard-quota preflight failed: %w", err)
		}
		return nil
	}
	cfg, err := platformconfig.Load(configPath)
	if err != nil {
		return err
	}
	workerConfig := cfg.Runtime.BuildWorker
	if !workerConfig.Enabled {
		return errors.New("runtime.build_worker.enabled must be true")
	}
	pollInterval, _ := workerConfig.PollIntervalDuration()
	leaseDuration, _ := workerConfig.LeaseDurationValue()
	operationTimeout, _ := workerConfig.OperationTimeoutDuration()
	checkoutTimeout, _ := workerConfig.CheckoutTimeoutDuration()
	workerID, err := id.New()
	if err != nil {
		return fmt.Errorf("create Build Worker identity: %w", err)
	}
	workerID = "build-" + workerID
	logger := slog.With("service.name", serviceName, "service.version", version, "worker.id", workerID)
	tracing, err := platformobservability.NewTracing(
		ctx, cfg.Observability.Tracing, serviceName, version, workerID,
	)
	if err != nil {
		return fmt.Errorf("create Build Worker tracing: %w", err)
	}
	defer func() {
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = tracing.Shutdown(shutdownContext)
	}()
	metrics := platformobservability.NewMetrics()
	client, err := platformmongo.Open(ctx, cfg.Database.Mongo)
	if err != nil {
		return fmt.Errorf("open MongoDB: %w", err)
	}
	defer func() {
		closeContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = client.Close(closeContext)
	}()
	if err := migration.NewRunner(client.Database(), workerID).Run(ctx, migration.Default()); err != nil {
		return fmt.Errorf("run MongoDB migrations: %w", err)
	}
	buildLogRetention, err := workerConfig.BuildLogRetentionDuration()
	if err != nil {
		return fmt.Errorf("parse Build log retention: %w", err)
	}
	repository := builddata.NewMongoRepository(client.Database()).WithBuildLogLimits(
		buildLogRetention, workerConfig.BuildLogMaxBytesValue(), workerConfig.BuildLogChunkBytesValue(),
	)
	auditStore := platformaudit.NewMongoStore(client.Database())
	controller, err := buildworker.NewController(
		repository, client, auditStore,
		id.New, time.Now, leaseDuration,
	)
	if err != nil {
		return fmt.Errorf("create Build execution controller: %w", err)
	}
	var workspace *buildworker.LocalWorkspace
	if workerConfig.RequireWorkspaceQuota {
		workspace, err = buildworker.NewHardQuotaWorkspace(
			workerConfig.WorkspaceRoot, workerConfig.WorkspaceHardQuotaBytesValue(),
		)
	} else {
		workspace, err = buildworker.NewLocalWorkspace(workerConfig.WorkspaceRoot)
	}
	if err != nil {
		return fmt.Errorf("create Build workspace: %w", err)
	}
	secretResolver := builddata.NewEnvironmentRepositorySecretResolver()
	checkout, err := builddata.NewGitCheckoutGateway(
		secretResolver,
		builddata.GitCheckoutOptions{
			Executable: workerConfig.GitExecutable, ExpectedVersion: workerConfig.GitVersion,
			Timeout: checkoutTimeout, MaxWorkspaceBytes: workerConfig.MaxWorkspaceBytes,
			MaxWorkspaceFiles: workerConfig.MaxWorkspaceFiles,
			MaxWorkspaceDepth: workerConfig.MaxWorkspaceDepth,
			Network: builddata.GitNetworkOptions{
				CACertFile: cfg.Product.SourceGitCACertFile, HTTPSProxyURL: cfg.Product.SourceGitHTTPSProxy,
			},
		},
	)
	if err != nil {
		return fmt.Errorf("create pinned Git checkout: %w", err)
	}
	buildKitContext, cancelBuildKit := context.WithTimeout(ctx, 15*time.Second)
	defer cancelBuildKit()
	builder, err := builddata.NewBuildKitGateway(buildKitContext, secretResolver, builddata.BuildKitOptions{
		Endpoint: workerConfig.BuildKitEndpoint, ServerName: workerConfig.BuildKitServerName,
		CACertFile: workerConfig.BuildKitCACertFile, ClientCertFile: workerConfig.BuildKitClientCertFile,
		ClientKeyFile: workerConfig.BuildKitClientKeyFile, EgressProxyURL: workerConfig.BuildEgressProxyURL,
	})
	if err != nil {
		return fmt.Errorf("create pinned BuildKit gateway: %w", err)
	}
	controlPlaneStore := controlplanedata.NewMongoStore(client.Database())
	registrySource := builddata.NewBuildRegistrySource(controlPlaneStore)
	controlPlaneUseCase := controlplanebiz.NewUseCaseWithResources(
		controlPlaneStore, controlPlaneStore, controlPlaneStore, controlPlaneStore,
		controlPlaneStore, controlPlaneStore, client, auditStore, auditStore, id.New, time.Now,
	).WithArtifactReleases(controlPlaneStore)
	deploymentStore := deploymentdata.NewMongoRepository(client.Database())
	deploymentReferences := deploymentdata.NewFormalReferenceLookup(controlPlaneStore)
	deploymentUseCase := deploymentbiz.NewUseCase(deploymentStore, id.New, time.Now).
		WithFormalReferences(deploymentReferences).
		WithAutomaticReferences(deploymentReferences).
		WithFormalSecurity(client, auditStore)
	artifactReleases := builddata.NewArtifactReleaseAdapter(controlPlaneUseCase).
		WithAutomaticDeployments(deploymentUseCase)
	controller.WithArtifacts(repository)
	evidenceRepository := supplychaindata.NewMongoRepository(client.Database())
	registryCABundle, err := supplychaindata.LoadRegistryCABundle(cfg.Product.RegistryCACertFile)
	if err != nil {
		return fmt.Errorf("load Registry CA bundle: %w", err)
	}
	evidenceContentReader, err := supplychaindata.NewOCIContentReader(
		supplychaindata.OCIContentReaderOptions{
			Credentials:      supplychaindata.NewEnvironmentRegistryCredentialProvider(controlPlaneStore),
			MaxDocumentBytes: cfg.Runtime.EvidenceWorker.MaxDocumentBytesValue(),
			RegistryCABundle: registryCABundle, RegistryHTTPSProxy: cfg.Product.RegistryHTTPSProxy,
		},
	)
	if err != nil {
		return fmt.Errorf("create deployment admission Evidence reader: %w", err)
	}
	deploymentAdmission, err := supplychaindata.NewDeploymentAdmissionEvaluator(
		supplychaindata.DeploymentAdmissionOptions{
			Releases: controlPlaneStore, Artifacts: supplychaindata.NewArtifactLookupAdapter(repository),
			Policies: evidenceRepository, Evidence: evidenceRepository, Content: evidenceContentReader,
			Verifications: evidenceRepository, TrustPolicies: evidenceRepository,
			Vulnerabilities: evidenceRepository, Waivers: evidenceRepository, Now: time.Now,
		},
	)
	if err != nil {
		return fmt.Errorf("create deployment admission evaluator: %w", err)
	}
	deploymentUseCase.WithAdmissionEvaluator(deploymentAdmission)
	controller.WithArtifactEvidence(supplychaindata.NewArtifactEvidenceScheduler(
		evidenceRepository, id.New, time.Now,
	).WithProvenance(repository, supplychaindata.ProvenanceBuilderIdentity{
		BuilderID:      supplychainbiz.OwnDockBuildKitBuilderIDV1,
		BuilderVersion: version, BuilderCommit: commit,
		BuildKitVersion: builddata.PinnedBuildKitVersion,
		BuildKitImage:   builddata.PinnedBuildKitImage,
		FrontendImage:   builddata.PinnedDockerfileFrontend,
	}).WithSignatureTrustPolicies(evidenceRepository).
		WithSignatureSigningProfiles(evidenceRepository).
		WithVulnerabilityScanning())
	runner, err := buildworker.NewRunner(
		controller, repository, registrySource, checkout, builder, workspace, workerID, leaseDuration,
	)
	if err != nil {
		return fmt.Errorf("create Build Worker runner: %w", err)
	}
	runner.WithArtifactReleases(repository, artifactReleases)
	runner.WithBuildLogs(repository, time.Now, func(logErr error) {
		logger.Error("Persist Build log failed", "error", logErr)
	})
	runner.WithObservability(tracing.Tracer(serviceName), metrics.RecordBuildOperation, metrics.RecordBuildLog)
	loop, err := buildworker.NewLoop(runner, pollInterval, operationTimeout, func(runErr error) {
		logger.Error("Build operation failed", "error", runErr)
	})
	if err != nil {
		return fmt.Errorf("create Build Worker loop: %w", err)
	}
	loop.WithObservability(func(result string, duration time.Duration) {
		metrics.RecordWorkerPoll("build", result, duration)
	})
	logger.Info("Build Worker started", "git.version", workerConfig.GitVersion,
		"buildkit.version", builddata.PinnedBuildKitVersion,
		"metrics.address", workerConfig.MetricsAddressValue())
	listener, err := net.Listen("tcp", workerConfig.MetricsAddressValue())
	if err != nil {
		return fmt.Errorf("listen for Build Worker metrics: %w", err)
	}
	metricsServer := &http.Server{
		Handler: newOperationsHandler(metrics, client.Ping), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: time.Minute,
	}
	defer func() {
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = metricsServer.Shutdown(shutdownContext)
	}()
	runContext, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	errorsChannel := make(chan error, 2)
	go func() { errorsChannel <- loop.Run(runContext) }()
	go func() { errorsChannel <- metricsServer.Serve(listener) }()
	runErr := <-errorsChannel
	cancelRun()
	if runErr != nil && !errors.Is(runErr, context.Canceled) && !errors.Is(runErr, http.ErrServerClosed) {
		return runErr
	}
	return nil
}

func newOperationsHandler(
	metrics *platformobservability.Metrics,
	ping func(context.Context) error,
) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", metrics.Handler())
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if ping == nil || ping(request.Context()) != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("not ready\n"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	return mux
}
