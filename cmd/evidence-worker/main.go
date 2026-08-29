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

	controlplanedata "github.com/owndock/owndock/internal/modules/controlplane/data"
	supplychainbiz "github.com/owndock/owndock/internal/modules/supplychain/biz"
	supplychaindata "github.com/owndock/owndock/internal/modules/supplychain/data"
	supplychainworker "github.com/owndock/owndock/internal/modules/supplychain/worker"
	platformconfig "github.com/owndock/owndock/internal/platform/config"
	"github.com/owndock/owndock/internal/platform/id"
	"github.com/owndock/owndock/internal/platform/migration"
	platformmongo "github.com/owndock/owndock/internal/platform/mongo"
	platformobservability "github.com/owndock/owndock/internal/platform/observability"
)

const serviceName = "owndock-evidence-worker"

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
	flags.StringVar(&configPath, "conf", "configs/config.yaml", "Evidence Worker configuration file or directory")
	flags.BoolVar(&showVersion, "version", false, "print version and exit")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if showVersion {
		_, err := fmt.Fprintf(os.Stdout, "%s %s (%s, %s)\n", serviceName, version, commit, buildTime)
		return err
	}
	cfg, err := platformconfig.Load(configPath)
	if err != nil {
		return err
	}
	workerConfig := cfg.Runtime.EvidenceWorker
	if !workerConfig.Enabled {
		return errors.New("runtime.evidence_worker.enabled must be true")
	}
	pollInterval, _ := workerConfig.PollIntervalDuration()
	leaseDuration, _ := workerConfig.LeaseDurationValue()
	operationTimeout, _ := workerConfig.OperationTimeoutDuration()
	vulnerabilityFreshness, _ := workerConfig.VulnerabilityFreshnessDuration()
	workerID, err := id.New()
	if err != nil {
		return fmt.Errorf("create Evidence Worker identity: %w", err)
	}
	workerID = "evidence-" + workerID
	logger := slog.With("service.name", serviceName, "service.version", version, "worker.id", workerID)
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
	repository := supplychaindata.NewMongoRepository(client.Database())
	controller, err := supplychainworker.NewController(repository, time.Now, leaseDuration)
	if err != nil {
		return fmt.Errorf("create Evidence Worker controller: %w", err)
	}
	credentialProvider := supplychaindata.NewEnvironmentRegistryCredentialProvider(
		controlplanedata.NewMongoStore(client.Database()),
	)
	generator, err := supplychaindata.NewSyftGenerator(supplychaindata.SyftOptions{
		Executable: workerConfig.SyftExecutable, ExpectedVersion: workerConfig.SyftVersion,
		MaxOutputBytes: workerConfig.MaxDocumentBytesValue(),
		MaxLayerBytes:  workerConfig.MaxLayerBytesValue(), Credentials: credentialProvider,
	})
	if err != nil {
		return fmt.Errorf("create pinned Syft generator: %w", err)
	}
	verifyContext, cancelVerify := context.WithTimeout(ctx, 10*time.Second)
	err = generator.Verify(verifyContext)
	cancelVerify()
	if err != nil {
		return fmt.Errorf("verify pinned Syft generator: %w", err)
	}
	publisher, err := supplychaindata.NewORASPublisher(supplychaindata.ORASPublisherOptions{
		Credentials: credentialProvider, MaxDocumentBytes: workerConfig.MaxDocumentBytesValue(),
	})
	if err != nil {
		return fmt.Errorf("create OCI Evidence publisher: %w", err)
	}
	runner, err := supplychainworker.NewRunner(
		controller, generator, publisher, id.New, time.Now, workerID, leaseDuration,
	)
	if err != nil {
		return fmt.Errorf("create Evidence Worker runner: %w", err)
	}
	provenanceGenerator, err := supplychaindata.NewSLSAProvenanceGenerator(
		supplychainbiz.MaximumProvenanceDocumentSize,
	)
	if err != nil {
		return fmt.Errorf("create SLSA provenance generator: %w", err)
	}
	runner, err = runner.WithProvenance(provenanceGenerator, publisher)
	if err != nil {
		return fmt.Errorf("enable SLSA provenance: %w", err)
	}
	cosignVerifier, err := supplychaindata.NewCosignVerifier(supplychaindata.CosignVerifierOptions{
		Executable: workerConfig.CosignExecutable, ExpectedVersion: workerConfig.CosignVersion,
		Credentials: credentialProvider, TemporaryRoot: os.TempDir(),
	})
	if err != nil {
		return fmt.Errorf("create pinned Cosign verifier: %w", err)
	}
	verifyContext, cancelVerify = context.WithTimeout(ctx, 10*time.Second)
	err = cosignVerifier.Verify(verifyContext)
	cancelVerify()
	if err != nil {
		return fmt.Errorf("verify pinned Cosign verifier: %w", err)
	}
	trustResolver, err := supplychaindata.NewFileSignatureTrustResolver(workerConfig.TrustedRootsDirectory)
	if err != nil {
		return fmt.Errorf("create offline signature trust resolver: %w", err)
	}
	runner, err = runner.WithSignatures(cosignVerifier, trustResolver)
	if err != nil {
		return fmt.Errorf("enable signature verification: %w", err)
	}
	cosignSigner, err := supplychaindata.NewCosignSigner(supplychaindata.CosignSignerOptions{
		Executable: workerConfig.CosignExecutable, ExpectedVersion: workerConfig.CosignVersion,
		Credentials:        credentialProvider,
		SigningEnvironment: supplychaindata.EnvironmentSigningEnvironmentResolver{},
		TemporaryRoot:      os.TempDir(),
	})
	if err != nil {
		return fmt.Errorf("create pinned Cosign signer: %w", err)
	}
	runner, err = runner.WithSigning(cosignSigner)
	if err != nil {
		return fmt.Errorf("enable KMS signature creation: %w", err)
	}
	trivyScanner, err := supplychaindata.NewTrivyScanner(supplychaindata.TrivyOptions{
		Executable: workerConfig.TrivyExecutable, ExpectedVersion: workerConfig.TrivyVersion,
		CacheDirectory: workerConfig.TrivyCacheDirectory,
		MaxOutputBytes: minInt64(workerConfig.MaxDocumentBytesValue(), supplychainbiz.MaximumVulnerabilityReportSize),
		Credentials:    credentialProvider,
	})
	if err != nil {
		return fmt.Errorf("create pinned Trivy scanner: %w", err)
	}
	verifyContext, cancelVerify = context.WithTimeout(ctx, 10*time.Second)
	err = trivyScanner.Verify(verifyContext)
	cancelVerify()
	if err != nil {
		return fmt.Errorf("verify pinned Trivy scanner and database: %w", err)
	}
	runner, err = runner.WithVulnerabilityScanning(trivyScanner, publisher, vulnerabilityFreshness)
	if err != nil {
		return fmt.Errorf("enable vulnerability scanning: %w", err)
	}
	loop, err := supplychainworker.NewLoop(runner, pollInterval, operationTimeout, func(runErr error) {
		logger.Error("Evidence operation failed", "error", runErr)
	})
	if err != nil {
		return fmt.Errorf("create Evidence Worker loop: %w", err)
	}
	loop.WithObservability(func(result string, duration time.Duration) {
		metrics.RecordWorkerPoll("evidence", result, duration)
	})
	listener, err := net.Listen("tcp", workerConfig.MetricsAddressValue())
	if err != nil {
		return fmt.Errorf("listen for Evidence Worker metrics: %w", err)
	}
	operationsServer := &http.Server{
		Handler: newOperationsHandler(metrics, client.Ping), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: time.Minute,
	}
	defer func() {
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = operationsServer.Shutdown(shutdownContext)
	}()
	logger.Info("Evidence Worker started", "syft.version", workerConfig.SyftVersion,
		"cosign.version", workerConfig.CosignVersion,
		"trivy.version", workerConfig.TrivyVersion,
		"oras.version", supplychaindata.ORASGoVersion,
		"provenance.predicate", supplychainbiz.SLSAProvenancePredicateV1,
		"metrics.address", workerConfig.MetricsAddressValue())
	runContext, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	errorsChannel := make(chan error, 2)
	go func() { errorsChannel <- loop.Run(runContext) }()
	go func() { errorsChannel <- operationsServer.Serve(listener) }()
	runErr := <-errorsChannel
	cancelRun()
	if runErr != nil && !errors.Is(runErr, context.Canceled) && !errors.Is(runErr, http.ErrServerClosed) {
		return runErr
	}
	return nil
}

func minInt64(left, right int64) int64 {
	if left < right {
		return left
	}
	return right
}

func newOperationsHandler(
	metrics *platformobservability.Metrics,
	ping func(context.Context) error,
) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", metrics.Handler())
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
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
