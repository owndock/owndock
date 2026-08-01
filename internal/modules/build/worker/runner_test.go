package worker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/build/biz"
	"github.com/owndock/owndock/internal/shared/runtimespec"
	"github.com/owndock/owndock/internal/shared/transaction"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

type executionSourcesStub struct {
	source     biz.SourceRepository
	credential biz.RepositoryCredential
}

type executionRegistriesStub struct {
	credential biz.BuildRegistryCredential
	err        error
}

func (s executionRegistriesStub) GetBuildRegistryCredential(context.Context, string, string) (biz.BuildRegistryCredential, error) {
	return s.credential, s.err
}

func (s executionSourcesStub) GetSource(context.Context, string, string) (biz.SourceRepository, error) {
	return s.source, nil
}
func (s executionSourcesStub) GetCredential(context.Context, string, string) (biz.RepositoryCredential, error) {
	return s.credential, nil
}

type checkoutStub struct {
	request biz.CheckoutRequest
	err     error
}

type buildExecutorStub struct {
	request biz.BuildExecutionRequest
	output  biz.BuildExecutionOutput
	err     error
}

type artifactReleaseCreatorStub struct {
	request   biz.ArtifactReleaseRequest
	releaseID string
	err       error
}

type buildLogWriterStub struct {
	items []biz.BuildLogAppend
	err   error
}

func (s *buildLogWriterStub) AppendBuildLog(_ context.Context, item biz.BuildLogAppend) error {
	s.items = append(s.items, item)
	return s.err
}

func (s *artifactReleaseCreatorStub) CreateArtifactRelease(_ context.Context, request biz.ArtifactReleaseRequest) (string, error) {
	s.request = request
	return s.releaseID, s.err
}

func (s *buildExecutorStub) Build(_ context.Context, request biz.BuildExecutionRequest) (biz.BuildExecutionOutput, error) {
	s.request = request
	return s.output, s.err
}

func (s *checkoutStub) Checkout(_ context.Context, request biz.CheckoutRequest) error {
	s.request = request
	if s.err == nil {
		return os.WriteFile(filepath.Join(request.Destination, "checked-out"), []byte(request.Revision.CommitSHA), 0o600)
	}
	return s.err
}

func TestRunnerChecksOutBuildsAndRecordsPushedDigest(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	queue := &queueStub{item: checkoutTestBuild(now)}
	audit := &auditStub{}
	controller, err := NewController(queue, transaction.Passthrough{}, audit,
		func() (string, error) { return "audit-1", nil }, func() time.Time { return now }, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	controller.WithArtifacts(queue)
	checkout := &checkoutStub{}
	builder := &buildExecutorStub{output: biz.BuildExecutionOutput{
		ImageDigest: "registry.example.com/team/api@sha256:" + strings.Repeat("a", 64),
	}}
	workspace, err := NewLocalWorkspace(filepath.Join(t.TempDir(), "builds"))
	if err != nil {
		t.Fatal(err)
	}
	runner, err := NewRunner(controller, checkoutSources(), checkoutRegistries(), checkout, builder,
		workspace, "source-worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	logs := &buildLogWriterStub{}
	runner.WithBuildLogs(logs, func() time.Time { return now }, nil)
	var observedResult string
	var observedLogBytes int
	spanRecorder := tracetest.NewSpanRecorder()
	tracerProvider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spanRecorder))
	t.Cleanup(func() { _ = tracerProvider.Shutdown(context.Background()) })
	runner.WithObservability(tracerProvider.Tracer("build-worker"), func(result string, _ time.Duration) {
		observedResult = result
	}, func(_ string, bytes int, err error) {
		if err == nil {
			observedLogBytes += bytes
		}
	})
	if err := runner.RunOnce(t.Context()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if queue.item.Status != biz.BuildStatusSucceeded || checkout.request.Revision != queue.item.Revision ||
		queue.item.ImageDigest != builder.output.ImageDigest || builder.request.Generation == 0 {
		t.Fatalf("build/request = %+v / %+v", queue.item, checkout.request)
	}
	if _, err := os.Stat(checkout.request.Destination); !os.IsNotExist(err) {
		t.Fatalf("ephemeral checkout was not removed: %v", err)
	}
	if len(audit.events) != 6 || audit.events[0].Action != "build.checking_out" ||
		audit.events[1].Action != "build.building" || audit.events[2].Action != "build.pushing" ||
		audit.events[3].Action != "build.image_pushed" || audit.events[4].Action != "artifact.create" ||
		audit.events[5].Action != "build.succeeded" || len(queue.artifacts) != 1 ||
		queue.item.ArtifactID != queue.artifacts[0].ID {
		t.Fatalf("audit events = %+v", audit.events)
	}
	if len(logs.items) < 6 || logs.items[0].Stage != biz.BuildLogStageSystem ||
		logs.items[1].Stage != biz.BuildLogStageCheckout ||
		logs.items[len(logs.items)-1].Stage != biz.BuildLogStageRelease {
		t.Fatalf("build logs = %+v", logs.items)
	}
	if observedResult != "success" || observedLogBytes == 0 {
		t.Fatalf("observed result/bytes = %q/%d", observedResult, observedLogBytes)
	}
	endedSpans := spanRecorder.Ended()
	if len(endedSpans) != 1 || endedSpans[0].Name() != "build.execute" ||
		endedSpans[0].Status().Code != codes.Unset {
		t.Fatalf("ended spans = %+v", endedSpans)
	}
}

func TestRunnerMapsCheckoutFailureWithoutLeakingCause(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	queue := &queueStub{item: checkoutTestBuild(now)}
	controller, err := NewController(queue, transaction.Passthrough{}, &auditStub{},
		func() (string, error) { return "audit-1", nil }, func() time.Time { return now }, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	checkout := &checkoutStub{err: errors.New("token=do-not-leak")}
	workspace, err := NewLocalWorkspace(filepath.Join(t.TempDir(), "builds"))
	if err != nil {
		t.Fatal(err)
	}
	runner, err := NewRunner(controller, checkoutSources(), checkoutRegistries(), checkout,
		&buildExecutorStub{}, workspace, "source-worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	err = runner.RunOnce(t.Context())
	if err == nil || queue.item.Status != biz.BuildStatusFailed || queue.item.FailureCategory != biz.BuildFailureCheckout {
		t.Fatalf("RunOnce() = %v, build = %+v", err, queue.item)
	}
	if contains := errors.Is(err, checkout.err) || stringContains(err.Error(), "do-not-leak"); contains {
		t.Fatalf("checkout cause leaked: %v", err)
	}
}

func TestRunnerRecoversPushedDigestWithoutRebuildingAndCreatesRelease(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	item := checkoutTestBuild(now)
	item.Status = biz.BuildStatusPushing
	item.Configuration.AutoCreateRelease = true
	item.Configuration.ReleaseRuntimeSpec = runtimespec.Spec{
		Ports:     []runtimespec.Port{{Name: "http", ContainerPort: 8080, Protocol: "tcp"}},
		Resources: runtimespec.Resources{CPUMilli: 750, MemoryBytes: 384 * 1024 * 1024},
	}
	item.ImageDigest = "registry.example.com/team/api@sha256:" + strings.Repeat("b", 64)
	queue := &queueStub{item: item}
	audit := &auditStub{}
	sequence := 0
	controller, err := NewController(queue, transaction.Passthrough{}, audit,
		func() (string, error) { sequence++; return fmt.Sprintf("id-%d", sequence), nil },
		func() time.Time { return now }, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	controller.WithArtifacts(queue)
	checkout := &checkoutStub{}
	builder := &buildExecutorStub{}
	workspace, err := NewLocalWorkspace(filepath.Join(t.TempDir(), "builds"))
	if err != nil {
		t.Fatal(err)
	}
	releases := &artifactReleaseCreatorStub{releaseID: "release-1"}
	runner, err := NewRunner(controller, checkoutSources(), checkoutRegistries(), checkout, builder,
		workspace, "source-worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	runner.WithArtifactReleases(queue, releases)
	if err := runner.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if checkout.request.Destination != "" || builder.request.BuildID != "" ||
		queue.item.Status != biz.BuildStatusSucceeded || len(queue.artifacts) != 1 ||
		queue.artifacts[0].ReleaseStatus != biz.ArtifactReleaseCreated ||
		queue.artifacts[0].ReleaseID != "release-1" || releases.request.ArtifactID != queue.artifacts[0].ID ||
		len(releases.request.RuntimeSpec.Ports) != 1 || releases.request.RuntimeSpec.Ports[0].ContainerPort != 8080 ||
		releases.request.RuntimeSpec.Resources.CPUMilli != 750 {
		t.Fatalf("build=%+v artifact=%+v checkout=%+v builder=%+v release=%+v",
			queue.item, queue.artifacts, checkout.request, builder.request, releases.request)
	}
}

func TestRunnerMapsRegistryFailureWithoutLeakingCause(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	queue := &queueStub{item: checkoutTestBuild(now)}
	controller, err := NewController(queue, transaction.Passthrough{}, &auditStub{},
		func() (string, error) { return "audit-1", nil }, func() time.Time { return now }, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	controller.WithArtifacts(queue)
	workspace, err := NewLocalWorkspace(filepath.Join(t.TempDir(), "builds"))
	if err != nil {
		t.Fatal(err)
	}
	builder := &buildExecutorStub{err: fmt.Errorf("registry token=do-not-leak: %w", biz.ErrRegistryAuthentication)}
	runner, err := NewRunner(controller, checkoutSources(), checkoutRegistries(), &checkoutStub{}, builder,
		workspace, "source-worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	err = runner.RunOnce(t.Context())
	if err == nil || queue.item.Status != biz.BuildStatusFailed ||
		queue.item.FailureCategory != biz.BuildFailureRegistryAuthentication {
		t.Fatalf("RunOnce() = %v, build = %+v", err, queue.item)
	}
	if strings.Contains(err.Error(), "do-not-leak") || errors.Is(err, builder.err) {
		t.Fatalf("BuildKit cause leaked: %v", err)
	}
	if len(queue.artifacts) != 0 || queue.item.ArtifactID != "" {
		t.Fatalf("failed build published an Artifact: %+v", queue.artifacts)
	}
	failedID := queue.item.ID
	retry, retryErr := queue.item.Retry("build-retry", "retry-after-network", "user-1", now.Add(time.Second))
	if retryErr != nil {
		t.Fatal(retryErr)
	}
	queue.item = retry
	builder.err = nil
	builder.output = biz.BuildExecutionOutput{
		ImageDigest: "registry.example.com/team/api@sha256:" + strings.Repeat("c", 64),
	}
	if err := runner.RunOnce(t.Context()); err != nil {
		t.Fatalf("retry RunOnce() error = %v", err)
	}
	if queue.item.Status != biz.BuildStatusSucceeded || queue.item.SourceBuildID != failedID ||
		len(queue.artifacts) != 1 || queue.artifacts[0].BuildID != retry.ID {
		t.Fatalf("recovered retry = %+v artifacts=%+v", queue.item, queue.artifacts)
	}
}

func TestRunnerMapsBuildKitDiskExhaustionWithoutPublishingOrLeaking(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	queue := &queueStub{item: checkoutTestBuild(now)}
	controller, err := NewController(queue, transaction.Passthrough{}, &auditStub{},
		func() (string, error) { return "audit-1", nil }, func() time.Time { return now }, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	controller.WithArtifacts(queue)
	workspace, err := NewLocalWorkspace(filepath.Join(t.TempDir(), "builds"))
	if err != nil {
		t.Fatal(err)
	}
	builderCause := fmt.Errorf("no space at /secret/customer/path: %w", biz.ErrBuildResourceLimit)
	runner, err := NewRunner(controller, checkoutSources(), checkoutRegistries(), &checkoutStub{},
		&buildExecutorStub{err: builderCause}, workspace, "source-worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	err = runner.RunOnce(t.Context())
	if err == nil || queue.item.Status != biz.BuildStatusFailed ||
		queue.item.FailureCategory != biz.BuildFailureResourceLimit || len(queue.artifacts) != 0 {
		t.Fatalf("disk exhaustion RunOnce() = %v build=%+v artifacts=%+v", err, queue.item, queue.artifacts)
	}
	if strings.Contains(err.Error(), "/secret/customer/path") || errors.Is(err, builderCause) {
		t.Fatalf("disk exhaustion detail leaked: %v", err)
	}
}

func TestRunnerCompletesCooperativeCancellationWithoutCheckout(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	item := checkoutTestBuild(now)
	item.Status = biz.BuildStatusCanceling
	queue := &queueStub{item: item}
	controller, err := NewController(queue, transaction.Passthrough{}, &auditStub{},
		func() (string, error) { return "audit-1", nil }, func() time.Time { return now }, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	checkout := &checkoutStub{}
	workspace, err := NewLocalWorkspace(filepath.Join(t.TempDir(), "builds"))
	if err != nil {
		t.Fatal(err)
	}
	runner, err := NewRunner(controller, checkoutSources(), checkoutRegistries(), checkout,
		&buildExecutorStub{}, workspace, "source-worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.RunOnce(t.Context()); err != nil || queue.item.Status != biz.BuildStatusCanceled || checkout.request.Destination != "" {
		t.Fatalf("RunOnce() = %v, build/request = %+v/%+v", err, queue.item, checkout.request)
	}
}

func checkoutTestBuild(now time.Time) biz.Build {
	return biz.Build{
		ID: "build-1", OrganizationID: "organization-1", ProjectID: "project-1",
		ApplicationID: "application-1", BuildConfigurationID: "configuration-1",
		Revision: biz.SourceRevision{SourceRepositoryID: "source-1", Ref: "refs/heads/main", CommitSHA: "a975c10d68a2d7461634f13b15c52a2efba72d16"},
		Configuration: biz.BuildConfigurationSnapshot{
			ConfigurationID: "configuration-1", ConfigurationVersion: 1,
			SourceRepositoryID: "source-1", DockerfilePath: "Dockerfile", ContextPath: ".",
			RegistryCredentialID: "registry-1", ImageRepository: "registry.example.com/team/api",
			TargetPlatform: biz.BuildPlatformLinuxAMD64, TimeoutSeconds: 300,
			Resources: biz.BuildResources{CPUMilli: 2000, MemoryBytes: 2 * 1024 * 1024 * 1024, DiskBytes: 10 * 1024 * 1024 * 1024},
		},
		Status: biz.BuildStatusQueued, Version: 1, CreatedAt: now, UpdatedAt: now,
	}
}

func checkoutRegistries() executionRegistriesStub {
	return executionRegistriesStub{credential: biz.BuildRegistryCredential{
		ID: "registry-1", ProjectID: "project-1", Server: "registry.example.com",
		Username: "builder", PasswordRef: "secret://production",
	}}
}

func checkoutSources() executionSourcesStub {
	return executionSourcesStub{source: biz.SourceRepository{
		ID: "source-1", ProjectID: "project-1", RepositoryURL: "https://git.example.com/team/api.git",
		Protocol: biz.RepositoryProtocolHTTPS, Status: biz.SourceRepositoryStatusReady,
	}}
}

func stringContains(value, fragment string) bool {
	for index := 0; index+len(fragment) <= len(value); index++ {
		if value[index:index+len(fragment)] == fragment {
			return true
		}
	}
	return false
}
