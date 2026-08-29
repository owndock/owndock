package worker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/modules/build/biz"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

var (
	ErrMissingSourceRepository = errors.New("build execution source repository is required")
	ErrMissingRegistrySource   = errors.New("build execution registry source is required")
	ErrMissingCheckoutGateway  = errors.New("build checkout gateway is required")
	ErrMissingBuildExecutor    = errors.New("build executor is required")
	ErrMissingArtifactReleases = errors.New("artifact release coordinator is required")
	ErrMissingWorkspace        = errors.New("build workspace is required")
	ErrInvalidWorkerID         = errors.New("build worker id is invalid")
	ErrLeaseRenewal            = errors.New("build lease renewal failed")
)

// Runner executes the isolated checkout, BuildKit push, Artifact publication,
// and optional Release handoff. The API Server only validates and queues work.
type Runner struct {
	controller    *Controller
	sources       biz.ExecutionSourceRepository
	registries    biz.BuildRegistrySource
	checkout      biz.CheckoutGateway
	builder       biz.BuildExecutor
	artifacts     biz.ArtifactRepository
	releases      biz.ArtifactReleaseCreator
	workspace     Workspace
	workerID      string
	leaseDuration time.Duration
	logs          biz.BuildLogWriter
	logNow        biz.Clock
	logError      func(error)
	tracer        trace.Tracer
	observeRun    func(string, time.Duration)
	observeLog    func(string, int, error)
}

func (r *Runner) WithArtifactReleases(artifacts biz.ArtifactRepository, releases biz.ArtifactReleaseCreator) *Runner {
	r.artifacts, r.releases = artifacts, releases
	return r
}

func (r *Runner) WithBuildLogs(logs biz.BuildLogWriter, now biz.Clock, onError func(error)) *Runner {
	r.logs, r.logNow, r.logError = logs, now, onError
	return r
}

func (r *Runner) WithObservability(tracer trace.Tracer,
	observeRun func(string, time.Duration), observeLog func(string, int, error)) *Runner {
	r.tracer, r.observeRun, r.observeLog = tracer, observeRun, observeLog
	return r
}

func NewRunner(controller *Controller, sources biz.ExecutionSourceRepository,
	registries biz.BuildRegistrySource, checkout biz.CheckoutGateway,
	builder biz.BuildExecutor, workspace Workspace, workerID string,
	leaseDuration time.Duration) (*Runner, error) {
	workerID = strings.TrimSpace(workerID)
	if controller == nil {
		return nil, ErrMissingQueue
	}
	if sources == nil {
		return nil, ErrMissingSourceRepository
	}
	if registries == nil {
		return nil, ErrMissingRegistrySource
	}
	if checkout == nil {
		return nil, ErrMissingCheckoutGateway
	}
	if builder == nil {
		return nil, ErrMissingBuildExecutor
	}
	if workspace == nil {
		return nil, ErrMissingWorkspace
	}
	if workerID == "" || leaseDuration <= 0 {
		return nil, ErrInvalidWorkerID
	}
	controller.WithClaimStatuses(biz.BuildStatusCanceling, biz.BuildStatusQueued, biz.BuildStatusCheckingOut,
		biz.BuildStatusBuilding, biz.BuildStatusPushing)
	return &Runner{controller: controller, sources: sources, registries: registries,
		checkout: checkout, builder: builder,
		workspace: workspace, workerID: workerID, leaseDuration: leaseDuration}, nil
}

func (r *Runner) RunOnce(ctx context.Context) (runErr error) {
	item, claimed, err := r.controller.Claim(ctx, r.workerID)
	if err != nil {
		return err
	}
	if !claimed {
		return r.coordinatePendingRelease(ctx)
	}
	startedAt := time.Now()
	var span trace.Span
	if r.tracer != nil {
		ctx, span = r.tracer.Start(ctx, "build.execute", trace.WithAttributes(
			attribute.String("build.id", item.ID),
			attribute.String("build.project_id", item.ProjectID),
			attribute.String("build.status", string(item.Status)),
			attribute.Int64("build.lease_generation", int64(item.Lease.Generation)),
		))
		defer span.End()
	}
	defer func() {
		result := "success"
		if runErr != nil {
			result = "error"
			if span != nil {
				span.SetStatus(codes.Error, "Build operation failed")
			}
		}
		if r.observeRun != nil {
			r.observeRun(result, time.Since(startedAt))
		}
	}()
	r.appendLog(ctx, item, biz.BuildLogStageSystem, "Build claimed by an isolated worker")
	if item.Status == biz.BuildStatusCanceling {
		r.appendLog(ctx, item, biz.BuildLogStageSystem, "Cancel requested; cleaning the ephemeral workspace")
		if err := r.workspace.Cleanup(item.ID); err != nil {
			return fmt.Errorf("clean canceled build workspace: %w", err)
		}
		_, err = r.controller.Advance(ctx, item, r.workerID, biz.BuildStatusCanceled)
		if err == nil {
			r.appendLog(ctx, item, biz.BuildLogStageSystem, "Build canceled")
		}
		return err
	}
	if item.Status == biz.BuildStatusQueued {
		item, err = r.controller.Advance(ctx, item, r.workerID, biz.BuildStatusCheckingOut)
		if err != nil {
			return err
		}
	}
	if item.Status == biz.BuildStatusPushing && item.ImageDigest != "" {
		r.appendLog(ctx, item, biz.BuildLogStagePush, "Recovered the pushed image digest; publishing the Artifact without rebuilding")
		return r.publishArtifact(ctx, item)
	}
	if item.Status != biz.BuildStatusCheckingOut && item.Status != biz.BuildStatusBuilding &&
		item.Status != biz.BuildStatusPushing {
		return nil
	}
	destination, err := r.workspace.Prepare(item.ID, item.Lease.Generation)
	if err != nil {
		return r.fail(ctx, item, biz.BuildFailureResourceLimit)
	}
	defer func() { _ = r.workspace.Cleanup(item.ID) }()

	source, credential, err := r.resolveSource(ctx, item)
	if err != nil {
		return r.fail(ctx, item, categorizeCheckout(err))
	}
	r.appendLog(ctx, item, biz.BuildLogStageCheckout, "Checking out the pinned Git commit")
	item, err = r.runCheckout(ctx, item, biz.CheckoutRequest{
		Source: source, Credential: credential, Revision: item.Revision, Destination: destination,
	})
	if err != nil {
		if errors.Is(err, ErrLeaseRenewal) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return r.fail(ctx, item, categorizeCheckout(err))
	}
	r.appendLog(ctx, item, biz.BuildLogStageCheckout, "Pinned Git commit verified")
	if item.Status == biz.BuildStatusCheckingOut {
		item, err = r.controller.Advance(ctx, item, r.workerID, biz.BuildStatusBuilding)
		if err != nil {
			return err
		}
	}
	if item.Status == biz.BuildStatusBuilding {
		item, err = r.controller.Advance(ctx, item, r.workerID, biz.BuildStatusPushing)
		if err != nil {
			return err
		}
	}
	r.appendLog(ctx, item, biz.BuildLogStageBuild, "Starting the isolated Dockerfile build")
	registryCredential, err := r.registries.GetBuildRegistryCredential(
		ctx, item.ProjectID, item.Configuration.RegistryCredentialID,
	)
	if err != nil {
		return r.fail(ctx, item, biz.BuildFailureConfiguration)
	}
	var output biz.BuildExecutionOutput
	item, err = r.runStep(ctx, item, func(stepContext context.Context) error {
		var buildErr error
		output, buildErr = r.builder.Build(stepContext, biz.BuildExecutionRequest{
			BuildID: item.ID, ProjectID: item.ProjectID, Generation: item.Lease.Generation,
			Workspace: destination, Configuration: item.Configuration, Credential: registryCredential,
			LogSink: r.buildLogSink(item),
		})
		return buildErr
	})
	if err != nil {
		if errors.Is(err, ErrLeaseRenewal) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return r.fail(ctx, item, categorizeBuildExecution(err))
	}
	r.appendLog(ctx, item, biz.BuildLogStagePush, "Registry accepted the image and returned a canonical digest")
	item, err = r.controller.RecordPushedImage(ctx, item, r.workerID, output.ImageDigest)
	if err != nil {
		return err
	}
	return r.publishArtifact(ctx, item)
}

func (r *Runner) publishArtifact(ctx context.Context, item biz.Build) error {
	_, artifact, err := r.controller.PublishArtifact(ctx, item, r.workerID)
	if err != nil {
		return err
	}
	r.appendLog(ctx, item, biz.BuildLogStageRelease, "Immutable Artifact published")
	if artifact.ReleaseStatus != biz.ArtifactReleasePending {
		return nil
	}
	return r.createArtifactRelease(ctx, artifact)
}

func (r *Runner) coordinatePendingRelease(ctx context.Context) error {
	if r.artifacts == nil || r.releases == nil {
		return ErrMissingArtifactReleases
	}
	artifact, found, err := r.artifacts.NextPendingArtifact(ctx)
	if err != nil || !found {
		return err
	}
	return r.createArtifactRelease(ctx, artifact)
}

func (r *Runner) createArtifactRelease(ctx context.Context, artifact biz.Artifact) error {
	if r.artifacts == nil || r.releases == nil {
		return ErrMissingArtifactReleases
	}
	releaseID, err := r.releases.CreateArtifactRelease(ctx, biz.ArtifactReleaseRequest{
		ArtifactID: artifact.ID, OrganizationID: artifact.OrganizationID,
		ProjectID: artifact.ProjectID, ApplicationID: artifact.ApplicationID,
		RegistryCredentialID: artifact.RegistryCredentialID,
		ImageDigest:          artifact.ImageDigest,
		RuntimeSpec:          artifact.ReleaseRuntimeSpec,
		AutomaticDeployments: append([]biz.AutomaticDeploymentRule(nil), artifact.AutomaticDeployments...),
		BuildID:              artifact.BuildID,
		BuildConfigurationID: artifact.BuildConfigurationID,
		ActorID:              "system:" + r.workerID,
	})
	if err != nil {
		return fmt.Errorf("coordinate artifact release: %w", err)
	}
	_, err = r.controller.RecordArtifactRelease(ctx, artifact, r.workerID, releaseID)
	if errors.Is(err, biz.ErrVersionConflict) {
		current, getErr := r.artifacts.GetArtifact(ctx, artifact.ProjectID, artifact.ID)
		if getErr == nil && current.ReleaseStatus == biz.ArtifactReleaseCreated && current.ReleaseID == releaseID {
			return nil
		}
	}
	if err == nil {
		r.appendLog(ctx, biz.Build{ID: artifact.BuildID, ProjectID: artifact.ProjectID},
			biz.BuildLogStageRelease, "Immutable Release created from the Artifact")
	}
	return err
}

func (r *Runner) resolveSource(ctx context.Context, item biz.Build) (biz.SourceRepository, *biz.RepositoryCredential, error) {
	source, err := r.sources.GetSource(ctx, item.ProjectID, item.Revision.SourceRepositoryID)
	if err != nil {
		return biz.SourceRepository{}, nil, err
	}
	if source.CredentialID == "" {
		return source, nil, nil
	}
	credential, err := r.sources.GetCredential(ctx, item.ProjectID, source.CredentialID)
	if err != nil {
		return biz.SourceRepository{}, nil, err
	}
	return source, &credential, nil
}

func (r *Runner) runCheckout(ctx context.Context, item biz.Build, request biz.CheckoutRequest) (biz.Build, error) {
	return r.runStep(ctx, item, func(stepContext context.Context) error {
		return r.checkout.Checkout(stepContext, request)
	})
}

func (r *Runner) runStep(ctx context.Context, item biz.Build, operation func(context.Context) error) (biz.Build, error) {
	item, err := r.controller.Heartbeat(ctx, item, r.workerID)
	if err != nil {
		return item, errors.Join(ErrLeaseRenewal, err)
	}
	stepContext, cancel := context.WithCancel(ctx)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- operation(stepContext) }()
	heartbeatInterval := r.leaseDuration / 3
	if heartbeatInterval <= 0 {
		heartbeatInterval = time.Nanosecond
	}
	heartbeat := time.NewTicker(heartbeatInterval)
	defer heartbeat.Stop()
	for {
		select {
		case err := <-result:
			return item, err
		case <-heartbeat.C:
			item, err = r.controller.Heartbeat(ctx, item, r.workerID)
			if err != nil {
				cancel()
				<-result
				return item, errors.Join(ErrLeaseRenewal, err)
			}
		case <-ctx.Done():
			cancel()
			<-result
			return item, ctx.Err()
		}
	}
}

func (r *Runner) fail(ctx context.Context, item biz.Build, category biz.BuildFailureCategory) error {
	r.appendLog(ctx, item, biz.BuildLogStageSystem, "Build failed: "+string(category))
	_, saveErr := r.controller.Fail(ctx, item, r.workerID, category)
	return errors.Join(fmt.Errorf("execute build %s: %w", item.ID, safeExecutionError(category)), saveErr)
}

func (r *Runner) buildLogSink(item biz.Build) biz.BuildLogSink {
	if r.logs == nil {
		return nil
	}
	return func(ctx context.Context, stage biz.BuildLogStage, message string) {
		r.appendLog(ctx, item, stage, message)
	}
}

func (r *Runner) appendLog(ctx context.Context, item biz.Build, stage biz.BuildLogStage, message string) {
	if r.logs == nil || r.logNow == nil {
		return
	}
	err := r.logs.AppendBuildLog(ctx, biz.BuildLogAppend{
		BuildID: item.ID, ProjectID: item.ProjectID, Stage: stage,
		Message: message, CreatedAt: r.logNow().UTC(),
	})
	if r.observeLog != nil {
		r.observeLog(string(stage), len([]byte(message)), err)
	}
	if err != nil && r.logError != nil {
		r.logError(err)
	}
}

func categorizeCheckout(err error) biz.BuildFailureCategory {
	switch {
	case errors.Is(err, biz.ErrCheckoutAuthentication):
		return biz.BuildFailureRepositoryAuthentication
	case errors.Is(err, biz.ErrCheckoutUnreachable):
		return biz.BuildFailureRepositoryUnreachable
	case errors.Is(err, biz.ErrCheckoutRevision):
		return biz.BuildFailureRevisionNotFound
	case errors.Is(err, biz.ErrCheckoutResourceLimit), errors.Is(err, biz.ErrBuildResourceLimit):
		return biz.BuildFailureResourceLimit
	default:
		return biz.BuildFailureCheckout
	}
}

func categorizeBuildExecution(err error) biz.BuildFailureCategory {
	switch {
	case errors.Is(err, biz.ErrRegistryAuthentication):
		return biz.BuildFailureRegistryAuthentication
	case errors.Is(err, biz.ErrRegistryPushFailed):
		return biz.BuildFailureRegistryPush
	case errors.Is(err, biz.ErrInvalidBuildExecution):
		return biz.BuildFailureConfiguration
	case errors.Is(err, biz.ErrCheckoutResourceLimit), errors.Is(err, biz.ErrBuildResourceLimit):
		return biz.BuildFailureResourceLimit
	case errors.Is(err, biz.ErrBuildNetworkDenied):
		return biz.BuildFailureNetworkPolicy
	default:
		return biz.BuildFailureBuild
	}
}

func safeExecutionError(category biz.BuildFailureCategory) error {
	return fmt.Errorf("build execution failed (%s)", category)
}
