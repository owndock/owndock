package biz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/runtimespec"
	"github.com/owndock/owndock/internal/shared/security"
	"github.com/owndock/owndock/internal/shared/transaction"
)

type IDGenerator func() (string, error)
type Clock func() time.Time

type ProjectLookup interface {
	ProjectExists(context.Context, string, string) (bool, error)
}

type ApplicationLookup interface {
	ApplicationExists(context.Context, string, string) (bool, error)
}

type RegistryCredentialLookup interface {
	RegistryServer(context.Context, string, string) (string, error)
}

type AutomaticDeploymentReferenceLookup interface {
	ValidateAutomaticDeployment(context.Context, string, string, string) error
}

type Repository interface {
	ListCredentials(context.Context, string) ([]CredentialSummary, error)
	CreateCredential(context.Context, RepositoryCredential) (CredentialSummary, error)
	GetCredential(context.Context, string, string) (RepositoryCredential, error)
	ListSources(context.Context, string) ([]SourceRepository, error)
	CreateSource(context.Context, SourceRepository) (SourceRepository, error)
	GetSource(context.Context, string, string) (SourceRepository, error)
	UpdateSourceProbe(
		context.Context,
		string,
		string,
		SourceRepositoryStatus,
		time.Time,
	) (SourceRepository, error)
	ListBuildConfigurations(context.Context, string, string) ([]BuildConfiguration, error)
	CreateBuildConfiguration(context.Context, BuildConfiguration) (BuildConfiguration, error)
	GetBuildConfiguration(context.Context, string, string, string) (BuildConfiguration, error)
	UpdateBuildConfiguration(
		context.Context,
		BuildConfiguration,
		uint64,
	) (BuildConfiguration, error)
	ListBuilds(context.Context, string) ([]Build, error)
	CreateBuild(context.Context, Build) (Build, error)
	SaveBuild(context.Context, Build, uint64) (Build, error)
	GetBuild(context.Context, string, string) (Build, error)
	GetBuildByIdempotency(context.Context, string, string) (Build, error)
	ListBuildTriggers(context.Context, string, string, string) ([]BuildTrigger, error)
	CreateBuildTrigger(context.Context, BuildTrigger) (BuildTrigger, error)
	GetBuildTrigger(context.Context, string) (BuildTrigger, error)
	RevokeBuildTrigger(context.Context, BuildTrigger, uint64) (BuildTrigger, error)
	ListBuildHooks(context.Context, string, string, string) ([]BuildHookSummary, error)
	CreateBuildHook(context.Context, BuildHook) (BuildHookSummary, error)
	GetBuildHook(context.Context, string) (BuildHook, error)
	RevokeBuildHook(context.Context, BuildHook, uint64) (BuildHookSummary, error)
	CreateWebhookDelivery(context.Context, WebhookDelivery) error
	GetWebhookDelivery(context.Context, string, WebhookProvider, string) (WebhookDelivery, error)
}

type BuildTriggerRateGuard interface {
	ReserveBuildTrigger(context.Context, string, time.Time, int, time.Duration) (bool, time.Time, error)
}

type WebhookRateGuard interface {
	ReserveBuildWebhook(context.Context, string, time.Time, int, time.Duration) (bool, time.Time, error)
}

type BuildTriggerRateLimitError struct{ RetryAfter time.Duration }

func (e *BuildTriggerRateLimitError) Error() string { return ErrBuildTriggerRateLimited.Error() }
func (e *BuildTriggerRateLimitError) Is(target error) bool {
	return target == ErrBuildTriggerRateLimited
}

type WebhookRateLimitError struct{ RetryAfter time.Duration }

func (e *WebhookRateLimitError) Error() string { return ErrWebhookRateLimited.Error() }
func (e *WebhookRateLimitError) Is(target error) bool {
	return target == ErrWebhookRateLimited
}

type SourceProber interface {
	ProbeSource(
		context.Context,
		SourceRepository,
		*RepositoryCredential,
	) (SourceRepositoryStatus, error)
}

type SourceRevisionResolver interface {
	ResolveSourceRevision(
		context.Context,
		SourceRepository,
		*RepositoryCredential,
		string,
		string,
	) (SourceRevision, error)
}

var ErrSourceProbeUnavailable = errors.New("source repository probe is unavailable")

type UseCase struct {
	projects         ProjectLookup
	repository       Repository
	transaction      transaction.Manager
	audit            sharedaudit.Recorder
	newID            IDGenerator
	now              Clock
	prober           SourceProber
	resolver         SourceRevisionResolver
	applications     ApplicationLookup
	registries       RegistryCredentialLookup
	automation       AutomaticDeploymentReferenceLookup
	triggerTokens    BuildTriggerTokens
	triggerGuard     BuildTriggerRateGuard
	triggerLimit     int
	triggerWindow    time.Duration
	webhooks         WebhookVerifier
	webhookGuard     WebhookRateGuard
	webhookLimit     int
	webhookWindow    time.Duration
	artifacts        ArtifactRepository
	artifactReleases ArtifactReleaseCreator
	buildLogs        BuildLogRepository
}

func (u *UseCase) WithArtifactReleases(repository ArtifactRepository, creator ArtifactReleaseCreator) *UseCase {
	u.artifacts, u.artifactReleases = repository, creator
	return u
}

func (u *UseCase) WithBuildLogs(repository BuildLogRepository) *UseCase {
	u.buildLogs = repository
	return u
}

func (u *UseCase) WithWebhookVerifier(verifier WebhookVerifier) *UseCase {
	u.webhooks = verifier
	return u
}

// WithWebhookAdmission installs a shared admission limit for unique, validly
// signed deliveries. Replays are authenticated but do not consume another slot.
func (u *UseCase) WithWebhookAdmission(
	guard WebhookRateGuard,
	limit int,
	window time.Duration,
) *UseCase {
	u.webhookGuard, u.webhookLimit, u.webhookWindow = guard, limit, window
	return u
}

func (u *UseCase) WithBuildTriggerAutomation(
	tokens BuildTriggerTokens,
	guard BuildTriggerRateGuard,
	limit int,
	window time.Duration,
) *UseCase {
	u.triggerTokens, u.triggerGuard = tokens, guard
	u.triggerLimit, u.triggerWindow = limit, window
	return u
}

func (u *UseCase) WithSourceRevisionResolver(resolver SourceRevisionResolver) *UseCase {
	u.resolver = resolver
	return u
}

func (u *UseCase) WithConfigurationReferences(
	applications ApplicationLookup,
	registries RegistryCredentialLookup,
) *UseCase {
	u.applications = applications
	u.registries = registries
	return u
}

func (u *UseCase) WithAutomaticDeploymentReferences(
	references AutomaticDeploymentReferenceLookup,
) *UseCase {
	u.automation = references
	return u
}

func (u *UseCase) WithSourceProber(prober SourceProber) *UseCase {
	u.prober = prober
	return u
}

func NewUseCase(
	projects ProjectLookup,
	repository Repository,
	transactionManager transaction.Manager,
	audit sharedaudit.Recorder,
	newID IDGenerator,
	now Clock,
) *UseCase {
	return &UseCase{
		projects: projects, repository: repository,
		transaction: transactionManager, audit: audit,
		newID: newID, now: now,
	}
}

func (u *UseCase) ListCredentials(
	ctx context.Context,
	principal security.Principal,
	projectID string,
) ([]CredentialSummary, error) {
	if err := principal.Require(security.PermissionSourceRepositoryRead); err != nil {
		return nil, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return nil, err
	}
	return u.repository.ListCredentials(ctx, projectID)
}

func (u *UseCase) CreateCredential(
	ctx context.Context,
	principal security.Principal,
	projectID, name string,
	credentialType CredentialType,
	username, secretReference, publicKeyFingerprint, requestID string,
) (CredentialSummary, error) {
	if err := principal.Require(security.PermissionSourceRepositoryWrite); err != nil {
		return CredentialSummary{}, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return CredentialSummary{}, err
	}
	id, auditID, now, err := u.identifiers()
	if err != nil {
		return CredentialSummary{}, err
	}
	credential, err := NewRepositoryCredential(
		id, projectID, name, credentialType, username, secretReference,
		publicKeyFingerprint, principal.UserID, now,
	)
	if err != nil {
		return CredentialSummary{}, err
	}
	var created CredentialSummary
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		var createErr error
		created, createErr = u.repository.CreateCredential(transactionContext, credential)
		if createErr != nil {
			return createErr
		}
		return u.record(
			transactionContext, principal, auditID,
			"repository_credential.create", "repository_credential",
			created.ID, projectID, requestID, now,
		)
	})
	return created, err
}

func (u *UseCase) ListSources(
	ctx context.Context,
	principal security.Principal,
	projectID string,
) ([]SourceRepository, error) {
	if err := principal.Require(security.PermissionSourceRepositoryRead); err != nil {
		return nil, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return nil, err
	}
	return u.repository.ListSources(ctx, projectID)
}

func (u *UseCase) GetSource(
	ctx context.Context,
	principal security.Principal,
	projectID, sourceID string,
) (SourceRepository, error) {
	if err := principal.Require(security.PermissionSourceRepositoryRead); err != nil {
		return SourceRepository{}, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return SourceRepository{}, err
	}
	return u.repository.GetSource(ctx, projectID, sourceID)
}

func (u *UseCase) CreateSource(
	ctx context.Context,
	principal security.Principal,
	projectID, name, repositoryURL, defaultBranch, credentialID,
	sshHostKeyFingerprint, requestID string,
) (SourceRepository, error) {
	if err := principal.Require(security.PermissionSourceRepositoryWrite); err != nil {
		return SourceRepository{}, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return SourceRepository{}, err
	}
	id, auditID, now, err := u.identifiers()
	if err != nil {
		return SourceRepository{}, err
	}
	source, err := NewSourceRepository(
		id, projectID, name, repositoryURL, defaultBranch, credentialID,
		sshHostKeyFingerprint, principal.UserID, now,
	)
	if err != nil {
		return SourceRepository{}, err
	}
	if credentialID != "" {
		credential, lookupErr := u.repository.GetCredential(ctx, projectID, credentialID)
		if lookupErr != nil {
			return SourceRepository{}, lookupErr
		}
		if !CredentialSupportsProtocol(credential, source.Protocol) {
			return SourceRepository{}, ErrCredentialProtocolMismatch
		}
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		created, createErr := u.repository.CreateSource(transactionContext, source)
		if createErr != nil {
			return createErr
		}
		source = created
		return u.record(
			transactionContext, principal, auditID,
			"source_repository.create", "source_repository",
			source.ID, projectID, requestID, now,
		)
	})
	return source, err
}

func (u *UseCase) ProbeSource(
	ctx context.Context,
	principal security.Principal,
	projectID, sourceID, requestID string,
) (SourceRepository, error) {
	if err := principal.Require(security.PermissionSourceRepositoryWrite); err != nil {
		return SourceRepository{}, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return SourceRepository{}, err
	}
	if u.prober == nil {
		return SourceRepository{}, ErrSourceProbeUnavailable
	}
	source, err := u.repository.GetSource(ctx, projectID, sourceID)
	if err != nil {
		return SourceRepository{}, err
	}
	var credential *RepositoryCredential
	if source.CredentialID != "" {
		resolved, lookupErr := u.repository.GetCredential(ctx, projectID, source.CredentialID)
		if lookupErr != nil {
			return SourceRepository{}, lookupErr
		}
		if !CredentialSupportsProtocol(resolved, source.Protocol) {
			return SourceRepository{}, ErrCredentialProtocolMismatch
		}
		credential = &resolved
	}
	status, err := u.prober.ProbeSource(ctx, source, credential)
	if err != nil {
		return SourceRepository{}, err
	}
	if !status.ValidProbeResult() {
		return SourceRepository{}, ErrSourceProbeUnavailable
	}
	auditID, err := u.newID()
	if err != nil {
		return SourceRepository{}, err
	}
	now := u.now().UTC()
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		updated, updateErr := u.repository.UpdateSourceProbe(
			transactionContext, projectID, sourceID, status, now,
		)
		if updateErr != nil {
			return updateErr
		}
		source = updated
		return u.record(
			transactionContext, principal, auditID,
			"source_repository.probe", "source_repository",
			source.ID, projectID, requestID, now,
		)
	})
	return source, err
}

func (u *UseCase) ListBuildConfigurations(
	ctx context.Context,
	principal security.Principal,
	projectID, applicationID string,
) ([]BuildConfiguration, error) {
	if err := principal.Require(security.PermissionBuildConfigurationRead); err != nil {
		return nil, err
	}
	if err := u.requireProjectAndApplication(ctx, principal, projectID, applicationID); err != nil {
		return nil, err
	}
	return u.repository.ListBuildConfigurations(ctx, projectID, applicationID)
}

func (u *UseCase) GetBuildConfiguration(
	ctx context.Context,
	principal security.Principal,
	projectID, applicationID, configurationID string,
) (BuildConfiguration, error) {
	if err := principal.Require(security.PermissionBuildConfigurationRead); err != nil {
		return BuildConfiguration{}, err
	}
	if err := u.requireProjectAndApplication(ctx, principal, projectID, applicationID); err != nil {
		return BuildConfiguration{}, err
	}
	return u.repository.GetBuildConfiguration(ctx, projectID, applicationID, configurationID)
}

func (u *UseCase) CreateBuildConfiguration(
	ctx context.Context,
	principal security.Principal,
	projectID, applicationID, name, sourceRepositoryID,
	dockerfilePath, contextPath string,
	allowedRefs []string,
	registryCredentialID, imageRepository string,
	targetPlatform BuildPlatform,
	resources BuildResources,
	timeoutSeconds int64,
	maxConcurrency int,
	autoCreateRelease bool,
	requestID string,
) (BuildConfiguration, error) {
	return u.CreateBuildConfigurationWithReleaseSpec(
		ctx, principal, projectID, applicationID, name, sourceRepositoryID,
		dockerfilePath, contextPath, allowedRefs, registryCredentialID,
		imageRepository, targetPlatform, resources, timeoutSeconds,
		maxConcurrency, autoCreateRelease, runtimespec.Spec{}, requestID,
	)
}

func (u *UseCase) CreateBuildConfigurationWithReleaseSpec(
	ctx context.Context,
	principal security.Principal,
	projectID, applicationID, name, sourceRepositoryID,
	dockerfilePath, contextPath string,
	allowedRefs []string,
	registryCredentialID, imageRepository string,
	targetPlatform BuildPlatform,
	resources BuildResources,
	timeoutSeconds int64,
	maxConcurrency int,
	autoCreateRelease bool,
	releaseRuntimeSpec runtimespec.Spec,
	requestID string,
) (BuildConfiguration, error) {
	return u.CreateBuildConfigurationWithDeliverySpec(
		ctx, principal, projectID, applicationID, name, sourceRepositoryID,
		dockerfilePath, contextPath, allowedRefs, registryCredentialID,
		imageRepository, targetPlatform, resources, timeoutSeconds,
		maxConcurrency, autoCreateRelease, releaseRuntimeSpec, nil, requestID,
	)
}

func (u *UseCase) CreateBuildConfigurationWithDeliverySpec(
	ctx context.Context,
	principal security.Principal,
	projectID, applicationID, name, sourceRepositoryID,
	dockerfilePath, contextPath string,
	allowedRefs []string,
	registryCredentialID, imageRepository string,
	targetPlatform BuildPlatform,
	resources BuildResources,
	timeoutSeconds int64,
	maxConcurrency int,
	autoCreateRelease bool,
	releaseRuntimeSpec runtimespec.Spec,
	automaticDeployments []AutomaticDeploymentRule,
	requestID string,
) (BuildConfiguration, error) {
	if err := principal.Require(security.PermissionBuildConfigurationWrite); err != nil {
		return BuildConfiguration{}, err
	}
	if len(automaticDeployments) > 0 {
		if err := principal.Require(security.PermissionAutomaticDeploymentManage); err != nil {
			return BuildConfiguration{}, err
		}
	}
	if err := u.requireProjectAndApplication(ctx, principal, projectID, applicationID); err != nil {
		return BuildConfiguration{}, err
	}
	source, err := u.repository.GetSource(ctx, projectID, sourceRepositoryID)
	if err != nil {
		return BuildConfiguration{}, err
	}
	if len(allowedRefs) == 0 {
		allowedRefs = []string{"refs/heads/" + source.DefaultBranch}
	}
	id, auditID, now, err := u.identifiers()
	if err != nil {
		return BuildConfiguration{}, err
	}
	item, err := NewBuildConfigurationWithDeliverySpec(
		id, projectID, applicationID, name, sourceRepositoryID,
		dockerfilePath, contextPath, allowedRefs,
		registryCredentialID, imageRepository, targetPlatform,
		resources, timeoutSeconds, maxConcurrency, autoCreateRelease, releaseRuntimeSpec,
		automaticDeployments,
		principal.UserID, now,
	)
	if err != nil {
		return BuildConfiguration{}, err
	}
	if err := u.validateBuildConfigurationReferences(ctx, item); err != nil {
		return BuildConfiguration{}, err
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		created, createErr := u.repository.CreateBuildConfiguration(transactionContext, item)
		if createErr != nil {
			return createErr
		}
		item = created
		return u.record(
			transactionContext, principal, auditID,
			"build_configuration.create", "build_configuration",
			item.ID, projectID, requestID, now,
		)
	})
	return item, err
}

func (u *UseCase) UpdateBuildConfiguration(
	ctx context.Context,
	principal security.Principal,
	projectID, applicationID, configurationID string,
	expectedVersion uint64,
	patch BuildConfigurationPatch,
	requestID string,
) (BuildConfiguration, error) {
	if err := principal.Require(security.PermissionBuildConfigurationWrite); err != nil {
		return BuildConfiguration{}, err
	}
	if patch.AutomaticDeployments != nil {
		if err := principal.Require(security.PermissionAutomaticDeploymentManage); err != nil {
			return BuildConfiguration{}, err
		}
	}
	if expectedVersion == 0 || patch.Empty() {
		return BuildConfiguration{}, ErrInvalidBuildConfiguration
	}
	if err := u.requireProjectAndApplication(ctx, principal, projectID, applicationID); err != nil {
		return BuildConfiguration{}, err
	}
	current, err := u.repository.GetBuildConfiguration(
		ctx, projectID, applicationID, configurationID,
	)
	if err != nil {
		return BuildConfiguration{}, err
	}
	if current.Version != expectedVersion {
		return BuildConfiguration{}, ErrVersionConflict
	}
	updated, err := current.Apply(patch, principal.UserID, u.now().UTC())
	if err != nil {
		return BuildConfiguration{}, err
	}
	if err := u.validateBuildConfigurationReferences(ctx, updated); err != nil {
		return BuildConfiguration{}, err
	}
	auditID, err := u.newID()
	if err != nil {
		return BuildConfiguration{}, err
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		stored, updateErr := u.repository.UpdateBuildConfiguration(
			transactionContext, updated, expectedVersion,
		)
		if updateErr != nil {
			return updateErr
		}
		updated = stored
		return u.record(
			transactionContext, principal, auditID,
			"build_configuration.update", "build_configuration",
			updated.ID, projectID, requestID, updated.UpdatedAt,
		)
	})
	return updated, err
}

func (u *UseCase) ListBuilds(
	ctx context.Context,
	principal security.Principal,
	projectID string,
) ([]Build, error) {
	if err := principal.Require(security.PermissionBuildRead); err != nil {
		return nil, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return nil, err
	}
	return u.repository.ListBuilds(ctx, projectID)
}

func (u *UseCase) GetBuild(
	ctx context.Context,
	principal security.Principal,
	projectID, buildID string,
) (Build, error) {
	if err := principal.Require(security.PermissionBuildRead); err != nil {
		return Build{}, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return Build{}, err
	}
	return u.repository.GetBuild(ctx, projectID, buildID)
}

func (u *UseCase) ReadBuildLogs(ctx context.Context, principal security.Principal,
	projectID, buildID string, query BuildLogQuery) (BuildLogPage, error) {
	if err := principal.Require(security.PermissionBuildRead); err != nil {
		return BuildLogPage{}, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return BuildLogPage{}, err
	}
	if u.buildLogs == nil {
		return BuildLogPage{}, ErrBuildLogsUnavailable
	}
	build, err := u.repository.GetBuild(ctx, projectID, buildID)
	if err != nil {
		return BuildLogPage{}, err
	}
	page, err := u.buildLogs.ReadBuildLogs(ctx, projectID, buildID, query)
	if err != nil {
		return BuildLogPage{}, err
	}
	page.Complete = build.Terminal()
	return page, nil
}

func (u *UseCase) ListArtifacts(
	ctx context.Context,
	principal security.Principal,
	projectID string,
) ([]Artifact, error) {
	if err := principal.Require(security.PermissionBuildRead); err != nil {
		return nil, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return nil, err
	}
	if u.artifacts == nil {
		return nil, ErrNotFound
	}
	return u.artifacts.ListArtifacts(ctx, projectID)
}

func (u *UseCase) GetArtifact(
	ctx context.Context,
	principal security.Principal,
	projectID, artifactID string,
) (Artifact, error) {
	if err := principal.Require(security.PermissionBuildRead); err != nil {
		return Artifact{}, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return Artifact{}, err
	}
	if u.artifacts == nil {
		return Artifact{}, ErrNotFound
	}
	return u.artifacts.GetArtifact(ctx, projectID, artifactID)
}

func (u *UseCase) CreateReleaseFromArtifact(
	ctx context.Context,
	principal security.Principal,
	projectID, artifactID string,
	runtimeSpec runtimespec.Spec,
	requestID string,
) (Artifact, error) {
	if err := principal.Require(security.PermissionBuildRead); err != nil {
		return Artifact{}, err
	}
	if err := principal.Require(security.PermissionReleaseCreate); err != nil {
		return Artifact{}, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return Artifact{}, err
	}
	if u.artifacts == nil || u.artifactReleases == nil {
		return Artifact{}, ErrArtifactReleaseUnavailable
	}
	item, err := u.artifacts.GetArtifact(ctx, projectID, artifactID)
	if err != nil {
		return Artifact{}, err
	}
	if item.ReleaseStatus == ArtifactReleaseCreated {
		return item, nil
	}
	releaseID, err := u.artifactReleases.CreateArtifactRelease(ctx, ArtifactReleaseRequest{
		ArtifactID: item.ID, OrganizationID: item.OrganizationID,
		ProjectID: item.ProjectID, ApplicationID: item.ApplicationID,
		RegistryCredentialID: item.RegistryCredentialID,
		ImageDigest:          item.ImageDigest, RuntimeSpec: runtimeSpec,
		AutomaticDeployments: cloneAutomaticDeployments(item.AutomaticDeployments),
		BuildID:              item.BuildID,
		BuildConfigurationID: item.BuildConfigurationID,
		ActorID:              principal.UserID, RequestID: requestID,
	})
	if err != nil {
		return Artifact{}, err
	}
	expectedVersion, now := item.Version, u.now().UTC()
	if err := item.MarkReleaseCreated(releaseID, now); err != nil {
		return Artifact{}, err
	}
	auditID, err := u.newID()
	if err != nil {
		return Artifact{}, err
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		var saveErr error
		item, saveErr = u.artifacts.SaveArtifactRelease(transactionContext, item, expectedVersion)
		if saveErr != nil {
			return saveErr
		}
		return u.record(transactionContext, principal, auditID, "artifact.release_created", "artifact", item.ID, projectID, requestID, now)
	})
	if errors.Is(err, ErrVersionConflict) {
		current, getErr := u.artifacts.GetArtifact(ctx, projectID, artifactID)
		if getErr == nil && current.ReleaseStatus == ArtifactReleaseCreated && current.ReleaseID == releaseID {
			return current, nil
		}
	}
	return item, err
}

func (u *UseCase) CancelBuild(ctx context.Context, principal security.Principal,
	projectID, buildID, requestID string) (Build, error) {
	if err := principal.Require(security.PermissionBuildTrigger); err != nil {
		return Build{}, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return Build{}, err
	}
	item, err := u.repository.GetBuild(ctx, projectID, buildID)
	if err != nil {
		return Build{}, err
	}
	if item.Status == BuildStatusCanceling || item.Status == BuildStatusCanceled {
		return item, nil
	}
	expectedVersion, now := item.Version, u.now().UTC()
	if err := item.Cancel(now); err != nil {
		return Build{}, err
	}
	auditID, err := u.newID()
	if err != nil {
		return Build{}, err
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		var saveErr error
		item, saveErr = u.repository.SaveBuild(transactionContext, item, expectedVersion)
		if saveErr != nil {
			return saveErr
		}
		return u.record(transactionContext, principal, auditID, "build.cancel_requested", "build", item.ID, projectID, requestID, now)
	})
	if errors.Is(err, ErrVersionConflict) {
		current, getErr := u.repository.GetBuild(ctx, projectID, buildID)
		if getErr == nil && (current.Status == BuildStatusCanceling || current.Status == BuildStatusCanceled) {
			return current, nil
		}
	}
	return item, err
}

func (u *UseCase) RetryBuild(ctx context.Context, principal security.Principal,
	projectID, buildID, idempotencyKey, requestID string) (Build, error) {
	if err := principal.Require(security.PermissionBuildTrigger); err != nil {
		return Build{}, err
	}
	projectID, buildID, idempotencyKey = strings.TrimSpace(projectID), strings.TrimSpace(buildID), strings.TrimSpace(idempotencyKey)
	if !validIdentifier(buildID) || !validIdentifier(idempotencyKey) {
		return Build{}, ErrInvalidBuild
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return Build{}, err
	}
	if existing, err := u.repository.GetBuildByIdempotency(ctx, projectID, idempotencyKey); err == nil {
		if existing.MatchesRetry(buildID) {
			return existing, nil
		}
		return Build{}, ErrIdempotencyMismatch
	} else if !errors.Is(err, ErrNotFound) {
		return Build{}, err
	}
	source, err := u.repository.GetBuild(ctx, projectID, buildID)
	if err != nil {
		return Build{}, err
	}
	id, auditID, now, err := u.identifiers()
	if err != nil {
		return Build{}, err
	}
	item, err := source.Retry(id, idempotencyKey, principal.UserID, now)
	if err != nil {
		return Build{}, err
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		var createErr error
		item, createErr = u.repository.CreateBuild(transactionContext, item)
		if createErr != nil {
			return createErr
		}
		return u.record(transactionContext, principal, auditID, "build.retry", "build", item.ID, projectID, requestID, now)
	})
	if errors.Is(err, ErrDuplicateIdempotency) {
		existing, getErr := u.repository.GetBuildByIdempotency(ctx, projectID, idempotencyKey)
		if getErr == nil && existing.MatchesRetry(buildID) {
			return existing, nil
		}
		if getErr != nil {
			return Build{}, getErr
		}
		return Build{}, ErrIdempotencyMismatch
	}
	return item, err
}

func (u *UseCase) TriggerManualBuild(
	ctx context.Context,
	principal security.Principal,
	projectID, applicationID, configurationID, ref, expectedCommitSHA,
	idempotencyKey, requestID string,
) (Build, error) {
	if err := principal.Require(security.PermissionBuildTrigger); err != nil {
		return Build{}, err
	}
	projectID = strings.TrimSpace(projectID)
	applicationID = strings.TrimSpace(applicationID)
	configurationID = strings.TrimSpace(configurationID)
	ref = strings.TrimSpace(ref)
	expectedCommitSHA = strings.ToLower(strings.TrimSpace(expectedCommitSHA))
	idempotencyKey = strings.TrimSpace(idempotencyKey)
	if !validIdentifier(applicationID) || !validIdentifier(configurationID) ||
		!validExactRef(ref) || !validIdentifier(idempotencyKey) ||
		(expectedCommitSHA != "" && !commitSHAPattern.MatchString(expectedCommitSHA)) {
		return Build{}, ErrInvalidBuild
	}
	if err := u.requireProjectAndApplication(ctx, principal, projectID, applicationID); err != nil {
		return Build{}, err
	}
	if existing, replayed, err := u.findBuildReplay(
		ctx, projectID, applicationID, configurationID, ref,
		expectedCommitSHA, "", idempotencyKey, BuildTriggerSourceManual,
	); err != nil {
		return Build{}, err
	} else if replayed {
		return existing, nil
	}
	configuration, err := u.repository.GetBuildConfiguration(
		ctx, projectID, applicationID, configurationID,
	)
	if err != nil {
		return Build{}, err
	}
	if !containsString(configuration.AllowedRefs, ref) {
		return Build{}, ErrRevisionNotFound
	}
	source, err := u.repository.GetSource(ctx, projectID, configuration.SourceRepositoryID)
	if err != nil {
		return Build{}, err
	}
	var credential *RepositoryCredential
	if source.CredentialID != "" {
		item, credentialErr := u.repository.GetCredential(ctx, projectID, source.CredentialID)
		if credentialErr != nil {
			return Build{}, credentialErr
		}
		credential = &item
	}
	if u.resolver == nil {
		return Build{}, ErrRevisionResolveUnavailable
	}
	revision, err := u.resolver.ResolveSourceRevision(
		ctx, source, credential, ref, expectedCommitSHA,
	)
	if err != nil {
		return Build{}, err
	}
	id, auditID, now, err := u.identifiers()
	if err != nil {
		return Build{}, err
	}
	item, err := NewBuild(
		id, principal.OrganizationID, projectID, applicationID,
		configuration, revision, BuildTriggerSourceManual, "",
		idempotencyKey, principal.UserID, now,
	)
	if err != nil {
		return Build{}, err
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		created, createErr := u.repository.CreateBuild(transactionContext, item)
		if createErr != nil {
			return createErr
		}
		item = created
		return u.record(
			transactionContext, principal, auditID,
			"build.trigger_manual", "build", item.ID, projectID, requestID, now,
		)
	})
	if errors.Is(err, ErrDuplicateIdempotency) {
		existing, replayed, replayErr := u.findBuildReplay(
			ctx, projectID, applicationID, configurationID, ref,
			expectedCommitSHA, "", idempotencyKey, BuildTriggerSourceManual,
		)
		if replayErr != nil {
			return Build{}, replayErr
		}
		if replayed {
			return existing, nil
		}
	}
	return item, err
}

func (u *UseCase) findBuildReplay(
	ctx context.Context,
	projectID, applicationID, configurationID, ref, expectedCommitSHA, triggerID,
	idempotencyKey string,
	source BuildTriggerSource,
) (Build, bool, error) {
	existing, err := u.repository.GetBuildByIdempotency(ctx, projectID, idempotencyKey)
	if errors.Is(err, ErrNotFound) {
		return Build{}, false, nil
	}
	if err != nil {
		return Build{}, false, err
	}
	if !existing.MatchesTrigger(
		applicationID, configurationID, ref, expectedCommitSHA, triggerID, source,
	) {
		return Build{}, false, ErrIdempotencyMismatch
	}
	return existing, true, nil
}

func (u *UseCase) ListBuildTriggers(
	ctx context.Context,
	principal security.Principal,
	projectID, applicationID, configurationID string,
) ([]BuildTrigger, error) {
	if err := principal.Require(security.PermissionBuildTriggerManage); err != nil {
		return nil, err
	}
	if err := u.requireProjectAndApplication(ctx, principal, projectID, applicationID); err != nil {
		return nil, err
	}
	if _, err := u.repository.GetBuildConfiguration(ctx, projectID, applicationID, configurationID); err != nil {
		return nil, err
	}
	items, err := u.repository.ListBuildTriggers(ctx, projectID, applicationID, configurationID)
	for index := range items {
		items[index].TokenHash = ""
	}
	return items, err
}

func (u *UseCase) CreateBuildTrigger(
	ctx context.Context,
	principal security.Principal,
	projectID, applicationID, configurationID, name string,
	allowedRefs []string,
	requestID string,
) (BuildTriggerCredential, error) {
	if err := principal.Require(security.PermissionBuildTriggerManage); err != nil {
		return BuildTriggerCredential{}, err
	}
	if err := u.requireProjectAndApplication(ctx, principal, projectID, applicationID); err != nil {
		return BuildTriggerCredential{}, err
	}
	configuration, err := u.repository.GetBuildConfiguration(ctx, projectID, applicationID, configurationID)
	if err != nil {
		return BuildTriggerCredential{}, err
	}
	refs, ok := normalizeAllowedRefs(allowedRefs)
	if !ok || !refsSubset(refs, configuration.AllowedRefs) || u.triggerTokens == nil {
		return BuildTriggerCredential{}, ErrInvalidBuildTrigger
	}
	raw, tokenHash, err := u.triggerTokens.New()
	if err != nil {
		return BuildTriggerCredential{}, err
	}
	id, auditID, now, err := u.identifiers()
	if err != nil {
		return BuildTriggerCredential{}, err
	}
	item, err := NewBuildTrigger(
		id, principal.OrganizationID, projectID, applicationID, configurationID,
		name, refs, tokenHash, principal.UserID, now,
	)
	if err != nil {
		return BuildTriggerCredential{}, err
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		created, createErr := u.repository.CreateBuildTrigger(transactionContext, item)
		if createErr != nil {
			return createErr
		}
		item = created
		return u.record(transactionContext, principal, auditID, "build_trigger.create", "build_trigger", item.ID, projectID, requestID, now)
	})
	if err != nil {
		return BuildTriggerCredential{}, err
	}
	item.TokenHash = ""
	return BuildTriggerCredential{Trigger: item, Token: raw}, nil
}

func (u *UseCase) RevokeBuildTrigger(
	ctx context.Context,
	principal security.Principal,
	projectID, applicationID, configurationID, triggerID, requestID string,
) (BuildTrigger, error) {
	if err := principal.Require(security.PermissionBuildTriggerManage); err != nil {
		return BuildTrigger{}, err
	}
	if err := u.requireProjectAndApplication(ctx, principal, projectID, applicationID); err != nil {
		return BuildTrigger{}, err
	}
	item, err := u.repository.GetBuildTrigger(ctx, triggerID)
	if err != nil || item.ProjectID != projectID || item.ApplicationID != applicationID || item.BuildConfigurationID != configurationID {
		return BuildTrigger{}, ErrNotFound
	}
	now := u.now().UTC()
	updated, err := item.Revoke(principal.UserID, now)
	if err != nil {
		if item.Status == BuildTriggerStatusRevoked {
			item.TokenHash = ""
			return item, nil
		}
		return BuildTrigger{}, err
	}
	auditID, err := u.newID()
	if err != nil {
		return BuildTrigger{}, err
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		var updateErr error
		updated, updateErr = u.repository.RevokeBuildTrigger(transactionContext, updated, item.Version)
		if updateErr != nil {
			return updateErr
		}
		return u.record(transactionContext, principal, auditID, "build_trigger.revoke", "build_trigger", item.ID, projectID, requestID, now)
	})
	updated.TokenHash = ""
	return updated, err
}

// TriggerExternalBuild authenticates a purpose-limited automation token. It
// deliberately does not accept a user Principal or caller-selected repository.
func (u *UseCase) TriggerExternalBuild(
	ctx context.Context,
	triggerID, rawToken, ref, commitSHA, idempotencyKey, requestID string,
) (Build, error) {
	triggerID, rawToken, ref = strings.TrimSpace(triggerID), strings.TrimSpace(rawToken), strings.TrimSpace(ref)
	commitSHA = strings.ToLower(strings.TrimSpace(commitSHA))
	idempotencyKey = strings.TrimSpace(idempotencyKey)
	if !validIdentifier(triggerID) || rawToken == "" || len(rawToken) > 256 || !validExactRef(ref) ||
		!commitSHAPattern.MatchString(commitSHA) || !validIdentifier(idempotencyKey) {
		return Build{}, ErrInvalidBuild
	}
	if u.triggerTokens == nil {
		return Build{}, ErrInvalidBuildTriggerToken
	}
	trigger, err := u.repository.GetBuildTrigger(ctx, triggerID)
	if err != nil {
		return Build{}, ErrInvalidBuildTriggerToken
	}
	if !trigger.MatchesToken(u.triggerTokens.Hash(rawToken)) {
		return Build{}, ErrInvalidBuildTriggerToken
	}
	if trigger.Status != BuildTriggerStatusActive {
		return Build{}, ErrBuildTriggerRevoked
	}
	if u.triggerGuard == nil || u.triggerLimit < 1 || u.triggerWindow <= 0 {
		return Build{}, ErrBuildTriggerRateLimited
	}
	now := u.now().UTC()
	allowed, retryAt, err := u.triggerGuard.ReserveBuildTrigger(ctx, trigger.ID, now, u.triggerLimit, u.triggerWindow)
	if err != nil {
		return Build{}, err
	}
	if !allowed {
		return Build{}, &BuildTriggerRateLimitError{RetryAfter: maxDuration(retryAt.Sub(now), time.Second)}
	}
	if !trigger.AllowsRef(ref) {
		return Build{}, ErrRevisionNotFound
	}
	if existing, replayed, replayErr := u.findBuildReplay(
		ctx, trigger.ProjectID, trigger.ApplicationID, trigger.BuildConfigurationID,
		ref, commitSHA, trigger.ID, idempotencyKey, BuildTriggerSourceTriggerAPI,
	); replayErr != nil {
		return Build{}, replayErr
	} else if replayed {
		return existing, nil
	}
	configuration, err := u.repository.GetBuildConfiguration(ctx, trigger.ProjectID, trigger.ApplicationID, trigger.BuildConfigurationID)
	if err != nil {
		return Build{}, err
	}
	if !containsString(configuration.AllowedRefs, ref) {
		return Build{}, ErrRevisionNotFound
	}
	source, err := u.repository.GetSource(ctx, trigger.ProjectID, configuration.SourceRepositoryID)
	if err != nil {
		return Build{}, err
	}
	var credential *RepositoryCredential
	if source.CredentialID != "" {
		resolved, credentialErr := u.repository.GetCredential(ctx, trigger.ProjectID, source.CredentialID)
		if credentialErr != nil {
			return Build{}, credentialErr
		}
		credential = &resolved
	}
	if u.resolver == nil {
		return Build{}, ErrRevisionResolveUnavailable
	}
	revision, err := u.resolver.ResolveSourceRevision(ctx, source, credential, ref, commitSHA)
	if err != nil {
		return Build{}, err
	}
	id, auditID, _, err := u.identifiers()
	if err != nil {
		return Build{}, err
	}
	item, err := NewBuild(id, trigger.OrganizationID, trigger.ProjectID, trigger.ApplicationID,
		configuration, revision, BuildTriggerSourceTriggerAPI, trigger.ID,
		idempotencyKey, trigger.ID, now)
	if err != nil {
		return Build{}, err
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		created, createErr := u.repository.CreateBuild(transactionContext, item)
		if createErr != nil {
			return createErr
		}
		item = created
		return u.audit.Record(transactionContext, sharedaudit.Event{
			ID: auditID, OrganizationID: trigger.OrganizationID, ProjectID: trigger.ProjectID,
			ActorID: trigger.ID, Action: "build.trigger_api", ResourceType: "build",
			ResourceID: item.ID, RequestID: requestID, CreatedAt: now,
		})
	})
	if errors.Is(err, ErrDuplicateIdempotency) {
		existing, replayed, replayErr := u.findBuildReplay(ctx, trigger.ProjectID,
			trigger.ApplicationID, trigger.BuildConfigurationID, ref, commitSHA,
			trigger.ID, idempotencyKey, BuildTriggerSourceTriggerAPI)
		if replayErr != nil {
			return Build{}, replayErr
		}
		if replayed {
			return existing, nil
		}
	}
	return item, err
}

func refsSubset(values, allowed []string) bool {
	for _, value := range values {
		if !containsString(allowed, value) {
			return false
		}
	}
	return true
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

func (u *UseCase) ListBuildHooks(ctx context.Context, principal security.Principal,
	projectID, applicationID, configurationID string) ([]BuildHookSummary, error) {
	if err := principal.Require(security.PermissionBuildTriggerManage); err != nil {
		return nil, err
	}
	if err := u.requireProjectAndApplication(ctx, principal, projectID, applicationID); err != nil {
		return nil, err
	}
	if _, err := u.repository.GetBuildConfiguration(ctx, projectID, applicationID, configurationID); err != nil {
		return nil, err
	}
	return u.repository.ListBuildHooks(ctx, projectID, applicationID, configurationID)
}

func (u *UseCase) CreateBuildHook(ctx context.Context, principal security.Principal,
	projectID, applicationID, configurationID, name string, provider WebhookProvider,
	allowedRefs []string, secretReference, requestID string) (BuildHookSummary, error) {
	if err := principal.Require(security.PermissionBuildTriggerManage); err != nil {
		return BuildHookSummary{}, err
	}
	if err := u.requireProjectAndApplication(ctx, principal, projectID, applicationID); err != nil {
		return BuildHookSummary{}, err
	}
	configuration, err := u.repository.GetBuildConfiguration(ctx, projectID, applicationID, configurationID)
	if err != nil {
		return BuildHookSummary{}, err
	}
	refs, ok := normalizeAllowedRefs(allowedRefs)
	if !ok || !refsSubset(refs, configuration.AllowedRefs) {
		return BuildHookSummary{}, ErrInvalidBuildHook
	}
	id, auditID, now, err := u.identifiers()
	if err != nil {
		return BuildHookSummary{}, err
	}
	hook, err := NewBuildHook(id, principal.OrganizationID, projectID, applicationID,
		configurationID, name, provider, refs, secretReference, principal.UserID, now)
	if err != nil {
		return BuildHookSummary{}, err
	}
	var summary BuildHookSummary
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		var createErr error
		summary, createErr = u.repository.CreateBuildHook(transactionContext, hook)
		if createErr != nil {
			return createErr
		}
		return u.record(transactionContext, principal, auditID, "build_hook.create", "build_hook", hook.ID, projectID, requestID, now)
	})
	return summary, err
}

func (u *UseCase) RevokeBuildHook(ctx context.Context, principal security.Principal,
	projectID, applicationID, configurationID, hookID, requestID string) (BuildHookSummary, error) {
	if err := principal.Require(security.PermissionBuildTriggerManage); err != nil {
		return BuildHookSummary{}, err
	}
	if err := u.requireProjectAndApplication(ctx, principal, projectID, applicationID); err != nil {
		return BuildHookSummary{}, err
	}
	hook, err := u.repository.GetBuildHook(ctx, hookID)
	if err != nil || hook.ProjectID != projectID || hook.ApplicationID != applicationID || hook.BuildConfigurationID != configurationID {
		return BuildHookSummary{}, ErrNotFound
	}
	if hook.Status == BuildHookStatusRevoked {
		return hook.Summary(), nil
	}
	now := u.now().UTC()
	updated, err := hook.Revoke(principal.UserID, now)
	if err != nil {
		return BuildHookSummary{}, err
	}
	auditID, err := u.newID()
	if err != nil {
		return BuildHookSummary{}, err
	}
	var summary BuildHookSummary
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		var updateErr error
		summary, updateErr = u.repository.RevokeBuildHook(transactionContext, updated, hook.Version)
		if updateErr != nil {
			return updateErr
		}
		return u.record(transactionContext, principal, auditID, "build_hook.revoke", "build_hook", hook.ID, projectID, requestID, now)
	})
	return summary, err
}

func (u *UseCase) HandleWebhook(ctx context.Context, provider WebhookProvider, hookID string,
	envelope WebhookEnvelope, requestID string) (WebhookReceipt, error) {
	hookID = strings.TrimSpace(hookID)
	if !provider.Valid() || !validIdentifier(hookID) || u.webhooks == nil {
		return WebhookReceipt{}, ErrInvalidWebhook
	}
	hook, err := u.repository.GetBuildHook(ctx, hookID)
	if err != nil || hook.Provider != provider || hook.Status != BuildHookStatusActive {
		return WebhookReceipt{}, ErrNotFound
	}
	event, err := u.webhooks.VerifyAndParse(ctx, hook, envelope)
	if err != nil {
		return WebhookReceipt{}, err
	}
	envelope.DeliveryID, envelope.Event = strings.TrimSpace(envelope.DeliveryID), strings.TrimSpace(envelope.Event)
	if existing, found, replayErr := u.webhookReplay(ctx, hook, envelope.DeliveryID); replayErr != nil {
		return WebhookReceipt{}, replayErr
	} else if found {
		return existing, nil
	}
	if u.webhookGuard == nil || u.webhookLimit < 1 || u.webhookWindow <= 0 {
		return WebhookReceipt{}, ErrWebhookRateLimited
	}
	now := u.now().UTC()
	allowed, retryAt, err := u.webhookGuard.ReserveBuildWebhook(
		ctx, hook.ID, now, u.webhookLimit, u.webhookWindow,
	)
	if err != nil {
		return WebhookReceipt{}, err
	}
	if !allowed {
		return WebhookReceipt{}, &WebhookRateLimitError{
			RetryAfter: maxDuration(retryAt.Sub(now), time.Second),
		}
	}
	if !event.Supported || !validExactRef(event.Ref) || !commitSHAPattern.MatchString(event.CommitSHA) || !hook.AllowsRef(event.Ref) {
		return u.saveIgnoredWebhook(ctx, hook, envelope, event, requestID)
	}
	configuration, err := u.repository.GetBuildConfiguration(ctx, hook.ProjectID, hook.ApplicationID, hook.BuildConfigurationID)
	if err != nil {
		return WebhookReceipt{}, err
	}
	if !containsString(configuration.AllowedRefs, event.Ref) {
		return u.saveIgnoredWebhook(ctx, hook, envelope, event, requestID)
	}
	source, err := u.repository.GetSource(ctx, hook.ProjectID, configuration.SourceRepositoryID)
	if err != nil {
		return WebhookReceipt{}, err
	}
	var credential *RepositoryCredential
	if source.CredentialID != "" {
		resolved, credentialErr := u.repository.GetCredential(ctx, hook.ProjectID, source.CredentialID)
		if credentialErr != nil {
			return WebhookReceipt{}, credentialErr
		}
		credential = &resolved
	}
	if u.resolver == nil {
		return WebhookReceipt{}, ErrRevisionResolveUnavailable
	}
	revision, err := u.resolver.ResolveSourceRevision(ctx, source, credential, event.Ref, event.CommitSHA)
	// Webhook providers do not guarantee that deliveries arrive in push order.
	// If the advertised commit is no longer the remote ref head, this is a valid
	// but stale delivery: acknowledge and record it without enqueueing a build.
	if errors.Is(err, ErrRevisionMismatch) {
		return u.saveIgnoredWebhook(ctx, hook, envelope, event, requestID)
	}
	if err != nil {
		return WebhookReceipt{}, err
	}
	buildID, auditID, now, err := u.identifiers()
	if err != nil {
		return WebhookReceipt{}, err
	}
	deliveryID, err := u.newID()
	if err != nil {
		return WebhookReceipt{}, err
	}
	idempotencyKey := webhookIdempotencyKey(provider, hook.ID, envelope.DeliveryID)
	build, err := NewBuild(buildID, hook.OrganizationID, hook.ProjectID, hook.ApplicationID,
		configuration, revision, BuildTriggerSourceWebhook, hook.ID, idempotencyKey, hook.ID, now)
	if err != nil {
		return WebhookReceipt{}, err
	}
	delivery := WebhookDelivery{
		ID: deliveryID, OrganizationID: hook.OrganizationID, ProjectID: hook.ProjectID,
		HookID: hook.ID, Provider: provider, DeliveryID: envelope.DeliveryID, Event: envelope.Event,
		Ref: event.Ref, CommitSHA: event.CommitSHA, Status: WebhookDeliveryStatusAccepted,
		BuildID: build.ID, CreatedAt: now,
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		if createErr := u.repository.CreateWebhookDelivery(transactionContext, delivery); createErr != nil {
			return createErr
		}
		if _, createErr := u.repository.CreateBuild(transactionContext, build); createErr != nil {
			return createErr
		}
		return u.audit.Record(transactionContext, sharedaudit.Event{
			ID: auditID, OrganizationID: hook.OrganizationID, ProjectID: hook.ProjectID,
			ActorID: hook.ID, Action: "build.trigger_webhook", ResourceType: "build",
			ResourceID: build.ID, RequestID: requestID, CreatedAt: now,
		})
	})
	if errors.Is(err, ErrDuplicateWebhookDelivery) {
		if receipt, found, replayErr := u.webhookReplay(ctx, hook, envelope.DeliveryID); replayErr != nil {
			return WebhookReceipt{}, replayErr
		} else if found {
			return receipt, nil
		}
	}
	return WebhookReceipt{Status: WebhookDeliveryStatusAccepted, BuildID: build.ID}, err
}

func (u *UseCase) saveIgnoredWebhook(ctx context.Context, hook BuildHook, envelope WebhookEnvelope,
	event WebhookEvent, requestID string) (WebhookReceipt, error) {
	deliveryID, auditID, now, err := u.identifiers()
	if err != nil {
		return WebhookReceipt{}, err
	}
	delivery := WebhookDelivery{
		ID: deliveryID, OrganizationID: hook.OrganizationID, ProjectID: hook.ProjectID,
		HookID: hook.ID, Provider: hook.Provider, DeliveryID: envelope.DeliveryID,
		Event: envelope.Event, Ref: event.Ref, CommitSHA: event.CommitSHA,
		Status: WebhookDeliveryStatusIgnored, CreatedAt: now,
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		if createErr := u.repository.CreateWebhookDelivery(transactionContext, delivery); createErr != nil {
			return createErr
		}
		return u.audit.Record(transactionContext, sharedaudit.Event{
			ID: auditID, OrganizationID: hook.OrganizationID, ProjectID: hook.ProjectID,
			ActorID: hook.ID, Action: "build_hook.delivery_ignored", ResourceType: "webhook_delivery",
			ResourceID: delivery.ID, RequestID: requestID, CreatedAt: now,
		})
	})
	if errors.Is(err, ErrDuplicateWebhookDelivery) {
		if receipt, found, replayErr := u.webhookReplay(ctx, hook, envelope.DeliveryID); replayErr != nil {
			return WebhookReceipt{}, replayErr
		} else if found {
			return receipt, nil
		}
	}
	return WebhookReceipt{Status: WebhookDeliveryStatusIgnored}, err
}

func (u *UseCase) webhookReplay(ctx context.Context, hook BuildHook, deliveryID string) (WebhookReceipt, bool, error) {
	delivery, err := u.repository.GetWebhookDelivery(ctx, hook.ID, hook.Provider, deliveryID)
	if errors.Is(err, ErrNotFound) {
		return WebhookReceipt{}, false, nil
	}
	if err != nil {
		return WebhookReceipt{}, false, err
	}
	return WebhookReceipt{Status: delivery.Status, BuildID: delivery.BuildID}, true, nil
}

func webhookIdempotencyKey(provider WebhookProvider, hookID, deliveryID string) string {
	sum := sha256.Sum256([]byte(string(provider) + "\x00" + hookID + "\x00" + deliveryID))
	return "wh:" + hex.EncodeToString(sum[:])
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func (u *UseCase) requireProjectAndApplication(
	ctx context.Context,
	principal security.Principal,
	projectID, applicationID string,
) error {
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return err
	}
	if u.applications == nil {
		return ErrNotFound
	}
	exists, err := u.applications.ApplicationExists(ctx, projectID, applicationID)
	if err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	return nil
}

func (u *UseCase) validateBuildConfigurationReferences(
	ctx context.Context,
	item BuildConfiguration,
) error {
	if _, err := u.repository.GetSource(ctx, item.ProjectID, item.SourceRepositoryID); err != nil {
		return err
	}
	if u.registries == nil {
		return ErrNotFound
	}
	server, err := u.registries.RegistryServer(
		ctx, item.ProjectID, item.RegistryCredentialID,
	)
	if err != nil {
		return err
	}
	registry, err := ImageRepositoryRegistry(item.ImageRepository)
	if err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(server), registry) {
		return ErrRegistryMismatch
	}
	if len(item.AutomaticDeployments) > 0 && u.automation == nil {
		return ErrNotFound
	}
	for _, rule := range item.AutomaticDeployments {
		if err := u.automation.ValidateAutomaticDeployment(
			ctx, item.ProjectID, rule.EnvironmentID, rule.RuntimeTargetID,
		); err != nil {
			return err
		}
	}
	return nil
}

func (u *UseCase) requireProject(
	ctx context.Context,
	principal security.Principal,
	projectID string,
) error {
	exists, err := u.projects.ProjectExists(ctx, principal.OrganizationID, projectID)
	if err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	return nil
}

func (u *UseCase) identifiers() (string, string, time.Time, error) {
	id, err := u.newID()
	if err != nil {
		return "", "", time.Time{}, err
	}
	auditID, err := u.newID()
	if err != nil {
		return "", "", time.Time{}, err
	}
	return id, auditID, u.now().UTC(), nil
}

func (u *UseCase) record(
	ctx context.Context,
	principal security.Principal,
	auditID, action, resourceType, resourceID, projectID, requestID string,
	now time.Time,
) error {
	return u.audit.Record(ctx, sharedaudit.Event{
		ID: auditID, OrganizationID: principal.OrganizationID,
		ProjectID: projectID, ActorID: principal.UserID,
		Action: action, ResourceType: resourceType, ResourceID: resourceID,
		RequestID: requestID, CreatedAt: now,
	})
}
