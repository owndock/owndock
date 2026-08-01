package biz

import (
	"regexp"
	"strings"
	"time"

	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
	"github.com/owndock/owndock/internal/shared/runtimespec"
)

var commitSHAPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

type BuildStatus string

const (
	BuildStatusQueued      BuildStatus = "queued"
	BuildStatusCheckingOut BuildStatus = "checking_out"
	BuildStatusBuilding    BuildStatus = "building"
	BuildStatusPushing     BuildStatus = "pushing"
	BuildStatusSucceeded   BuildStatus = "succeeded"
	BuildStatusFailed      BuildStatus = "failed"
	BuildStatusCanceling   BuildStatus = "canceling"
	BuildStatusCanceled    BuildStatus = "canceled"
)

type BuildFailureCategory string

const (
	BuildFailureRepositoryAuthentication BuildFailureCategory = "repository_authentication"
	BuildFailureRepositoryUnreachable    BuildFailureCategory = "repository_unreachable"
	BuildFailureRevisionNotFound         BuildFailureCategory = "revision_not_found"
	BuildFailureCheckout                 BuildFailureCategory = "checkout_failed"
	BuildFailureConfiguration            BuildFailureCategory = "build_configuration"
	BuildFailureResourceLimit            BuildFailureCategory = "build_resource_limit"
	BuildFailureBuild                    BuildFailureCategory = "build_failed"
	BuildFailureRegistryAuthentication   BuildFailureCategory = "registry_authentication"
	BuildFailureRegistryPush             BuildFailureCategory = "registry_push"
	BuildFailureCanceled                 BuildFailureCategory = "canceled"
	BuildFailureUnknown                  BuildFailureCategory = "unknown"
)

func (c BuildFailureCategory) Valid() bool {
	switch c {
	case BuildFailureRepositoryAuthentication, BuildFailureRepositoryUnreachable,
		BuildFailureRevisionNotFound, BuildFailureCheckout, BuildFailureConfiguration,
		BuildFailureResourceLimit, BuildFailureBuild, BuildFailureRegistryAuthentication,
		BuildFailureRegistryPush, BuildFailureCanceled, BuildFailureUnknown:
		return true
	default:
		return false
	}
}

type BuildLease struct {
	Owner      string
	ExpiresAt  time.Time
	Generation uint64
}

func (l BuildLease) Active(now time.Time) bool {
	return strings.TrimSpace(l.Owner) != "" && l.ExpiresAt.After(now)
}

type BuildClaim struct {
	WorkerID  string
	Now       time.Time
	ExpiresAt time.Time
	Statuses  []BuildStatus
}

func (c BuildClaim) Validate() error {
	if !validIdentifier(strings.TrimSpace(c.WorkerID)) || c.Now.IsZero() || !c.ExpiresAt.After(c.Now) {
		return ErrInvalidBuildLease
	}
	seen := make(map[BuildStatus]struct{}, len(c.Statuses))
	for _, status := range c.Statuses {
		switch status {
		case BuildStatusQueued, BuildStatusCheckingOut, BuildStatusBuilding, BuildStatusPushing, BuildStatusCanceling:
		default:
			return ErrInvalidBuildLease
		}
		if _, duplicate := seen[status]; duplicate {
			return ErrInvalidBuildLease
		}
		seen[status] = struct{}{}
	}
	return nil
}

func (c BuildClaim) ClaimableStatuses() []BuildStatus {
	if len(c.Statuses) == 0 {
		return []BuildStatus{BuildStatusCanceling, BuildStatusQueued, BuildStatusCheckingOut, BuildStatusBuilding, BuildStatusPushing}
	}
	statuses := append([]BuildStatus(nil), c.Statuses...)
	for index, status := range statuses {
		if status == BuildStatusCanceling {
			copy(statuses[1:index+1], statuses[0:index])
			statuses[0] = BuildStatusCanceling
			break
		}
	}
	return statuses
}

type BuildTriggerSource string

const (
	BuildTriggerSourceManual     BuildTriggerSource = "manual"
	BuildTriggerSourceTriggerAPI BuildTriggerSource = "trigger_api"
	BuildTriggerSourceWebhook    BuildTriggerSource = "webhook"
	BuildTriggerSourceRetry      BuildTriggerSource = "retry"
)

func (s BuildTriggerSource) Valid() bool {
	return s == BuildTriggerSourceManual ||
		s == BuildTriggerSourceTriggerAPI ||
		s == BuildTriggerSourceWebhook ||
		s == BuildTriggerSourceRetry
}

type SourceRevision struct {
	SourceRepositoryID string
	Ref                string
	CommitSHA          string
}

func NewSourceRevision(sourceRepositoryID, ref, commitSHA string) (SourceRevision, error) {
	sourceRepositoryID = strings.TrimSpace(sourceRepositoryID)
	ref = strings.TrimSpace(ref)
	commitSHA = strings.ToLower(strings.TrimSpace(commitSHA))
	if !validIdentifier(sourceRepositoryID) || !validExactRef(ref) ||
		!commitSHAPattern.MatchString(commitSHA) {
		return SourceRevision{}, ErrInvalidBuild
	}
	return SourceRevision{
		SourceRepositoryID: sourceRepositoryID,
		Ref:                ref,
		CommitSHA:          commitSHA,
	}, nil
}

type BuildConfigurationSnapshot struct {
	ConfigurationID      string
	ConfigurationVersion uint64
	SourceRepositoryID   string
	DockerfilePath       string
	ContextPath          string
	AllowedRefs          []string
	RegistryCredentialID string
	ImageRepository      string
	TargetPlatform       BuildPlatform
	Resources            BuildResources
	TimeoutSeconds       int64
	MaxConcurrency       int
	AutoCreateRelease    bool
	ReleaseRuntimeSpec   runtimespec.Spec
	AutomaticDeployments []AutomaticDeploymentRule
}

func (c BuildConfiguration) Snapshot() BuildConfigurationSnapshot {
	return BuildConfigurationSnapshot{
		ConfigurationID:      c.ID,
		ConfigurationVersion: c.Version,
		SourceRepositoryID:   c.SourceRepositoryID,
		DockerfilePath:       c.DockerfilePath,
		ContextPath:          c.ContextPath,
		AllowedRefs:          append([]string(nil), c.AllowedRefs...),
		RegistryCredentialID: c.RegistryCredentialID,
		ImageRepository:      c.ImageRepository,
		TargetPlatform:       c.TargetPlatform,
		Resources:            c.Resources,
		TimeoutSeconds:       c.TimeoutSeconds,
		MaxConcurrency:       c.MaxConcurrency,
		AutoCreateRelease:    c.AutoCreateRelease,
		ReleaseRuntimeSpec:   cloneRuntimeSpec(c.ReleaseRuntimeSpec),
		AutomaticDeployments: cloneAutomaticDeployments(c.AutomaticDeployments),
	}
}

type Build struct {
	ID                   string
	OrganizationID       string
	ProjectID            string
	ApplicationID        string
	BuildConfigurationID string
	Revision             SourceRevision
	Configuration        BuildConfigurationSnapshot
	TriggerSource        BuildTriggerSource
	TriggerID            string
	IdempotencyKey       string
	Status               BuildStatus
	FailureCategory      BuildFailureCategory
	Version              uint64
	TriggeredBy          string
	SourceBuildID        string
	ImageDigest          string
	ArtifactID           string
	Lease                BuildLease
	CreatedAt            time.Time
	UpdatedAt            time.Time
	StartedAt            time.Time
	FinishedAt           time.Time
}

func NewBuild(
	id, organizationID, projectID, applicationID string,
	configuration BuildConfiguration,
	revision SourceRevision,
	triggerSource BuildTriggerSource,
	triggerID, idempotencyKey, triggeredBy string,
	now time.Time,
) (Build, error) {
	id = strings.TrimSpace(id)
	organizationID = strings.TrimSpace(organizationID)
	projectID = strings.TrimSpace(projectID)
	applicationID = strings.TrimSpace(applicationID)
	idempotencyKey = strings.TrimSpace(idempotencyKey)
	triggerID = strings.TrimSpace(triggerID)
	triggeredBy = strings.TrimSpace(triggeredBy)
	configuration, configurationErr := normalizeBuildConfiguration(configuration)
	revision, revisionErr := NewSourceRevision(
		revision.SourceRepositoryID, revision.Ref, revision.CommitSHA,
	)
	if !validIdentifier(id) || !validIdentifier(organizationID) ||
		!validIdentifier(projectID) || !validIdentifier(applicationID) ||
		!validIdentifier(idempotencyKey) || !validIdentifier(triggeredBy) ||
		!triggerSource.Valid() || triggerSource == BuildTriggerSourceRetry ||
		(triggerSource == BuildTriggerSourceManual && triggerID != "") ||
		(triggerSource != BuildTriggerSourceManual && !validIdentifier(triggerID)) ||
		now.IsZero() || configurationErr != nil || revisionErr != nil ||
		configuration.ProjectID != projectID || configuration.ApplicationID != applicationID ||
		configuration.ID == "" || configuration.Version == 0 ||
		revision.SourceRepositoryID != configuration.SourceRepositoryID {
		return Build{}, ErrInvalidBuild
	}
	return Build{
		ID: id, OrganizationID: organizationID, ProjectID: projectID,
		ApplicationID: applicationID, BuildConfigurationID: configuration.ID,
		Revision: revision, Configuration: configuration.Snapshot(),
		TriggerSource: triggerSource, TriggerID: triggerID, IdempotencyKey: idempotencyKey,
		Status: BuildStatusQueued, Version: 1,
		TriggeredBy: triggeredBy, CreatedAt: now.UTC(), UpdatedAt: now.UTC(),
	}, nil
}

func (b Build) MatchesTrigger(
	applicationID, configurationID, ref, expectedCommitSHA, triggerID string,
	source BuildTriggerSource,
) bool {
	expectedCommitSHA = strings.ToLower(strings.TrimSpace(expectedCommitSHA))
	return b.ApplicationID == strings.TrimSpace(applicationID) &&
		b.BuildConfigurationID == strings.TrimSpace(configurationID) &&
		b.Revision.Ref == strings.TrimSpace(ref) && b.TriggerSource == source &&
		b.TriggerID == strings.TrimSpace(triggerID) &&
		(expectedCommitSHA == "" || b.Revision.CommitSHA == expectedCommitSHA)
}

func (b Build) Terminal() bool {
	return b.Status == BuildStatusSucceeded || b.Status == BuildStatusFailed || b.Status == BuildStatusCanceled
}

func (b *Build) Acquire(claim BuildClaim) error {
	if err := claim.Validate(); err != nil {
		return err
	}
	switch b.Status {
	case BuildStatusQueued, BuildStatusCheckingOut, BuildStatusBuilding, BuildStatusPushing, BuildStatusCanceling:
		if b.Lease.Active(claim.Now) {
			return ErrBuildNotClaimable
		}
	default:
		return ErrBuildNotClaimable
	}
	b.Lease = BuildLease{Owner: strings.TrimSpace(claim.WorkerID), ExpiresAt: claim.ExpiresAt.UTC(), Generation: b.Lease.Generation + 1}
	b.UpdatedAt = claim.Now.UTC()
	return nil
}

func (b *Build) Renew(owner string, generation uint64, now, expiresAt time.Time) error {
	if strings.TrimSpace(owner) == "" || b.Lease.Owner != strings.TrimSpace(owner) ||
		b.Lease.Generation != generation || !b.Lease.Active(now) || !expiresAt.After(now) {
		return ErrInvalidBuildLease
	}
	b.Lease.ExpiresAt, b.UpdatedAt = expiresAt.UTC(), now.UTC()
	return nil
}

func (b *Build) Transition(next BuildStatus, now time.Time) error {
	valid := (b.Status == BuildStatusQueued && (next == BuildStatusCheckingOut || next == BuildStatusCanceling)) ||
		(b.Status == BuildStatusCheckingOut && (next == BuildStatusBuilding || next == BuildStatusFailed || next == BuildStatusCanceling)) ||
		(b.Status == BuildStatusBuilding && (next == BuildStatusPushing || next == BuildStatusFailed || next == BuildStatusCanceling)) ||
		(b.Status == BuildStatusPushing && (next == BuildStatusSucceeded || next == BuildStatusFailed || next == BuildStatusCanceling)) ||
		(b.Status == BuildStatusCanceling && next == BuildStatusCanceled)
	if !valid || now.IsZero() {
		return ErrInvalidBuildTransition
	}
	b.Status, b.UpdatedAt = next, now.UTC()
	if next == BuildStatusCheckingOut && b.StartedAt.IsZero() {
		b.StartedAt = now.UTC()
	}
	if next != BuildStatusFailed {
		b.FailureCategory = ""
	}
	if b.Terminal() {
		b.FinishedAt, b.Lease = now.UTC(), BuildLease{}
	}
	return nil
}

func (b *Build) Fail(category BuildFailureCategory, now time.Time) error {
	if !category.Valid() {
		return ErrInvalidBuildFailure
	}
	if err := b.Transition(BuildStatusFailed, now); err != nil {
		return err
	}
	b.FailureCategory = category
	return nil
}

func (b *Build) RecordPushedImage(value string, now time.Time) error {
	if b.Status != BuildStatusPushing || now.IsZero() || b.ImageDigest != "" {
		return ErrInvalidBuildOutput
	}
	named, err := reference.ParseNormalizedNamed(strings.TrimSpace(value))
	if err != nil || named.Name() != b.Configuration.ImageRepository {
		return ErrInvalidBuildOutput
	}
	canonical, ok := named.(reference.Canonical)
	if !ok || canonical.Digest().Algorithm() != digest.SHA256 {
		return ErrInvalidBuildOutput
	}
	b.ImageDigest = canonical.String()
	b.UpdatedAt = now.UTC()
	return nil
}

func (b *Build) Cancel(now time.Time) error {
	if b.Status == BuildStatusCanceling {
		return nil
	}
	if b.Terminal() {
		return ErrInvalidBuildTransition
	}
	return b.Transition(BuildStatusCanceling, now)
}

func (b Build) Retry(newID, idempotencyKey, triggeredBy string, now time.Time) (Build, error) {
	newID, idempotencyKey, triggeredBy = strings.TrimSpace(newID), strings.TrimSpace(idempotencyKey), strings.TrimSpace(triggeredBy)
	if b.Status != BuildStatusFailed {
		return Build{}, ErrBuildRetryRequiresFailed
	}
	if !validIdentifier(newID) || !validIdentifier(idempotencyKey) || !validIdentifier(triggeredBy) || now.IsZero() {
		return Build{}, ErrInvalidBuild
	}
	return Build{
		ID: newID, OrganizationID: b.OrganizationID, ProjectID: b.ProjectID,
		ApplicationID: b.ApplicationID, BuildConfigurationID: b.BuildConfigurationID,
		Revision: b.Revision, Configuration: b.Configuration.clone(),
		TriggerSource: BuildTriggerSourceRetry, IdempotencyKey: idempotencyKey,
		Status: BuildStatusQueued, Version: 1, TriggeredBy: triggeredBy,
		SourceBuildID: b.ID, CreatedAt: now.UTC(), UpdatedAt: now.UTC(),
	}, nil
}

func (s BuildConfigurationSnapshot) clone() BuildConfigurationSnapshot {
	s.AllowedRefs = append([]string(nil), s.AllowedRefs...)
	s.ReleaseRuntimeSpec = cloneRuntimeSpec(s.ReleaseRuntimeSpec)
	s.AutomaticDeployments = cloneAutomaticDeployments(s.AutomaticDeployments)
	return s
}

func cloneRuntimeSpec(value runtimespec.Spec) runtimespec.Spec {
	value.Ports = append([]runtimespec.Port(nil), value.Ports...)
	value.EnvironmentKeys = append([]string(nil), value.EnvironmentKeys...)
	if value.HealthCheck != nil {
		health := *value.HealthCheck
		health.Command = append([]string(nil), health.Command...)
		value.HealthCheck = &health
	}
	return value
}

func (b Build) MatchesRetry(sourceBuildID string) bool {
	return b.TriggerSource == BuildTriggerSourceRetry && b.SourceBuildID == strings.TrimSpace(sourceBuildID)
}

func validExactRef(value string) bool {
	_, ok := normalizeAllowedRefs([]string{value})
	return ok
}
