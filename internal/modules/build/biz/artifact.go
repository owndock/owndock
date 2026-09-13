package biz

import (
	"context"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
	"github.com/owndock/owndock/internal/shared/runtimespec"
)

type ArtifactReleaseStatus string

const (
	ArtifactReleaseAvailable ArtifactReleaseStatus = "available"
	ArtifactReleasePending   ArtifactReleaseStatus = "release_pending"
	ArtifactReleaseCreated   ArtifactReleaseStatus = "release_created"
	ArtifactReleaseSkipped   ArtifactReleaseStatus = "release_skipped"
)

func (s ArtifactReleaseStatus) Valid() bool {
	return s == ArtifactReleaseAvailable || s == ArtifactReleasePending ||
		s == ArtifactReleaseCreated || s == ArtifactReleaseSkipped
}

type ArtifactOrigin string

const (
	ArtifactOriginOwnDockBuild ArtifactOrigin = "owndock_build"
	ArtifactOriginExternal     ArtifactOrigin = "external"
)

func (o ArtifactOrigin) Valid() bool {
	return o == ArtifactOriginOwnDockBuild || o == ArtifactOriginExternal
}

type ArtifactProducerVerification string

const (
	ArtifactProducerVerified ArtifactProducerVerification = "verified"
	ArtifactProducerDeclared ArtifactProducerVerification = "declared"
)

func (v ArtifactProducerVerification) Valid() bool {
	return v == ArtifactProducerVerified || v == ArtifactProducerDeclared
}

// Artifact is the immutable OCI output of one Build. ReleaseID and
// ReleaseStatus are coordination metadata; repository, digest, platform and
// source identity never change after creation.
type Artifact struct {
	ID                   string
	OrganizationID       string
	ProjectID            string
	ApplicationID        string
	Origin               ArtifactOrigin
	Producer             string
	ProducerVerification ArtifactProducerVerification
	RegistrationKey      string
	BuildID              string
	BuildConfigurationID string
	RegistryCredentialID string
	ImageRepository      string
	ImageDigest          string
	TargetPlatform       BuildPlatform
	ReleaseRuntimeSpec   runtimespec.Spec
	AutomaticDeployments []AutomaticDeploymentRule
	ReleaseStatus        ArtifactReleaseStatus
	ReleaseID            string
	Version              uint64
	CreatedAt            time.Time
	ReleasedAt           time.Time
}

func NewArtifact(id string, build Build, now time.Time) (Artifact, error) {
	id = strings.TrimSpace(id)
	if !validIdentifier(id) || !validIdentifier(build.ID) ||
		!validIdentifier(build.OrganizationID) || !validIdentifier(build.ProjectID) ||
		!validIdentifier(build.ApplicationID) || !validIdentifier(build.BuildConfigurationID) ||
		!validIdentifier(build.Configuration.RegistryCredentialID) ||
		build.Status != BuildStatusPushing || strings.TrimSpace(build.ImageDigest) == "" ||
		!build.Configuration.TargetPlatform.Valid() || now.IsZero() {
		return Artifact{}, ErrInvalidArtifact
	}
	named, err := reference.ParseNormalizedNamed(strings.TrimSpace(build.ImageDigest))
	if err != nil || named.Name() != build.Configuration.ImageRepository {
		return Artifact{}, ErrInvalidArtifact
	}
	canonical, ok := named.(reference.Canonical)
	if !ok || canonical.Digest().Algorithm() != digest.SHA256 {
		return Artifact{}, ErrInvalidArtifact
	}
	releaseRuntimeSpec, err := runtimespec.Normalize(cloneRuntimeSpec(build.Configuration.ReleaseRuntimeSpec))
	if err != nil {
		return Artifact{}, ErrInvalidArtifact
	}
	releaseStatus := ArtifactReleaseAvailable
	if build.Configuration.AutoCreateRelease {
		releaseStatus = ArtifactReleasePending
	}
	return Artifact{
		ID: id, OrganizationID: build.OrganizationID, ProjectID: build.ProjectID,
		ApplicationID: build.ApplicationID, Origin: ArtifactOriginOwnDockBuild,
		Producer: "owndock-build-worker", ProducerVerification: ArtifactProducerVerified,
		BuildID:              build.ID,
		BuildConfigurationID: build.BuildConfigurationID,
		RegistryCredentialID: build.Configuration.RegistryCredentialID,
		ImageRepository:      named.Name(), ImageDigest: canonical.String(),
		TargetPlatform:       build.Configuration.TargetPlatform,
		ReleaseRuntimeSpec:   releaseRuntimeSpec,
		AutomaticDeployments: cloneAutomaticDeployments(build.Configuration.AutomaticDeployments),
		ReleaseStatus:        releaseStatus, Version: 1, CreatedAt: now.UTC(),
	}, nil
}

type ExternalArtifactInput struct {
	ID                   string
	OrganizationID       string
	ProjectID            string
	ApplicationID        string
	RegistryCredentialID string
	ImageDigest          string
	TargetPlatform       BuildPlatform
	Producer             string
	RegistrationKey      string
	ReleaseRuntimeSpec   runtimespec.Spec
	CreatedAt            time.Time
}

func NewExternalArtifact(input ExternalArtifactInput) (Artifact, error) {
	named, err := reference.ParseNormalizedNamed(strings.TrimSpace(input.ImageDigest))
	canonical, ok := named.(reference.Canonical)
	normalizedSpec, specErr := runtimespec.Normalize(cloneRuntimeSpec(input.ReleaseRuntimeSpec))
	item := Artifact{ID: strings.TrimSpace(input.ID), OrganizationID: strings.TrimSpace(input.OrganizationID),
		ProjectID: strings.TrimSpace(input.ProjectID), ApplicationID: strings.TrimSpace(input.ApplicationID),
		Origin: ArtifactOriginExternal, Producer: strings.TrimSpace(input.Producer),
		ProducerVerification: ArtifactProducerDeclared,
		RegistrationKey:      strings.TrimSpace(input.RegistrationKey),
		RegistryCredentialID: strings.TrimSpace(input.RegistryCredentialID),
		ImageDigest:          strings.TrimSpace(input.ImageDigest), TargetPlatform: input.TargetPlatform,
		ReleaseRuntimeSpec: normalizedSpec, ReleaseStatus: ArtifactReleaseAvailable,
		Version: 1, CreatedAt: input.CreatedAt.UTC()}
	if err != nil || !ok || canonical.Digest().Algorithm() != digest.SHA256 || specErr != nil ||
		!validIdentifier(item.ID) || !validIdentifier(item.OrganizationID) ||
		!validIdentifier(item.ProjectID) || !validIdentifier(item.ApplicationID) ||
		!validIdentifier(item.RegistryCredentialID) || !validIdentifier(item.RegistrationKey) ||
		!validArtifactProducer(item.Producer) || !item.TargetPlatform.Valid() || item.CreatedAt.IsZero() {
		return Artifact{}, ErrInvalidArtifact
	}
	item.ImageRepository, item.ImageDigest = canonical.Name(), canonical.String()
	return item, nil
}

func validArtifactProducer(value string) bool {
	if value == "" || len(value) > 200 || strings.TrimSpace(value) != value || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func (a Artifact) MatchesExternal(input ExternalArtifactInput) bool {
	candidate, err := NewExternalArtifact(ExternalArtifactInput{ID: a.ID,
		OrganizationID: input.OrganizationID, ProjectID: input.ProjectID,
		ApplicationID: input.ApplicationID, RegistryCredentialID: input.RegistryCredentialID,
		ImageDigest: input.ImageDigest, TargetPlatform: input.TargetPlatform, Producer: input.Producer,
		RegistrationKey: input.RegistrationKey, ReleaseRuntimeSpec: input.ReleaseRuntimeSpec,
		CreatedAt: a.CreatedAt})
	return err == nil && a.Origin == ArtifactOriginExternal && a.OrganizationID == candidate.OrganizationID &&
		a.ProjectID == candidate.ProjectID && a.ApplicationID == candidate.ApplicationID &&
		a.RegistryCredentialID == candidate.RegistryCredentialID && a.ImageDigest == candidate.ImageDigest &&
		a.TargetPlatform == candidate.TargetPlatform && a.Producer == candidate.Producer &&
		a.ProducerVerification == ArtifactProducerDeclared && a.RegistrationKey == candidate.RegistrationKey &&
		reflect.DeepEqual(a.ReleaseRuntimeSpec, candidate.ReleaseRuntimeSpec)
}

func (a *Artifact) MarkReleaseCreated(releaseID string, now time.Time) error {
	releaseID = strings.TrimSpace(releaseID)
	if !validIdentifier(releaseID) || now.IsZero() {
		return ErrInvalidArtifact
	}
	if a.ReleaseStatus == ArtifactReleaseCreated {
		if a.ReleaseID == releaseID {
			return nil
		}
		return ErrArtifactAlreadyReleased
	}
	if a.ReleaseStatus != ArtifactReleasePending && a.ReleaseStatus != ArtifactReleaseAvailable {
		return ErrInvalidArtifact
	}
	a.ReleaseStatus, a.ReleaseID = ArtifactReleaseCreated, releaseID
	a.ReleasedAt = now.UTC()
	return nil
}

func (a *Artifact) SkipPendingRelease() error {
	if a.ReleaseStatus == ArtifactReleaseSkipped {
		return nil
	}
	if a.ReleaseStatus != ArtifactReleasePending {
		return ErrInvalidArtifact
	}
	a.ReleaseStatus = ArtifactReleaseSkipped
	a.ReleaseID = ""
	return nil
}

type ArtifactRepository interface {
	ListArtifacts(context.Context, string) ([]Artifact, error)
	GetArtifact(context.Context, string, string) (Artifact, error)
	GetArtifactByBuild(context.Context, string) (Artifact, error)
	GetArtifactByRegistrationKey(context.Context, string, string) (Artifact, error)
	CreateArtifact(context.Context, Artifact) (Artifact, error)
	NextPendingArtifact(context.Context) (Artifact, bool, error)
	SaveArtifactRelease(context.Context, Artifact, uint64) (Artifact, error)
}

type ArtifactEvidenceScheduler interface {
	EnsureArtifactEvidence(context.Context, Artifact) error
}

type ArtifactAvailabilityProbe interface {
	ProbeArtifact(context.Context, string, string, string, string) error
}

type ArtifactReleaseRequest struct {
	ArtifactID           string
	OrganizationID       string
	ProjectID            string
	ApplicationID        string
	RegistryCredentialID string
	ImageDigest          string
	RuntimeSpec          runtimespec.Spec
	AutomaticDeployments []AutomaticDeploymentRule
	BuildID              string
	BuildConfigurationID string
	ActorID              string
	RequestID            string
}

type ArtifactReleaseCreator interface {
	CreateArtifactRelease(context.Context, ArtifactReleaseRequest) (string, error)
}
