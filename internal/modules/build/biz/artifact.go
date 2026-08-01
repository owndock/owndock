package biz

import (
	"context"
	"strings"
	"time"

	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
	"github.com/owndock/owndock/internal/shared/runtimespec"
)

type ArtifactReleaseStatus string

const (
	ArtifactReleaseAvailable ArtifactReleaseStatus = "available"
	ArtifactReleasePending   ArtifactReleaseStatus = "release_pending"
	ArtifactReleaseCreated   ArtifactReleaseStatus = "release_created"
)

func (s ArtifactReleaseStatus) Valid() bool {
	return s == ArtifactReleaseAvailable || s == ArtifactReleasePending || s == ArtifactReleaseCreated
}

// Artifact is the immutable OCI output of one Build. ReleaseID and
// ReleaseStatus are coordination metadata; repository, digest, platform and
// source identity never change after creation.
type Artifact struct {
	ID                   string
	OrganizationID       string
	ProjectID            string
	ApplicationID        string
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
		ApplicationID: build.ApplicationID, BuildID: build.ID,
		BuildConfigurationID: build.BuildConfigurationID,
		RegistryCredentialID: build.Configuration.RegistryCredentialID,
		ImageRepository:      named.Name(), ImageDigest: canonical.String(),
		TargetPlatform:       build.Configuration.TargetPlatform,
		ReleaseRuntimeSpec:   releaseRuntimeSpec,
		AutomaticDeployments: cloneAutomaticDeployments(build.Configuration.AutomaticDeployments),
		ReleaseStatus:        releaseStatus, Version: 1, CreatedAt: now.UTC(),
	}, nil
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

type ArtifactRepository interface {
	ListArtifacts(context.Context, string) ([]Artifact, error)
	GetArtifact(context.Context, string, string) (Artifact, error)
	GetArtifactByBuild(context.Context, string) (Artifact, error)
	CreateArtifact(context.Context, Artifact) (Artifact, error)
	NextPendingArtifact(context.Context) (Artifact, bool, error)
	SaveArtifactRelease(context.Context, Artifact, uint64) (Artifact, error)
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
