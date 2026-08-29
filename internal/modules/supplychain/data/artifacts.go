package data

import (
	"context"
	"errors"

	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
	buildbiz "github.com/owndock/owndock/internal/modules/build/biz"
	"github.com/owndock/owndock/internal/modules/supplychain/biz"
)

type buildArtifactRepository interface {
	GetArtifact(context.Context, string, string) (buildbiz.Artifact, error)
}

// ArtifactLookupAdapter is the narrow cross-module boundary. Supply-chain
// code receives only immutable OCI identity, never the Build repository type.
type ArtifactLookupAdapter struct {
	repository buildArtifactRepository
}

func NewArtifactLookupAdapter(repository buildArtifactRepository) *ArtifactLookupAdapter {
	return &ArtifactLookupAdapter{repository: repository}
}

func (a *ArtifactLookupAdapter) ResolveArtifact(ctx context.Context,
	organizationID, projectID, artifactID string) (biz.ArtifactSubject, error) {
	if a == nil || a.repository == nil {
		return biz.ArtifactSubject{}, biz.ErrUnavailable
	}
	item, err := a.repository.GetArtifact(ctx, projectID, artifactID)
	if errors.Is(err, buildbiz.ErrNotFound) {
		return biz.ArtifactSubject{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.ArtifactSubject{}, err
	}
	if item.OrganizationID != organizationID || item.ProjectID != projectID {
		return biz.ArtifactSubject{}, biz.ErrNotFound
	}
	named, err := reference.ParseNormalizedNamed(item.ImageDigest)
	canonical, ok := named.(reference.Canonical)
	if err != nil || !ok || canonical.Name() != item.ImageRepository ||
		canonical.Digest().Algorithm() != digest.SHA256 {
		return biz.ArtifactSubject{}, biz.ErrInvalidEvidence
	}
	return biz.ArtifactSubject{
		ID: item.ID, OrganizationID: item.OrganizationID, ProjectID: item.ProjectID,
		SubjectDigest: canonical.Digest().String(), RegistryRepository: item.ImageRepository,
		RegistryCredentialID: item.RegistryCredentialID,
	}, nil
}
