package data

import (
	"context"
	"errors"
	"strings"
	"testing"

	buildbiz "github.com/owndock/owndock/internal/modules/build/biz"
	"github.com/owndock/owndock/internal/modules/supplychain/biz"
)

type artifactRepositoryStub struct {
	item buildbiz.Artifact
	err  error
}

func (s artifactRepositoryStub) GetArtifact(context.Context, string, string) (buildbiz.Artifact, error) {
	return s.item, s.err
}

func TestArtifactLookupAdapterReturnsOnlyImmutableOCIIdentity(t *testing.T) {
	repository := artifactRepositoryStub{item: buildbiz.Artifact{
		ID: "artifact-1", OrganizationID: "organization-1", ProjectID: "project-1",
		RegistryCredentialID: "registry-1",
		ImageRepository:      "registry.example.com/team/api",
		ImageDigest:          "registry.example.com/team/api@sha256:" + strings.Repeat("a", 64),
	}}
	item, err := NewArtifactLookupAdapter(repository).ResolveArtifact(
		t.Context(), "organization-1", "project-1", "artifact-1",
	)
	if err != nil || item.SubjectDigest != "sha256:"+strings.Repeat("a", 64) ||
		item.RegistryRepository != repository.item.ImageRepository || item.RegistryCredentialID != "registry-1" {
		t.Fatalf("ResolveArtifact() = %+v, %v", item, err)
	}
	if _, err := NewArtifactLookupAdapter(repository).ResolveArtifact(
		t.Context(), "another-organization", "project-1", "artifact-1",
	); !errors.Is(err, biz.ErrNotFound) {
		t.Fatalf("cross-organization error = %v", err)
	}
}

func TestArtifactLookupAdapterFailsClosed(t *testing.T) {
	if _, err := NewArtifactLookupAdapter(nil).ResolveArtifact(
		t.Context(), "organization-1", "project-1", "artifact-1",
	); !errors.Is(err, biz.ErrUnavailable) {
		t.Fatalf("nil repository error = %v", err)
	}
	if _, err := NewArtifactLookupAdapter(artifactRepositoryStub{err: buildbiz.ErrNotFound}).ResolveArtifact(
		t.Context(), "organization-1", "project-1", "artifact-1",
	); !errors.Is(err, biz.ErrNotFound) {
		t.Fatalf("missing artifact error = %v", err)
	}
	malformed := artifactRepositoryStub{item: buildbiz.Artifact{
		ID: "artifact-1", OrganizationID: "organization-1", ProjectID: "project-1",
		ImageRepository: "registry.example.com/team/api", ImageDigest: "malformed",
	}}
	if _, err := NewArtifactLookupAdapter(malformed).ResolveArtifact(
		t.Context(), "organization-1", "project-1", "artifact-1",
	); !errors.Is(err, biz.ErrInvalidEvidence) {
		t.Fatalf("malformed digest error = %v", err)
	}
}
