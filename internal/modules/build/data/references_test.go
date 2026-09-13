package data

import (
	"context"
	"errors"
	"testing"

	"github.com/owndock/owndock/internal/modules/build/biz"
	controlplanebiz "github.com/owndock/owndock/internal/modules/controlplane/biz"
	deploymentbiz "github.com/owndock/owndock/internal/modules/deployment/biz"
)

type artifactReleaseSourceStub struct{}

func (artifactReleaseSourceStub) CreateReleaseFromArtifact(
	_ context.Context,
	input controlplanebiz.ArtifactReleaseInput,
) (controlplanebiz.Release, error) {
	return controlplanebiz.Release{
		ID: "release-1", ProjectID: input.ProjectID,
		ApplicationID: input.ApplicationID, SourceArtifactID: input.ArtifactID,
	}, nil
}

type artifactReleaseRetirementSourceStub struct {
	release controlplanebiz.Release
	err     error
}

func (s artifactReleaseRetirementSourceStub) GetReleaseByArtifact(
	context.Context, string, string,
) (controlplanebiz.Release, error) {
	return s.release, s.err
}

func TestArtifactReleaseRetirementResolverDistinguishesExistingRelease(t *testing.T) {
	if _, _, err := (*ArtifactReleaseRetirementResolver)(nil).ResolveArtifactRelease(
		t.Context(), "project-1", "artifact-1",
	); !errors.Is(err, biz.ErrBuildRetirementUnavailable) {
		t.Fatalf("nil resolver error = %v", err)
	}
	missing := NewArtifactReleaseRetirementResolver(
		artifactReleaseRetirementSourceStub{err: controlplanebiz.ErrNotFound},
	)
	if id, found, err := missing.ResolveArtifactRelease(
		t.Context(), "project-1", "artifact-1",
	); err != nil || found || id != "" {
		t.Fatalf("missing Release = %q/%t/%v", id, found, err)
	}
	existing := NewArtifactReleaseRetirementResolver(
		artifactReleaseRetirementSourceStub{release: controlplanebiz.Release{ID: "release-1"}},
	)
	if id, found, err := existing.ResolveArtifactRelease(
		t.Context(), "project-1", "artifact-1",
	); err != nil || !found || id != "release-1" {
		t.Fatalf("existing Release = %q/%t/%v", id, found, err)
	}
	failure := errors.New("read Release")
	failing := NewArtifactReleaseRetirementResolver(
		artifactReleaseRetirementSourceStub{err: failure},
	)
	if _, _, err := failing.ResolveArtifactRelease(
		t.Context(), "project-1", "artifact-1",
	); !errors.Is(err, failure) {
		t.Fatalf("Release read failure = %v", err)
	}
}

type automaticDeploymentCreatorStub struct {
	inputs []deploymentbiz.AutomaticDeploymentInput
	err    error
}

func (s *automaticDeploymentCreatorStub) CreateAutomatic(
	_ context.Context,
	input deploymentbiz.AutomaticDeploymentInput,
) (deploymentbiz.Deployment, error) {
	s.inputs = append(s.inputs, input)
	return deploymentbiz.Deployment{ID: "deployment-1"}, s.err
}

func TestArtifactReleaseAdapterCoordinatesSnapshottedAutomaticDeployments(t *testing.T) {
	creator := &automaticDeploymentCreatorStub{}
	adapter := NewArtifactReleaseAdapter(artifactReleaseSourceStub{}).
		WithAutomaticDeployments(creator)
	releaseID, err := adapter.CreateArtifactRelease(t.Context(), biz.ArtifactReleaseRequest{
		ArtifactID: "artifact-1", OrganizationID: "organization-1",
		ProjectID: "project-1", ApplicationID: "application-1",
		BuildID: "build-1", BuildConfigurationID: "configuration-1",
		AutomaticDeployments: []biz.AutomaticDeploymentRule{{
			EnvironmentID: "development-1", RuntimeTargetID: "target-1",
		}},
	})
	if err != nil || releaseID != "release-1" || len(creator.inputs) != 1 {
		t.Fatalf("CreateArtifactRelease() = %q/%+v/%v", releaseID, creator.inputs, err)
	}
	input := creator.inputs[0]
	if input.ReleaseID != releaseID || input.ArtifactID != "artifact-1" ||
		input.BuildID != "build-1" || input.BuildConfigurationID != "configuration-1" {
		t.Fatalf("automatic deployment input = %+v", input)
	}
}

func TestArtifactReleaseAdapterKeepsHandoffPendingWhenAutomaticDeploymentFails(t *testing.T) {
	creator := &automaticDeploymentCreatorStub{err: deploymentbiz.ErrRuntimeTargetNotReady}
	adapter := NewArtifactReleaseAdapter(artifactReleaseSourceStub{}).
		WithAutomaticDeployments(creator)
	_, err := adapter.CreateArtifactRelease(t.Context(), biz.ArtifactReleaseRequest{
		ArtifactID: "artifact-1", OrganizationID: "organization-1",
		ProjectID: "project-1", ApplicationID: "application-1",
		BuildID: "build-1", BuildConfigurationID: "configuration-1",
		AutomaticDeployments: []biz.AutomaticDeploymentRule{{
			EnvironmentID: "development-1", RuntimeTargetID: "target-1",
		}},
	})
	if !errors.Is(err, biz.ErrArtifactReleaseUnavailable) {
		t.Fatalf("automatic deployment failure = %v", err)
	}
}
