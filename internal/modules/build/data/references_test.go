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
