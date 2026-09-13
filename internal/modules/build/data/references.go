package data

import (
	"context"
	"errors"

	"github.com/owndock/owndock/internal/modules/build/biz"
	controlplanebiz "github.com/owndock/owndock/internal/modules/controlplane/biz"
	deploymentbiz "github.com/owndock/owndock/internal/modules/deployment/biz"
)

type configurationReferenceSource interface {
	ApplicationExists(context.Context, string, string) (bool, error)
	FenceProductResourceAdmission(context.Context, string, string, string) (bool, error)
	GetRegistryCredential(context.Context, string, string) (controlplanebiz.RegistryCredential, error)
	EnvironmentStage(context.Context, string, string) (string, error)
	RuntimeTargetExists(context.Context, string, string) (bool, error)
}

type ConfigurationReferenceLookup struct {
	source configurationReferenceSource
}

type BuildRegistrySourceAdapter struct {
	source configurationReferenceSource
}

type artifactReleaseSource interface {
	CreateReleaseFromArtifact(context.Context, controlplanebiz.ArtifactReleaseInput) (controlplanebiz.Release, error)
}

type ArtifactReleaseAdapter struct {
	source      artifactReleaseSource
	deployments interface {
		CreateAutomatic(context.Context, deploymentbiz.AutomaticDeploymentInput) (deploymentbiz.Deployment, error)
	}
}

func (a *ArtifactReleaseAdapter) WithAutomaticDeployments(creator interface {
	CreateAutomatic(context.Context, deploymentbiz.AutomaticDeploymentInput) (deploymentbiz.Deployment, error)
}) *ArtifactReleaseAdapter {
	a.deployments = creator
	return a
}

func NewConfigurationReferenceLookup(source configurationReferenceSource) *ConfigurationReferenceLookup {
	return &ConfigurationReferenceLookup{source: source}
}

func NewBuildRegistrySource(source configurationReferenceSource) *BuildRegistrySourceAdapter {
	return &BuildRegistrySourceAdapter{source: source}
}

func NewArtifactReleaseAdapter(source artifactReleaseSource) *ArtifactReleaseAdapter {
	return &ArtifactReleaseAdapter{source: source}
}

func (l *ConfigurationReferenceLookup) ApplicationExists(
	ctx context.Context,
	projectID, applicationID string,
) (bool, error) {
	return l.source.ApplicationExists(ctx, projectID, applicationID)
}

func (l *ConfigurationReferenceLookup) FenceProductResourceAdmission(
	ctx context.Context,
	projectID, applicationID, environmentID string,
) (bool, error) {
	return l.source.FenceProductResourceAdmission(
		ctx, projectID, applicationID, environmentID,
	)
}

func (l *ConfigurationReferenceLookup) RegistryServer(
	ctx context.Context,
	projectID, credentialID string,
) (string, error) {
	credential, err := l.source.GetRegistryCredential(ctx, projectID, credentialID)
	if err != nil {
		if errors.Is(err, controlplanebiz.ErrNotFound) {
			return "", biz.ErrNotFound
		}
		return "", err
	}
	return credential.Server, nil
}

func (l *ConfigurationReferenceLookup) ValidateAutomaticDeployment(
	ctx context.Context,
	projectID, environmentID, runtimeTargetID string,
) error {
	stage, err := l.source.EnvironmentStage(ctx, projectID, environmentID)
	if err != nil {
		if errors.Is(err, controlplanebiz.ErrNotFound) {
			return biz.ErrNotFound
		}
		return err
	}
	if stage != string(controlplanebiz.EnvironmentStageDevelopment) {
		return biz.ErrAutomaticDeploymentDenied
	}
	exists, err := l.source.RuntimeTargetExists(ctx, projectID, runtimeTargetID)
	if err != nil {
		return err
	}
	if !exists {
		return biz.ErrNotFound
	}
	return nil
}

func (s *BuildRegistrySourceAdapter) GetBuildRegistryCredential(
	ctx context.Context,
	projectID, credentialID string,
) (biz.BuildRegistryCredential, error) {
	credential, err := s.source.GetRegistryCredential(ctx, projectID, credentialID)
	if err != nil {
		if errors.Is(err, controlplanebiz.ErrNotFound) {
			return biz.BuildRegistryCredential{}, biz.ErrNotFound
		}
		return biz.BuildRegistryCredential{}, err
	}
	result := biz.BuildRegistryCredential{
		ID: credential.ID, ProjectID: credential.ProjectID, Server: credential.Server,
		AuthenticationMode: credential.AuthenticationMode,
		Username:           credential.Username, PasswordRef: credential.PasswordRef,
	}
	if err := result.Validate(projectID, credentialID); err != nil {
		return biz.BuildRegistryCredential{}, biz.ErrInvalidBuildExecution
	}
	return result, nil
}

func (a *ArtifactReleaseAdapter) CreateArtifactRelease(
	ctx context.Context,
	request biz.ArtifactReleaseRequest,
) (string, error) {
	item, err := a.source.CreateReleaseFromArtifact(ctx, controlplanebiz.ArtifactReleaseInput{
		ArtifactID: request.ArtifactID, OrganizationID: request.OrganizationID,
		ProjectID: request.ProjectID, ApplicationID: request.ApplicationID,
		RegistryCredentialID: request.RegistryCredentialID,
		ImageDigest:          request.ImageDigest, RuntimeSpec: request.RuntimeSpec,
		ActorID: request.ActorID, RequestID: request.RequestID,
	})
	if err != nil {
		switch {
		case errors.Is(err, controlplanebiz.ErrNotFound):
			return "", biz.ErrNotFound
		case errors.Is(err, controlplanebiz.ErrInvalidImage),
			errors.Is(err, controlplanebiz.ErrInvalidRegistry),
			errors.Is(err, controlplanebiz.ErrInvalidRuntimeSpec),
			errors.Is(err, controlplanebiz.ErrDuplicateRelease):
			return "", biz.ErrInvalidArtifact
		default:
			return "", biz.ErrArtifactReleaseUnavailable
		}
	}
	if len(request.AutomaticDeployments) > 0 && a.deployments == nil {
		return "", biz.ErrArtifactReleaseUnavailable
	}
	for _, rule := range request.AutomaticDeployments {
		_, deploymentErr := a.deployments.CreateAutomatic(ctx, deploymentbiz.AutomaticDeploymentInput{
			OrganizationID: request.OrganizationID, ProjectID: request.ProjectID,
			ReleaseID: item.ID, ApplicationID: request.ApplicationID,
			EnvironmentID: rule.EnvironmentID, RuntimeTargetID: rule.RuntimeTargetID,
			ArtifactID: request.ArtifactID, BuildID: request.BuildID,
			BuildConfigurationID: request.BuildConfigurationID,
		})
		if deploymentErr != nil {
			switch {
			case errors.Is(deploymentErr, deploymentbiz.ErrAutomaticDeploymentNotAllowed),
				errors.Is(deploymentErr, deploymentbiz.ErrInvalidEnvironment),
				errors.Is(deploymentErr, deploymentbiz.ErrInvalidRuntimeTarget):
				return "", biz.ErrInvalidArtifact
			default:
				return "", biz.ErrArtifactReleaseUnavailable
			}
		}
	}
	return item.ID, nil
}

var (
	_ biz.ApplicationLookup                  = (*ConfigurationReferenceLookup)(nil)
	_ biz.ProductResourceAdmissionFence      = (*ConfigurationReferenceLookup)(nil)
	_ biz.RegistryCredentialLookup           = (*ConfigurationReferenceLookup)(nil)
	_ biz.AutomaticDeploymentReferenceLookup = (*ConfigurationReferenceLookup)(nil)
	_ biz.BuildRegistrySource                = (*BuildRegistrySourceAdapter)(nil)
	_ biz.ArtifactReleaseCreator             = (*ArtifactReleaseAdapter)(nil)
)
