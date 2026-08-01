package biz

import (
	"context"
	"errors"
	"strings"
)

var (
	ErrInvalidBuildExecution     = errors.New("build execution request is invalid")
	ErrBuildKitUnavailable       = errors.New("BuildKit is unavailable")
	ErrBuildExecutionFailed      = errors.New("image build failed")
	ErrBuildResourceLimit        = errors.New("build resource limit exceeded")
	ErrRegistryAuthentication    = errors.New("registry authentication failed")
	ErrRegistryPushFailed        = errors.New("registry push failed")
	ErrInvalidBuildOutput        = errors.New("build output is invalid")
	ErrRegistrySecretUnavailable = errors.New("registry secret is unavailable")
)

// BuildRegistryCredential carries only the metadata required for one image
// push. Password bytes are resolved for the operation and are never stored in
// Build or Build Configuration snapshots.
type BuildRegistryCredential struct {
	ID          string
	ProjectID   string
	Server      string
	Username    string
	PasswordRef string
}

func (c BuildRegistryCredential) Validate(projectID, credentialID string) error {
	if strings.TrimSpace(c.ID) != strings.TrimSpace(credentialID) ||
		strings.TrimSpace(c.ProjectID) != strings.TrimSpace(projectID) ||
		strings.TrimSpace(c.Server) == "" || strings.TrimSpace(c.Username) == "" ||
		strings.TrimSpace(c.PasswordRef) == "" {
		return ErrInvalidBuildExecution
	}
	return nil
}

type BuildExecutionRequest struct {
	BuildID       string
	ProjectID     string
	Generation    uint64
	Workspace     string
	Configuration BuildConfigurationSnapshot
	Credential    BuildRegistryCredential
	LogSink       BuildLogSink
}

func (r BuildExecutionRequest) Validate() error {
	contextPath, contextOK := safeRepositoryPath(r.Configuration.ContextPath, true)
	dockerfilePath, dockerfileOK := safeRepositoryPath(r.Configuration.DockerfilePath, false)
	imageRepository, imageOK := normalizeImageRepository(r.Configuration.ImageRepository)
	if !validIdentifier(strings.TrimSpace(r.BuildID)) ||
		!validIdentifier(strings.TrimSpace(r.ProjectID)) || r.Generation == 0 ||
		strings.TrimSpace(r.Workspace) == "" ||
		!validIdentifier(r.Configuration.ConfigurationID) ||
		r.Configuration.ConfigurationVersion == 0 ||
		!validIdentifier(r.Configuration.SourceRepositoryID) ||
		!validIdentifier(r.Configuration.RegistryCredentialID) ||
		!contextOK || contextPath != r.Configuration.ContextPath ||
		!dockerfileOK || dockerfilePath != r.Configuration.DockerfilePath ||
		!pathWithinContext(contextPath, dockerfilePath) ||
		!imageOK || imageRepository != r.Configuration.ImageRepository ||
		!r.Configuration.TargetPlatform.Valid() ||
		!r.Configuration.Resources.valid() ||
		r.Configuration.TimeoutSeconds < 60 || r.Configuration.TimeoutSeconds > 2*60*60 ||
		r.Credential.Validate(r.ProjectID, r.Configuration.RegistryCredentialID) != nil {
		return ErrInvalidBuildExecution
	}
	registry, err := ImageRepositoryRegistry(r.Configuration.ImageRepository)
	if err != nil || registry != strings.TrimSpace(r.Credential.Server) {
		return ErrInvalidBuildExecution
	}
	return nil
}

type BuildExecutionOutput struct {
	ImageDigest string
}

type BuildExecutor interface {
	Build(context.Context, BuildExecutionRequest) (BuildExecutionOutput, error)
}

type BuildRegistrySource interface {
	GetBuildRegistryCredential(context.Context, string, string) (BuildRegistryCredential, error)
}

type RegistrySecretResolver interface {
	ResolveRegistryPassword(context.Context, BuildRegistryCredential) ([]byte, error)
}
