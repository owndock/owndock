package biz

import (
	"context"
	"errors"
	"time"

	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/runtimespec"
)

type FailureCategory string

const (
	FailureConfiguration     FailureCategory = "configuration"
	FailureCredential        FailureCategory = "credential"
	FailureTargetUnreachable FailureCategory = "target_unreachable"
	FailureImagePull         FailureCategory = "image_pull"
	FailureRuntime           FailureCategory = "runtime"
	FailureUnsupportedTarget FailureCategory = "unsupported_target"
	FailureUnknown           FailureCategory = "unknown"
)

func (c FailureCategory) Valid() bool {
	switch c {
	case FailureConfiguration, FailureCredential, FailureTargetUnreachable,
		FailureImagePull, FailureRuntime, FailureUnsupportedTarget, FailureUnknown:
		return true
	default:
		return false
	}
}

// ExecutionError carries a safe category across the runtime boundary. Cause is
// retained for internal diagnostics but must never be returned through the API.
type ExecutionError struct {
	Category FailureCategory
	Cause    error
}

func (e *ExecutionError) Error() string {
	if e == nil || !e.Category.Valid() {
		return string(FailureUnknown)
	}
	return string(e.Category)
}

func (e *ExecutionError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func CategorizeExecutionError(err error, fallback FailureCategory) FailureCategory {
	var executionError *ExecutionError
	if errors.As(err, &executionError) && executionError.Category.Valid() {
		return executionError.Category
	}
	if fallback.Valid() {
		return fallback
	}
	return FailureUnknown
}

type ExecutionPlan struct {
	DeploymentID        string
	WorkerID            string
	FencingToken        uint64
	ProjectID           string
	ApplicationID       string
	EnvironmentID       string
	RuntimeTargetID     string
	ImageDigest         string
	TargetConnection    runtimeaccess.Connection
	RegistryServer      string
	RegistryUsername    string
	RegistryPasswordRef string
	RuntimeSpec         runtimespec.Spec
	EnvironmentBindings map[string]string
	Environment         []string
	ContainerName       string
}

type RuntimeCredential struct {
	DirectDocker          *DirectDockerCredential
	RegistryAuthorization []byte
}

type DirectDockerCredential struct {
	CACertificate     []byte
	ClientCertificate []byte
	ClientKey         []byte
}

type ExecutionResolver interface {
	ResolveExecution(context.Context, Deployment) (ExecutionPlan, error)
}

type CredentialResolver interface {
	ResolveCredential(context.Context, runtimeaccess.Connection) (RuntimeCredential, error)
}

type RegistryCredentialResolver interface {
	ResolveRegistryAuthorization(
		context.Context,
		string,
		string,
		string,
	) ([]byte, error)
}

type ConfigurationResolver interface {
	ResolveConfigurationValue(context.Context, string) (string, error)
}

type FenceValidator interface {
	ValidateFence(
		context.Context,
		string,
		string,
		string,
		uint64,
		time.Time,
	) error
}

type RuntimeGateway interface {
	Prepare(context.Context, ExecutionPlan, RuntimeCredential) error
	Deploy(context.Context, ExecutionPlan, RuntimeCredential) error
	Cancel(context.Context, ExecutionPlan, RuntimeCredential) error
}

type Executor interface {
	Prepare(context.Context, Deployment) error
	Deploy(context.Context, Deployment) error
	Cancel(context.Context, Deployment) error
}
