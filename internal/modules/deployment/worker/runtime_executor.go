package worker

import (
	"context"
	"errors"
	"sort"

	"github.com/owndock/owndock/internal/modules/deployment/biz"
)

var (
	ErrMissingExecutionResolver  = errors.New("deployment execution resolver is required")
	ErrMissingCredentialResolver = errors.New("runtime credential resolver is required")
	ErrMissingRuntimeGateway     = errors.New("runtime gateway is required")
)

// RuntimeExecutor resolves immutable deployment references immediately before
// each idempotent gateway operation. Secrets are kept in memory only for the
// duration of that call and are never added to Deployment or audit records.
type RuntimeExecutor struct {
	executions    biz.ExecutionResolver
	credentials   biz.CredentialResolver
	registries    biz.RegistryCredentialResolver
	configuration biz.ConfigurationResolver
	gateway       biz.RuntimeGateway
}

func (e *RuntimeExecutor) WithConfiguration(
	resolver biz.ConfigurationResolver,
) *RuntimeExecutor {
	e.configuration = resolver
	return e
}

func (e *RuntimeExecutor) WithRegistryCredentials(
	resolver biz.RegistryCredentialResolver,
) *RuntimeExecutor {
	e.registries = resolver
	return e
}

func NewRuntimeExecutor(
	executions biz.ExecutionResolver,
	credentials biz.CredentialResolver,
	gateway biz.RuntimeGateway,
) (*RuntimeExecutor, error) {
	if executions == nil {
		return nil, ErrMissingExecutionResolver
	}
	if credentials == nil {
		return nil, ErrMissingCredentialResolver
	}
	if gateway == nil {
		return nil, ErrMissingRuntimeGateway
	}
	return &RuntimeExecutor{
		executions: executions, credentials: credentials, gateway: gateway,
	}, nil
}

func (e *RuntimeExecutor) Prepare(ctx context.Context, deployment biz.Deployment) error {
	return e.execute(ctx, deployment, e.gateway.Prepare)
}

func (e *RuntimeExecutor) Deploy(ctx context.Context, deployment biz.Deployment) error {
	return e.execute(ctx, deployment, e.gateway.Deploy)
}

func (e *RuntimeExecutor) Cancel(ctx context.Context, deployment biz.Deployment) error {
	return e.execute(ctx, deployment, e.gateway.Cancel)
}

func (e *RuntimeExecutor) execute(
	ctx context.Context,
	deployment biz.Deployment,
	run func(context.Context, biz.ExecutionPlan, biz.RuntimeCredential) error,
) error {
	plan, err := e.executions.ResolveExecution(ctx, deployment)
	if err != nil {
		return &biz.ExecutionError{Category: biz.FailureConfiguration, Cause: err}
	}
	if err := plan.TargetConnection.Validate(); err != nil {
		return &biz.ExecutionError{Category: biz.FailureConfiguration, Cause: err}
	}
	credential, err := e.credentials.ResolveCredential(ctx, plan.TargetConnection)
	if err != nil {
		return &biz.ExecutionError{Category: biz.FailureCredential, Cause: err}
	}
	defer clearCredential(&credential)
	if plan.RegistryPasswordRef != "" {
		if e.registries == nil {
			return &biz.ExecutionError{
				Category: biz.FailureConfiguration,
				Cause:    errors.New("registry credential resolver is required"),
			}
		}
		credential.RegistryAuthorization, err = e.registries.ResolveRegistryAuthorization(
			ctx, plan.RegistryServer, plan.RegistryUsername, plan.RegistryPasswordRef,
		)
		if err != nil {
			return &biz.ExecutionError{Category: biz.FailureCredential, Cause: err}
		}
	}
	if len(plan.EnvironmentBindings) > 0 {
		if e.configuration == nil {
			return &biz.ExecutionError{
				Category: biz.FailureConfiguration,
				Cause:    errors.New("configuration resolver is required"),
			}
		}
		names := make([]string, 0, len(plan.EnvironmentBindings))
		for name := range plan.EnvironmentBindings {
			names = append(names, name)
		}
		sort.Strings(names)
		plan.Environment = make([]string, 0, len(names))
		for _, name := range names {
			value, resolveErr := e.configuration.ResolveConfigurationValue(
				ctx, plan.EnvironmentBindings[name],
			)
			if resolveErr != nil {
				return &biz.ExecutionError{Category: biz.FailureCredential, Cause: resolveErr}
			}
			plan.Environment = append(plan.Environment, name+"="+value)
		}
	}
	if err := run(ctx, plan, credential); err != nil {
		var executionError *biz.ExecutionError
		if errors.As(err, &executionError) {
			return executionError
		}
		return &biz.ExecutionError{Category: biz.FailureRuntime, Cause: err}
	}
	return nil
}

func clearCredential(credential *biz.RuntimeCredential) {
	values := [][]byte{credential.RegistryAuthorization}
	if credential.DirectDocker != nil {
		values = append(values,
			credential.DirectDocker.CACertificate,
			credential.DirectDocker.ClientCertificate,
			credential.DirectDocker.ClientKey,
		)
	}
	for _, value := range values {
		for index := range value {
			value[index] = 0
		}
	}
}
