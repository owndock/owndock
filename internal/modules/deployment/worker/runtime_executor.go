package worker

import (
	"context"
	"errors"
	"sort"
	"time"

	applicationroutebiz "github.com/owndock/owndock/internal/modules/applicationroute/biz"
	"github.com/owndock/owndock/internal/modules/deployment/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
)

var (
	ErrMissingExecutionResolver  = errors.New("deployment execution resolver is required")
	ErrMissingCredentialResolver = errors.New("runtime credential resolver is required")
	ErrMissingRuntimeGateway     = errors.New("runtime gateway is required")
	ErrInvalidIngressDrain       = errors.New("managed ingress drain must be between zero and sixty seconds")
	ErrManagedIngressUnavailable = errors.New("managed ingress runtime gateway is unavailable")
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
	ingress       *applicationroutebiz.CutoverCoordinator
	ingressDrain  time.Duration
}

func (e *RuntimeExecutor) WithManagedIngress(
	coordinator *applicationroutebiz.CutoverCoordinator,
	drain time.Duration,
) (*RuntimeExecutor, error) {
	if coordinator == nil || drain < 0 || drain > 60*time.Second {
		return nil, ErrInvalidIngressDrain
	}
	e.ingress, e.ingressDrain = coordinator, drain
	return e, nil
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
	return e.execute(ctx, deployment, func(
		ctx context.Context,
		plan biz.ExecutionPlan,
		credential biz.RuntimeCredential,
	) error {
		if e.ingress == nil || plan.TargetConnection.Mode != runtimeaccess.ModeAgent {
			return e.gateway.Deploy(ctx, plan, credential)
		}
		request, err := managedIngressCutoverRequest(deployment, plan)
		if err != nil {
			return err
		}
		required, err := e.ingress.Required(ctx, request)
		if err != nil {
			return err
		}
		if !required {
			return e.gateway.Deploy(ctx, plan, credential)
		}
		managed, ok := e.gateway.(biz.ManagedIngressRuntimeGateway)
		if !ok {
			return ErrManagedIngressUnavailable
		}
		original, err := e.ingress.Begin(ctx, request)
		if err != nil {
			return err
		}
		executionPlan := plan
		executionPlan.WorkerID = original.WorkerID
		executionPlan.FencingToken = original.FencingToken
		executionPlan.ManagedIngress = true
		if err := managed.Stage(ctx, executionPlan, credential); err != nil {
			if biz.CategorizeExecutionError(err, biz.FailureUnknown) == biz.FailureTargetUnreachable {
				return errors.Join(biz.ErrExecutionRetryable, err)
			}
			return e.abortManagedCutover(ctx, deployment.ID, managed, plan, executionPlan, err)
		}
		if err := e.ingress.Prepare(ctx, deployment.ID); err != nil {
			if errors.Is(err, applicationroutebiz.ErrCutoverAmbiguous) {
				return errors.Join(biz.ErrExecutionRetryable, err)
			}
			return e.abortManagedCutover(ctx, deployment.ID, managed, plan, executionPlan, err)
		}
		if err := managed.ActivatePrepared(ctx, plan, executionPlan); err != nil {
			if biz.CategorizeExecutionError(err, biz.FailureUnknown) == biz.FailureTargetUnreachable {
				return errors.Join(biz.ErrExecutionRetryable, err)
			}
			return e.abortManagedCutover(ctx, deployment.ID, managed, plan, executionPlan, err)
		}
		return nil
	})
}

func (e *RuntimeExecutor) abortManagedCutover(
	ctx context.Context,
	deploymentID string,
	managed biz.ManagedIngressRuntimeGateway,
	authorization biz.ExecutionPlan,
	execution biz.ExecutionPlan,
	cause error,
) error {
	if err := e.ingress.Restore(ctx, deploymentID); err != nil {
		return errors.Join(biz.ErrExecutionRetryable, cause, err)
	}
	if err := managed.CancelPrepared(ctx, authorization, execution); err != nil {
		return errors.Join(biz.ErrExecutionRetryable, cause, err)
	}
	if err := e.ingress.FinalizeAbort(ctx, deploymentID); err != nil {
		return errors.Join(biz.ErrExecutionRetryable, cause, err)
	}
	return cause
}

// MarkControlPlaneCommitted is called inside the same transaction that moves
// the Deployment to committing. The route store makes it a no-op when this
// Deployment has no managed ingress transaction.
func (e *RuntimeExecutor) MarkControlPlaneCommitted(ctx context.Context, deployment biz.Deployment) error {
	if e.ingress == nil {
		return nil
	}
	plan, err := e.executions.ResolveExecution(ctx, deployment)
	if err != nil {
		return err
	}
	request, err := managedIngressCutoverRequest(deployment, plan)
	if err != nil {
		return err
	}
	return e.ingress.MarkControlPlaneCommitted(ctx, request)
}

func (e *RuntimeExecutor) Commit(ctx context.Context, deployment biz.Deployment) error {
	if e.ingress == nil {
		return nil
	}
	request, exists, err := e.ingress.Commit(ctx, deployment.ID)
	if err != nil || !exists {
		return err
	}
	if e.ingressDrain > 0 {
		timer := time.NewTimer(e.ingressDrain)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	plan, err := e.executions.ResolveExecution(ctx, deployment)
	if err != nil {
		return err
	}
	plan.WorkerID, plan.FencingToken = request.WorkerID, request.FencingToken
	plan.ManagedIngress = true
	managed, ok := e.gateway.(biz.ManagedIngressRuntimeGateway)
	if !ok {
		return ErrManagedIngressUnavailable
	}
	if err := managed.Retire(ctx, plan); err != nil {
		return err
	}
	return e.ingress.Finish(ctx, deployment.ID)
}

func managedIngressCutoverRequest(
	deployment biz.Deployment,
	plan biz.ExecutionPlan,
) (applicationroutebiz.CutoverRequest, error) {
	ports := make(map[string]uint16, len(plan.RuntimeSpec.Ports))
	for _, port := range plan.RuntimeSpec.Ports {
		if port.Protocol != "" && port.Protocol != "tcp" {
			continue
		}
		ports[port.Name] = port.ContainerPort
	}
	request := applicationroutebiz.CutoverRequest{
		OrganizationID: deployment.OrganizationID, ProjectID: plan.ProjectID,
		ApplicationID: plan.ApplicationID, EnvironmentID: plan.EnvironmentID,
		RuntimeTargetID: plan.RuntimeTargetID,
		ManagedHostID:   plan.TargetConnection.ManagedHostID,
		DeploymentID:    plan.DeploymentID, WorkerID: plan.WorkerID,
		ContainerName: plan.ContainerName, FencingToken: plan.FencingToken,
		CutoverSequence: plan.CutoverSequence, Ports: ports,
	}
	if err := request.Validate(); err != nil {
		return applicationroutebiz.CutoverRequest{}, err
	}
	return request, nil
}

func (e *RuntimeExecutor) Cancel(ctx context.Context, deployment biz.Deployment) error {
	resolver := e.executions.ResolveExecution
	if cancellationResolver, ok := e.executions.(biz.CancellationExecutionResolver); ok {
		resolver = cancellationResolver.ResolveCancellation
	}
	return e.executeWithResolver(ctx, deployment, resolver, func(
		ctx context.Context,
		plan biz.ExecutionPlan,
		credential biz.RuntimeCredential,
	) error {
		if e.ingress == nil || plan.TargetConnection.Mode != runtimeaccess.ModeAgent {
			return e.gateway.Cancel(ctx, plan, credential)
		}
		original, exists, err := e.ingress.Pending(ctx, deployment.ID)
		if err != nil {
			return err
		}
		if !exists {
			return e.gateway.Cancel(ctx, plan, credential)
		}
		managed, ok := e.gateway.(biz.ManagedIngressRuntimeGateway)
		if !ok {
			return ErrManagedIngressUnavailable
		}
		executionPlan := plan
		executionPlan.WorkerID = original.WorkerID
		executionPlan.FencingToken = original.FencingToken
		executionPlan.ManagedIngress = true
		if err := e.ingress.Restore(ctx, deployment.ID); err != nil {
			return errors.Join(biz.ErrExecutionRetryable, err)
		}
		if err := managed.CancelPrepared(ctx, plan, executionPlan); err != nil {
			return errors.Join(biz.ErrExecutionRetryable, err)
		}
		if err := e.ingress.FinalizeAbort(ctx, deployment.ID); err != nil {
			return errors.Join(biz.ErrExecutionRetryable, err)
		}
		return nil
	})
}

func (e *RuntimeExecutor) execute(
	ctx context.Context,
	deployment biz.Deployment,
	run func(context.Context, biz.ExecutionPlan, biz.RuntimeCredential) error,
) error {
	return e.executeWithResolver(ctx, deployment, e.executions.ResolveExecution, run)
}

func (e *RuntimeExecutor) executeWithResolver(
	ctx context.Context,
	deployment biz.Deployment,
	resolve func(context.Context, biz.Deployment) (biz.ExecutionPlan, error),
	run func(context.Context, biz.ExecutionPlan, biz.RuntimeCredential) error,
) error {
	plan, err := resolve(ctx, deployment)
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
		if errors.Is(err, biz.ErrExecutionRetryable) {
			return err
		}
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
