package biz

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/shared/security"
)

// DeleteApplication closes admission immediately and starts a durable cleanup
// workflow. Immutable Release, Deployment, Build and Audit history remains.
func (u *UseCase) DeleteApplication(
	ctx context.Context,
	principal security.Principal,
	projectID, applicationID, requestID string,
) (bool, error) {
	if err := principal.Require(security.PermissionApplicationWrite); err != nil {
		return false, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return false, err
	}
	if u.resourceLifecycle == nil || u.resourceRetirer == nil {
		return false, ErrResourceRetirementUnavailable
	}
	retirement := productResourceRetirement(principal, requestID, u.now().UTC())
	item, found, err := u.beginApplicationRetirement(ctx, principal, projectID, applicationID, retirement)
	if err != nil || !found {
		return !found, err
	}
	return u.continueApplicationRetirement(ctx, item)
}

func (u *UseCase) beginApplicationRetirement(
	ctx context.Context,
	principal security.Principal,
	projectID, applicationID string,
	retirement ProductResourceRetirement,
) (Application, bool, error) {
	auditID, err := u.newID()
	if err != nil {
		return Application{}, false, err
	}
	var item Application
	found := true
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		var changed bool
		var beginErr error
		item, changed, beginErr = u.resourceLifecycle.BeginApplicationRetirement(
			transactionContext, projectID, applicationID, retirement,
		)
		if errors.Is(beginErr, ErrNotFound) {
			found = false
			return nil
		}
		if beginErr != nil || !changed {
			return beginErr
		}
		return u.record(
			transactionContext, principal, auditID,
			"application.retirement_started", "application", applicationID,
			projectID, retirement.RequestID, retirement.StartedAt,
		)
	})
	return item, found, err
}

// DeleteEnvironment mirrors Application retirement while retaining immutable
// deployment history that references the Environment ID.
func (u *UseCase) DeleteEnvironment(
	ctx context.Context,
	principal security.Principal,
	projectID, environmentID, requestID string,
) (bool, error) {
	if err := principal.Require(security.PermissionEnvironmentWrite); err != nil {
		return false, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return false, err
	}
	if u.resourceLifecycle == nil || u.resourceRetirer == nil {
		return false, ErrResourceRetirementUnavailable
	}
	retirement := productResourceRetirement(principal, requestID, u.now().UTC())
	item, found, err := u.beginEnvironmentRetirement(ctx, principal, projectID, environmentID, retirement)
	if err != nil || !found {
		return !found, err
	}
	return u.continueEnvironmentRetirement(ctx, item)
}

func (u *UseCase) beginEnvironmentRetirement(
	ctx context.Context,
	principal security.Principal,
	projectID, environmentID string,
	retirement ProductResourceRetirement,
) (Environment, bool, error) {
	auditID, err := u.newID()
	if err != nil {
		return Environment{}, false, err
	}
	var item Environment
	found := true
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		var changed bool
		var beginErr error
		item, changed, beginErr = u.resourceLifecycle.BeginEnvironmentRetirement(
			transactionContext, projectID, environmentID, retirement,
		)
		if errors.Is(beginErr, ErrNotFound) {
			found = false
			return nil
		}
		if beginErr != nil || !changed {
			return beginErr
		}
		return u.record(
			transactionContext, principal, auditID,
			"environment.retirement_started", "environment", environmentID,
			projectID, retirement.RequestID, retirement.StartedAt,
		)
	})
	return item, found, err
}

func productResourceRetirement(
	principal security.Principal,
	requestID string,
	startedAt time.Time,
) ProductResourceRetirement {
	return ProductResourceRetirement{
		OrganizationID: principal.OrganizationID, ActorID: principal.UserID,
		RequestID: requestID, StartedAt: startedAt,
	}
}

// ContinueProductResourceRetirements resumes accepted Application and
// Environment work after requests return and after process restarts.
func (u *UseCase) ContinueProductResourceRetirements(
	ctx context.Context,
	limit int64,
) (int, error) {
	if u.resourceLifecycle == nil || u.resourceRetirer == nil {
		return 0, ErrResourceRetirementUnavailable
	}
	if limit < 1 || limit > 100 {
		return 0, errors.New("product resource retirement limit must be between 1 and 100")
	}
	applications, err := u.resourceLifecycle.ListRetiringApplications(ctx, limit)
	if err != nil {
		return 0, err
	}
	environments, err := u.resourceLifecycle.ListRetiringEnvironments(ctx, limit)
	if err != nil {
		return 0, err
	}
	completed := 0
	var result error
	for _, item := range applications {
		done, continueErr := u.continueApplicationRetirement(ctx, item)
		if continueErr != nil {
			result = errors.Join(result, continueErr)
		} else if done {
			completed++
		}
	}
	for _, item := range environments {
		done, continueErr := u.continueEnvironmentRetirement(ctx, item)
		if continueErr != nil {
			result = errors.Join(result, continueErr)
		} else if done {
			completed++
		}
	}
	return completed, result
}

func (u *UseCase) continueApplicationRetirement(ctx context.Context, item Application) (bool, error) {
	retirement, principal, err := validateProductResourceRetirement(item.Retirement)
	if err != nil {
		return false, err
	}
	scope := ProductResourceRetirementScope{
		ProjectID: item.ProjectID, ApplicationID: item.ID,
	}
	dependenciesPending, err := u.convergeProductResourceDependencies(ctx, scope, *retirement)
	if err != nil {
		return false, err
	}
	err = u.resourceRetirer.RetireProductResource(ctx, scope, principal, retirement.RequestID)
	if errors.Is(err, ErrResourceRetirementPending) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if dependenciesPending {
		return false, nil
	}
	return u.completeProductResourceRetirement(
		ctx, principal, item.ProjectID, item.ID, "application",
		retirement.RequestID, u.resourceLifecycle.CompleteApplicationRetirement,
	)
}

func (u *UseCase) continueEnvironmentRetirement(ctx context.Context, item Environment) (bool, error) {
	retirement, principal, err := validateProductResourceRetirement(item.Retirement)
	if err != nil {
		return false, err
	}
	scope := ProductResourceRetirementScope{
		ProjectID: item.ProjectID, EnvironmentID: item.ID,
	}
	dependenciesPending, err := u.convergeProductResourceDependencies(ctx, scope, *retirement)
	if err != nil {
		return false, err
	}
	err = u.resourceRetirer.RetireProductResource(ctx, scope, principal, retirement.RequestID)
	if errors.Is(err, ErrResourceRetirementPending) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if dependenciesPending {
		return false, nil
	}
	return u.completeProductResourceRetirement(
		ctx, principal, item.ProjectID, item.ID, "environment",
		retirement.RequestID, u.resourceLifecycle.CompleteEnvironmentRetirement,
	)
}

func (u *UseCase) convergeProductResourceDependencies(
	ctx context.Context,
	scope ProductResourceRetirementScope,
	retirement ProductResourceRetirement,
) (bool, error) {
	pending := false
	for _, dependency := range u.resourceDependencies {
		if dependency == nil {
			return false, ErrResourceRetirementUnavailable
		}
		dependencyPending, err := dependency.ConvergeProductResource(
			ctx, retirement.OrganizationID, scope.ProjectID,
			scope.ApplicationID, scope.EnvironmentID,
			retirement.ActorID, retirement.RequestID,
		)
		if err != nil {
			return false, err
		}
		pending = pending || dependencyPending
	}
	return pending, nil
}

type completeProductResource func(context.Context, string, string, time.Time) error

func (u *UseCase) completeProductResourceRetirement(
	ctx context.Context,
	principal security.Principal,
	projectID, resourceID, resourceType, requestID string,
	complete completeProductResource,
) (bool, error) {
	auditID, err := u.newID()
	if err != nil {
		return false, err
	}
	retiredAt := u.now().UTC()
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		if completeErr := complete(transactionContext, projectID, resourceID, retiredAt); completeErr != nil {
			return completeErr
		}
		return u.record(
			transactionContext, principal, auditID,
			resourceType+".retired", resourceType, resourceID,
			projectID, requestID, retiredAt,
		)
	})
	if errors.Is(err, ErrNotFound) {
		return true, nil
	}
	return err == nil, err
}

func validateProductResourceRetirement(
	retirement *ProductResourceRetirement,
) (*ProductResourceRetirement, security.Principal, error) {
	if retirement == nil || strings.TrimSpace(retirement.OrganizationID) == "" ||
		strings.TrimSpace(retirement.ActorID) == "" || retirement.StartedAt.IsZero() {
		return nil, security.Principal{}, ErrResourceRetirementUnavailable
	}
	return retirement, security.Principal{
		UserID: retirement.ActorID, OrganizationID: retirement.OrganizationID,
	}, nil
}
