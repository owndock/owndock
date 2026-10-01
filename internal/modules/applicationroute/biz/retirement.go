package biz

import (
	"context"
	"errors"
	"strings"

	"github.com/owndock/owndock/internal/shared/security"
)

var (
	ErrRetirementUnavailable = errors.New("application route retirement is unavailable")
	ErrRetirementPending     = errors.New("application route retirement is pending")
	ErrRetirementConflict    = errors.New("application route retirement conflicts")
)

const retirementControllerActor = "system:application-route-retirement"

type RetirementRepository interface {
	ListRetiring(context.Context, int64) ([]ApplicationRoute, error)
	ListByProductResource(context.Context, string, string, string, string) ([]ApplicationRoute, error)
	ListByRuntimeTarget(context.Context, string, string, string) ([]ApplicationRoute, error)
}

type RouteRetirer interface {
	Retire(context.Context, string) (completed bool, err error)
}

// Delete immediately closes route admission, then attempts gateway cleanup.
// Incomplete external work remains durable and is resumed by the worker.
func (u *UseCase) Delete(
	ctx context.Context,
	principal security.Principal,
	projectID, routeID, requestID string,
) (bool, error) {
	if err := principal.Require(security.PermissionApplicationRouteWrite); err != nil {
		return false, err
	}
	projectID, routeID = strings.TrimSpace(projectID), strings.TrimSpace(routeID)
	if !validID(projectID) || !validID(routeID) {
		return false, ErrInvalidRoute
	}
	if u.retirementRepository == nil || u.retirer == nil {
		return false, ErrRetirementUnavailable
	}
	current, err := u.repository.Get(ctx, principal.OrganizationID, projectID, routeID)
	if errors.Is(err, ErrNotFound) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	current, err = u.beginRetirement(ctx, principal, current, requestID)
	if err != nil {
		return false, err
	}
	return u.continueRetirement(ctx, current)
}

func (u *UseCase) beginRetirement(
	ctx context.Context,
	principal security.Principal,
	current ApplicationRoute,
	requestID string,
) (ApplicationRoute, error) {
	if current.Status == StatusRetiring {
		return current, nil
	}
	next, err := current.BeginRetirement(principal.UserID, requestID, u.now().UTC())
	if err != nil {
		return ApplicationRoute{}, err
	}
	if u.transaction == nil || u.auditor == nil {
		return u.repository.Save(ctx, next, current.Version)
	}
	var saved ApplicationRoute
	err = u.transaction.WithinTransaction(ctx, func(tx context.Context) error {
		var saveErr error
		saved, saveErr = u.repository.Save(tx, next, current.Version)
		if saveErr != nil {
			return saveErr
		}
		return u.recordAudit(
			tx, principal, saved, "application_route.retirement_started",
			requestID, saved.UpdatedAt,
		)
	})
	return saved, err
}

func (u *UseCase) continueRetirement(
	ctx context.Context,
	item ApplicationRoute,
) (bool, error) {
	if item.Status != StatusRetiring || item.Retirement == nil {
		return false, ErrRetirementConflict
	}
	completed, err := u.retirer.Retire(ctx, item.ID)
	if errors.Is(err, ErrRetirementPending) || errors.Is(err, ErrGatewayUnavailable) {
		return false, nil
	}
	return completed, err
}

// ContinueRouteRetirements resumes accepted route deletions after request
// cancellation and process restart.
func (u *UseCase) ContinueRouteRetirements(ctx context.Context, limit int64) (int, error) {
	if u.retirementRepository == nil || u.retirer == nil {
		return 0, ErrRetirementUnavailable
	}
	if limit < 1 || limit > 100 {
		return 0, errors.New("application route retirement limit must be between 1 and 100")
	}
	items, err := u.retirementRepository.ListRetiring(ctx, limit)
	if err != nil {
		return 0, err
	}
	completed := 0
	var result error
	for _, item := range items {
		done, continueErr := u.continueRetirement(ctx, item)
		if continueErr != nil {
			result = errors.Join(result, continueErr)
		} else if done {
			completed++
		}
	}
	return completed, result
}

// ConvergeProductResource removes public ingress before an Application or
// Environment retirement is allowed to remove its runtime backends.
func (u *UseCase) ConvergeProductResource(
	ctx context.Context,
	organizationID, projectID, applicationID, environmentID, actorID, requestID string,
) (bool, error) {
	organizationID, projectID = strings.TrimSpace(organizationID), strings.TrimSpace(projectID)
	applicationID, environmentID = strings.TrimSpace(applicationID), strings.TrimSpace(environmentID)
	actorID = strings.TrimSpace(actorID)
	if !validID(organizationID) || !validID(projectID) || !validID(actorID) ||
		(applicationID == "") == (environmentID == "") ||
		(applicationID != "" && !validID(applicationID)) ||
		(environmentID != "" && !validID(environmentID)) {
		return false, ErrRetirementUnavailable
	}
	if u.retirementRepository == nil || u.retirer == nil {
		return false, ErrRetirementUnavailable
	}
	items, err := u.retirementRepository.ListByProductResource(
		ctx, organizationID, projectID, applicationID, environmentID,
	)
	if err != nil {
		return false, err
	}
	return u.converge(ctx, items, security.Principal{
		UserID: actorID, OrganizationID: organizationID, Role: security.RoleOwner,
	}, requestID)
}

// ConvergeRuntimeTarget removes public ingress before a Runtime Target and
// its deployed containers are retired.
func (u *UseCase) ConvergeRuntimeTarget(
	ctx context.Context,
	organizationID, projectID, runtimeTargetID, actorID, requestID string,
) (bool, error) {
	organizationID, projectID = strings.TrimSpace(organizationID), strings.TrimSpace(projectID)
	runtimeTargetID, actorID = strings.TrimSpace(runtimeTargetID), strings.TrimSpace(actorID)
	if !validID(organizationID) || !validID(projectID) || !validID(runtimeTargetID) ||
		!validID(actorID) || u.retirementRepository == nil || u.retirer == nil {
		return false, ErrRetirementUnavailable
	}
	items, err := u.retirementRepository.ListByRuntimeTarget(
		ctx, organizationID, projectID, runtimeTargetID,
	)
	if err != nil {
		return false, err
	}
	return u.converge(ctx, items, security.Principal{
		UserID: actorID, OrganizationID: organizationID, Role: security.RoleOwner,
	}, requestID)
}

func (u *UseCase) converge(
	ctx context.Context,
	items []ApplicationRoute,
	principal security.Principal,
	requestID string,
) (bool, error) {
	pending := false
	var result error
	for _, item := range items {
		if item.Status != StatusRetiring {
			var err error
			item, err = u.beginRetirement(ctx, principal, item, requestID)
			if err != nil {
				result = errors.Join(result, err)
				continue
			}
		}
		done, err := u.continueRetirement(ctx, item)
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		pending = pending || !done
	}
	return pending, result
}

type RouteRetirementTransaction struct {
	RouteID          string
	OrganizationID   string
	Desired          HostDesiredConfig
	Prepared         bool
	GatewayCommitted bool
}

type RouteRetirementStore interface {
	Begin(context.Context, string) (RouteRetirementTransaction, bool, error)
	MarkPrepared(context.Context, RouteRetirementTransaction, GatewayObservation) error
	MarkGatewayCommitted(context.Context, RouteRetirementTransaction, GatewayObservation) error
	Finish(context.Context, RouteRetirementTransaction) error
}

type RetirementCoordinator struct {
	store   RouteRetirementStore
	gateway Gateway
}

func NewRetirementCoordinator(
	store RouteRetirementStore,
	gateway Gateway,
) (*RetirementCoordinator, error) {
	if store == nil || gateway == nil {
		return nil, ErrRetirementUnavailable
	}
	return &RetirementCoordinator{store: store, gateway: gateway}, nil
}

func (c *RetirementCoordinator) Retire(ctx context.Context, routeID string) (bool, error) {
	routeID = strings.TrimSpace(routeID)
	if !validID(routeID) {
		return false, ErrRetirementUnavailable
	}
	transactionValue, completed, err := c.store.Begin(ctx, routeID)
	if err != nil || completed {
		return completed, err
	}
	if !transactionValue.Prepared {
		observation, prepareErr := c.gateway.Prepare(ctx, transactionValue.Desired)
		if prepareErr != nil {
			return false, prepareErr
		}
		if err := c.store.MarkPrepared(ctx, transactionValue, observation); err != nil {
			return false, err
		}
		transactionValue.Prepared = true
	}
	if !transactionValue.GatewayCommitted {
		observation, commitErr := c.gateway.Commit(ctx, transactionValue.Desired)
		if commitErr != nil {
			return false, commitErr
		}
		if err := c.store.MarkGatewayCommitted(ctx, transactionValue, observation); err != nil {
			return false, err
		}
		transactionValue.GatewayCommitted = true
	}
	if err := c.store.Finish(ctx, transactionValue); err != nil {
		return false, err
	}
	return true, nil
}

var _ RouteRetirer = (*RetirementCoordinator)(nil)
