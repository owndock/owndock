package biz

import (
	"context"
	"errors"
	"strings"
)

var (
	ErrReconciliationUnavailable   = errors.New("application route reconciliation is unavailable")
	ErrReconciliationPending       = errors.New("application route reconciliation is pending")
	ErrReconciliationConflict      = errors.New("application route reconciliation conflicts")
	ErrReconciliationConfiguration = errors.New("application route backend configuration is invalid")
	ErrHostOperationPending        = errors.New("application ingress host operation is pending")
)

const reconciliationControllerActor = "system:application-route-reconciliation"

// ActiveBackend is the secret-free identity of the stable runtime that a
// pending Route may safely publish. It is resolved from the latest successful
// Deployment for the Route's immutable slot.
type ActiveBackend struct {
	OrganizationID  string
	ProjectID       string
	ApplicationID   string
	EnvironmentID   string
	RuntimeTargetID string
	ManagedHostID   string
	DeploymentID    string
	CutoverSequence uint64
	Port            uint16
}

func (b ActiveBackend) validFor(route ApplicationRoute) bool {
	return validID(strings.TrimSpace(b.OrganizationID)) &&
		validID(strings.TrimSpace(b.ProjectID)) &&
		validID(strings.TrimSpace(b.ApplicationID)) &&
		validID(strings.TrimSpace(b.EnvironmentID)) &&
		validID(strings.TrimSpace(b.RuntimeTargetID)) &&
		validID(strings.TrimSpace(b.ManagedHostID)) &&
		validID(strings.TrimSpace(b.DeploymentID)) &&
		b.CutoverSequence > 0 && b.Port > 0 &&
		b.OrganizationID == route.OrganizationID && b.ProjectID == route.ProjectID &&
		b.ApplicationID == route.ApplicationID && b.EnvironmentID == route.EnvironmentID &&
		b.RuntimeTargetID == route.RuntimeTargetID
}

type ActiveBackendResolver interface {
	ResolveActiveBackend(context.Context, ApplicationRoute) (ActiveBackend, bool, error)
}

type ReconciliationRepository interface {
	ListReconciliationCandidates(context.Context, int64) ([]ApplicationRoute, error)
}

type RouteReconciler interface {
	Reconcile(context.Context, ApplicationRoute) (settled bool, err error)
}

type RouteReconciliationTransaction struct {
	RouteID        string
	RouteRevision  uint64
	OrganizationID string
	Backend        ActiveBackend
	Desired        HostDesiredConfig
	Prepared       bool
}

type RouteReconciliationStore interface {
	Begin(context.Context, ApplicationRoute, ActiveBackend) (RouteReconciliationTransaction, bool, error)
	MarkPrepared(context.Context, RouteReconciliationTransaction, GatewayObservation) error
	Complete(context.Context, RouteReconciliationTransaction, GatewayObservation) error
	Abort(context.Context, RouteReconciliationTransaction, FailureCode) error
	Degrade(context.Context, ApplicationRoute, FailureCode) error
}

type ReconciliationCoordinator struct {
	resolver ActiveBackendResolver
	store    RouteReconciliationStore
	gateway  Gateway
}

func NewReconciliationCoordinator(
	resolver ActiveBackendResolver,
	store RouteReconciliationStore,
	gateway Gateway,
) (*ReconciliationCoordinator, error) {
	if resolver == nil || store == nil || gateway == nil {
		return nil, ErrReconciliationUnavailable
	}
	return &ReconciliationCoordinator{resolver: resolver, store: store, gateway: gateway}, nil
}

// Reconcile publishes one Route against the latest successful Deployment.
// A missing successful Deployment is an expected pending state: the normal
// Deployment cutover will publish the Route when a backend first succeeds.
func (c *ReconciliationCoordinator) Reconcile(
	ctx context.Context,
	route ApplicationRoute,
) (bool, error) {
	backend, exists, err := c.resolver.ResolveActiveBackend(ctx, route)
	if errors.Is(err, ErrReconciliationConfiguration) {
		if degradeErr := c.store.Degrade(ctx, route, FailureConfiguration); degradeErr != nil {
			return false, degradeErr
		}
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if !exists {
		return false, nil
	}
	if !backend.validFor(route) {
		if err := c.store.Degrade(ctx, route, FailureConfiguration); err != nil {
			return false, err
		}
		return true, nil
	}
	transactionValue, settled, err := c.store.Begin(ctx, route, backend)
	if errors.Is(err, ErrReconciliationPending) || errors.Is(err, ErrHostOperationPending) {
		return false, nil
	}
	if err != nil || settled {
		return settled, err
	}
	if !transactionValue.Prepared {
		observation, prepareErr := c.gateway.Prepare(ctx, transactionValue.Desired)
		if prepareErr != nil {
			if errors.Is(prepareErr, ErrGatewayUnavailable) {
				return false, nil
			}
			if _, abortErr := c.gateway.Abort(ctx, transactionValue.Desired); abortErr != nil {
				return false, errors.Join(ErrReconciliationPending, prepareErr, abortErr)
			}
			if abortErr := c.store.Abort(
				ctx, transactionValue, FailureCodeFromError(prepareErr),
			); abortErr != nil {
				return false, abortErr
			}
			return true, nil
		}
		if err := c.store.MarkPrepared(ctx, transactionValue, observation); err != nil {
			return false, err
		}
		transactionValue.Prepared = true
	}
	observation, err := c.gateway.Commit(ctx, transactionValue.Desired)
	if err != nil {
		// A lost commit response is ambiguous. Keep the durable transaction and
		// replay the same Host revision instead of restoring or allocating a new one.
		return false, nil
	}
	if err := c.store.Complete(ctx, transactionValue, observation); err != nil {
		return false, err
	}
	return true, nil
}

// ContinueRouteReconciliations applies Route creates and updates to an already
// successful Deployment without requiring another Deployment.
func (u *UseCase) ContinueRouteReconciliations(ctx context.Context, limit int64) (int, error) {
	if u.reconciliationRepository == nil || u.reconciler == nil {
		return 0, ErrReconciliationUnavailable
	}
	if limit < 1 || limit > 100 {
		return 0, errors.New("application route reconciliation limit must be between 1 and 100")
	}
	items, err := u.reconciliationRepository.ListReconciliationCandidates(ctx, limit)
	if err != nil {
		return 0, err
	}
	settled := 0
	var result error
	for _, item := range items {
		done, reconcileErr := u.reconciler.Reconcile(ctx, item)
		if reconcileErr != nil {
			result = errors.Join(result, reconcileErr)
		} else if done {
			settled++
		}
	}
	return settled, result
}

var _ RouteReconciler = (*ReconciliationCoordinator)(nil)
