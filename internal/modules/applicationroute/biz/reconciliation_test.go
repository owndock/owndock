package biz

import (
	"context"
	"errors"
	"testing"
	"time"
)

type activeBackendResolverStub struct {
	backend ActiveBackend
	exists  bool
	err     error
	calls   int
}

func (r *activeBackendResolverStub) ResolveActiveBackend(
	context.Context,
	ApplicationRoute,
) (ActiveBackend, bool, error) {
	r.calls++
	return r.backend, r.exists, r.err
}

type reconciliationStoreStub struct {
	transaction RouteReconciliationTransaction
	settled     bool
	err         error
	prepared    int
	completed   int
	aborted     int
	degraded    int
	failure     FailureCode
}

func (s *reconciliationStoreStub) Begin(
	context.Context,
	ApplicationRoute,
	ActiveBackend,
) (RouteReconciliationTransaction, bool, error) {
	return s.transaction, s.settled, s.err
}

func (s *reconciliationStoreStub) MarkPrepared(
	context.Context,
	RouteReconciliationTransaction,
	GatewayObservation,
) error {
	s.prepared++
	return nil
}

func (s *reconciliationStoreStub) Complete(
	context.Context,
	RouteReconciliationTransaction,
	GatewayObservation,
) error {
	s.completed++
	return nil
}

func (s *reconciliationStoreStub) Abort(
	_ context.Context,
	_ RouteReconciliationTransaction,
	failure FailureCode,
) error {
	s.aborted++
	s.failure = failure
	return nil
}

func (s *reconciliationStoreStub) Degrade(
	_ context.Context,
	_ ApplicationRoute,
	failure FailureCode,
) error {
	s.degraded++
	s.failure = failure
	return nil
}

func reconciliationBackend() ActiveBackend {
	return ActiveBackend{
		OrganizationID: "organization-1", ProjectID: "project-1",
		ApplicationID: "application-1", EnvironmentID: "environment-1",
		RuntimeTargetID: "target-1", ManagedHostID: "host-1",
		DeploymentID: "deployment-1", CutoverSequence: 3, Port: 8080,
	}
}

func TestReconciliationCoordinatorPublishesExistingStableBackend(t *testing.T) {
	route, _ := NewApplicationRoute(validInput())
	backend := reconciliationBackend()
	resolver := &activeBackendResolverStub{backend: backend, exists: true}
	store := &reconciliationStoreStub{transaction: RouteReconciliationTransaction{
		RouteID: route.ID, RouteRevision: route.Revision,
		OrganizationID: route.OrganizationID, Backend: backend,
		Desired: HostDesiredConfig{ManagedHostID: "host-1", HostRevision: 2},
	}}
	gateway := &cutoverGatewayStub{}
	coordinator, err := NewReconciliationCoordinator(resolver, store, gateway)
	if err != nil {
		t.Fatal(err)
	}
	settled, err := coordinator.Reconcile(t.Context(), route)
	if err != nil || !settled || gateway.prepareCalls != 1 || gateway.commitCalls != 1 ||
		store.prepared != 1 || store.completed != 1 {
		t.Fatalf("Reconcile() = %t, %v; gateway=%d/%d store=%d/%d", settled, err,
			gateway.prepareCalls, gateway.commitCalls, store.prepared, store.completed)
	}

	store.transaction.Prepared = true
	gateway.prepareCalls, gateway.commitCalls = 0, 0
	settled, err = coordinator.Reconcile(t.Context(), route)
	if err != nil || !settled || gateway.prepareCalls != 0 || gateway.commitCalls != 1 {
		t.Fatalf("prepared replay = %t, %v; gateway=%d/%d", settled, err,
			gateway.prepareCalls, gateway.commitCalls)
	}
}

func TestReconciliationCoordinatorKeepsExpectedPendingStates(t *testing.T) {
	route, _ := NewApplicationRoute(validInput())
	resolver := &activeBackendResolverStub{}
	store := &reconciliationStoreStub{}
	gateway := &cutoverGatewayStub{}
	coordinator, _ := NewReconciliationCoordinator(resolver, store, gateway)

	settled, err := coordinator.Reconcile(t.Context(), route)
	if err != nil || settled {
		t.Fatalf("missing backend = %t, %v", settled, err)
	}
	resolver.backend, resolver.exists = reconciliationBackend(), true
	store.err = ErrHostOperationPending
	settled, err = coordinator.Reconcile(t.Context(), route)
	if err != nil || settled {
		t.Fatalf("host operation pending = %t, %v", settled, err)
	}

	store.err = nil
	store.transaction = RouteReconciliationTransaction{
		RouteID: route.ID, RouteRevision: route.Revision,
		OrganizationID: route.OrganizationID, Backend: resolver.backend,
		Desired: HostDesiredConfig{ManagedHostID: "host-1", HostRevision: 2},
	}
	gateway.prepareErr = ErrGatewayUnavailable
	settled, err = coordinator.Reconcile(t.Context(), route)
	if err != nil || settled || store.aborted != 0 {
		t.Fatalf("gateway unavailable = %t, %v; aborted=%d", settled, err, store.aborted)
	}
}

func TestReconciliationCoordinatorDegradesDeterministicFailures(t *testing.T) {
	route, _ := NewApplicationRoute(validInput())
	resolver := &activeBackendResolverStub{backend: reconciliationBackend(), exists: true}
	store := &reconciliationStoreStub{transaction: RouteReconciliationTransaction{
		RouteID: route.ID, RouteRevision: route.Revision,
		OrganizationID: route.OrganizationID, Backend: reconciliationBackend(),
		Desired: HostDesiredConfig{ManagedHostID: "host-1", HostRevision: 2},
	}}
	gateway := &cutoverGatewayStub{prepareErr: ErrGatewayBackendUnhealthy}
	coordinator, _ := NewReconciliationCoordinator(resolver, store, gateway)
	settled, err := coordinator.Reconcile(t.Context(), route)
	if err != nil || !settled || gateway.abortCalls != 1 || store.aborted != 1 ||
		store.failure != FailureBackendUnhealthy {
		t.Fatalf("probe failure = %t, %v; abort=%d/%d failure=%s", settled, err,
			gateway.abortCalls, store.aborted, store.failure)
	}

	resolver.err = ErrReconciliationConfiguration
	settled, err = coordinator.Reconcile(t.Context(), route)
	if err != nil || !settled || store.degraded != 1 || store.failure != FailureConfiguration {
		t.Fatalf("configuration failure = %t, %v; degraded=%d failure=%s", settled, err,
			store.degraded, store.failure)
	}
}

type routeReconcilerStub struct {
	settled bool
	err     error
	calls   int
}

func (r *routeReconcilerStub) Reconcile(context.Context, ApplicationRoute) (bool, error) {
	r.calls++
	return r.settled, r.err
}

func TestUseCaseContinuesRouteReconciliations(t *testing.T) {
	repository := &fakeRepository{}
	route, _ := NewApplicationRoute(validInput())
	repository.item = route
	reconciler := &routeReconcilerStub{settled: true}
	useCase, _ := NewUseCase(repository, &fakeReferences{}, func() (string, error) {
		return "id-1", nil
	}, func() time.Time { return fixedTime })
	useCase.WithReconciliation(repository, reconciler)
	processed, err := useCase.ContinueRouteReconciliations(t.Context(), 16)
	if err != nil || processed != 1 || reconciler.calls != 1 {
		t.Fatalf("ContinueRouteReconciliations() = %d, %v; calls=%d", processed, err, reconciler.calls)
	}
	reconciler.err = errors.New("reconcile")
	if _, err := useCase.ContinueRouteReconciliations(t.Context(), 16); err == nil {
		t.Fatal("reconciliation error was discarded")
	}
}
