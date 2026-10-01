package biz

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/shared/security"
	"github.com/owndock/owndock/internal/shared/transaction"
)

type routeRetirerStub struct {
	completed bool
	err       error
	calls     int
}

func (r *routeRetirerStub) Retire(context.Context, string) (bool, error) {
	r.calls++
	return r.completed, r.err
}

func TestUseCaseDeleteDurablyStartsAndResumesRetirement(t *testing.T) {
	repository := &fakeRepository{}
	item, _ := NewApplicationRoute(validInput())
	repository.item = item
	retirer := &routeRetirerStub{err: ErrRetirementPending}
	auditor := &fakeAudit{}
	useCase, _ := NewUseCase(repository,
		&fakeReferences{result: References{EnvironmentStage: "development", AgentTarget: true}},
		func() (string, error) { return "audit-1", nil },
		func() time.Time { return fixedTime.Add(time.Hour) })
	useCase.WithAudit(transaction.Passthrough{}, auditor).
		WithRetirement(repository, retirer)
	completed, err := useCase.Delete(
		t.Context(), principal(security.RoleMaintainer), "project-1", "route-1", "request-1",
	)
	if err != nil || completed || repository.item.Status != StatusRetiring ||
		repository.item.Retirement == nil || repository.item.Retirement.RequestID != "request-1" {
		t.Fatalf("Delete() = %t, %v, route = %+v", completed, err, repository.item)
	}
	if len(auditor.events) != 1 || auditor.events[0].Action != "application_route.retirement_started" {
		t.Fatalf("audit events = %+v", auditor.events)
	}
	retirer.err, retirer.completed = nil, true
	processed, err := useCase.ContinueRouteRetirements(t.Context(), 16)
	if err != nil || processed != 1 || retirer.calls != 2 {
		t.Fatalf("ContinueRouteRetirements() = %d, %v; calls = %d", processed, err, retirer.calls)
	}
}

func TestUseCaseRetirementConvergesProductAndRuntimeScopes(t *testing.T) {
	repository := &fakeRepository{}
	item, _ := NewApplicationRoute(validInput())
	repository.item = item
	retirer := &routeRetirerStub{completed: true}
	useCase, _ := NewUseCase(repository,
		&fakeReferences{result: References{EnvironmentStage: "development", AgentTarget: true}},
		func() (string, error) { return "audit-1", nil },
		func() time.Time { return fixedTime.Add(time.Hour) })
	useCase.WithRetirement(repository, retirer)
	pending, err := useCase.ConvergeProductResource(t.Context(), "organization-1", "project-1",
		"application-1", "", "owner-1", "request-1")
	if err != nil || pending || repository.productLists != 1 {
		t.Fatalf("ConvergeProductResource() = %t, %v", pending, err)
	}
	repository.item = item
	pending, err = useCase.ConvergeRuntimeTarget(t.Context(), "organization-1", "project-1",
		"target-1", "owner-1", "request-2")
	if err != nil || pending || repository.targetLists != 1 {
		t.Fatalf("ConvergeRuntimeTarget() = %t, %v", pending, err)
	}
	if _, err := useCase.ContinueRouteRetirements(t.Context(), 0); err == nil {
		t.Fatal("invalid retirement batch size was accepted")
	}
}

type retirementStoreStub struct {
	transaction RouteRetirementTransaction
	completed   bool
	err         error
	prepared    int
	committed   int
	finished    int
}

func (s *retirementStoreStub) Begin(context.Context, string) (RouteRetirementTransaction, bool, error) {
	return s.transaction, s.completed, s.err
}
func (s *retirementStoreStub) MarkPrepared(context.Context, RouteRetirementTransaction, GatewayObservation) error {
	s.prepared++
	return nil
}
func (s *retirementStoreStub) MarkGatewayCommitted(context.Context, RouteRetirementTransaction, GatewayObservation) error {
	s.committed++
	return nil
}
func (s *retirementStoreStub) Finish(context.Context, RouteRetirementTransaction) error {
	s.finished++
	return nil
}

func TestRetirementCoordinatorRunsReplayableGatewayPhases(t *testing.T) {
	store := &retirementStoreStub{transaction: RouteRetirementTransaction{
		RouteID: "route-1", OrganizationID: "organization-1",
		Desired: HostDesiredConfig{ManagedHostID: "host-1", HostRevision: 2},
	}}
	gateway := &cutoverGatewayStub{}
	coordinator, err := NewRetirementCoordinator(store, gateway)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := coordinator.Retire(t.Context(), "route-1")
	if err != nil || !completed || gateway.prepareCalls != 1 || gateway.commitCalls != 1 ||
		store.prepared != 1 || store.committed != 1 || store.finished != 1 {
		t.Fatalf("Retire() = %t, %v; gateway=%d/%d store=%d/%d/%d", completed, err,
			gateway.prepareCalls, gateway.commitCalls, store.prepared, store.committed, store.finished)
	}
	store.transaction.Prepared, store.transaction.GatewayCommitted = true, true
	gateway.prepareCalls, gateway.commitCalls = 0, 0
	completed, err = coordinator.Retire(t.Context(), "route-1")
	if err != nil || !completed || gateway.prepareCalls != 0 || gateway.commitCalls != 0 {
		t.Fatalf("committed replay = %t, %v; gateway=%d/%d", completed, err,
			gateway.prepareCalls, gateway.commitCalls)
	}
	store.err = ErrRetirementPending
	if _, err := coordinator.Retire(t.Context(), "route-1"); !errors.Is(err, ErrRetirementPending) {
		t.Fatalf("pending error = %v", err)
	}
}
