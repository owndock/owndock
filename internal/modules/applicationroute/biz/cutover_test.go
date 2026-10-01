package biz

import (
	"context"
	"errors"
	"testing"
)

func TestCutoverCoordinatorRunsDurableThreePhaseProtocol(t *testing.T) {
	request := validCutoverRequest()
	desired := HostDesiredConfig{ManagedHostID: request.ManagedHostID, HostRevision: 2}
	store := &cutoverStoreStub{required: true,
		transaction: CutoverTransaction{Request: request, Desired: desired}}
	gateway := &cutoverGatewayStub{}
	coordinator, err := NewCutoverCoordinator(store, gateway)
	if err != nil {
		t.Fatal(err)
	}
	if required, err := coordinator.Required(t.Context(), request); err != nil || !required {
		t.Fatalf("Required() = %t, %v", required, err)
	}
	if _, err := coordinator.Begin(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Prepare(t.Context(), request.DeploymentID); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.MarkControlPlaneCommitted(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	committed, exists, err := coordinator.Commit(t.Context(), request.DeploymentID)
	if err != nil || !exists || committed.FencingToken != request.FencingToken {
		t.Fatalf("Commit() = %+v, %t, %v", committed, exists, err)
	}
	if err := coordinator.Finish(t.Context(), request.DeploymentID); err != nil {
		t.Fatal(err)
	}
	if gateway.prepareCalls != 1 || gateway.commitCalls != 1 || store.completeCalls != 1 {
		t.Fatalf("calls = gateway prepare %d commit %d, store complete %d",
			gateway.prepareCalls, gateway.commitCalls, store.completeCalls)
	}
}

func TestCutoverCoordinatorAbortsPreparedGatewayOnFailure(t *testing.T) {
	request := validCutoverRequest()
	store := &cutoverStoreStub{transaction: CutoverTransaction{Request: request,
		Desired: HostDesiredConfig{ManagedHostID: request.ManagedHostID, HostRevision: 2}}}
	gateway := &cutoverGatewayStub{prepareErr: ErrGatewayBackendUnhealthy}
	coordinator, _ := NewCutoverCoordinator(store, gateway)
	if _, err := coordinator.Begin(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Prepare(t.Context(), request.DeploymentID); !errors.Is(err, ErrGatewayBackendUnhealthy) {
		t.Fatalf("Prepare() error = %v", err)
	}
	if gateway.abortCalls != 1 || store.abortCalls != 0 {
		t.Fatalf("abort calls = gateway %d store %d", gateway.abortCalls, store.abortCalls)
	}
}

func TestCutoverCoordinatorReplaysOriginalWorkerIdentity(t *testing.T) {
	original := validCutoverRequest()
	replacement := original
	replacement.WorkerID = "worker-2"
	replacement.FencingToken = 7
	store := &cutoverStoreStub{transaction: CutoverTransaction{Request: original,
		Desired: HostDesiredConfig{ManagedHostID: original.ManagedHostID, HostRevision: 2}}}
	coordinator, _ := NewCutoverCoordinator(store, &cutoverGatewayStub{})
	replayed, err := coordinator.Begin(t.Context(), replacement)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.WorkerID != original.WorkerID || replayed.FencingToken != original.FencingToken {
		t.Fatalf("replayed request = %+v", replayed)
	}
}

func TestCutoverCoordinatorRejectsChangedRuntimeIdentity(t *testing.T) {
	request := validCutoverRequest()
	changed := request
	changed.ContainerName = "container-2"
	store := &cutoverStoreStub{transaction: CutoverTransaction{Request: request}}
	coordinator, _ := NewCutoverCoordinator(store, &cutoverGatewayStub{})
	if _, err := coordinator.Begin(t.Context(), changed); !errors.Is(err, ErrCutoverConflict) {
		t.Fatalf("Begin() error = %v", err)
	}
}

func TestCutoverCoordinatorReportsAmbiguousFailedAbort(t *testing.T) {
	request := validCutoverRequest()
	store := &cutoverStoreStub{transaction: CutoverTransaction{Request: request,
		Desired: HostDesiredConfig{ManagedHostID: request.ManagedHostID, HostRevision: 2}}}
	gateway := &cutoverGatewayStub{prepareErr: ErrGatewayUnavailable, abortErr: ErrGatewayUnavailable}
	coordinator, _ := NewCutoverCoordinator(store, gateway)
	if _, err := coordinator.Begin(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Prepare(t.Context(), request.DeploymentID); !errors.Is(err, ErrCutoverAmbiguous) {
		t.Fatalf("Prepare() ambiguous error = %v", err)
	}
	if store.abortCalls != 0 {
		t.Fatalf("store abort calls = %d", store.abortCalls)
	}
}

func validCutoverRequest() CutoverRequest {
	return CutoverRequest{OrganizationID: "organization-1", ProjectID: "project-1",
		ApplicationID: "application-1", EnvironmentID: "environment-1",
		RuntimeTargetID: "target-1", ManagedHostID: "host-1",
		DeploymentID: "deployment-1", WorkerID: "worker-1", ContainerName: "container-1",
		FencingToken: 2, CutoverSequence: 3, Ports: map[string]uint16{"http": 8080}}
}

type cutoverStoreStub struct {
	required      bool
	transaction   CutoverTransaction
	completeCalls int
	abortCalls    int
}

func (s *cutoverStoreStub) Required(context.Context, CutoverRequest) (bool, error) {
	return s.required, nil
}
func (s *cutoverStoreStub) Begin(context.Context, CutoverRequest) (CutoverTransaction, error) {
	return s.transaction, nil
}
func (*cutoverStoreStub) Prepared(context.Context, CutoverTransaction, GatewayObservation) error {
	return nil
}

func (s *cutoverStoreStub) MarkControlPlaneCommitted(context.Context, CutoverRequest) error {
	s.transaction.ControlPlaneCommitted = true
	return nil
}
func (s *cutoverStoreStub) Get(context.Context, string) (CutoverTransaction, bool, error) {
	return s.transaction, true, nil
}
func (s *cutoverStoreStub) Complete(context.Context, CutoverTransaction, GatewayObservation) error {
	s.completeCalls++
	return nil
}
func (*cutoverStoreStub) Finish(context.Context, CutoverTransaction) error { return nil }
func (s *cutoverStoreStub) Abort(context.Context, CutoverTransaction, FailureCode) error {
	s.abortCalls++
	return nil
}

type cutoverGatewayStub struct {
	prepareCalls int
	commitCalls  int
	abortCalls   int
	prepareErr   error
	abortErr     error
}

func (g *cutoverGatewayStub) Prepare(context.Context, HostDesiredConfig) (GatewayObservation, error) {
	g.prepareCalls++
	return GatewayObservation{HostRevision: 2,
		ConfigDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}, g.prepareErr
}
func (g *cutoverGatewayStub) Commit(context.Context, HostDesiredConfig) (GatewayObservation, error) {
	g.commitCalls++
	return GatewayObservation{HostRevision: 2,
		ConfigDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}, nil
}
func (g *cutoverGatewayStub) Abort(context.Context, HostDesiredConfig) (GatewayObservation, error) {
	g.abortCalls++
	return GatewayObservation{}, g.abortErr
}
