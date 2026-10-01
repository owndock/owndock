package biz

import (
	"context"
	"errors"
	"testing"
	"time"

	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/security"
	"github.com/owndock/owndock/internal/shared/transaction"
)

var fixedTime = time.Date(2026, time.October, 1, 8, 0, 0, 0, time.UTC)

func TestNewApplicationRouteNormalizesAndValidatesHostname(t *testing.T) {
	item, err := NewApplicationRoute(validInput())
	if err != nil {
		t.Fatalf("NewApplicationRoute() error = %v", err)
	}
	if item.Hostname != "api.example.com" {
		t.Fatalf("Hostname = %q", item.Hostname)
	}
	for _, hostname := range []string{"", "localhost.", "-api.example.com", "api..example.com", "127.0.0.1", "127.0.0.1:80"} {
		input := validInput()
		input.Hostname = hostname
		if _, err := NewApplicationRoute(input); !errors.Is(err, ErrInvalidRoute) {
			t.Errorf("hostname %q error = %v", hostname, err)
		}
	}
	for _, hostname := range []string{"localhost", "api.internal", "service"} {
		input := validInput()
		input.Hostname, input.TLSMode = hostname, TLSModeAutomatic
		if _, err := NewApplicationRoute(input); !errors.Is(err, ErrInvalidRoute) {
			t.Errorf("automatic TLS hostname %q error = %v", hostname, err)
		}
	}
}

func TestApplicationRouteTransitionEnforcesLifecycle(t *testing.T) {
	item, err := NewApplicationRoute(validInput())
	if err != nil {
		t.Fatal(err)
	}
	item, err = item.Transition(StatusProvisioning, "controller", fixedTime.Add(time.Minute))
	if err != nil || item.Version != 2 || item.Revision != 1 || item.Status != StatusProvisioning {
		t.Fatalf("Transition() = %#v, %v", item, err)
	}
	if _, err := item.Transition(StatusRetired, "controller", fixedTime.Add(2*time.Minute)); !errors.Is(err, ErrRouteConflict) {
		t.Fatalf("invalid Transition() error = %v", err)
	}
	observation := Observation{Revision: 1, DeploymentID: "deployment-1", CutoverSequence: 1,
		ConfigDigest:      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		CertificateStatus: CertificateStatusNotApplicable, ObservedAt: fixedTime.Add(2 * time.Minute)}
	ready, err := item.ObserveReady(observation, "controller", fixedTime.Add(2*time.Minute))
	if err != nil || ready.Status != StatusReady || ready.Observation == nil || ready.Observation.Revision != 1 {
		t.Fatalf("ObserveReady() = %#v, %v", ready, err)
	}
	if _, err := item.ObserveReady(Observation{Revision: 2}, "controller", fixedTime.Add(2*time.Minute)); !errors.Is(err, ErrRouteConflict) {
		t.Fatalf("stale ObserveReady() error = %v", err)
	}
	item, err = ready.Transition(StatusRetiring, "controller", fixedTime.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := item.Transition(StatusRetired, "controller", fixedTime.Add(4*time.Minute)); err != nil {
		t.Fatal(err)
	}
}

func TestUseCaseCreateAppliesSecurityAndEnvironmentRules(t *testing.T) {
	repository := &fakeRepository{}
	references := &fakeReferences{result: References{EnvironmentStage: "production", AgentTarget: true}}
	useCase, err := NewUseCase(repository, references, func() (string, error) { return "route-1", nil }, func() time.Time { return fixedTime })
	if err != nil {
		t.Fatal(err)
	}
	input := validInput()
	input.TLSMode = TLSModeAutomatic
	item, err := useCase.Create(context.Background(), principal(security.RoleMaintainer), "project-1", input, "request-1")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if item.Status != StatusPending || item.Revision != 1 || item.Version != 1 || repository.item.Hostname != "api.example.com" {
		t.Fatalf("Create() = %#v", item)
	}
	if _, err := useCase.Create(context.Background(), principal(security.RoleDeveloper), "project-1", input, "request-2"); !errors.Is(err, security.ErrForbidden) {
		t.Fatalf("developer Create() error = %v", err)
	}
	input.TLSMode = TLSModeDisabled
	if _, err := useCase.Create(context.Background(), principal(security.RoleMaintainer), "project-1", input, "request-3"); !errors.Is(err, ErrInvalidRoute) {
		t.Fatalf("production disabled TLS error = %v", err)
	}
}

func TestUseCaseCreateRejectsDirectTargetAndQuota(t *testing.T) {
	repository := &fakeRepository{}
	references := &fakeReferences{result: References{EnvironmentStage: "development", AgentTarget: false}}
	useCase, _ := NewUseCase(repository, references, func() (string, error) { return "route-1", nil }, func() time.Time { return fixedTime })
	if _, err := useCase.Create(context.Background(), principal(security.RoleMaintainer), "project-1", validInput(), ""); !errors.Is(err, ErrUnsupportedTarget) {
		t.Fatalf("direct target error = %v", err)
	}
	references.result.AgentTarget = true
	repository.createErr = ErrRouteLimitExceeded
	if _, err := useCase.Create(context.Background(), principal(security.RoleMaintainer), "project-1", validInput(), ""); !errors.Is(err, ErrRouteLimitExceeded) {
		t.Fatalf("quota error = %v", err)
	}
}

func TestUseCaseCreateRecordsAuditInTransaction(t *testing.T) {
	repository := &fakeRepository{}
	recorder := &fakeAudit{}
	ids := []string{"route-audit", "audit-event"}
	useCase, _ := NewUseCase(repository,
		&fakeReferences{result: References{EnvironmentStage: "development", AgentTarget: true}},
		func() (string, error) {
			value := ids[0]
			ids = ids[1:]
			return value, nil
		}, func() time.Time { return fixedTime })
	useCase.WithAudit(transaction.Passthrough{}, recorder)
	if _, err := useCase.Create(context.Background(), principal(security.RoleMaintainer), "project-1", validInput(), "request-audit"); err != nil {
		t.Fatal(err)
	}
	if len(recorder.events) != 1 || recorder.events[0].Action != "application_route.create" ||
		recorder.events[0].ResourceID != "route-audit" || recorder.events[0].RequestID != "request-audit" {
		t.Fatalf("audit events = %#v", recorder.events)
	}
}

func TestUseCaseUpdateKeepsBindingsImmutable(t *testing.T) {
	repository := &fakeRepository{}
	item, _ := NewApplicationRoute(validInput())
	repository.item = item
	useCase, _ := NewUseCase(repository, &fakeReferences{result: References{EnvironmentStage: "development", AgentTarget: true}},
		func() (string, error) { return "id", nil }, func() time.Time { return fixedTime.Add(time.Hour) })
	input := validInput()
	input.ApplicationID = "other-app"
	if _, err := useCase.Update(context.Background(), principal(security.RoleMaintainer), "project-1", "route-1", 1, input, ""); !errors.Is(err, ErrRouteConflict) {
		t.Fatalf("binding change error = %v", err)
	}
	input.ApplicationID = item.ApplicationID
	input.Hostname = "new.example.com"
	updated, err := useCase.Update(context.Background(), principal(security.RoleMaintainer), "project-1", "route-1", 1, input, "")
	if err != nil || updated.Revision != 2 || updated.Version != 2 || updated.Status != StatusPending || updated.Hostname != "new.example.com" {
		t.Fatalf("Update() = %#v, %v", updated, err)
	}
}

func TestUseCaseUpdateRejectsControllerOwnedProvisioningRoute(t *testing.T) {
	repository := &fakeRepository{}
	item, _ := NewApplicationRoute(validInput())
	item, _ = item.Transition(StatusProvisioning, "controller", fixedTime.Add(time.Minute))
	repository.item = item
	useCase, _ := NewUseCase(repository,
		&fakeReferences{result: References{EnvironmentStage: "development", AgentTarget: true}},
		func() (string, error) { return "id", nil }, func() time.Time { return fixedTime.Add(time.Hour) })
	input := validInput()
	input.Hostname = "new.example.com"
	if _, err := useCase.Update(context.Background(), principal(security.RoleMaintainer),
		"project-1", "route-1", item.Version, input, ""); !errors.Is(err, ErrRouteConflict) {
		t.Fatalf("provisioning update error = %v", err)
	}
}

func validInput() Input {
	return Input{ID: "route-1", OrganizationID: "organization-1", ProjectID: "project-1",
		ApplicationID: "application-1", EnvironmentID: "environment-1", RuntimeTargetID: "target-1",
		Hostname: " API.Example.com ", PortName: "http", TLSMode: TLSModeDisabled, Status: StatusPending,
		Revision: 1, Version: 1, CreatedBy: "user-1", UpdatedBy: "user-1", CreatedAt: fixedTime, UpdatedAt: fixedTime}
}

func principal(role security.Role) security.Principal {
	return security.Principal{UserID: "user-1", OrganizationID: "organization-1", SessionID: "session-1", Role: role}
}

type fakeRepository struct {
	item      ApplicationRoute
	createErr error
}

func (r *fakeRepository) Create(_ context.Context, item ApplicationRoute) (ApplicationRoute, error) {
	if r.createErr != nil {
		return ApplicationRoute{}, r.createErr
	}
	r.item = item
	return item, nil
}
func (r *fakeRepository) List(context.Context, string, string) ([]ApplicationRoute, error) {
	return []ApplicationRoute{r.item}, nil
}
func (r *fakeRepository) Get(context.Context, string, string, string) (ApplicationRoute, error) {
	if r.item.ID == "" {
		return ApplicationRoute{}, ErrNotFound
	}
	return r.item, nil
}
func (r *fakeRepository) Save(_ context.Context, item ApplicationRoute, _ uint64) (ApplicationRoute, error) {
	r.item = item
	return item, nil
}

type fakeReferences struct {
	result References
	err    error
}

func (r *fakeReferences) Resolve(context.Context, string, string, string, string, string) (References, error) {
	return r.result, r.err
}

type fakeAudit struct{ events []sharedaudit.Event }

func (a *fakeAudit) Record(_ context.Context, event sharedaudit.Event) error {
	a.events = append(a.events, event)
	return nil
}
