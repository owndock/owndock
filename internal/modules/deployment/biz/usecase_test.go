package biz_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/deployment/biz"
	"github.com/owndock/owndock/internal/modules/deployment/data"
	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/security"
	"github.com/owndock/owndock/internal/shared/transaction"
)

type referenceProbe struct{ calls int }

func (p *referenceProbe) ValidateProject(context.Context, string, string) error { return nil }
func (p *referenceProbe) Validate(context.Context, string, string, string, string, string) error {
	p.calls++
	return nil
}

type auditProbe struct{ events []sharedaudit.Event }

func (p *auditProbe) Record(_ context.Context, event sharedaudit.Event) error {
	p.events = append(p.events, event)
	return nil
}

func TestCreateFormalIsProjectScopedAuditedAndIdempotent(t *testing.T) {
	repository := data.NewMemoryRepository()
	references := &referenceProbe{}
	audits := &auditProbe{}
	sequence := 0
	useCase := biz.NewUseCase(repository, nil, nil, func() (string, error) {
		sequence++
		return fmt.Sprintf("id-%d", sequence), nil
	}, func() time.Time {
		return time.Unix(100, 0)
	}).WithFormalReferences(references).
		WithFormalSecurity(transaction.Passthrough{}, audits)
	principal := security.Principal{
		UserID: "user-1", OrganizationID: "organization-1", SessionID: "session-1",
		Role: security.RoleDeveloper,
	}

	first, err := useCase.CreateFormal(
		t.Context(), principal, "project-1", "release-1", "app-1", "env-1", "target-1", "request-1", "trace-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := useCase.CreateFormal(
		t.Context(), principal, "project-1", "release-1", "app-1", "env-1", "target-1", "request-1", "trace-2",
	)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.ID != first.ID || first.ProjectID != "project-1" ||
		first.OrganizationID != principal.OrganizationID {
		t.Fatalf("first = %+v, replayed = %+v", first, replayed)
	}
	if _, err := useCase.CreateFormal(
		t.Context(), principal, "project-1", "release-2", "app-1", "env-1", "target-1", "request-1", "trace-3",
	); err != biz.ErrIdempotencyMismatch {
		t.Fatalf("idempotency mismatch error = %v", err)
	}
	if references.calls != 1 {
		t.Fatalf("reference validations = %d, want 1", references.calls)
	}
	if len(audits.events) != 1 || audits.events[0].Action != biz.AuditActionCreate ||
		audits.events[0].ProjectID != "project-1" {
		t.Fatalf("audit events = %+v", audits.events)
	}
}

func TestCreateFormalRequiresDeploymentPermission(t *testing.T) {
	useCase := biz.NewUseCase(data.NewMemoryRepository(), nil, nil, func() (string, error) {
		return "id", nil
	}, time.Now).WithFormalReferences(&referenceProbe{}).
		WithFormalSecurity(transaction.Passthrough{}, &auditProbe{})
	viewer := security.Principal{
		UserID: "user", OrganizationID: "organization", SessionID: "session", Role: security.RoleViewer,
	}
	if _, err := useCase.CreateFormal(
		t.Context(), viewer, "project", "release", "app", "env", "target", "request", "trace",
	); err != security.ErrForbidden {
		t.Fatalf("CreateFormal() error = %v", err)
	}
}

func TestCancelFormalPersistsAndAuditsCommand(t *testing.T) {
	repository := data.NewMemoryRepository()
	audits := &auditProbe{}
	sequence := 0
	useCase := biz.NewUseCase(repository, nil, nil, func() (string, error) {
		sequence++
		return fmt.Sprintf("id-%d", sequence), nil
	}, func() time.Time { return time.Unix(100, 0) }).
		WithFormalReferences(&referenceProbe{}).
		WithFormalSecurity(transaction.Passthrough{}, audits)
	principal := security.Principal{
		UserID: "developer", OrganizationID: "organization", SessionID: "session",
		Role: security.RoleDeveloper,
	}
	created, err := useCase.CreateFormal(
		t.Context(), principal, "project", "release", "app", "env", "target", "request", "create-trace",
	)
	if err != nil {
		t.Fatal(err)
	}
	canceled, err := useCase.CancelFormal(t.Context(), principal, "project", created.ID, "cancel-trace")
	if err != nil {
		t.Fatal(err)
	}
	if canceled.Status != biz.StatusCanceling {
		t.Fatalf("status = %s", canceled.Status)
	}
	if len(audits.events) != 2 || audits.events[1].Action != biz.AuditActionCancel ||
		audits.events[1].RequestID != "cancel-trace" {
		t.Fatalf("audit events = %+v", audits.events)
	}
}

func TestRetryAndRollbackCreateAuditedLinkedOperations(t *testing.T) {
	repository := data.NewMemoryRepository()
	references := &referenceProbe{}
	audits := &auditProbe{}
	sequence := 0
	now := time.Unix(100, 0)
	useCase := biz.NewUseCase(repository, nil, nil, func() (string, error) {
		sequence++
		return fmt.Sprintf("id-%d", sequence), nil
	}, func() time.Time { return now }).
		WithFormalReferences(references).
		WithFormalSecurity(transaction.Passthrough{}, audits)
	principal := security.Principal{
		UserID: "maintainer", OrganizationID: "organization", SessionID: "session",
		Role: security.RoleMaintainer,
	}

	source, err := useCase.CreateFormal(
		t.Context(), principal, "project", "release-new", "app", "env", "target", "create-key", "create-trace",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Transition(biz.StatusPreparing, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := source.Transition(biz.StatusFailed, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	source, err = repository.Save(t.Context(), source, source.Version)
	if err != nil {
		t.Fatal(err)
	}

	retried, err := useCase.RetryFormal(
		t.Context(), principal, "project", source.ID, "retry-key", "retry-trace",
	)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := useCase.RetryFormal(
		t.Context(), principal, "project", source.ID, "retry-key", "retry-replay-trace",
	)
	if err != nil {
		t.Fatal(err)
	}
	if retried.Operation != biz.OperationRetry || retried.SourceDeploymentID != source.ID ||
		retried.ReleaseID != source.ReleaseID || replayed.ID != retried.ID {
		t.Fatalf("retried = %+v, replayed = %+v", retried, replayed)
	}

	previous, err := biz.NewFormal(
		"previous", "project", "release-old", "app", "env", "target", "previous-key", now.Add(-time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := previous.Transition(biz.StatusPreparing, now.Add(-59*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := previous.Transition(biz.StatusDeploying, now.Add(-58*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := previous.Transition(biz.StatusSucceeded, now.Add(-57*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Create(t.Context(), previous); err != nil {
		t.Fatal(err)
	}

	rolledBack, err := useCase.RollbackFormal(
		t.Context(), principal, "project", source.ID, previous.ReleaseID, "rollback-key", "rollback-trace",
	)
	if err != nil {
		t.Fatal(err)
	}
	if rolledBack.Operation != biz.OperationRollback || rolledBack.SourceDeploymentID != source.ID ||
		rolledBack.ReleaseID != previous.ReleaseID {
		t.Fatalf("rollback = %+v", rolledBack)
	}

	if len(audits.events) != 3 ||
		audits.events[1].Action != biz.AuditActionRetry ||
		audits.events[1].RequestID != "retry-trace" ||
		audits.events[2].Action != biz.AuditActionRollback ||
		audits.events[2].RequestID != "rollback-trace" {
		t.Fatalf("audit events = %+v", audits.events)
	}
}

func TestRollbackRequiresMaintainerAndPreviouslySuccessfulRelease(t *testing.T) {
	repository := data.NewMemoryRepository()
	useCase := biz.NewUseCase(repository, nil, nil, func() (string, error) {
		return "new-id", nil
	}, func() time.Time { return time.Unix(100, 0) }).
		WithFormalReferences(&referenceProbe{}).
		WithFormalSecurity(transaction.Passthrough{}, &auditProbe{})
	source, err := biz.NewFormal(
		"source", "project", "release-new", "app", "env", "target", "source-key", time.Unix(1, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Transition(biz.StatusPreparing, time.Unix(2, 0)); err != nil {
		t.Fatal(err)
	}
	if err := source.Transition(biz.StatusFailed, time.Unix(3, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Create(t.Context(), source); err != nil {
		t.Fatal(err)
	}
	developer := security.Principal{
		UserID: "developer", OrganizationID: "organization", SessionID: "session",
		Role: security.RoleDeveloper,
	}
	if _, err := useCase.RollbackFormal(
		t.Context(), developer, "project", source.ID, "release-old", "rollback-key", "trace",
	); err != security.ErrForbidden {
		t.Fatalf("developer rollback error = %v", err)
	}
	maintainer := developer
	maintainer.Role = security.RoleMaintainer
	if _, err := useCase.RollbackFormal(
		t.Context(), maintainer, "project", source.ID, "release-old", "rollback-key", "trace",
	); err != biz.ErrRollbackNotSucceeded {
		t.Fatalf("unsuccessful release rollback error = %v", err)
	}
}
