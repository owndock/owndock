package biz_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/deployment/biz"
	"github.com/owndock/owndock/internal/modules/deployment/data"
	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/security"
	"github.com/owndock/owndock/internal/shared/transaction"
)

type referenceProbe struct {
	calls        int
	automaticErr error
	active       *bool
	fenceErr     error
}

func (p *referenceProbe) ValidateProject(context.Context, string, string) error { return nil }
func (p *referenceProbe) Validate(context.Context, string, string, string, string, string) error {
	p.calls++
	return nil
}
func (p *referenceProbe) ValidateAutomatic(context.Context, string, string, string, string, string) error {
	p.calls++
	return p.automaticErr
}
func (p *referenceProbe) FenceProductResourceAdmission(
	context.Context, string, string, string,
) (bool, error) {
	if p.fenceErr != nil {
		return false, p.fenceErr
	}
	if p.active != nil {
		return *p.active, nil
	}
	return true, nil
}

type auditProbe struct{ events []sharedaudit.Event }

type allowAdmission struct{}

func (allowAdmission) EvaluateAdmission(context.Context,
	biz.AdmissionRequest) (biz.AdmissionSnapshot, error) {
	return (biz.AdmissionSnapshot{EvaluatedAt: time.Unix(100, 0), EnvironmentStage: "development",
		Policies: []biz.AdmissionPolicySnapshot{}, Evidence: []biz.AdmissionEvidenceSnapshot{},
		Verifications: []biz.AdmissionVerificationSnapshot{}, Waivers: []biz.AdmissionWaiverSnapshot{},
		Violations: []biz.AdmissionViolation{}, Decision: biz.AdmissionNotConfigured}).Seal()
}

type changingAdmission struct{ calls int }

func (e *changingAdmission) EvaluateAdmission(context.Context,
	biz.AdmissionRequest) (biz.AdmissionSnapshot, error) {
	e.calls++
	return (biz.AdmissionSnapshot{EvaluatedAt: time.Unix(int64(100+e.calls), 0), EnvironmentStage: "production",
		ArtifactID: "artifact-1", SubjectDigest: "sha256:" + strings.Repeat("a", 64),
		Policies: []biz.AdmissionPolicySnapshot{{ID: "policy-1", Version: uint64(e.calls), Scope: "project",
			Mode: "enforced", Requirements: biz.AdmissionRequirementsSnapshot{RequireSBOM: true,
				AllowedSignaturePolicyIDs: []string{}}}},
		Evidence: []biz.AdmissionEvidenceSnapshot{{ID: "evidence-1", Kind: "sbom",
			DescriptorDigest: "sha256:" + strings.Repeat("b", 64),
			ContentDigest:    "sha256:" + strings.Repeat("c", 64)}},
		Verifications: []biz.AdmissionVerificationSnapshot{}, Waivers: []biz.AdmissionWaiverSnapshot{},
		Violations: []biz.AdmissionViolation{}, Decision: biz.AdmissionAdmitted}).Seal()
}

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
		WithFormalSecurity(transaction.Passthrough{}, audits).
		WithAdmissionEvaluator(allowAdmission{})
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

func TestCreateFormalFailsWhenProductAdmissionFenceCloses(t *testing.T) {
	repository := data.NewMemoryRepository()
	active := false
	references := &referenceProbe{active: &active}
	useCase := biz.NewUseCase(
		repository, nil, nil, func() (string, error) { return "deployment-1", nil },
		func() time.Time { return time.Unix(100, 0) },
	).WithFormalReferences(references).
		WithFormalSecurity(transaction.Passthrough{}, &auditProbe{}).
		WithAdmissionEvaluator(allowAdmission{})
	principal := security.Principal{
		UserID: "user-1", OrganizationID: "organization-1",
		SessionID: "session-1", Role: security.RoleDeveloper,
	}
	if _, err := useCase.CreateFormal(
		t.Context(), principal, "project-1", "release-1", "app-1", "env-1",
		"target-1", "request-1", "trace-1",
	); !errors.Is(err, biz.ErrApplicationNotFound) {
		t.Fatalf("closed product resource fence error = %v", err)
	}
	items, err := repository.List(t.Context(), "project-1", "app-1", "env-1")
	if err != nil || len(items) != 0 {
		t.Fatalf("Deployment persisted after closed fence: %+v/%v", items, err)
	}

	fenceFailure := errors.New("fence unavailable")
	references.fenceErr = fenceFailure
	if _, err := useCase.CreateFormal(
		t.Context(), principal, "project-1", "release-1", "app-1", "env-1",
		"target-1", "request-2", "trace-2",
	); !errors.Is(err, fenceFailure) {
		t.Fatalf("fence failure = %v", err)
	}
}

func TestCreateFormalReplaysFrozenAdmissionBeforeReevaluation(t *testing.T) {
	repository := data.NewMemoryRepository()
	evaluator := &changingAdmission{}
	sequence := 0
	useCase := biz.NewUseCase(repository, nil, nil, func() (string, error) {
		sequence++
		return fmt.Sprintf("deployment-%d", sequence), nil
	}, func() time.Time { return time.Unix(100, 0) }).
		WithFormalReferences(&referenceProbe{}).
		WithFormalSecurity(transaction.Passthrough{}, &auditProbe{}).
		WithAdmissionEvaluator(evaluator)
	principal := security.Principal{UserID: "developer", OrganizationID: "organization-1",
		SessionID: "session-1", Role: security.RoleDeveloper}
	first, err := useCase.CreateFormal(t.Context(), principal, "project-1", "release-1",
		"application-1", "environment-1", "target-1", "same-key", "request-1")
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := useCase.CreateFormal(t.Context(), principal, "project-1", "release-1",
		"application-1", "environment-1", "target-1", "same-key", "request-2")
	if err != nil || replayed.ID != first.ID || replayed.Admission.EvaluationDigest != first.Admission.EvaluationDigest ||
		evaluator.calls != 1 || replayed.Admission.Policies[0].Version != 1 {
		t.Fatalf("replay = %+v, %v calls=%d", replayed, err, evaluator.calls)
	}
	second, err := useCase.CreateFormal(t.Context(), principal, "project-1", "release-1",
		"application-1", "environment-1", "target-1", "new-key", "request-3")
	if err != nil || evaluator.calls != 2 || second.Admission.Policies[0].Version != 2 ||
		second.Admission.EvaluationDigest == first.Admission.EvaluationDigest {
		t.Fatalf("future deployment = %+v, %v calls=%d", second, err, evaluator.calls)
	}
}

func TestCreateFormalRequiresDeploymentPermission(t *testing.T) {
	useCase := biz.NewUseCase(data.NewMemoryRepository(), nil, nil, func() (string, error) {
		return "id", nil
	}, time.Now).WithFormalReferences(&referenceProbe{}).
		WithFormalSecurity(transaction.Passthrough{}, &auditProbe{}).
		WithAdmissionEvaluator(allowAdmission{})
	viewer := security.Principal{
		UserID: "user", OrganizationID: "organization", SessionID: "session", Role: security.RoleViewer,
	}
	if _, err := useCase.CreateFormal(
		t.Context(), viewer, "project", "release", "app", "env", "target", "request", "trace",
	); err != security.ErrForbidden {
		t.Fatalf("CreateFormal() error = %v", err)
	}
}

func TestCreateAutomaticIsDevelopmentOnlyAuditedAndIdempotent(t *testing.T) {
	repository := data.NewMemoryRepository()
	references := &referenceProbe{}
	audits := &auditProbe{}
	sequence := 0
	useCase := biz.NewUseCase(repository, nil, nil, func() (string, error) {
		sequence++
		return fmt.Sprintf("automatic-%d", sequence), nil
	}, func() time.Time { return time.Unix(100, 0) }).
		WithAutomaticReferences(references).
		WithFormalSecurity(transaction.Passthrough{}, audits).
		WithAdmissionEvaluator(allowAdmission{})
	input := biz.AutomaticDeploymentInput{
		OrganizationID: "organization-1", ProjectID: "project-1",
		ReleaseID: "release-1", ApplicationID: "application-1",
		EnvironmentID: "development-1", RuntimeTargetID: "target-1",
		ArtifactID: "artifact-1", BuildID: "build-1", BuildConfigurationID: "configuration-1",
	}
	first, err := useCase.CreateAutomatic(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := useCase.CreateAutomatic(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.ID != first.ID || first.TriggerSource != biz.TriggerSourceAutomatic ||
		first.SourceArtifactID != input.ArtifactID || first.SourceBuildID != input.BuildID ||
		first.BuildConfigurationID != input.BuildConfigurationID {
		t.Fatalf("automatic/replayed Deployment = %+v/%+v", first, replayed)
	}
	if references.calls != 1 || len(audits.events) != 1 ||
		audits.events[0].Action != biz.AuditActionAutomatic ||
		audits.events[0].ActorID != "system:auto-deployment" {
		t.Fatalf("automatic references/audit = %d/%+v", references.calls, audits.events)
	}
	references.automaticErr = biz.ErrAutomaticDeploymentNotAllowed
	input.ArtifactID = "artifact-2"
	if _, err := useCase.CreateAutomatic(t.Context(), input); !errors.Is(err, biz.ErrAutomaticDeploymentNotAllowed) {
		t.Fatalf("production automatic Deployment error = %v", err)
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
		WithFormalSecurity(transaction.Passthrough{}, audits).
		WithAdmissionEvaluator(allowAdmission{})
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
		WithFormalSecurity(transaction.Passthrough{}, audits).
		WithAdmissionEvaluator(allowAdmission{})
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
		WithFormalSecurity(transaction.Passthrough{}, &auditProbe{}).
		WithAdmissionEvaluator(allowAdmission{})
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
