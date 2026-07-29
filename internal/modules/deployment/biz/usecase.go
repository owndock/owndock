package biz

import (
	"context"
	"errors"
	"time"

	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/security"
	"github.com/owndock/owndock/internal/shared/transaction"
)

type IDGenerator func() (string, error)

type Clock func() time.Time

type UseCase struct {
	repo             Repository
	applications     ApplicationLookup
	environments     EnvironmentLookup
	formalReferences FormalReferenceLookup
	transaction      transaction.Manager
	audit            sharedaudit.Recorder
	newID            IDGenerator
	now              Clock
}

type FormalReferenceLookup interface {
	ValidateProject(context.Context, string, string) error
	Validate(context.Context, string, string, string, string, string) error
}

func (u *UseCase) WithFormalReferences(references FormalReferenceLookup) *UseCase {
	u.formalReferences = references
	return u
}

func (u *UseCase) WithFormalSecurity(manager transaction.Manager, recorder sharedaudit.Recorder) *UseCase {
	u.transaction, u.audit = manager, recorder
	return u
}

func NewUseCase(
	repo Repository,
	applications ApplicationLookup,
	environments EnvironmentLookup,
	newID IDGenerator,
	now Clock,
) *UseCase {
	return &UseCase{
		repo: repo, applications: applications, environments: environments,
		newID: newID, now: now,
	}
}

func (u *UseCase) List(ctx context.Context, applicationID, environmentID string) ([]Deployment, error) {
	return u.repo.List(ctx, "", applicationID, environmentID)
}

func (u *UseCase) Create(ctx context.Context, applicationID, environmentID, revision string) (Deployment, error) {
	id, err := u.newID()
	if err != nil {
		return Deployment{}, err
	}
	item, err := New(applicationID, environmentID, revision, id, u.now())
	if err != nil {
		return Deployment{}, err
	}

	exists, err := u.applications.Exists(ctx, item.ApplicationID)
	if err != nil {
		return Deployment{}, err
	}
	if !exists {
		return Deployment{}, ErrApplicationNotFound
	}
	exists, err = u.environments.Exists(ctx, item.EnvironmentID)
	if err != nil {
		return Deployment{}, err
	}
	if !exists {
		return Deployment{}, ErrEnvironmentNotFound
	}
	return u.repo.Create(ctx, item)
}

// CreateFormal persists a product deployment with immutable release and target
// references. The repository enforces idempotency uniqueness; execution is
// deliberately handled by the worker layer.
func (u *UseCase) CreateFormal(
	ctx context.Context,
	principal security.Principal,
	projectID, releaseID, applicationID, environmentID, runtimeTargetID, idempotencyKey, requestID string,
) (Deployment, error) {
	if err := principal.Require(security.PermissionDeploymentCreate); err != nil {
		return Deployment{}, err
	}
	if u.transaction == nil || u.audit == nil {
		return Deployment{}, ErrFormalSecurity
	}
	id, err := u.newID()
	if err != nil {
		return Deployment{}, err
	}
	item, err := NewFormal(id, projectID, releaseID, applicationID, environmentID, runtimeTargetID, idempotencyKey, u.now())
	if err != nil {
		return Deployment{}, err
	}
	item.OrganizationID = principal.OrganizationID
	if u.formalReferences == nil {
		return Deployment{}, ErrReferenceLookup
	}
	if err := u.formalReferences.ValidateProject(ctx, principal.OrganizationID, item.ProjectID); err != nil {
		return Deployment{}, err
	}
	if existing, replayed, err := u.findReplay(ctx, item); err != nil {
		return Deployment{}, err
	} else if replayed {
		return existing, nil
	}
	if err := u.formalReferences.Validate(
		ctx, item.ProjectID, item.ReleaseID, item.ApplicationID, item.EnvironmentID, item.RuntimeTargetID,
	); err != nil {
		return Deployment{}, err
	}
	return u.persistFormal(ctx, principal, item, requestID, AuditActionCreate)
}

func (u *UseCase) ListFormal(
	ctx context.Context,
	principal security.Principal,
	projectID, applicationID, environmentID string,
) ([]Deployment, error) {
	if err := principal.Require(security.PermissionDeploymentRead); err != nil {
		return nil, err
	}
	if u.formalReferences == nil {
		return nil, ErrReferenceLookup
	}
	if err := u.formalReferences.ValidateProject(ctx, principal.OrganizationID, projectID); err != nil {
		return nil, err
	}
	return u.repo.List(ctx, projectID, applicationID, environmentID)
}

func (u *UseCase) GetFormal(
	ctx context.Context,
	principal security.Principal,
	projectID, deploymentID string,
) (Deployment, error) {
	if err := principal.Require(security.PermissionDeploymentRead); err != nil {
		return Deployment{}, err
	}
	if u.formalReferences == nil {
		return Deployment{}, ErrReferenceLookup
	}
	if err := u.formalReferences.ValidateProject(ctx, principal.OrganizationID, projectID); err != nil {
		return Deployment{}, err
	}
	return u.repo.Get(ctx, projectID, deploymentID)
}

func (u *UseCase) CancelFormal(
	ctx context.Context,
	principal security.Principal,
	projectID, deploymentID, requestID string,
) (Deployment, error) {
	if err := principal.Require(security.PermissionDeploymentCancel); err != nil {
		return Deployment{}, err
	}
	if u.formalReferences == nil {
		return Deployment{}, ErrReferenceLookup
	}
	if u.transaction == nil || u.audit == nil {
		return Deployment{}, ErrFormalSecurity
	}
	if err := u.formalReferences.ValidateProject(ctx, principal.OrganizationID, projectID); err != nil {
		return Deployment{}, err
	}
	item, err := u.repo.Get(ctx, projectID, deploymentID)
	if err != nil {
		return Deployment{}, err
	}
	expectedVersion := item.Version
	now := u.now().UTC()
	if err := item.Cancel(now); err != nil {
		return Deployment{}, err
	}
	auditID, err := u.newID()
	if err != nil {
		return Deployment{}, err
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		saved, saveErr := u.repo.Save(transactionContext, item, expectedVersion)
		if saveErr != nil {
			return saveErr
		}
		item = saved
		return u.audit.Record(transactionContext, sharedaudit.Event{
			ID: auditID, OrganizationID: principal.OrganizationID, ProjectID: projectID,
			ActorID: principal.UserID, Action: AuditActionCancel, ResourceType: "deployment",
			ResourceID: item.ID, RequestID: requestID, CreatedAt: now,
		})
	})
	return item, err
}

func (u *UseCase) RetryFormal(
	ctx context.Context,
	principal security.Principal,
	projectID, sourceDeploymentID, idempotencyKey, requestID string,
) (Deployment, error) {
	if err := principal.Require(security.PermissionDeploymentCreate); err != nil {
		return Deployment{}, err
	}
	return u.createDerivedFormal(
		ctx, principal, projectID, sourceDeploymentID, "", idempotencyKey, requestID, AuditActionRetry,
	)
}

func (u *UseCase) RollbackFormal(
	ctx context.Context,
	principal security.Principal,
	projectID, sourceDeploymentID, releaseID, idempotencyKey, requestID string,
) (Deployment, error) {
	if err := principal.Require(security.PermissionDeploymentRollback); err != nil {
		return Deployment{}, err
	}
	return u.createDerivedFormal(
		ctx, principal, projectID, sourceDeploymentID, releaseID, idempotencyKey, requestID, AuditActionRollback,
	)
}

func (u *UseCase) createDerivedFormal(
	ctx context.Context,
	principal security.Principal,
	projectID, sourceDeploymentID, releaseID, idempotencyKey, requestID, action string,
) (Deployment, error) {
	if u.formalReferences == nil {
		return Deployment{}, ErrReferenceLookup
	}
	if u.transaction == nil || u.audit == nil {
		return Deployment{}, ErrFormalSecurity
	}
	if err := u.formalReferences.ValidateProject(ctx, principal.OrganizationID, projectID); err != nil {
		return Deployment{}, err
	}
	source, err := u.repo.Get(ctx, projectID, sourceDeploymentID)
	if err != nil {
		return Deployment{}, err
	}
	id, err := u.newID()
	if err != nil {
		return Deployment{}, err
	}
	var item Deployment
	switch action {
	case AuditActionRetry:
		item, err = source.Retry(id, idempotencyKey, u.now())
	case AuditActionRollback:
		item, err = source.Rollback(id, releaseID, idempotencyKey, u.now())
	default:
		return Deployment{}, ErrInvalidTransition
	}
	if err != nil {
		return Deployment{}, err
	}
	if existing, replayed, replayErr := u.findReplay(ctx, item); replayErr != nil {
		return Deployment{}, replayErr
	} else if replayed {
		return existing, nil
	}
	if err := u.formalReferences.Validate(
		ctx, item.ProjectID, item.ReleaseID, item.ApplicationID, item.EnvironmentID, item.RuntimeTargetID,
	); err != nil {
		return Deployment{}, err
	}
	if action == AuditActionRollback {
		succeeded, succeededErr := u.repo.HasSucceeded(
			ctx, item.ProjectID, item.ReleaseID, item.ApplicationID, item.EnvironmentID, item.RuntimeTargetID,
		)
		if succeededErr != nil {
			return Deployment{}, succeededErr
		}
		if !succeeded {
			return Deployment{}, ErrRollbackNotSucceeded
		}
	}
	return u.persistFormal(ctx, principal, item, requestID, action)
}

func (u *UseCase) findReplay(ctx context.Context, intent Deployment) (Deployment, bool, error) {
	existing, err := u.repo.GetByIdempotency(ctx, intent.ProjectID, intent.IdempotencyKey)
	if errors.Is(err, ErrNotFound) {
		return Deployment{}, false, nil
	}
	if err != nil {
		return Deployment{}, false, err
	}
	if existing.ReleaseID != intent.ReleaseID || existing.ApplicationID != intent.ApplicationID ||
		existing.EnvironmentID != intent.EnvironmentID || existing.RuntimeTargetID != intent.RuntimeTargetID ||
		existing.Operation != intent.Operation || existing.SourceDeploymentID != intent.SourceDeploymentID {
		return Deployment{}, false, ErrIdempotencyMismatch
	}
	return existing, true, nil
}

func (u *UseCase) persistFormal(
	ctx context.Context,
	principal security.Principal,
	item Deployment,
	requestID, action string,
) (Deployment, error) {
	auditID, err := u.newID()
	if err != nil {
		return Deployment{}, err
	}
	now := u.now().UTC()
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		created, createErr := u.repo.Create(transactionContext, item)
		if createErr != nil {
			return createErr
		}
		item = created
		return u.audit.Record(transactionContext, sharedaudit.Event{
			ID: auditID, OrganizationID: principal.OrganizationID, ProjectID: item.ProjectID,
			ActorID: principal.UserID, Action: action, ResourceType: "deployment",
			ResourceID: item.ID, RequestID: requestID, CreatedAt: now,
		})
	})
	if errors.Is(err, ErrDuplicateIdempotency) {
		existing, replayed, replayErr := u.findReplay(ctx, item)
		if replayErr != nil {
			return Deployment{}, replayErr
		}
		if replayed {
			return existing, nil
		}
	}
	return item, err
}
