package biz

import (
	"context"
	"time"

	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/security"
	"github.com/owndock/owndock/internal/shared/transaction"
)

type IDGenerator func() (string, error)
type Clock func() time.Time

type UseCase struct {
	projects     ProjectRepository
	applications ApplicationRepository
	releases     ReleaseRepository
	targets      RuntimeTargetRepository
	environments EnvironmentRepository
	transaction  transaction.Manager
	audit        sharedaudit.Recorder
	auditReader  sharedaudit.Reader
	newID        IDGenerator
	now          Clock
}

func NewUseCaseWithEnvironment(
	projects ProjectRepository,
	applications ApplicationRepository,
	releases ReleaseRepository,
	targets RuntimeTargetRepository,
	environments EnvironmentRepository,
	transaction transaction.Manager,
	auditRecorder sharedaudit.Recorder,
	auditReader sharedaudit.Reader,
	newID IDGenerator,
	now Clock,
) *UseCase {
	useCase := NewUseCase(projects, applications, releases, targets, transaction, auditRecorder, auditReader, newID, now)
	useCase.environments = environments
	return useCase
}

func NewUseCase(
	projects ProjectRepository,
	applications ApplicationRepository,
	releases ReleaseRepository,
	targets RuntimeTargetRepository,
	transaction transaction.Manager,
	auditRecorder sharedaudit.Recorder,
	auditReader sharedaudit.Reader,
	newID IDGenerator,
	now Clock,
) *UseCase {
	return &UseCase{
		projects: projects, applications: applications, releases: releases, targets: targets,
		transaction: transaction, audit: auditRecorder, auditReader: auditReader,
		newID: newID, now: now,
	}
}

func (u *UseCase) ListProjects(ctx context.Context, principal security.Principal) ([]Project, error) {
	if err := principal.Require(security.PermissionProjectRead); err != nil {
		return nil, err
	}
	return u.projects.ListProjects(ctx, principal.OrganizationID)
}

func (u *UseCase) CreateProject(ctx context.Context, principal security.Principal, name, requestID string) (Project, error) {
	if err := principal.Require(security.PermissionProjectCreate); err != nil {
		return Project{}, err
	}
	id, auditID, now, err := u.identifiers()
	if err != nil {
		return Project{}, err
	}
	item, err := NewProject(id, principal.OrganizationID, name, principal.UserID, now)
	if err != nil {
		return Project{}, err
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		created, err := u.projects.CreateProject(transactionContext, item)
		if err != nil {
			return err
		}
		item = created
		return u.record(transactionContext, principal, auditID, "project.create", "project", item.ID, item.ID, requestID, now)
	})
	return item, err
}

func (u *UseCase) ListApplications(ctx context.Context, principal security.Principal, projectID string) ([]Application, error) {
	if err := principal.Require(security.PermissionApplicationRead); err != nil {
		return nil, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return nil, err
	}
	return u.applications.ListApplications(ctx, projectID)
}

func (u *UseCase) CreateApplication(
	ctx context.Context,
	principal security.Principal,
	projectID, name, requestID string,
) (Application, error) {
	if err := principal.Require(security.PermissionApplicationWrite); err != nil {
		return Application{}, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return Application{}, err
	}
	id, auditID, now, err := u.identifiers()
	if err != nil {
		return Application{}, err
	}
	item, err := NewApplication(id, projectID, name, principal.UserID, now)
	if err != nil {
		return Application{}, err
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		created, err := u.applications.CreateApplication(transactionContext, item)
		if err != nil {
			return err
		}
		item = created
		return u.record(transactionContext, principal, auditID, "application.create", "application", item.ID, projectID, requestID, now)
	})
	return item, err
}

func (u *UseCase) ListReleases(
	ctx context.Context,
	principal security.Principal,
	projectID, applicationID string,
) ([]Release, error) {
	if err := principal.Require(security.PermissionReleaseRead); err != nil {
		return nil, err
	}
	if err := u.requireProjectAndApplication(ctx, principal, projectID, applicationID); err != nil {
		return nil, err
	}
	return u.releases.ListReleases(ctx, projectID, applicationID)
}

func (u *UseCase) CreateRelease(
	ctx context.Context,
	principal security.Principal,
	projectID, applicationID, image, requestID string,
) (Release, error) {
	if err := principal.Require(security.PermissionReleaseCreate); err != nil {
		return Release{}, err
	}
	if err := u.requireProjectAndApplication(ctx, principal, projectID, applicationID); err != nil {
		return Release{}, err
	}
	id, auditID, now, err := u.identifiers()
	if err != nil {
		return Release{}, err
	}
	item, err := NewRelease(id, projectID, applicationID, image, principal.UserID, now)
	if err != nil {
		return Release{}, err
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		created, err := u.releases.CreateRelease(transactionContext, item)
		if err != nil {
			return err
		}
		item = created
		return u.record(transactionContext, principal, auditID, "release.create", "release", item.ID, projectID, requestID, now)
	})
	return item, err
}

func (u *UseCase) ListRuntimeTargets(
	ctx context.Context,
	principal security.Principal,
	projectID string,
) ([]RuntimeTarget, error) {
	if err := principal.Require(security.PermissionRuntimeTargetRead); err != nil {
		return nil, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return nil, err
	}
	return u.targets.ListRuntimeTargets(ctx, projectID)
}

func (u *UseCase) CreateRuntimeTarget(
	ctx context.Context,
	principal security.Principal,
	projectID, name, endpoint, tlsServerName, credentialRef, requestID string,
) (RuntimeTarget, error) {
	if err := principal.Require(security.PermissionRuntimeTargetWrite); err != nil {
		return RuntimeTarget{}, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return RuntimeTarget{}, err
	}
	id, auditID, now, err := u.identifiers()
	if err != nil {
		return RuntimeTarget{}, err
	}
	item, err := NewRuntimeTarget(
		id, projectID, name, endpoint, tlsServerName, credentialRef, principal.UserID, now,
	)
	if err != nil {
		return RuntimeTarget{}, err
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		created, err := u.targets.CreateRuntimeTarget(transactionContext, item)
		if err != nil {
			return err
		}
		item = created
		return u.record(transactionContext, principal, auditID, "runtime_target.create", "runtime_target", item.ID, projectID, requestID, now)
	})
	return item, err
}

func (u *UseCase) ListEnvironments(ctx context.Context, principal security.Principal, projectID string) ([]Environment, error) {
	if u.environments == nil {
		return nil, ErrNotFound
	}
	if err := principal.Require(security.PermissionEnvironmentRead); err != nil {
		return nil, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return nil, err
	}
	return u.environments.ListEnvironments(ctx, projectID)
}

func (u *UseCase) CreateEnvironment(ctx context.Context, principal security.Principal, projectID, name, stage, requestID string) (Environment, error) {
	if u.environments == nil {
		return Environment{}, ErrNotFound
	}
	if err := principal.Require(security.PermissionEnvironmentWrite); err != nil {
		return Environment{}, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return Environment{}, err
	}
	id, auditID, now, err := u.identifiers()
	if err != nil {
		return Environment{}, err
	}
	item, err := NewEnvironment(id, projectID, name, stage, principal.UserID, now)
	if err != nil {
		return Environment{}, err
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		created, createErr := u.environments.CreateEnvironment(transactionContext, item)
		if createErr != nil {
			return createErr
		}
		item = created
		return u.record(transactionContext, principal, auditID, "environment.create", "environment", item.ID, projectID, requestID, now)
	})
	return item, err
}

func (u *UseCase) ListAuditEvents(
	ctx context.Context,
	principal security.Principal,
	projectID string,
	limit int64,
) ([]sharedaudit.Event, error) {
	if err := principal.Require(security.PermissionAuditRead); err != nil {
		return nil, err
	}
	if projectID != "" {
		if err := u.requireProject(ctx, principal, projectID); err != nil {
			return nil, err
		}
	}
	return u.auditReader.List(ctx, principal.OrganizationID, projectID, limit)
}

func (u *UseCase) requireProject(ctx context.Context, principal security.Principal, projectID string) error {
	exists, err := u.projects.ProjectExists(ctx, principal.OrganizationID, projectID)
	if err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	return nil
}

func (u *UseCase) requireProjectAndApplication(
	ctx context.Context,
	principal security.Principal,
	projectID, applicationID string,
) error {
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return err
	}
	exists, err := u.applications.ApplicationExists(ctx, projectID, applicationID)
	if err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	return nil
}

func (u *UseCase) identifiers() (string, string, time.Time, error) {
	id, err := u.newID()
	if err != nil {
		return "", "", time.Time{}, err
	}
	auditID, err := u.newID()
	if err != nil {
		return "", "", time.Time{}, err
	}
	return id, auditID, u.now().UTC(), nil
}

func (u *UseCase) record(
	ctx context.Context,
	principal security.Principal,
	auditID, action, resourceType, resourceID, projectID, requestID string,
	now time.Time,
) error {
	return u.audit.Record(ctx, sharedaudit.Event{
		ID: auditID, OrganizationID: principal.OrganizationID, ProjectID: projectID,
		ActorID: principal.UserID, Action: action, ResourceType: resourceType,
		ResourceID: resourceID, RequestID: requestID, CreatedAt: now,
	})
}
