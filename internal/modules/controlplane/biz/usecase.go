package biz

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"time"

	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/runtimespec"
	"github.com/owndock/owndock/internal/shared/security"
	"github.com/owndock/owndock/internal/shared/transaction"
)

type ArtifactReleaseInput struct {
	ArtifactID           string
	OrganizationID       string
	ProjectID            string
	ApplicationID        string
	RegistryCredentialID string
	ImageDigest          string
	RuntimeSpec          runtimespec.Spec
	ActorID              string
	RequestID            string
}

type IDGenerator func() (string, error)
type Clock func() time.Time

type ManagedHostLookup interface {
	ConnectionMode(context.Context, string, string) (runtimeaccess.Mode, bool, error)
}

type UseCase struct {
	projects         ProjectRepository
	members          ProjectMemberRepository
	applications     ApplicationRepository
	releases         ReleaseRepository
	artifactReleases ArtifactReleaseRepository
	targets          RuntimeTargetRepository
	targetProbes     RuntimeTargetProbeRepository
	targetProber     RuntimeTargetProber
	managedHosts     ManagedHostLookup
	registries       RegistryCredentialRepository
	environments     EnvironmentRepository
	templates        TemplateCatalog
	transaction      transaction.Manager
	audit            sharedaudit.Recorder
	auditReader      sharedaudit.Reader
	newID            IDGenerator
	now              Clock
}

func (u *UseCase) WithProjectMembers(repository ProjectMemberRepository) *UseCase {
	u.members = repository
	return u
}

func (u *UseCase) WithTemplates(catalog TemplateCatalog) *UseCase {
	u.templates = catalog
	return u
}

func (u *UseCase) WithArtifactReleases(repository ArtifactReleaseRepository) *UseCase {
	u.artifactReleases = repository
	return u
}

func (u *UseCase) WithManagedHosts(lookup ManagedHostLookup) *UseCase {
	u.managedHosts = lookup
	return u
}

func (u *UseCase) WithRuntimeTargetProbe(
	repository RuntimeTargetProbeRepository,
	prober RuntimeTargetProber,
) *UseCase {
	u.targetProbes = repository
	u.targetProber = prober
	return u
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

func NewUseCaseWithResources(
	projects ProjectRepository,
	applications ApplicationRepository,
	releases ReleaseRepository,
	targets RuntimeTargetRepository,
	registries RegistryCredentialRepository,
	environments EnvironmentRepository,
	transaction transaction.Manager,
	auditRecorder sharedaudit.Recorder,
	auditReader sharedaudit.Reader,
	newID IDGenerator,
	now Clock,
) *UseCase {
	useCase := NewUseCaseWithEnvironment(
		projects, applications, releases, targets, environments,
		transaction, auditRecorder, auditReader, newID, now,
	)
	useCase.registries = registries
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
	items, err := u.projects.ListProjects(ctx, principal.OrganizationID)
	if err != nil || principal.Role == security.RoleOwner {
		return items, err
	}
	if u.members == nil {
		return nil, ErrNotFound
	}
	projectIDs, err := u.members.ListProjectIDsForUser(ctx, principal.OrganizationID, principal.UserID)
	if err != nil {
		return nil, err
	}
	allowed := make(map[string]struct{}, len(projectIDs))
	for _, projectID := range projectIDs {
		allowed[projectID] = struct{}{}
	}
	result := make([]Project, 0, len(projectIDs))
	for _, item := range items {
		if _, ok := allowed[item.ID]; ok {
			result = append(result, item)
		}
	}
	return result, nil
}

func (u *UseCase) ListProjectMembers(
	ctx context.Context, principal security.Principal, projectID string,
) ([]ProjectMember, error) {
	if err := principal.Require(security.PermissionProjectMemberRead); err != nil {
		return nil, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return nil, err
	}
	if u.members == nil {
		return nil, ErrNotFound
	}
	return u.members.ListProjectMembers(ctx, projectID)
}

func (u *UseCase) CreateProjectMember(
	ctx context.Context, principal security.Principal, projectID, email string,
	role security.Role, requestID string,
) (ProjectMember, error) {
	if err := principal.Require(security.PermissionProjectMemberManage); err != nil {
		return ProjectMember{}, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return ProjectMember{}, err
	}
	if u.members == nil {
		return ProjectMember{}, ErrNotFound
	}
	if !validProjectMemberRole(role) {
		return ProjectMember{}, ErrInvalidProjectMember
	}
	email, err := normalizeProjectMemberEmail(email)
	if err != nil {
		return ProjectMember{}, err
	}
	user, err := u.members.FindOrganizationUserByEmail(ctx, principal.OrganizationID, email)
	if err != nil {
		return ProjectMember{}, err
	}
	if user.ID == principal.UserID {
		return ProjectMember{}, ErrCannotModifySelf
	}
	auditID, err := u.newID()
	if err != nil {
		return ProjectMember{}, err
	}
	now := u.now().UTC()
	item, err := NewProjectMember(projectID, user, role, principal.UserID, now)
	if err != nil {
		return ProjectMember{}, err
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		created, createErr := u.members.CreateProjectMember(transactionContext, item)
		if createErr != nil {
			return createErr
		}
		item = created
		return u.record(transactionContext, principal, auditID, "project_member.create", "project_member", item.UserID, projectID, requestID, now)
	})
	return item, err
}

func (u *UseCase) UpdateProjectMember(
	ctx context.Context, principal security.Principal, projectID, userID string,
	role security.Role, expectedVersion uint64, requestID string,
) (ProjectMember, error) {
	if err := principal.Require(security.PermissionProjectMemberManage); err != nil {
		return ProjectMember{}, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return ProjectMember{}, err
	}
	if u.members == nil {
		return ProjectMember{}, ErrNotFound
	}
	if expectedVersion == 0 {
		return ProjectMember{}, ErrInvalidProjectMember
	}
	if strings.TrimSpace(userID) == principal.UserID {
		return ProjectMember{}, ErrCannotModifySelf
	}
	current, err := u.members.GetProjectMember(ctx, projectID, userID)
	if err != nil {
		return ProjectMember{}, err
	}
	item, err := current.ChangeRole(role, principal.UserID, u.now().UTC())
	if err != nil {
		return ProjectMember{}, err
	}
	auditID, err := u.newID()
	if err != nil {
		return ProjectMember{}, err
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		updated, updateErr := u.members.UpdateProjectMember(transactionContext, item, expectedVersion)
		if updateErr != nil {
			return updateErr
		}
		item = updated
		return u.record(transactionContext, principal, auditID, "project_member.update", "project_member", item.UserID, projectID, requestID, item.UpdatedAt)
	})
	return item, err
}

func (u *UseCase) DeleteProjectMember(
	ctx context.Context, principal security.Principal, projectID, userID string,
	expectedVersion uint64, requestID string,
) error {
	if err := principal.Require(security.PermissionProjectMemberManage); err != nil {
		return err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return err
	}
	if u.members == nil {
		return ErrNotFound
	}
	userID = strings.TrimSpace(userID)
	if expectedVersion == 0 {
		return ErrInvalidProjectMember
	}
	if userID == principal.UserID {
		return ErrCannotModifySelf
	}
	auditID, err := u.newID()
	if err != nil {
		return err
	}
	now := u.now().UTC()
	return u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		if deleteErr := u.members.DeleteProjectMember(transactionContext, projectID, userID, expectedVersion); deleteErr != nil {
			return deleteErr
		}
		return u.record(transactionContext, principal, auditID, "project_member.delete", "project_member", userID, projectID, requestID, now)
	})
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
	return u.CreateApplicationFromTemplate(
		ctx, principal, projectID, name, "", requestID,
	)
}

func (u *UseCase) ListTemplates(
	ctx context.Context,
	principal security.Principal,
) ([]Template, error) {
	if err := principal.Require(security.PermissionApplicationRead); err != nil {
		return nil, err
	}
	if u.templates == nil {
		return nil, ErrInvalidTemplate
	}
	return u.templates.ListTemplates(ctx)
}

func (u *UseCase) GetTemplate(
	ctx context.Context,
	principal security.Principal,
	templateID string,
) (Template, error) {
	if err := principal.Require(security.PermissionApplicationRead); err != nil {
		return Template{}, err
	}
	if u.templates == nil {
		return Template{}, ErrInvalidTemplate
	}
	return u.templates.GetTemplate(ctx, strings.TrimSpace(templateID))
}

func (u *UseCase) CreateApplicationFromTemplate(
	ctx context.Context,
	principal security.Principal,
	projectID, name, templateID, requestID string,
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
	var selected *Template
	templateID = strings.TrimSpace(templateID)
	if templateID != "" {
		if u.templates == nil {
			return Application{}, ErrInvalidTemplate
		}
		template, templateErr := u.templates.GetTemplate(ctx, templateID)
		if templateErr != nil {
			return Application{}, templateErr
		}
		selected = &template
	}
	item, err := NewApplicationFromTemplate(
		id, projectID, name, principal.UserID, now, selected,
	)
	if err != nil {
		return Application{}, err
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		created, err := u.applications.CreateApplication(transactionContext, item)
		if err != nil {
			return err
		}
		item = created
		action := "application.create"
		if item.TemplateSnapshot != nil {
			action = "application.create_from_template"
		}
		return u.record(transactionContext, principal, auditID, action, "application", item.ID, projectID, requestID, now)
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
	return u.CreateReleaseWithRegistry(
		ctx, principal, projectID, applicationID, image, "", requestID,
	)
}

func (u *UseCase) CreateReleaseWithRegistry(
	ctx context.Context,
	principal security.Principal,
	projectID, applicationID, image, registryCredentialID, requestID string,
) (Release, error) {
	return u.CreateReleaseWithRuntimeSpec(
		ctx, principal, projectID, applicationID, image, registryCredentialID,
		runtimespec.Spec{}, requestID,
	)
}

func (u *UseCase) CreateReleaseWithRuntimeSpec(
	ctx context.Context,
	principal security.Principal,
	projectID, applicationID, image, registryCredentialID string,
	runtimeSpec runtimespec.Spec,
	requestID string,
) (Release, error) {
	if err := principal.Require(security.PermissionReleaseCreate); err != nil {
		return Release{}, err
	}
	if err := u.requireProjectAndApplication(ctx, principal, projectID, applicationID); err != nil {
		return Release{}, err
	}
	if registryCredentialID != "" {
		if u.registries == nil {
			return Release{}, ErrNotFound
		}
		credential, err := u.registries.GetRegistryCredential(ctx, projectID, registryCredentialID)
		if err != nil {
			return Release{}, err
		}
		imageRegistry, err := ImageRegistry(image)
		if err != nil {
			return Release{}, err
		}
		if imageRegistry != credential.Server {
			return Release{}, ErrInvalidRegistry
		}
	}
	id, auditID, now, err := u.identifiers()
	if err != nil {
		return Release{}, err
	}
	item, err := NewReleaseWithRuntimeSpec(
		id, projectID, applicationID, image, registryCredentialID,
		runtimeSpec, principal.UserID, now,
	)
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

// CreateReleaseFromArtifact is the narrow system boundary used by the Build
// module. It is idempotent by SourceArtifactID and deliberately does not
// expose a way to mutate an existing Release.
func (u *UseCase) CreateReleaseFromArtifact(ctx context.Context, input ArtifactReleaseInput) (Release, error) {
	input.ArtifactID = strings.TrimSpace(input.ArtifactID)
	input.OrganizationID = strings.TrimSpace(input.OrganizationID)
	input.ProjectID = strings.TrimSpace(input.ProjectID)
	input.ApplicationID = strings.TrimSpace(input.ApplicationID)
	input.RegistryCredentialID = strings.TrimSpace(input.RegistryCredentialID)
	input.ActorID = strings.TrimSpace(input.ActorID)
	if input.ArtifactID == "" || input.OrganizationID == "" || input.ProjectID == "" ||
		input.ApplicationID == "" || input.RegistryCredentialID == "" || input.ActorID == "" {
		return Release{}, ErrNotFound
	}
	if u.artifactReleases == nil {
		return Release{}, ErrNotFound
	}
	if existing, err := u.artifactReleases.GetReleaseByArtifact(ctx, input.ProjectID, input.ArtifactID); err == nil {
		if releaseMatchesArtifact(existing, input) {
			return existing, nil
		}
		return Release{}, ErrDuplicateRelease
	} else if !errors.Is(err, ErrNotFound) {
		return Release{}, err
	}
	projectExists, err := u.projects.ProjectExists(ctx, input.OrganizationID, input.ProjectID)
	if err != nil {
		return Release{}, err
	}
	applicationExists, err := u.applications.ApplicationExists(ctx, input.ProjectID, input.ApplicationID)
	if err != nil {
		return Release{}, err
	}
	if !projectExists || !applicationExists || u.registries == nil {
		return Release{}, ErrNotFound
	}
	credential, err := u.registries.GetRegistryCredential(ctx, input.ProjectID, input.RegistryCredentialID)
	if err != nil {
		return Release{}, err
	}
	imageRegistry, err := ImageRegistry(input.ImageDigest)
	if err != nil || imageRegistry != credential.Server {
		return Release{}, ErrInvalidRegistry
	}
	id, auditID, now, err := u.identifiers()
	if err != nil {
		return Release{}, err
	}
	item, err := NewReleaseFromArtifact(
		id, input.ProjectID, input.ApplicationID, input.ImageDigest,
		input.RegistryCredentialID, input.ArtifactID, input.RuntimeSpec,
		input.ActorID, now,
	)
	if err != nil {
		return Release{}, err
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		created, createErr := u.releases.CreateRelease(transactionContext, item)
		if createErr != nil {
			return createErr
		}
		item = created
		return u.audit.Record(transactionContext, sharedaudit.Event{
			ID: auditID, OrganizationID: input.OrganizationID, ProjectID: input.ProjectID,
			ActorID: input.ActorID, Action: "release.create_from_artifact",
			ResourceType: "release", ResourceID: item.ID,
			RequestID: input.RequestID, CreatedAt: now,
		})
	})
	if errors.Is(err, ErrDuplicateRelease) {
		existing, getErr := u.artifactReleases.GetReleaseByArtifact(ctx, input.ProjectID, input.ArtifactID)
		if getErr == nil && releaseMatchesArtifact(existing, input) {
			return existing, nil
		}
	}
	return item, err
}

func releaseMatchesArtifact(item Release, input ArtifactReleaseInput) bool {
	normalizedSpec, err := canonicalRuntimeSpec(input.RuntimeSpec)
	if err != nil {
		return false
	}
	storedSpec, err := canonicalRuntimeSpec(item.RuntimeSpec)
	return err == nil && item.ProjectID == input.ProjectID &&
		item.ApplicationID == input.ApplicationID && item.SourceArtifactID == input.ArtifactID &&
		item.ImageDigest == strings.TrimSpace(input.ImageDigest) &&
		item.RegistryCredentialID == input.RegistryCredentialID &&
		reflect.DeepEqual(storedSpec, normalizedSpec)
}

func canonicalRuntimeSpec(value runtimespec.Spec) (runtimespec.Spec, error) {
	normalized, err := runtimespec.Normalize(value)
	if err != nil {
		return runtimespec.Spec{}, err
	}
	if len(normalized.Ports) == 0 {
		normalized.Ports = nil
	}
	if len(normalized.EnvironmentKeys) == 0 {
		normalized.EnvironmentKeys = nil
	}
	if normalized.HealthCheck != nil && len(normalized.HealthCheck.Command) == 0 {
		normalized.HealthCheck.Command = nil
	}
	return normalized, nil
}

func (u *UseCase) ListRegistryCredentials(
	ctx context.Context,
	principal security.Principal,
	projectID string,
) ([]RegistryCredential, error) {
	if u.registries == nil {
		return nil, ErrNotFound
	}
	if err := principal.Require(security.PermissionRegistryRead); err != nil {
		return nil, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return nil, err
	}
	return u.registries.ListRegistryCredentials(ctx, projectID)
}

func (u *UseCase) CreateRegistryCredential(
	ctx context.Context,
	principal security.Principal,
	projectID, name, server, username, passwordRef, requestID string,
) (RegistryCredential, error) {
	if u.registries == nil {
		return RegistryCredential{}, ErrNotFound
	}
	if err := principal.Require(security.PermissionRegistryWrite); err != nil {
		return RegistryCredential{}, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return RegistryCredential{}, err
	}
	id, auditID, now, err := u.identifiers()
	if err != nil {
		return RegistryCredential{}, err
	}
	item, err := NewRegistryCredential(
		id, projectID, name, server, username, passwordRef, principal.UserID, now,
	)
	if err != nil {
		return RegistryCredential{}, err
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		created, createErr := u.registries.CreateRegistryCredential(transactionContext, item)
		if createErr != nil {
			return createErr
		}
		item = created
		return u.record(
			transactionContext, principal, auditID, "registry_credential.create",
			"registry_credential", item.ID, projectID, requestID, now,
		)
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
	projectID, name, managedHostID string,
	connectionMode runtimeaccess.Mode,
	endpoint, tlsServerName, credentialRef, requestID string,
) (RuntimeTarget, error) {
	if err := principal.Require(security.PermissionRuntimeTargetWrite); err != nil {
		return RuntimeTarget{}, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return RuntimeTarget{}, err
	}
	if u.managedHosts == nil {
		return RuntimeTarget{}, ErrManagedHostNotFound
	}
	hostMode, found, err := u.managedHosts.ConnectionMode(
		ctx, principal.OrganizationID, managedHostID,
	)
	if err != nil {
		return RuntimeTarget{}, err
	}
	if !found {
		return RuntimeTarget{}, ErrManagedHostNotFound
	}
	if hostMode != connectionMode {
		return RuntimeTarget{}, ErrRuntimeTargetHostMismatch
	}
	id, auditID, now, err := u.identifiers()
	if err != nil {
		return RuntimeTarget{}, err
	}
	item, err := NewRuntimeTarget(
		id, projectID, name, managedHostID, connectionMode,
		endpoint, tlsServerName, credentialRef, principal.UserID, now,
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

func (u *UseCase) ProbeRuntimeTarget(
	ctx context.Context,
	principal security.Principal,
	projectID, targetID, requestID string,
) (RuntimeTarget, error) {
	if u.targetProbes == nil || u.targetProber == nil {
		return RuntimeTarget{}, ErrNotFound
	}
	if err := principal.Require(security.PermissionRuntimeTargetWrite); err != nil {
		return RuntimeTarget{}, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return RuntimeTarget{}, err
	}
	target, err := u.targetProbes.GetRuntimeTarget(ctx, projectID, targetID)
	if err != nil {
		return RuntimeTarget{}, err
	}
	status, err := u.targetProber.ProbeRuntimeTarget(ctx, target)
	if err != nil {
		return RuntimeTarget{}, err
	}
	if err := ctx.Err(); err != nil {
		return RuntimeTarget{}, err
	}
	switch status {
	case RuntimeTargetStatusReady, RuntimeTargetStatusUnreachable, RuntimeTargetStatusCredentialError:
	default:
		status = RuntimeTargetStatusUnreachable
	}
	auditID, err := u.newID()
	if err != nil {
		return RuntimeTarget{}, err
	}
	now := u.now().UTC()
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		updated, updateErr := u.targetProbes.UpdateRuntimeTargetProbe(
			transactionContext, projectID, targetID, status, now,
		)
		if updateErr != nil {
			return updateErr
		}
		target = updated
		return u.record(
			transactionContext, principal, auditID,
			"runtime_target.probe."+string(status), "runtime_target",
			target.ID, projectID, requestID, now,
		)
	})
	return target, err
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
	return u.CreateEnvironmentWithVariables(
		ctx, principal, projectID, name, stage, nil, requestID,
	)
}

func (u *UseCase) CreateEnvironmentWithVariables(
	ctx context.Context,
	principal security.Principal,
	projectID, name, stage string,
	variables map[string]string,
	requestID string,
) (Environment, error) {
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
	item, err := NewEnvironmentWithVariables(
		id, projectID, name, stage, variables, principal.UserID, now,
	)
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
	if principal.Role != security.RoleOwner && u.members != nil {
		if _, err := u.members.ResolveProjectRole(ctx, principal.OrganizationID, projectID, principal.UserID); err != nil {
			return err
		}
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
