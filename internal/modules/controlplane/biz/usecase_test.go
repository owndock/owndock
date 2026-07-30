package biz

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/runtimespec"
	"github.com/owndock/owndock/internal/shared/security"
	"github.com/owndock/owndock/internal/shared/transaction"
)

func TestAcceptedProductResourceFlow(t *testing.T) {
	store := &fakeStore{}
	audits := &fakeAudits{}
	ids := 0
	useCase := NewUseCase(
		store, store, store, store,
		transaction.Passthrough{}, audits, audits,
		func() (string, error) {
			ids++
			return fmt.Sprintf("id-%d", ids), nil
		},
		func() time.Time { return time.Unix(100, 0) },
	).WithManagedHosts(store)
	owner := security.Principal{
		UserID: "owner", OrganizationID: "organization", SessionID: "session", Role: security.RoleOwner,
	}
	project, err := useCase.CreateProject(context.Background(), owner, "Delivery", "request-1")
	if err != nil {
		t.Fatalf("CreateProject() error = %v", err)
	}
	application, err := useCase.CreateApplication(context.Background(), owner, project.ID, "API", "request-2")
	if err != nil {
		t.Fatalf("CreateApplication() error = %v", err)
	}
	release, err := useCase.CreateRelease(
		context.Background(), owner, project.ID, application.ID,
		"registry.example.com/team/api@sha256:"+strings.Repeat("b", 64),
		"request-3",
	)
	if err != nil {
		t.Fatalf("CreateRelease() error = %v", err)
	}
	target, err := useCase.CreateRuntimeTarget(
		context.Background(), owner, project.ID, "production", "host-1",
		runtimeaccess.ModeDirectDocker,
		"tcp://docker.example.com:2376", "docker.example.com", "secret://docker",
		"request-4",
	)
	if err != nil {
		t.Fatalf("CreateRuntimeTarget() error = %v", err)
	}
	if release.ApplicationID != application.ID || target.ProjectID != project.ID {
		t.Fatalf("release=%+v target=%+v", release, target)
	}
	events, err := useCase.ListAuditEvents(context.Background(), owner, project.ID, 100)
	if err != nil {
		t.Fatalf("ListAuditEvents() error = %v", err)
	}
	if len(events) != 4 {
		t.Fatalf("audit count = %d, want 4", len(events))
	}

	viewer := owner
	viewer.Role = security.RoleViewer
	if _, err := useCase.CreateApplication(context.Background(), viewer, project.ID, "Denied", "request-5"); err != security.ErrForbidden {
		t.Fatalf("viewer CreateApplication() error = %v, want ErrForbidden", err)
	}
}

func TestRegistryCredentialMustMatchReleaseImage(t *testing.T) {
	store := &fakeStore{}
	audits := &fakeAudits{}
	sequence := 0
	useCase := NewUseCaseWithResources(
		store, store, store, store, store, store,
		transaction.Passthrough{}, audits, audits,
		func() (string, error) {
			sequence++
			return fmt.Sprintf("id-%d", sequence), nil
		},
		func() time.Time { return time.Unix(100, 0) },
	)
	owner := security.Principal{
		UserID: "owner", OrganizationID: "organization", SessionID: "session", Role: security.RoleOwner,
	}
	project, err := useCase.CreateProject(t.Context(), owner, "Delivery", "request-project")
	if err != nil {
		t.Fatal(err)
	}
	application, err := useCase.CreateApplication(t.Context(), owner, project.ID, "API", "request-application")
	if err != nil {
		t.Fatal(err)
	}
	credential, err := useCase.CreateRegistryCredential(
		t.Context(), owner, project.ID, "Registry", "registry.example.com",
		"robot", "secret://registry-password", "request-registry",
	)
	if err != nil {
		t.Fatal(err)
	}
	release, err := useCase.CreateReleaseWithRuntimeSpec(
		t.Context(), owner, project.ID, application.ID,
		"registry.example.com/team/api@sha256:"+strings.Repeat("c", 64),
		credential.ID,
		runtimespec.Spec{EnvironmentKeys: []string{"DATABASE_URL"}},
		"request-release",
	)
	if err != nil || release.RegistryCredentialID != credential.ID {
		t.Fatalf("release = %+v, error = %v", release, err)
	}
	if _, err := useCase.CreateReleaseWithRegistry(
		t.Context(), owner, project.ID, application.ID,
		"other.example.com/team/api@sha256:"+strings.Repeat("d", 64),
		credential.ID, "request-mismatch",
	); err != ErrInvalidRegistry {
		t.Fatalf("mismatched registry error = %v", err)
	}
}

type runtimeTargetProberStub struct {
	status RuntimeTargetStatus
}

type managedHostLookupStub struct {
	mode  runtimeaccess.Mode
	found bool
}

func (s managedHostLookupStub) ConnectionMode(
	context.Context,
	string,
	string,
) (runtimeaccess.Mode, bool, error) {
	return s.mode, s.found, nil
}

func (p runtimeTargetProberStub) ProbeRuntimeTarget(
	context.Context,
	RuntimeTarget,
) (RuntimeTargetStatus, error) {
	return p.status, nil
}

func TestProbeRuntimeTargetPersistsSafeStatusAndAudit(t *testing.T) {
	store := &fakeStore{
		projects: []Project{{
			ID: "project", OrganizationID: "organization", Name: "Delivery",
		}},
		targets: []RuntimeTarget{{
			ID: "target", ProjectID: "project", Name: "Production",
			ConnectionMode: runtimeaccess.ModeDirectDocker,
			Status:         RuntimeTargetStatusPending,
		}},
	}
	audits := &fakeAudits{}
	useCase := NewUseCase(
		store, store, store, store,
		transaction.Passthrough{}, audits, audits,
		func() (string, error) { return "audit", nil },
		func() time.Time { return time.Unix(100, 0) },
	).WithRuntimeTargetProbe(
		store,
		runtimeTargetProberStub{status: RuntimeTargetStatusReady},
	)
	owner := security.Principal{
		UserID: "owner", OrganizationID: "organization",
		SessionID: "session", Role: security.RoleOwner,
	}
	target, err := useCase.ProbeRuntimeTarget(
		t.Context(), owner, "project", "target", "request",
	)
	if err != nil {
		t.Fatal(err)
	}
	if target.Status != RuntimeTargetStatusReady || target.LastProbedAt.IsZero() ||
		len(audits.events) != 1 ||
		audits.events[0].Action != "runtime_target.probe.ready" {
		t.Fatalf("target = %+v, audits = %+v", target, audits.events)
	}
}

func TestCreateRuntimeTargetRequiresMatchingManagedHostMode(t *testing.T) {
	store := &fakeStore{projects: []Project{{
		ID: "project", OrganizationID: "organization",
	}}}
	audits := &fakeAudits{}
	useCase := NewUseCase(
		store, store, store, store,
		transaction.Passthrough{}, audits, audits,
		func() (string, error) { return "id", nil },
		func() time.Time { return time.Unix(100, 0) },
	).WithManagedHosts(managedHostLookupStub{
		mode: runtimeaccess.ModeAgent, found: true,
	})
	owner := security.Principal{
		UserID: "owner", OrganizationID: "organization",
		SessionID: "session", Role: security.RoleOwner,
	}
	_, err := useCase.CreateRuntimeTarget(
		t.Context(), owner, "project", "Production", "host",
		runtimeaccess.ModeDirectDocker,
		"tcp://docker.example.com:2376", "docker.example.com", "secret://docker",
		"request",
	)
	if err != ErrRuntimeTargetHostMismatch {
		t.Fatalf("error = %v", err)
	}
}

func TestAgentRuntimeTargetProbeUsesConfiguredProber(t *testing.T) {
	store := &fakeStore{
		projects: []Project{{
			ID: "project", OrganizationID: "organization",
		}},
		targets: []RuntimeTarget{{
			ID: "target", ProjectID: "project",
			ManagedHostID: "host", ConnectionMode: runtimeaccess.ModeAgent,
			Status: RuntimeTargetStatusPending,
		}},
	}
	useCase := NewUseCase(
		store, store, store, store,
		transaction.Passthrough{}, &fakeAudits{}, &fakeAudits{},
		func() (string, error) { return "id", nil }, time.Now,
	).WithRuntimeTargetProbe(
		store, runtimeTargetProberStub{status: RuntimeTargetStatusReady},
	)
	owner := security.Principal{
		UserID: "owner", OrganizationID: "organization",
		SessionID: "session", Role: security.RoleOwner,
	}
	target, err := useCase.ProbeRuntimeTarget(
		t.Context(), owner, "project", "target", "request",
	)
	if err != nil {
		t.Fatal(err)
	}
	if target.Status != RuntimeTargetStatusReady {
		t.Fatalf("status = %s", target.Status)
	}
}

type fakeStore struct {
	projects     []Project
	applications []Application
	releases     []Release
	targets      []RuntimeTarget
	registries   []RegistryCredential
	environments []Environment
}

func (s *fakeStore) ListProjects(_ context.Context, organizationID string) ([]Project, error) {
	var result []Project
	for _, item := range s.projects {
		if item.OrganizationID == organizationID {
			result = append(result, item)
		}
	}
	return result, nil
}

func (s *fakeStore) CreateProject(_ context.Context, item Project) (Project, error) {
	s.projects = append(s.projects, item)
	return item, nil
}

func (s *fakeStore) ProjectExists(_ context.Context, organizationID, projectID string) (bool, error) {
	for _, item := range s.projects {
		if item.ID == projectID && item.OrganizationID == organizationID {
			return true, nil
		}
	}
	return false, nil
}

func (s *fakeStore) ListApplications(_ context.Context, projectID string) ([]Application, error) {
	var result []Application
	for _, item := range s.applications {
		if item.ProjectID == projectID {
			result = append(result, item)
		}
	}
	return result, nil
}

func (s *fakeStore) CreateApplication(_ context.Context, item Application) (Application, error) {
	s.applications = append(s.applications, item)
	return item, nil
}

func (s *fakeStore) ApplicationExists(_ context.Context, projectID, applicationID string) (bool, error) {
	for _, item := range s.applications {
		if item.ID == applicationID && item.ProjectID == projectID {
			return true, nil
		}
	}
	return false, nil
}

func (s *fakeStore) ListReleases(_ context.Context, projectID, applicationID string) ([]Release, error) {
	var result []Release
	for _, item := range s.releases {
		if item.ProjectID == projectID && item.ApplicationID == applicationID {
			result = append(result, item)
		}
	}
	return result, nil
}

func (s *fakeStore) CreateRelease(_ context.Context, item Release) (Release, error) {
	s.releases = append(s.releases, item)
	return item, nil
}

func (s *fakeStore) ListRuntimeTargets(_ context.Context, projectID string) ([]RuntimeTarget, error) {
	var result []RuntimeTarget
	for _, item := range s.targets {
		if item.ProjectID == projectID {
			result = append(result, item)
		}
	}
	return result, nil
}

func (s *fakeStore) CreateRuntimeTarget(_ context.Context, item RuntimeTarget) (RuntimeTarget, error) {
	s.targets = append(s.targets, item)
	return item, nil
}

func (s *fakeStore) ConnectionMode(
	_ context.Context,
	_, hostID string,
) (runtimeaccess.Mode, bool, error) {
	return runtimeaccess.ModeDirectDocker, hostID == "host-1", nil
}

func (s *fakeStore) GetRuntimeTarget(
	_ context.Context,
	projectID, targetID string,
) (RuntimeTarget, error) {
	for _, item := range s.targets {
		if item.ProjectID == projectID && item.ID == targetID {
			return item, nil
		}
	}
	return RuntimeTarget{}, ErrNotFound
}

func (s *fakeStore) UpdateRuntimeTargetProbe(
	_ context.Context,
	projectID, targetID string,
	status RuntimeTargetStatus,
	probedAt time.Time,
) (RuntimeTarget, error) {
	for i := range s.targets {
		if s.targets[i].ProjectID == projectID && s.targets[i].ID == targetID {
			s.targets[i].Status = status
			s.targets[i].LastProbedAt = probedAt
			return s.targets[i], nil
		}
	}
	return RuntimeTarget{}, ErrNotFound
}

func (s *fakeStore) ListRegistryCredentials(_ context.Context, projectID string) ([]RegistryCredential, error) {
	var result []RegistryCredential
	for _, item := range s.registries {
		if item.ProjectID == projectID {
			result = append(result, item)
		}
	}
	return result, nil
}

func (s *fakeStore) CreateRegistryCredential(_ context.Context, item RegistryCredential) (RegistryCredential, error) {
	s.registries = append(s.registries, item)
	return item, nil
}

func (s *fakeStore) GetRegistryCredential(_ context.Context, projectID, credentialID string) (RegistryCredential, error) {
	for _, item := range s.registries {
		if item.ProjectID == projectID && item.ID == credentialID {
			return item, nil
		}
	}
	return RegistryCredential{}, ErrNotFound
}

func (s *fakeStore) ListEnvironments(_ context.Context, projectID string) ([]Environment, error) {
	var result []Environment
	for _, item := range s.environments {
		if item.ProjectID == projectID {
			result = append(result, item)
		}
	}
	return result, nil
}

func (s *fakeStore) CreateEnvironment(_ context.Context, item Environment) (Environment, error) {
	s.environments = append(s.environments, item)
	return item, nil
}

type fakeAudits struct {
	events []sharedaudit.Event
}

func (a *fakeAudits) Record(_ context.Context, event sharedaudit.Event) error {
	a.events = append(a.events, event)
	return nil
}

func (a *fakeAudits) List(_ context.Context, organizationID, projectID string, limit int64) ([]sharedaudit.Event, error) {
	var result []sharedaudit.Event
	for _, event := range a.events {
		if event.OrganizationID == organizationID && (projectID == "" || event.ProjectID == projectID) {
			result = append(result, event)
		}
	}
	if int64(len(result)) > limit {
		result = result[:limit]
	}
	return result, nil
}
