package biz

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/registryauth"
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

type runtimeTargetRetirerProbe struct {
	err    error
	calls  int
	onCall func()
}

func (p *runtimeTargetRetirerProbe) RetireRuntimeTarget(
	context.Context,
	RuntimeTarget,
	security.Principal,
	string,
) error {
	p.calls++
	if p.onCall != nil {
		p.onCall()
	}
	return p.err
}

func TestDeleteRuntimeTargetFencesAndBackgroundContinuationCompletes(t *testing.T) {
	store := &fakeStore{
		projects: []Project{{ID: "project-1", OrganizationID: "organization-1"}},
		targets: []RuntimeTarget{{
			ID: "target-1", ProjectID: "project-1", Name: "production",
			ManagedHostID: "host-1", ConnectionMode: runtimeaccess.ModeAgent,
			Status: RuntimeTargetStatusReady,
		}},
	}
	audits := &fakeAudits{}
	retirer := &runtimeTargetRetirerProbe{err: ErrRuntimeTargetRetirementPending}
	ids := 0
	useCase := NewUseCase(
		store, store, store, store, transaction.Passthrough{}, audits, audits,
		func() (string, error) {
			ids++
			return fmt.Sprintf("id-%d", ids), nil
		},
		func() time.Time { return time.Unix(int64(100+ids), 0) },
	).WithRuntimeTargetRetirement(store, retirer)
	principal := security.Principal{
		UserID: "owner-1", OrganizationID: "organization-1",
		SessionID: "session-1", Role: security.RoleOwner,
	}
	completed, err := useCase.DeleteRuntimeTarget(
		t.Context(), principal, "project-1", "target-1", "request-1",
	)
	if err != nil || completed || store.targets[0].Status != RuntimeTargetStatusRetiring {
		t.Fatalf("first delete = %v/%v, target = %+v", completed, err, store.targets)
	}
	if retirement := store.targets[0].Retirement; retirement == nil ||
		retirement.OrganizationID != principal.OrganizationID ||
		retirement.ActorID != principal.UserID ||
		retirement.RequestID != "request-1" {
		t.Fatalf("retirement metadata = %+v", retirement)
	}
	retirer.err = nil
	processed, err := useCase.ContinueRuntimeTargetRetirements(t.Context(), 10)
	if err != nil || processed != 1 || len(store.targets) != 0 || retirer.calls != 2 {
		t.Fatalf("continuation = %d/%v, targets = %+v calls = %d", processed, err, store.targets, retirer.calls)
	}
	if len(audits.events) != 2 ||
		audits.events[0].Action != "runtime_target.retirement_started" ||
		audits.events[1].Action != "runtime_target.delete" {
		t.Fatalf("audit events = %+v", audits.events)
	}
}

func TestDeleteRuntimeTargetRequiresLifecyclePermissionAndProject(t *testing.T) {
	store := &fakeStore{}
	audits := &fakeAudits{}
	newUseCase := func() *UseCase {
		return NewUseCase(
			store, store, store, store, transaction.Passthrough{}, audits, audits,
			func() (string, error) { return "id-1", nil }, time.Now,
		)
	}
	owner := security.Principal{
		UserID: "owner-1", OrganizationID: "organization-1",
		SessionID: "session-1", Role: security.RoleOwner,
	}
	if _, err := newUseCase().DeleteRuntimeTarget(
		t.Context(), owner, "project-1", "target-1", "request-1",
	); err != ErrRuntimeTargetRetirementUnavailable {
		t.Fatalf("missing lifecycle error = %v", err)
	}
	if _, err := newUseCase().ContinueRuntimeTargetRetirements(
		t.Context(), 1,
	); err != ErrRuntimeTargetRetirementUnavailable {
		t.Fatalf("missing continuation lifecycle error = %v", err)
	}
	configured := newUseCase().WithRuntimeTargetRetirement(
		store, &runtimeTargetRetirerProbe{},
	)
	viewer := owner
	viewer.Role = security.RoleViewer
	if _, err := configured.DeleteRuntimeTarget(
		t.Context(), viewer, "project-1", "target-1", "request-1",
	); err != security.ErrForbidden {
		t.Fatalf("viewer error = %v", err)
	}
	if _, err := configured.DeleteRuntimeTarget(
		t.Context(), owner, "project-1", "target-1", "request-1",
	); err != ErrNotFound {
		t.Fatalf("missing project error = %v", err)
	}
}

func TestContinueRuntimeTargetRetirementsValidatesDurableMetadata(t *testing.T) {
	store := &fakeStore{targets: []RuntimeTarget{{
		ID: "target-1", ProjectID: "project-1",
		Status: RuntimeTargetStatusRetiring,
	}}}
	retirer := &runtimeTargetRetirerProbe{}
	useCase := NewUseCase(
		store, store, store, store, transaction.Passthrough{},
		&fakeAudits{}, &fakeAudits{},
		func() (string, error) { return "audit-1", nil }, time.Now,
	).WithRuntimeTargetRetirement(store, retirer)
	if _, err := useCase.ContinueRuntimeTargetRetirements(
		t.Context(), 0,
	); err == nil {
		t.Fatal("invalid batch size was accepted")
	}
	processed, err := useCase.ContinueRuntimeTargetRetirements(t.Context(), 1)
	if !errors.Is(err, ErrRuntimeTargetRetirementUnavailable) ||
		processed != 0 || retirer.calls != 0 {
		t.Fatalf("continuation = %d/%v, retirer calls = %d", processed, err, retirer.calls)
	}
}

func TestContinueRuntimeTargetRetirementToleratesConcurrentCompletion(t *testing.T) {
	retirement := RuntimeTargetRetirement{
		OrganizationID: "organization-1", ActorID: "owner-1",
		RequestID: "request-1", StartedAt: time.Unix(100, 0),
	}
	store := &fakeStore{targets: []RuntimeTarget{{
		ID: "target-1", ProjectID: "project-1",
		Status: RuntimeTargetStatusRetiring, Retirement: &retirement,
	}}}
	retirer := &runtimeTargetRetirerProbe{
		onCall: func() { store.targets = nil },
	}
	useCase := NewUseCase(
		store, store, store, store, transaction.Passthrough{},
		&fakeAudits{}, &fakeAudits{},
		func() (string, error) { return "audit-1", nil }, time.Now,
	).WithRuntimeTargetRetirement(store, retirer)
	processed, err := useCase.ContinueRuntimeTargetRetirements(t.Context(), 1)
	if err != nil || processed != 1 {
		t.Fatalf("continuation = %d/%v", processed, err)
	}
}

type templateCatalogStub struct {
	item Template
}

func (s templateCatalogStub) ListTemplates(context.Context) ([]Template, error) {
	return []Template{s.item}, nil
}

func (s templateCatalogStub) GetTemplate(
	_ context.Context,
	id string,
) (Template, error) {
	if id != s.item.ID {
		return Template{}, ErrNotFound
	}
	return s.item, nil
}

func TestCreateApplicationFromTemplatePersistsAuditableSnapshot(t *testing.T) {
	store := &fakeStore{}
	audits := &fakeAudits{}
	sequence := 0
	template := Template{
		ID: "http-service", Version: 1,
		Name: LocalizedText{
			English: "HTTP service", SimplifiedChinese: "HTTP 服务",
		},
		Description: LocalizedText{
			English: "Web service", SimplifiedChinese: "Web 服务",
		},
		Preset: TemplatePreset{
			DockerfilePath: "Dockerfile", ContextPath: ".",
			RuntimeSpec: runtimespec.Spec{Ports: []runtimespec.Port{{
				Name: "http", ContainerPort: 8080,
			}}},
		},
	}
	useCase := NewUseCase(
		store, store, store, store,
		transaction.Passthrough{}, audits, audits,
		func() (string, error) {
			sequence++
			return fmt.Sprintf("id-%d", sequence), nil
		},
		func() time.Time { return time.Unix(100, 0) },
	).WithTemplates(templateCatalogStub{item: template})
	owner := security.Principal{
		UserID: "owner", OrganizationID: "organization",
		SessionID: "session", Role: security.RoleOwner,
	}
	project, err := useCase.CreateProject(
		t.Context(), owner, "Delivery", "request-project",
	)
	if err != nil {
		t.Fatal(err)
	}
	item, err := useCase.CreateApplicationFromTemplate(
		t.Context(), owner, project.ID, "API", template.ID, "request-app",
	)
	if err != nil {
		t.Fatal(err)
	}
	template.Preset.RuntimeSpec.Ports[0].ContainerPort = 9090
	if item.TemplateSnapshot == nil ||
		item.TemplateSnapshot.TemplateID != "http-service" ||
		item.TemplateSnapshot.RuntimeSpec.Ports[0].ContainerPort != 8080 ||
		len(audits.events) != 2 ||
		audits.events[1].Action != "application.create_from_template" {
		t.Fatalf("application = %+v, audits = %+v", item, audits.events)
	}
	if _, err := useCase.CreateApplicationFromTemplate(
		t.Context(), owner, project.ID, "Missing", "missing", "request-missing",
	); err != ErrNotFound {
		t.Fatalf("missing template error = %v", err)
	}
}

func TestTemplateCatalogRequiresIdentityAndConfiguredCatalog(t *testing.T) {
	template := Template{
		ID: "worker", Version: 1,
		Name: LocalizedText{English: "Worker", SimplifiedChinese: "任务"},
		Description: LocalizedText{
			English: "Background worker", SimplifiedChinese: "后台任务",
		},
		Preset: TemplatePreset{
			DockerfilePath: "Dockerfile", ContextPath: ".",
		},
	}
	store := &fakeStore{}
	useCase := NewUseCase(
		store, store, store, store,
		transaction.Passthrough{}, &fakeAudits{}, &fakeAudits{},
		func() (string, error) { return "id", nil }, time.Now,
	)
	viewer := security.Principal{
		UserID: "viewer", OrganizationID: "organization",
		SessionID: "session", Role: security.RoleViewer,
	}
	if _, err := useCase.ListTemplates(t.Context(), viewer); err != ErrInvalidTemplate {
		t.Fatalf("missing catalog error = %v", err)
	}
	useCase.WithTemplates(templateCatalogStub{item: template})
	items, err := useCase.ListTemplates(t.Context(), viewer)
	if err != nil || len(items) != 1 {
		t.Fatalf("templates = %+v, error = %v", items, err)
	}
	if _, err := useCase.GetTemplate(
		t.Context(), security.Principal{}, template.ID,
	); err != security.ErrUnauthenticated {
		t.Fatalf("unauthenticated template error = %v", err)
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
		registryauth.ModeBasic, "robot", "secret://registry-password", "request-registry",
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

func TestCreateReleaseFromArtifactIsIdempotent(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	store := &fakeStore{
		projects:     []Project{{ID: "project-1", OrganizationID: "organization-1"}},
		applications: []Application{{ID: "application-1", ProjectID: "project-1"}},
		registries: []RegistryCredential{{
			ID: "registry-1", ProjectID: "project-1", Server: "registry.example.com",
			AuthenticationMode: registryauth.ModeBasic,
		}},
	}
	audits := &fakeAudits{}
	sequence := 0
	useCase := NewUseCaseWithResources(
		store, store, store, store, store, store,
		transaction.Passthrough{}, audits, audits,
		func() (string, error) { sequence++; return fmt.Sprintf("id-%d", sequence), nil },
		func() time.Time { return now },
	).WithArtifactReleases(store)
	input := ArtifactReleaseInput{
		ArtifactID: "artifact-1", OrganizationID: "organization-1",
		ProjectID: "project-1", ApplicationID: "application-1",
		RegistryCredentialID: "registry-1",
		ImageDigest:          "registry.example.com/team/api@sha256:" + strings.Repeat("a", 64),
		ActorID:              "system:build-worker", RequestID: "request-1",
	}
	first, err := useCase.CreateReleaseFromArtifact(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := useCase.CreateReleaseFromArtifact(t.Context(), input)
	if err != nil || second.ID != first.ID || len(store.releases) != 1 ||
		first.SourceArtifactID != input.ArtifactID || len(audits.events) != 1 {
		t.Fatalf("first=%+v second=%+v releases=%d audits=%d err=%v", first, second, len(store.releases), len(audits.events), err)
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

func (s *fakeStore) GetReleaseByArtifact(_ context.Context, projectID, artifactID string) (Release, error) {
	for _, item := range s.releases {
		if item.ProjectID == projectID && item.SourceArtifactID == artifactID {
			return item, nil
		}
	}
	return Release{}, ErrNotFound
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

func (s *fakeStore) BeginRuntimeTargetRetirement(
	_ context.Context,
	projectID, targetID string,
	retirement RuntimeTargetRetirement,
) (RuntimeTarget, bool, error) {
	for index := range s.targets {
		if s.targets[index].ProjectID == projectID && s.targets[index].ID == targetID {
			changed := s.targets[index].Status != RuntimeTargetStatusRetiring
			s.targets[index].Status = RuntimeTargetStatusRetiring
			if changed {
				s.targets[index].Retirement = &retirement
			}
			return s.targets[index], changed, nil
		}
	}
	return RuntimeTarget{}, false, ErrNotFound
}

func (s *fakeStore) ListRetiringRuntimeTargets(
	_ context.Context,
	limit int64,
) ([]RuntimeTarget, error) {
	result := make([]RuntimeTarget, 0, limit)
	for _, item := range s.targets {
		if item.Status == RuntimeTargetStatusRetiring {
			result = append(result, item)
			if int64(len(result)) == limit {
				break
			}
		}
	}
	return result, nil
}

func (s *fakeStore) DeleteRetiringRuntimeTarget(
	_ context.Context,
	projectID, targetID string,
) error {
	for index := range s.targets {
		if s.targets[index].ProjectID == projectID && s.targets[index].ID == targetID &&
			s.targets[index].Status == RuntimeTargetStatusRetiring {
			s.targets = append(s.targets[:index], s.targets[index+1:]...)
			return nil
		}
	}
	return ErrNotFound
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
