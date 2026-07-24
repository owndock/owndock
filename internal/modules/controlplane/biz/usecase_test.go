package biz

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
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
	)
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
		context.Background(), owner, project.ID, "production",
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

type fakeStore struct {
	projects     []Project
	applications []Application
	releases     []Release
	targets      []RuntimeTarget
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
