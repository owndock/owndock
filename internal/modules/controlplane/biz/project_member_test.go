package biz

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/shared/security"
	"github.com/owndock/owndock/internal/shared/transaction"
)

type projectMemberRepositoryStub struct {
	users   []OrganizationUser
	members []ProjectMember
}

func (s *projectMemberRepositoryStub) ListProjectIDsForUser(_ context.Context, organizationID, userID string) ([]string, error) {
	var result []string
	for _, member := range s.members {
		if member.OrganizationID == organizationID && member.UserID == userID {
			result = append(result, member.ProjectID)
		}
	}
	return result, nil
}

func (s *projectMemberRepositoryStub) ResolveProjectRole(_ context.Context, organizationID, projectID, userID string) (security.Role, error) {
	for _, member := range s.members {
		if member.OrganizationID == organizationID && member.ProjectID == projectID && member.UserID == userID {
			return member.Role, nil
		}
	}
	return "", ErrNotFound
}

func (s *projectMemberRepositoryStub) FindOrganizationUserByEmail(_ context.Context, organizationID, email string) (OrganizationUser, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	for _, user := range s.users {
		if user.OrganizationID == organizationID && user.Email == email {
			return user, nil
		}
	}
	return OrganizationUser{}, ErrNotFound
}

func (s *projectMemberRepositoryStub) ListProjectMembers(_ context.Context, projectID string) ([]ProjectMember, error) {
	var result []ProjectMember
	for _, member := range s.members {
		if member.ProjectID == projectID {
			result = append(result, member)
		}
	}
	return result, nil
}

func (s *projectMemberRepositoryStub) GetProjectMember(_ context.Context, projectID, userID string) (ProjectMember, error) {
	for _, member := range s.members {
		if member.ProjectID == projectID && member.UserID == userID {
			return member, nil
		}
	}
	return ProjectMember{}, ErrNotFound
}

func (s *projectMemberRepositoryStub) CreateProjectMember(_ context.Context, item ProjectMember) (ProjectMember, error) {
	if _, err := s.GetProjectMember(context.Background(), item.ProjectID, item.UserID); err == nil {
		return ProjectMember{}, ErrProjectMemberConflict
	}
	s.members = append(s.members, item)
	return item, nil
}

func (s *projectMemberRepositoryStub) UpdateProjectMember(_ context.Context, item ProjectMember, expectedVersion uint64) (ProjectMember, error) {
	for i, member := range s.members {
		if member.ProjectID == item.ProjectID && member.UserID == item.UserID {
			if member.Version != expectedVersion {
				return ProjectMember{}, ErrProjectMemberConflict
			}
			s.members[i] = item
			return item, nil
		}
	}
	return ProjectMember{}, ErrProjectMemberConflict
}

func (s *projectMemberRepositoryStub) DeleteProjectMember(_ context.Context, projectID, userID string, expectedVersion uint64) error {
	for i, member := range s.members {
		if member.ProjectID == projectID && member.UserID == userID {
			if member.Version != expectedVersion {
				return ErrProjectMemberConflict
			}
			s.members = append(s.members[:i], s.members[i+1:]...)
			return nil
		}
	}
	return ErrProjectMemberConflict
}

func TestProjectMemberLifecycleAndProjectFiltering(t *testing.T) {
	projectStore := &fakeStore{projects: []Project{
		{ID: "project-1", OrganizationID: "organization-1"},
		{ID: "project-2", OrganizationID: "organization-1"},
	}}
	members := &projectMemberRepositoryStub{users: []OrganizationUser{{
		ID: "user-1", OrganizationID: "organization-1", Email: "dev@example.com", Role: security.RoleViewer,
	}}}
	now := time.Unix(1_700_000_000, 0).UTC()
	useCase := NewUseCase(
		projectStore, projectStore, projectStore, projectStore,
		transaction.Passthrough{}, &fakeAudits{}, &fakeAudits{},
		func() (string, error) { return "audit-id", nil }, func() time.Time { return now },
	).WithProjectMembers(members)
	owner := security.Principal{
		UserID: "owner", OrganizationID: "organization-1", SessionID: "owner-session", Role: security.RoleOwner,
	}

	member, err := useCase.CreateProjectMember(
		context.Background(), owner, "project-1", "DEV@example.com", security.RoleDeveloper, "request-1",
	)
	if err != nil {
		t.Fatalf("CreateProjectMember() error = %v", err)
	}
	if member.Role != security.RoleDeveloper || member.Version != 1 {
		t.Fatalf("member = %#v", member)
	}
	viewerSession := security.Principal{
		UserID: "user-1", OrganizationID: "organization-1", SessionID: "user-session", Role: security.RoleViewer,
	}
	projects, err := useCase.ListProjects(context.Background(), viewerSession)
	if err != nil || len(projects) != 1 || projects[0].ID != "project-1" {
		t.Fatalf("ListProjects() = %#v, %v", projects, err)
	}

	member, err = useCase.UpdateProjectMember(
		context.Background(), owner, "project-1", "user-1", security.RoleMaintainer, 1, "request-2",
	)
	if err != nil || member.Role != security.RoleMaintainer || member.Version != 2 {
		t.Fatalf("UpdateProjectMember() = %#v, %v", member, err)
	}
	if _, err := useCase.UpdateProjectMember(
		context.Background(), owner, "project-1", "user-1", security.RoleViewer, 1, "stale",
	); !errors.Is(err, ErrProjectMemberConflict) {
		t.Fatalf("stale UpdateProjectMember() error = %v", err)
	}
	if err := useCase.DeleteProjectMember(
		context.Background(), owner, "project-1", "user-1", 2, "request-3",
	); err != nil {
		t.Fatalf("DeleteProjectMember() error = %v", err)
	}
	projects, err = useCase.ListProjects(context.Background(), viewerSession)
	if err != nil || len(projects) != 0 {
		t.Fatalf("projects after removal = %#v, %v", projects, err)
	}
}

func TestProjectMemberRejectsOwnerRowsAndSelfMutation(t *testing.T) {
	now := time.Now()
	if _, err := NewProjectMember("project", OrganizationUser{
		ID: "owner", OrganizationID: "organization", Email: "owner@example.com", Role: security.RoleOwner,
	}, security.RoleMaintainer, "owner", now); !errors.Is(err, ErrInvalidProjectMember) {
		t.Fatalf("NewProjectMember(owner) error = %v", err)
	}
	if _, err := NewProjectMember("project", OrganizationUser{
		ID: "user", OrganizationID: "organization", Email: "user@example.com", Role: security.RoleViewer,
	}, security.RoleOwner, "owner", now); !errors.Is(err, ErrInvalidProjectMember) {
		t.Fatalf("NewProjectMember(owner role) error = %v", err)
	}
}
