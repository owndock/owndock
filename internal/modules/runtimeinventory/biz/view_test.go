package biz

import (
	"context"
	"errors"
	"testing"
	"time"

	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/security"
)

type viewRepositoryStub struct {
	projectOrganizationID string
	projectID             string
	hostOrganizationID    string
	hostID                string
	query                 ViewQuery
	page                  StatePage
	err                   error
}

func (r *viewRepositoryStub) ListProject(
	_ context.Context, organizationID, projectID string, query ViewQuery,
) (StatePage, error) {
	r.projectOrganizationID, r.projectID, r.query = organizationID, projectID, query
	return r.page, r.err
}

func (r *viewRepositoryStub) ListHost(
	_ context.Context, organizationID, hostID string, query ViewQuery,
) (StatePage, error) {
	r.hostOrganizationID, r.hostID, r.query = organizationID, hostID, query
	return r.page, r.err
}

type viewAuditStub struct {
	event sharedaudit.Event
	err   error
}

func (a *viewAuditStub) Record(_ context.Context, event sharedaudit.Event) error {
	a.event = event
	return a.err
}

func TestViewUseCaseScopesAndAuditsReads(t *testing.T) {
	now := time.Date(2026, 7, 31, 10, 0, 0, 0, time.UTC)
	repository := &viewRepositoryStub{page: StatePage{NextCursor: "next"}}
	audit := &viewAuditStub{}
	useCase, err := NewViewUseCase(
		repository, audit, func() (string, error) { return "audit-1", nil }, func() time.Time { return now },
	)
	if err != nil {
		t.Fatalf("NewViewUseCase() error = %v", err)
	}
	principal := security.Principal{
		UserID: "user-1", OrganizationID: "organization-1",
		SessionID: "session-1", Role: security.RoleViewer,
	}
	page, err := useCase.ListProject(
		context.Background(), principal, "project-1", ViewQuery{}, "request-1",
	)
	if err != nil {
		t.Fatalf("ListProject() error = %v", err)
	}
	if page.NextCursor != "next" || repository.projectOrganizationID != "organization-1" ||
		repository.projectID != "project-1" || repository.query.Limit != DefaultPageSize {
		t.Fatalf("project query = %+v, page = %+v", repository, page)
	}
	if audit.event.Action != "runtime_inventory.project.list" ||
		audit.event.ProjectID != "project-1" || audit.event.RequestID != "request-1" {
		t.Fatalf("project audit = %+v", audit.event)
	}

	principal.Role = security.RoleMaintainer
	_, err = useCase.ListHost(
		context.Background(), principal, "host-1", ViewQuery{Limit: 2}, "request-2",
	)
	if err != nil {
		t.Fatalf("ListHost() error = %v", err)
	}
	if repository.hostOrganizationID != "organization-1" || repository.hostID != "host-1" ||
		audit.event.Action != "runtime_inventory.host.list" || audit.event.ResourceID != "host-1" {
		t.Fatalf("host query = %+v, audit = %+v", repository, audit.event)
	}
}

func TestViewUseCaseSeparatesHostPermissionAndFailsClosedOnAudit(t *testing.T) {
	repository := &viewRepositoryStub{}
	audit := &viewAuditStub{err: errors.New("audit unavailable")}
	useCase, err := NewViewUseCase(
		repository, audit, func() (string, error) { return "audit-1", nil }, time.Now,
	)
	if err != nil {
		t.Fatalf("NewViewUseCase() error = %v", err)
	}
	developer := security.Principal{
		UserID: "user-1", OrganizationID: "organization-1",
		SessionID: "session-1", Role: security.RoleDeveloper,
	}
	if _, err := useCase.ListHost(
		context.Background(), developer, "host-1", ViewQuery{}, "",
	); !errors.Is(err, security.ErrForbidden) {
		t.Fatalf("ListHost() error = %v, want forbidden", err)
	}
	if _, err := useCase.ListProject(
		context.Background(), developer, "project-1", ViewQuery{}, "",
	); err == nil || errors.Is(err, security.ErrForbidden) {
		t.Fatalf("ListProject() error = %v, want audit failure", err)
	}
}

func TestViewQueryRejectsUnboundedOrMalformedInput(t *testing.T) {
	for _, query := range []ViewQuery{
		{Limit: MaximumPageSize + 1},
		{Limit: 1, Kind: "secret"},
		{Limit: 1, RuntimeTargetID: " invalid "},
		{Limit: 1, Cursor: " cursor "},
	} {
		if !errors.Is(query.Validate(), ErrInvalidViewQuery) {
			t.Errorf("Validate(%+v) did not reject query", query)
		}
	}
}
