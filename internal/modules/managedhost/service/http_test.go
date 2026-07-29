package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/managedhost/biz"
	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/security"
	"github.com/owndock/owndock/internal/shared/transaction"
)

type repositoryStub struct {
	items []biz.ManagedHost
}

func (r *repositoryStub) List(context.Context, string) ([]biz.ManagedHost, error) {
	return r.items, nil
}

func (r *repositoryStub) Get(_ context.Context, organizationID, hostID string) (biz.ManagedHost, error) {
	for _, item := range r.items {
		if item.OrganizationID == organizationID && item.ID == hostID {
			return item, nil
		}
	}
	return biz.ManagedHost{}, biz.ErrNotFound
}

func (r *repositoryStub) Create(_ context.Context, item biz.ManagedHost) (biz.ManagedHost, error) {
	r.items = append(r.items, item)
	return item, nil
}

func (r *repositoryStub) Disable(
	_ context.Context,
	organizationID, hostID string,
	now time.Time,
) (biz.ManagedHost, error) {
	for index := range r.items {
		if r.items[index].OrganizationID == organizationID &&
			r.items[index].ID == hostID {
			r.items[index].Status = biz.StatusDisabled
			r.items[index].AgentBootID = ""
			r.items[index].AgentSessionID = ""
			r.items[index].UpdatedAt = now
			return r.items[index], nil
		}
	}
	return biz.ManagedHost{}, biz.ErrNotFound
}

func (r *repositoryStub) ConnectionMode(
	context.Context, string, string,
) (runtimeaccess.Mode, bool, error) {
	return "", false, nil
}

type auditStub struct{}

func (auditStub) Record(context.Context, sharedaudit.Event) error { return nil }

func authenticatedRequest(method, path, body string, role security.Role) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	principal := security.Principal{
		UserID: "user-1", OrganizationID: "organization-1",
		SessionID: "session-1", Role: role,
	}
	return request.WithContext(security.WithPrincipal(request.Context(), principal))
}

func TestManagedHostHTTPCreateAndGet(t *testing.T) {
	repository := &repositoryStub{}
	sequence := 0
	handler := NewHTTP(biz.NewUseCase(
		repository, transaction.Passthrough{}, auditStub{},
		func() (string, error) {
			sequence++
			if sequence == 1 {
				return "host-1", nil
			}
			return "audit-1", nil
		},
		func() time.Time { return time.Unix(100, 0) },
	))
	create := httptest.NewRecorder()
	handler.ServeHTTP(create, authenticatedRequest(
		http.MethodPost, "/api/v1/managed-hosts",
		`{"name":"Production Host","connection_mode":"direct","direct_ssh_ref":"secret://production-ssh"}`,
		security.RoleOwner,
	))
	if create.Code != http.StatusCreated ||
		!strings.Contains(create.Body.String(), `"connection_mode":"direct"`) {
		t.Fatalf("create = %d %s", create.Code, create.Body.String())
	}
	get := httptest.NewRecorder()
	handler.ServeHTTP(get, authenticatedRequest(
		http.MethodGet, "/api/v1/managed-hosts/host-1", "", security.RoleMaintainer,
	))
	if get.Code != http.StatusOK ||
		!strings.Contains(get.Body.String(), `"id":"host-1"`) {
		t.Fatalf("get = %d %s", get.Code, get.Body.String())
	}
	disable := httptest.NewRecorder()
	handler.ServeHTTP(disable, authenticatedRequest(
		http.MethodPost, "/api/v1/managed-hosts/host-1:disable", "", security.RoleOwner,
	))
	if disable.Code != http.StatusOK ||
		!strings.Contains(disable.Body.String(), `"status":"disabled"`) {
		t.Fatalf("disable = %d %s", disable.Code, disable.Body.String())
	}
}
