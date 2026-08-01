package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/owndock/owndock/internal/modules/controlplane/biz"
	"github.com/owndock/owndock/internal/shared/security"
)

type projectRoleResolverStub struct {
	role  security.Role
	err   error
	calls int
}

func (s *projectRoleResolverStub) ResolveProjectRole(
	context.Context, string, string, string,
) (security.Role, error) {
	s.calls++
	return s.role, s.err
}

func TestProjectAccessResolvesRoleOnEveryProjectRequest(t *testing.T) {
	resolver := &projectRoleResolverStub{role: security.RoleDeveloper}
	access := NewProjectAccess(resolver)
	called := 0
	handler := access.Authorize(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		principal, ok := security.PrincipalFromContext(r.Context())
		if !ok || principal.Role != security.RoleDeveloper {
			t.Fatalf("principal = %#v, ok = %v", principal, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "/api/v1/projects/project-1/builds", nil)
	request = request.WithContext(security.WithPrincipal(request.Context(), security.Principal{
		UserID: "user-1", OrganizationID: "organization-1", SessionID: "session-1", Role: security.RoleViewer,
	}))

	handler.ServeHTTP(httptest.NewRecorder(), request)
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if called != 2 || resolver.calls != 2 {
		t.Fatalf("called = %d, resolver calls = %d", called, resolver.calls)
	}
}

func TestProjectAccessHidesMissingMembership(t *testing.T) {
	resolver := &projectRoleResolverStub{err: biz.ErrNotFound}
	handler := NewProjectAccess(resolver).Authorize(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("protected handler must not be called")
	}))
	request := httptest.NewRequest(http.MethodGet, "/api/v1/projects/project-1/deployments", nil)
	request = request.WithContext(security.WithPrincipal(request.Context(), security.Principal{
		UserID: "user-1", OrganizationID: "organization-1", SessionID: "session-1", Role: security.RoleViewer,
	}))
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound || resolver.calls != 1 {
		t.Fatalf("status = %d, calls = %d, body = %s", recorder.Code, resolver.calls, recorder.Body.String())
	}
}

func TestProjectAccessOwnerAndUnscopedRoutesBypassMembership(t *testing.T) {
	resolver := &projectRoleResolverStub{err: errors.New("must not be called")}
	handler := NewProjectAccess(resolver).Authorize(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	principal := security.Principal{
		UserID: "owner", OrganizationID: "organization-1", SessionID: "session-1", Role: security.RoleOwner,
	}
	for _, path := range []string{"/api/v1/projects/project-1/builds", "/api/v1/projects"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request = request.WithContext(security.WithPrincipal(request.Context(), principal))
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusNoContent {
			t.Fatalf("%s status = %d", path, recorder.Code)
		}
	}
	if resolver.calls != 0 {
		t.Fatalf("resolver calls = %d", resolver.calls)
	}
}
