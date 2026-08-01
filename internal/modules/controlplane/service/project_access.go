package service

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/owndock/owndock/internal/modules/controlplane/biz"
	"github.com/owndock/owndock/internal/platform/httpx"
	"github.com/owndock/owndock/internal/shared/security"
)

type ProjectRoleResolver interface {
	ResolveProjectRole(context.Context, string, string, string) (security.Role, error)
}

// ProjectAccess resolves the current role for every authenticated project
// request. It intentionally does not cache membership in the Session so a
// role change or removal takes effect on the next request.
type ProjectAccess struct {
	roles ProjectRoleResolver
}

func NewProjectAccess(roles ProjectRoleResolver) *ProjectAccess {
	return &ProjectAccess{roles: roles}
}

func (a *ProjectAccess) Authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := security.PrincipalFromContext(r.Context())
		if !ok {
			w.Header().Set("WWW-Authenticate", "Bearer")
			httpx.ErrorRequest(w, r, http.StatusUnauthorized, "unauthenticated")
			return
		}
		projectID := requestProjectID(r)
		if projectID == "" || principal.Role == security.RoleOwner {
			next.ServeHTTP(w, r)
			return
		}
		if a == nil || a.roles == nil {
			httpx.ErrorRequest(w, r, http.StatusInternalServerError, "internal_error")
			return
		}
		role, err := a.roles.ResolveProjectRole(
			r.Context(), principal.OrganizationID, projectID, principal.UserID,
		)
		if errors.Is(err, biz.ErrNotFound) {
			httpx.ErrorRequest(w, r, http.StatusNotFound, "not_found")
			return
		}
		if err != nil {
			httpx.ErrorRequest(w, r, http.StatusInternalServerError, "internal_error")
			return
		}
		principal.Role = role
		next.ServeHTTP(w, r.WithContext(security.WithPrincipal(r.Context(), principal)))
	})
}

func requestProjectID(r *http.Request) string {
	segments := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(segments) >= 4 && segments[0] == "api" && segments[1] == "v1" &&
		segments[2] == "projects" {
		return strings.TrimSpace(segments[3])
	}
	if len(segments) == 3 && segments[0] == "api" && segments[1] == "v1" &&
		segments[2] == "audit-events" {
		return strings.TrimSpace(r.URL.Query().Get("project_id"))
	}
	return ""
}
