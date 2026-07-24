package service

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/modules/controlplane/biz"
	"github.com/owndock/owndock/internal/platform/httpx"
	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/security"
)

type HTTP struct {
	useCase *biz.UseCase
}

func NewHTTP(useCase *biz.UseCase) *HTTP {
	return &HTTP{useCase: useCase}
}

func (s *HTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.Handle(w, r)
}

func (s *HTTP) Handle(w http.ResponseWriter, r *http.Request) {
	principal, ok := security.PrincipalFromContext(r.Context())
	if !ok {
		writeError(w, r, security.ErrUnauthenticated)
		return
	}
	segments := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(segments) == 3 && segments[0] == "api" && segments[1] == "v1" && segments[2] == "projects" {
		s.projects(w, r, principal)
		return
	}
	if len(segments) == 3 && segments[0] == "api" && segments[1] == "v1" && segments[2] == "audit-events" {
		s.auditEvents(w, r, principal)
		return
	}
	if len(segments) >= 5 && segments[0] == "api" && segments[1] == "v1" && segments[2] == "projects" {
		projectID := segments[3]
		switch {
		case len(segments) == 5 && segments[4] == "applications":
			s.applications(w, r, principal, projectID)
			return
		case len(segments) == 7 && segments[4] == "applications" && segments[6] == "releases":
			s.releases(w, r, principal, projectID, segments[5])
			return
		case len(segments) == 5 && segments[4] == "runtime-targets":
			s.runtimeTargets(w, r, principal, projectID)
			return
		}
	}
	httpx.ErrorRequest(w, r, http.StatusNotFound, "not_found")
}

func (s *HTTP) projects(w http.ResponseWriter, r *http.Request, principal security.Principal) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.useCase.ListProjects(r.Context(), principal)
		if writeError(w, r, err) {
			return
		}
		responses := make([]projectResponse, len(items))
		for i, item := range items {
			responses[i] = projectResponseFromDomain(item)
		}
		httpx.JSON(w, http.StatusOK, map[string]any{"items": responses})
	case http.MethodPost:
		var request struct {
			Name string `json:"name"`
		}
		if !decodeRequest(w, r, &request) {
			return
		}
		item, err := s.useCase.CreateProject(
			r.Context(), principal, request.Name, httpx.RequestIDFromContext(r.Context()),
		)
		if writeError(w, r, err) {
			return
		}
		httpx.JSON(w, http.StatusCreated, projectResponseFromDomain(item))
	default:
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func (s *HTTP) applications(
	w http.ResponseWriter,
	r *http.Request,
	principal security.Principal,
	projectID string,
) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.useCase.ListApplications(r.Context(), principal, projectID)
		if writeError(w, r, err) {
			return
		}
		responses := make([]applicationResponse, len(items))
		for i, item := range items {
			responses[i] = applicationResponseFromDomain(item)
		}
		httpx.JSON(w, http.StatusOK, map[string]any{"items": responses})
	case http.MethodPost:
		var request struct {
			Name string `json:"name"`
		}
		if !decodeRequest(w, r, &request) {
			return
		}
		item, err := s.useCase.CreateApplication(
			r.Context(), principal, projectID, request.Name, httpx.RequestIDFromContext(r.Context()),
		)
		if writeError(w, r, err) {
			return
		}
		httpx.JSON(w, http.StatusCreated, applicationResponseFromDomain(item))
	default:
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func (s *HTTP) releases(
	w http.ResponseWriter,
	r *http.Request,
	principal security.Principal,
	projectID, applicationID string,
) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.useCase.ListReleases(r.Context(), principal, projectID, applicationID)
		if writeError(w, r, err) {
			return
		}
		responses := make([]releaseResponse, len(items))
		for i, item := range items {
			responses[i] = releaseResponseFromDomain(item)
		}
		httpx.JSON(w, http.StatusOK, map[string]any{"items": responses})
	case http.MethodPost:
		var request struct {
			Image string `json:"image"`
		}
		if !decodeRequest(w, r, &request) {
			return
		}
		item, err := s.useCase.CreateRelease(
			r.Context(), principal, projectID, applicationID, request.Image,
			httpx.RequestIDFromContext(r.Context()),
		)
		if writeError(w, r, err) {
			return
		}
		httpx.JSON(w, http.StatusCreated, releaseResponseFromDomain(item))
	default:
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func (s *HTTP) runtimeTargets(
	w http.ResponseWriter,
	r *http.Request,
	principal security.Principal,
	projectID string,
) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.useCase.ListRuntimeTargets(r.Context(), principal, projectID)
		if writeError(w, r, err) {
			return
		}
		responses := make([]runtimeTargetResponse, len(items))
		for i, item := range items {
			responses[i] = runtimeTargetResponseFromDomain(item)
		}
		httpx.JSON(w, http.StatusOK, map[string]any{"items": responses})
	case http.MethodPost:
		var request struct {
			Name          string `json:"name"`
			Endpoint      string `json:"endpoint"`
			TLSServerName string `json:"tls_server_name"`
			CredentialRef string `json:"credential_ref"`
		}
		if !decodeRequest(w, r, &request) {
			return
		}
		item, err := s.useCase.CreateRuntimeTarget(
			r.Context(), principal, projectID,
			request.Name, request.Endpoint, request.TLSServerName, request.CredentialRef,
			httpx.RequestIDFromContext(r.Context()),
		)
		if writeError(w, r, err) {
			return
		}
		httpx.JSON(w, http.StatusCreated, runtimeTargetResponseFromDomain(item))
	default:
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func (s *HTTP) auditEvents(w http.ResponseWriter, r *http.Request, principal security.Principal) {
	if r.Method != http.MethodGet {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	var limit int64 = 100
	if rawLimit := r.URL.Query().Get("limit"); rawLimit != "" {
		parsed, err := strconv.ParseInt(rawLimit, 10, 64)
		if err != nil || parsed < 1 || parsed > 100 {
			httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_limit")
			return
		}
		limit = parsed
	}
	items, err := s.useCase.ListAuditEvents(r.Context(), principal, r.URL.Query().Get("project_id"), limit)
	if writeError(w, r, err) {
		return
	}
	responses := make([]auditResponse, len(items))
	for i, item := range items {
		responses[i] = auditResponseFromDomain(item)
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": responses})
}

func decodeRequest(w http.ResponseWriter, r *http.Request, target any) bool {
	if err := httpx.DecodeJSON(w, r, target); errors.Is(err, httpx.ErrUnsupportedMediaType) {
		httpx.ErrorRequest(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return false
	} else if err != nil {
		httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_json")
		return false
	}
	return true
}

func writeError(w http.ResponseWriter, r *http.Request, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, security.ErrUnauthenticated):
		w.Header().Set("WWW-Authenticate", "Bearer")
		httpx.ErrorRequest(w, r, http.StatusUnauthorized, "unauthenticated")
	case errors.Is(err, security.ErrForbidden):
		httpx.ErrorRequest(w, r, http.StatusForbidden, "forbidden")
	case errors.Is(err, biz.ErrNotFound):
		httpx.ErrorRequest(w, r, http.StatusNotFound, "not_found")
	case errors.Is(err, biz.ErrDuplicateName):
		httpx.ErrorRequest(w, r, http.StatusConflict, "name_conflict")
	case errors.Is(err, biz.ErrDuplicateRelease):
		httpx.ErrorRequest(w, r, http.StatusConflict, "release_conflict")
	case errors.Is(err, biz.ErrInvalidImage):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_image")
	case errors.Is(err, biz.ErrInvalidRuntimeTarget):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_runtime_target")
	case errors.Is(err, biz.ErrInvalidName):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_name")
	default:
		httpx.ErrorRequest(w, r, http.StatusInternalServerError, "internal_error")
	}
	return true
}

type projectResponse struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	Name           string    `json:"name"`
	CreatedBy      string    `json:"created_by"`
	CreatedAt      time.Time `json:"created_at"`
}

func projectResponseFromDomain(item biz.Project) projectResponse {
	return projectResponse{
		ID: item.ID, OrganizationID: item.OrganizationID, Name: item.Name,
		CreatedBy: item.CreatedBy, CreatedAt: item.CreatedAt,
	}
}

type applicationResponse struct {
	ID        string    `json:"id"`
	ProjectID string    `json:"project_id"`
	Name      string    `json:"name"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

func applicationResponseFromDomain(item biz.Application) applicationResponse {
	return applicationResponse{
		ID: item.ID, ProjectID: item.ProjectID, Name: item.Name,
		CreatedBy: item.CreatedBy, CreatedAt: item.CreatedAt,
	}
}

type releaseResponse struct {
	ID            string    `json:"id"`
	ProjectID     string    `json:"project_id"`
	ApplicationID string    `json:"application_id"`
	ImageDigest   string    `json:"image_digest"`
	CreatedBy     string    `json:"created_by"`
	CreatedAt     time.Time `json:"created_at"`
}

func releaseResponseFromDomain(item biz.Release) releaseResponse {
	return releaseResponse{
		ID: item.ID, ProjectID: item.ProjectID, ApplicationID: item.ApplicationID,
		ImageDigest: item.ImageDigest, CreatedBy: item.CreatedBy, CreatedAt: item.CreatedAt,
	}
}

type runtimeTargetResponse struct {
	ID            string                  `json:"id"`
	ProjectID     string                  `json:"project_id"`
	Name          string                  `json:"name"`
	Endpoint      string                  `json:"endpoint"`
	TLSServerName string                  `json:"tls_server_name"`
	CredentialRef string                  `json:"credential_ref"`
	Status        biz.RuntimeTargetStatus `json:"status"`
	CreatedBy     string                  `json:"created_by"`
	CreatedAt     time.Time               `json:"created_at"`
}

func runtimeTargetResponseFromDomain(item biz.RuntimeTarget) runtimeTargetResponse {
	return runtimeTargetResponse{
		ID: item.ID, ProjectID: item.ProjectID, Name: item.Name, Endpoint: item.Endpoint,
		TLSServerName: item.TLSServerName, CredentialRef: item.CredentialRef,
		Status: item.Status, CreatedBy: item.CreatedBy, CreatedAt: item.CreatedAt,
	}
}

type auditResponse struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	ProjectID      string    `json:"project_id,omitempty"`
	ActorID        string    `json:"actor_id"`
	Action         string    `json:"action"`
	ResourceType   string    `json:"resource_type"`
	ResourceID     string    `json:"resource_id"`
	RequestID      string    `json:"request_id,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

func auditResponseFromDomain(item sharedaudit.Event) auditResponse {
	return auditResponse{
		ID: item.ID, OrganizationID: item.OrganizationID, ProjectID: item.ProjectID,
		ActorID: item.ActorID, Action: item.Action, ResourceType: item.ResourceType,
		ResourceID: item.ResourceID, RequestID: item.RequestID, CreatedAt: item.CreatedAt,
	}
}
