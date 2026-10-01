package service

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/modules/applicationroute/biz"
	"github.com/owndock/owndock/internal/platform/httpx"
	"github.com/owndock/owndock/internal/shared/security"
)

type HTTP struct {
	useCase *biz.UseCase
}

func NewHTTP(useCase *biz.UseCase) *HTTP { return &HTTP{useCase: useCase} }

type routeRequest struct {
	ApplicationID   string      `json:"application_id"`
	EnvironmentID   string      `json:"environment_id"`
	RuntimeTargetID string      `json:"runtime_target_id"`
	Hostname        string      `json:"hostname"`
	PortName        string      `json:"port_name"`
	TLSMode         biz.TLSMode `json:"tls_mode"`
	ExpectedVersion uint64      `json:"expected_version,omitempty"`
}

type routeResponse struct {
	ID              string               `json:"id"`
	OrganizationID  string               `json:"organization_id"`
	ProjectID       string               `json:"project_id"`
	ApplicationID   string               `json:"application_id"`
	EnvironmentID   string               `json:"environment_id"`
	RuntimeTargetID string               `json:"runtime_target_id"`
	Hostname        string               `json:"hostname"`
	PortName        string               `json:"port_name"`
	TLSMode         biz.TLSMode          `json:"tls_mode"`
	Status          biz.Status           `json:"status"`
	Revision        uint64               `json:"revision"`
	Version         uint64               `json:"version"`
	Observation     *observationResponse `json:"observation,omitempty"`
	CreatedBy       string               `json:"created_by"`
	UpdatedBy       string               `json:"updated_by"`
	CreatedAt       time.Time            `json:"created_at"`
	UpdatedAt       time.Time            `json:"updated_at"`
}

type observationResponse struct {
	Revision          uint64                `json:"revision"`
	DeploymentID      string                `json:"deployment_id"`
	CutoverSequence   uint64                `json:"cutover_sequence"`
	ConfigDigest      string                `json:"config_digest"`
	CertificateStatus biz.CertificateStatus `json:"certificate_status"`
	ObservedAt        time.Time             `json:"observed_at"`
}

func observationResponseFromDomain(value *biz.Observation) *observationResponse {
	if value == nil {
		return nil
	}
	return &observationResponse{Revision: value.Revision, DeploymentID: value.DeploymentID,
		CutoverSequence: value.CutoverSequence, ConfigDigest: value.ConfigDigest,
		CertificateStatus: value.CertificateStatus, ObservedAt: value.ObservedAt}
}

func responseFromDomain(item biz.ApplicationRoute) routeResponse {
	return routeResponse{ID: item.ID, OrganizationID: item.OrganizationID, ProjectID: item.ProjectID,
		ApplicationID: item.ApplicationID, EnvironmentID: item.EnvironmentID,
		RuntimeTargetID: item.RuntimeTargetID, Hostname: item.Hostname, PortName: item.PortName,
		TLSMode: item.TLSMode, Status: item.Status, Revision: item.Revision, Version: item.Version,
		Observation: observationResponseFromDomain(item.Observation),
		CreatedBy:   item.CreatedBy, UpdatedBy: item.UpdatedBy,
		CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt}
}

func inputFromRequest(request routeRequest) biz.Input {
	return biz.Input{ApplicationID: request.ApplicationID, EnvironmentID: request.EnvironmentID,
		RuntimeTargetID: request.RuntimeTargetID, Hostname: request.Hostname,
		PortName: request.PortName, TLSMode: request.TLSMode}
}

func (s *HTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	principal, ok := security.PrincipalFromContext(r.Context())
	if !ok {
		writeError(w, r, security.ErrUnauthenticated)
		return
	}
	segments := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(segments) < 5 || len(segments) > 6 || segments[0] != "api" || segments[1] != "v1" ||
		segments[2] != "projects" || segments[3] == "" || segments[4] != "application-routes" {
		httpx.ErrorRequest(w, r, http.StatusNotFound, "not_found")
		return
	}
	if len(r.URL.Query()) != 0 {
		httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_application_route")
		return
	}
	if len(segments) == 5 {
		s.collection(w, r, principal, segments[3])
		return
	}
	if segments[5] == "" {
		httpx.ErrorRequest(w, r, http.StatusNotFound, "not_found")
		return
	}
	s.item(w, r, principal, segments[3], segments[5])
}

func (s *HTTP) collection(w http.ResponseWriter, r *http.Request, principal security.Principal, projectID string) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.useCase.List(r.Context(), principal, projectID)
		if writeError(w, r, err) {
			return
		}
		responses := make([]routeResponse, len(items))
		for index := range items {
			responses[index] = responseFromDomain(items[index])
		}
		httpx.JSON(w, http.StatusOK, map[string]any{"items": responses})
	case http.MethodPost:
		var request routeRequest
		if !decodeRequest(w, r, &request) {
			return
		}
		if request.ExpectedVersion != 0 {
			httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_application_route")
			return
		}
		item, err := s.useCase.Create(r.Context(), principal, projectID, inputFromRequest(request),
			httpx.RequestIDFromContext(r.Context()))
		if writeError(w, r, err) {
			return
		}
		httpx.JSON(w, http.StatusCreated, responseFromDomain(item))
	default:
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func (s *HTTP) item(w http.ResponseWriter, r *http.Request, principal security.Principal, projectID, routeID string) {
	switch r.Method {
	case http.MethodGet:
		item, err := s.useCase.Get(r.Context(), principal, projectID, routeID)
		if writeError(w, r, err) {
			return
		}
		httpx.JSON(w, http.StatusOK, responseFromDomain(item))
	case http.MethodPatch:
		var request routeRequest
		if !decodeRequest(w, r, &request) {
			return
		}
		item, err := s.useCase.Update(r.Context(), principal, projectID, routeID,
			request.ExpectedVersion, inputFromRequest(request), httpx.RequestIDFromContext(r.Context()))
		if writeError(w, r, err) {
			return
		}
		httpx.JSON(w, http.StatusOK, responseFromDomain(item))
	default:
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
	}
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
	case errors.Is(err, biz.ErrNotFound), errors.Is(err, biz.ErrReferenceNotFound):
		httpx.ErrorRequest(w, r, http.StatusNotFound, "application_route_not_found")
	case errors.Is(err, biz.ErrInvalidRoute):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_application_route")
	case errors.Is(err, biz.ErrUnsupportedTarget):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "application_route_target_unsupported")
	case errors.Is(err, biz.ErrRouteConflict):
		httpx.ErrorRequest(w, r, http.StatusConflict, "application_route_conflict")
	case errors.Is(err, biz.ErrRouteLimitExceeded):
		httpx.ErrorRequest(w, r, http.StatusConflict, "application_route_limit_exceeded")
	case errors.Is(err, biz.ErrUnavailable):
		httpx.ErrorRequest(w, r, http.StatusServiceUnavailable, "application_route_unavailable")
	default:
		httpx.ErrorRequest(w, r, http.StatusInternalServerError, "internal_error")
	}
	return true
}

var _ http.Handler = (*HTTP)(nil)
