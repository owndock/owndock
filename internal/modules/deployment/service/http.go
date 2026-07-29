package service

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/modules/deployment/biz"
	"github.com/owndock/owndock/internal/platform/httpx"
	"github.com/owndock/owndock/internal/shared/security"
)

type HTTP struct {
	useCase *biz.UseCase
}

type response struct {
	ID                 string              `json:"id"`
	ProjectID          string              `json:"project_id,omitempty"`
	ApplicationID      string              `json:"application_id"`
	EnvironmentID      string              `json:"environment_id"`
	Revision           string              `json:"revision"`
	Status             biz.Status          `json:"status"`
	FailureCategory    biz.FailureCategory `json:"failure_category,omitempty"`
	CreatedAt          time.Time           `json:"created_at"`
	UpdatedAt          *time.Time          `json:"updated_at,omitempty"`
	ReleaseID          string              `json:"release_id,omitempty"`
	RuntimeTargetID    string              `json:"runtime_target_id,omitempty"`
	Operation          biz.Operation       `json:"operation,omitempty"`
	SourceDeploymentID string              `json:"source_deployment_id,omitempty"`
}

func NewHTTP(useCase *biz.UseCase) *HTTP {
	return &HTTP{useCase: useCase}
}

func (s *HTTP) createFormal(w http.ResponseWriter, r *http.Request, principal security.Principal, projectID string) {
	var request struct {
		ReleaseID       string `json:"release_id"`
		ApplicationID   string `json:"application_id"`
		EnvironmentID   string `json:"environment_id"`
		RuntimeTargetID string `json:"runtime_target_id"`
	}
	if err := httpx.DecodeJSON(w, r, &request); errors.Is(err, httpx.ErrUnsupportedMediaType) {
		httpx.ErrorRequest(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return
	} else if err != nil {
		httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_json")
		return
	}
	headerKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	item, err := s.useCase.CreateFormal(
		r.Context(), principal, projectID, request.ReleaseID, request.ApplicationID,
		request.EnvironmentID, request.RuntimeTargetID, headerKey,
		r.Header.Get("X-Request-ID"),
	)
	if writeFormalError(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusCreated, toResponse(item))
}

func (s *HTTP) listFormal(w http.ResponseWriter, r *http.Request, principal security.Principal, projectID string) {
	items, err := s.useCase.ListFormal(
		r.Context(), principal, projectID,
		r.URL.Query().Get("application_id"), r.URL.Query().Get("environment_id"),
	)
	if writeFormalError(w, r, err) {
		return
	}
	responses := make([]response, len(items))
	for i := range items {
		responses[i] = toResponse(items[i])
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": responses})
}

func (s *HTTP) getFormal(
	w http.ResponseWriter, r *http.Request, principal security.Principal, projectID, deploymentID string,
) {
	item, err := s.useCase.GetFormal(r.Context(), principal, projectID, deploymentID)
	if writeFormalError(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, toResponse(item))
}

func (s *HTTP) cancelFormal(
	w http.ResponseWriter, r *http.Request, principal security.Principal, projectID, deploymentID string,
) {
	item, err := s.useCase.CancelFormal(
		r.Context(), principal, projectID, deploymentID, r.Header.Get("X-Request-ID"),
	)
	if writeFormalError(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusAccepted, toResponse(item))
}

func (s *HTTP) retryFormal(
	w http.ResponseWriter, r *http.Request, principal security.Principal, projectID, deploymentID string,
) {
	item, err := s.useCase.RetryFormal(
		r.Context(), principal, projectID, deploymentID,
		strings.TrimSpace(r.Header.Get("Idempotency-Key")), r.Header.Get("X-Request-ID"),
	)
	if writeFormalError(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusCreated, toResponse(item))
}

func (s *HTTP) rollbackFormal(
	w http.ResponseWriter, r *http.Request, principal security.Principal, projectID, deploymentID string,
) {
	var request struct {
		ReleaseID string `json:"release_id"`
	}
	if err := httpx.DecodeJSON(w, r, &request); errors.Is(err, httpx.ErrUnsupportedMediaType) {
		httpx.ErrorRequest(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return
	} else if err != nil {
		httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_json")
		return
	}
	item, err := s.useCase.RollbackFormal(
		r.Context(), principal, projectID, deploymentID, request.ReleaseID,
		strings.TrimSpace(r.Header.Get("Idempotency-Key")), r.Header.Get("X-Request-ID"),
	)
	if writeFormalError(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusCreated, toResponse(item))
}

func writeFormalError(w http.ResponseWriter, r *http.Request, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, security.ErrUnauthenticated):
		httpx.ErrorRequest(w, r, http.StatusUnauthorized, "unauthenticated")
	case errors.Is(err, security.ErrForbidden):
		httpx.ErrorRequest(w, r, http.StatusForbidden, "forbidden")
	case errors.Is(err, biz.ErrInvalidProject),
		errors.Is(err, biz.ErrInvalidRelease),
		errors.Is(err, biz.ErrInvalidApplication),
		errors.Is(err, biz.ErrInvalidEnvironment),
		errors.Is(err, biz.ErrInvalidRuntimeTarget),
		errors.Is(err, biz.ErrInvalidIdempotencyKey):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_deployment")
	case errors.Is(err, biz.ErrApplicationNotFound),
		errors.Is(err, biz.ErrEnvironmentNotFound),
		errors.Is(err, biz.ErrReleaseNotFound),
		errors.Is(err, biz.ErrRuntimeTargetNotFound):
		httpx.ErrorRequest(w, r, http.StatusNotFound, "deployment_reference_not_found")
	case errors.Is(err, biz.ErrIdempotencyMismatch):
		httpx.ErrorRequest(w, r, http.StatusConflict, "idempotency_key_mismatch")
	case errors.Is(err, biz.ErrRuntimeTargetNotReady):
		httpx.ErrorRequest(w, r, http.StatusConflict, "runtime_target_not_ready")
	case errors.Is(err, biz.ErrInvalidTransition),
		errors.Is(err, biz.ErrRetryRequiresFailed),
		errors.Is(err, biz.ErrRollbackRequiresFinal),
		errors.Is(err, biz.ErrRollbackSameRelease),
		errors.Is(err, biz.ErrRollbackNotSucceeded),
		errors.Is(err, biz.ErrConflict):
		httpx.ErrorRequest(w, r, http.StatusConflict, "deployment_conflict")
	case errors.Is(err, biz.ErrNotFound):
		httpx.ErrorRequest(w, r, http.StatusNotFound, "deployment_not_found")
	case err != nil:
		httpx.ErrorRequest(w, r, http.StatusInternalServerError, "internal_error")
	}
	return true
}

// HandleFormal is mounted behind session authentication by the product router.
func (s *HTTP) HandleFormal(w http.ResponseWriter, r *http.Request) {
	principal, ok := security.PrincipalFromContext(r.Context())
	if !ok {
		httpx.ErrorRequest(w, r, http.StatusUnauthorized, "unauthenticated")
		return
	}
	segments := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(segments) < 5 || segments[0] != "api" || segments[1] != "v1" ||
		segments[2] != "projects" || segments[4] != "deployments" || segments[3] == "" {
		httpx.ErrorRequest(w, r, http.StatusNotFound, "not_found")
		return
	}
	projectID := segments[3]
	switch {
	case len(segments) == 5 && r.Method == http.MethodGet:
		s.listFormal(w, r, principal, projectID)
	case len(segments) == 5 && r.Method == http.MethodPost:
		s.createFormal(w, r, principal, projectID)
	case len(segments) == 6 && r.Method == http.MethodGet:
		s.getFormal(w, r, principal, projectID, segments[5])
	case len(segments) == 7 && segments[6] == "cancel" && r.Method == http.MethodPost:
		s.cancelFormal(w, r, principal, projectID, segments[5])
	case len(segments) == 7 && segments[6] == "retry" && r.Method == http.MethodPost:
		s.retryFormal(w, r, principal, projectID, segments[5])
	case len(segments) == 7 && segments[6] == "rollback" && r.Method == http.MethodPost:
		s.rollbackFormal(w, r, principal, projectID, segments[5])
	default:
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func (s *HTTP) Handle(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.list(w, r)
	case http.MethodPost:
		s.create(w, r)
	default:
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func (s *HTTP) list(w http.ResponseWriter, r *http.Request) {
	items, err := s.useCase.List(r.Context(), r.URL.Query().Get("application_id"), r.URL.Query().Get("environment_id"))
	if err != nil {
		httpx.ErrorRequest(w, r, http.StatusInternalServerError, "internal_error")
		return
	}
	responses := make([]response, len(items))
	for i := range items {
		responses[i] = toResponse(items[i])
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": responses})
}

func (s *HTTP) create(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ApplicationID string `json:"application_id"`
		EnvironmentID string `json:"environment_id"`
		Revision      string `json:"revision"`
	}
	if err := httpx.DecodeJSON(w, r, &request); errors.Is(err, httpx.ErrUnsupportedMediaType) {
		httpx.ErrorRequest(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return
	} else if err != nil {
		httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_json")
		return
	}
	item, err := s.useCase.Create(r.Context(), request.ApplicationID, request.EnvironmentID, request.Revision)
	switch {
	case errors.Is(err, biz.ErrInvalidApplication), errors.Is(err, biz.ErrInvalidEnvironment):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_deployment")
	case errors.Is(err, biz.ErrApplicationNotFound):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "application_not_found")
	case errors.Is(err, biz.ErrEnvironmentNotFound):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "environment_not_found")
	case err != nil:
		httpx.ErrorRequest(w, r, http.StatusInternalServerError, "internal_error")
	default:
		httpx.JSON(w, http.StatusCreated, toResponse(item))
	}
}

func toResponse(item biz.Deployment) response {
	result := response{
		ID: item.ID, ProjectID: item.ProjectID, ApplicationID: item.ApplicationID,
		EnvironmentID: item.EnvironmentID, Revision: item.Revision, Status: item.Status,
		FailureCategory: item.FailureCategory,
		CreatedAt:       item.CreatedAt, ReleaseID: item.ReleaseID, RuntimeTargetID: item.RuntimeTargetID,
		Operation: item.Operation, SourceDeploymentID: item.SourceDeploymentID,
	}
	if item.ProjectID != "" {
		updatedAt := item.UpdatedAt
		result.UpdatedAt = &updatedAt
	}
	return result
}
