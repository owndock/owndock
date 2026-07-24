package service

import (
	"errors"
	"net/http"
	"time"

	"github.com/owndock/owndock/internal/modules/deployment/biz"
	"github.com/owndock/owndock/internal/platform/httpx"
)

type HTTP struct {
	useCase *biz.UseCase
}

type response struct {
	ID            string     `json:"id"`
	ApplicationID string     `json:"application_id"`
	EnvironmentID string     `json:"environment_id"`
	Revision      string     `json:"revision"`
	Status        biz.Status `json:"status"`
	CreatedAt     time.Time  `json:"created_at"`
}

func NewHTTP(useCase *biz.UseCase) *HTTP {
	return &HTTP{useCase: useCase}
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
	return response{
		ID:            item.ID,
		ApplicationID: item.ApplicationID,
		EnvironmentID: item.EnvironmentID,
		Revision:      item.Revision,
		Status:        item.Status,
		CreatedAt:     item.CreatedAt,
	}
}
