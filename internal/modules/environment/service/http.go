package service

import (
	"errors"
	"net/http"

	"github.com/owndock/owndock/internal/modules/environment/biz"
	"github.com/owndock/owndock/internal/platform/httpx"
)

type HTTP struct {
	useCase *biz.UseCase
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
	items, err := s.useCase.List(r.Context())
	if err != nil {
		httpx.ErrorRequest(w, r, http.StatusInternalServerError, "internal_error")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *HTTP) create(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Name     string `json:"name"`
		Provider string `json:"provider"`
	}
	if err := httpx.DecodeJSON(w, r, &request); errors.Is(err, httpx.ErrUnsupportedMediaType) {
		httpx.ErrorRequest(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return
	} else if err != nil {
		httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_json")
		return
	}
	item, err := s.useCase.Create(r.Context(), request.Name, request.Provider)
	switch {
	case errors.Is(err, biz.ErrInvalidName):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_environment")
	case errors.Is(err, biz.ErrDuplicateName):
		httpx.ErrorRequest(w, r, http.StatusConflict, "name_conflict")
	case err != nil:
		httpx.ErrorRequest(w, r, http.StatusInternalServerError, "internal_error")
	default:
		httpx.JSON(w, http.StatusCreated, item)
	}
}
