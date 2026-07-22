package service

import (
	"errors"
	"net/http"

	"github.com/owndock/owndock/internal/modules/application/biz"
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
		s.List(w, r)
	case http.MethodPost:
		s.Create(w, r)
	default:
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func (s *HTTP) List(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	items, err := s.useCase.List(r.Context())
	if err != nil {
		httpx.ErrorRequest(w, r, http.StatusInternalServerError, "internal_error")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *HTTP) Create(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	var request struct {
		Name string `json:"name"`
	}
	if err := httpx.DecodeJSON(w, r, &request); errors.Is(err, httpx.ErrUnsupportedMediaType) {
		httpx.ErrorRequest(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return
	} else if err != nil {
		httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_json")
		return
	}
	item, err := s.useCase.Create(r.Context(), request.Name)
	switch {
	case errors.Is(err, biz.ErrInvalidName):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_name")
	case errors.Is(err, biz.ErrDuplicateName):
		httpx.ErrorRequest(w, r, http.StatusConflict, "name_conflict")
	case err != nil:
		httpx.ErrorRequest(w, r, http.StatusInternalServerError, "internal_error")
	default:
		httpx.JSON(w, http.StatusCreated, item)
	}
}
