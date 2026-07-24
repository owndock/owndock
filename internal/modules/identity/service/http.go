package service

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/modules/identity/biz"
	"github.com/owndock/owndock/internal/platform/httpx"
	"github.com/owndock/owndock/internal/shared/security"
)

const bootstrapTokenHeader = "X-OwnDock-Bootstrap-Token"

type BootstrapToken func() (string, error)

type HTTP struct {
	useCase        *biz.UseCase
	bootstrapToken BootstrapToken
}

func NewHTTP(useCase *biz.UseCase, bootstrapToken BootstrapToken) *HTTP {
	return &HTTP{useCase: useCase, bootstrapToken: bootstrapToken}
}

func (s *HTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.Handle(w, r)
}

func (s *HTTP) Handle(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/v1/auth/bootstrap":
		s.bootstrap(w, r)
	case "/api/v1/auth/login":
		s.login(w, r)
	case "/api/v1/auth/logout":
		s.authenticated(s.logout).ServeHTTP(w, r)
	case "/api/v1/auth/me":
		s.authenticated(s.me).ServeHTTP(w, r)
	default:
		httpx.ErrorRequest(w, r, http.StatusNotFound, "not_found")
	}
}

func (s *HTTP) Authenticate(next http.Handler) http.Handler {
	return s.authenticated(next.ServeHTTP)
}

func (s *HTTP) authenticated(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization := strings.Fields(r.Header.Get("Authorization"))
		if len(authorization) != 2 || !strings.EqualFold(authorization[0], "Bearer") {
			unauthenticated(w, r)
			return
		}
		principal, err := s.useCase.Authenticate(r.Context(), authorization[1])
		if err != nil {
			unauthenticated(w, r)
			return
		}
		next.ServeHTTP(w, r.WithContext(security.WithPrincipal(r.Context(), principal)))
	})
}

func (s *HTTP) bootstrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	expected, err := s.bootstrapToken()
	received := r.Header.Get(bootstrapTokenHeader)
	if err != nil || expected == "" || len(expected) != len(received) ||
		subtle.ConstantTimeCompare([]byte(expected), []byte(received)) != 1 {
		httpx.ErrorRequest(w, r, http.StatusForbidden, "bootstrap_token_invalid")
		return
	}
	var request struct {
		OrganizationName string `json:"organization_name"`
		Email            string `json:"email"`
		Password         string `json:"password"`
	}
	if !decodeRequest(w, r, &request) {
		return
	}
	credentials, err := s.useCase.Bootstrap(
		r.Context(), request.OrganizationName, request.Email, request.Password,
		httpx.RequestIDFromContext(r.Context()),
	)
	if writeIdentityError(w, r, err) {
		return
	}
	writeCredentials(w, http.StatusCreated, credentials)
}

func (s *HTTP) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	var request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decodeRequest(w, r, &request) {
		return
	}
	credentials, err := s.useCase.Login(
		r.Context(), request.Email, request.Password,
		httpx.RequestIDFromContext(r.Context()),
	)
	if writeIdentityError(w, r, err) {
		return
	}
	writeCredentials(w, http.StatusOK, credentials)
}

func (s *HTTP) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	principal, _ := security.PrincipalFromContext(r.Context())
	if err := s.useCase.Logout(r.Context(), principal, httpx.RequestIDFromContext(r.Context())); err != nil {
		httpx.ErrorRequest(w, r, http.StatusInternalServerError, "internal_error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *HTTP) me(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	principal, _ := security.PrincipalFromContext(r.Context())
	httpx.JSON(w, http.StatusOK, map[string]any{
		"id": principal.UserID, "organization_id": principal.OrganizationID,
		"email": principal.Email, "role": principal.Role,
	})
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

func writeIdentityError(w http.ResponseWriter, r *http.Request, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, biz.ErrAlreadyBootstrapped):
		httpx.ErrorRequest(w, r, http.StatusConflict, "already_bootstrapped")
	case errors.Is(err, biz.ErrInvalidCredentials):
		unauthenticated(w, r)
	case errors.Is(err, biz.ErrInvalidEmail),
		errors.Is(err, biz.ErrInvalidName),
		errors.Is(err, biz.ErrInvalidPassword):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_identity")
	default:
		httpx.ErrorRequest(w, r, http.StatusInternalServerError, "internal_error")
	}
	return true
}

func unauthenticated(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	httpx.ErrorRequest(w, r, http.StatusUnauthorized, "unauthenticated")
}

func writeCredentials(w http.ResponseWriter, status int, credentials biz.Credentials) {
	w.Header().Set("Cache-Control", "no-store")
	response := map[string]any{
		"access_token": credentials.AccessToken,
		"token_type":   "Bearer",
		"expires_at":   credentials.ExpiresAt.UTC().Format(time.RFC3339),
		"user": map[string]any{
			"id": credentials.User.ID, "organization_id": credentials.User.OrganizationID,
			"email": credentials.User.Email, "role": credentials.User.Role,
		},
	}
	if credentials.Organization.ID != "" {
		response["organization"] = map[string]any{
			"id": credentials.Organization.ID, "name": credentials.Organization.Name,
		}
	}
	httpx.JSON(w, status, response)
}
