package service

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strconv"
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
	case "/api/v1/auth/sessions":
		s.authenticated(s.sessions).ServeHTTP(w, r)
	case "/api/v1/auth/users":
		s.authenticated(s.users).ServeHTTP(w, r)
	case "/api/v1/auth/invitations":
		s.authenticated(s.invitations).ServeHTTP(w, r)
	case "/api/v1/auth/invitations:accept":
		s.acceptInvitation(w, r)
	default:
		segments := strings.Split(
			strings.TrimPrefix(r.URL.Path, "/"),
			"/",
		)
		if len(segments) == 5 &&
			segments[0] == "api" &&
			segments[1] == "v1" &&
			segments[2] == "auth" &&
			segments[3] == "sessions" &&
			segments[4] != "" {
			s.authenticated(
				func(
					w http.ResponseWriter,
					r *http.Request,
				) {
					s.session(w, r, segments[4])
				},
			).ServeHTTP(w, r)
			return
		}
		if len(segments) == 6 && segments[0] == "api" && segments[1] == "v1" &&
			segments[2] == "auth" && segments[3] == "users" && segments[4] != "" &&
			segments[5] == "sessions" {
			s.authenticated(func(w http.ResponseWriter, r *http.Request) {
				s.userSessions(w, r, segments[4])
			}).ServeHTTP(w, r)
			return
		}
		if len(segments) == 7 && segments[0] == "api" && segments[1] == "v1" &&
			segments[2] == "auth" && segments[3] == "users" && segments[4] != "" &&
			segments[5] == "sessions" && segments[6] != "" {
			s.authenticated(func(w http.ResponseWriter, r *http.Request) {
				s.userSession(w, r, segments[4], segments[6])
			}).ServeHTTP(w, r)
			return
		}
		if len(segments) == 5 && segments[0] == "api" && segments[1] == "v1" &&
			segments[2] == "auth" && segments[3] == "invitations" &&
			strings.HasSuffix(segments[4], ":revoke") {
			invitationID := strings.TrimSuffix(segments[4], ":revoke")
			if invitationID != "" {
				s.authenticated(func(w http.ResponseWriter, r *http.Request) {
					s.revokeInvitation(w, r, invitationID)
				}).ServeHTTP(w, r)
				return
			}
		}
		httpx.ErrorRequest(w, r, http.StatusNotFound, "not_found")
	}
}

func (s *HTTP) users(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	principal, _ := security.PrincipalFromContext(r.Context())
	items, err := s.useCase.ListUsers(r.Context(), principal)
	if writeIdentityError(w, r, err) {
		return
	}
	result := make([]map[string]any, len(items))
	for index, item := range items {
		result[index] = map[string]any{
			"id": item.ID, "organization_id": item.OrganizationID, "email": item.Email,
			"role": item.Role, "created_at": item.CreatedAt.UTC().Format(time.RFC3339),
		}
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": result})
}

func (s *HTTP) invitations(w http.ResponseWriter, r *http.Request) {
	principal, _ := security.PrincipalFromContext(r.Context())
	switch r.Method {
	case http.MethodGet:
		items, err := s.useCase.ListInvitations(r.Context(), principal)
		if writeIdentityError(w, r, err) {
			return
		}
		result := make([]map[string]any, len(items))
		for index, item := range items {
			result[index] = invitationResponse(item)
		}
		httpx.JSON(w, http.StatusOK, map[string]any{"items": result})
	case http.MethodPost:
		var request struct {
			Email string `json:"email"`
		}
		if !decodeRequest(w, r, &request) {
			return
		}
		credential, err := s.useCase.CreateInvitation(r.Context(), principal, request.Email,
			httpx.RequestIDFromContext(r.Context()))
		if writeIdentityError(w, r, err) {
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		response := invitationResponse(credential.Invitation)
		response["token"] = credential.Token
		httpx.JSON(w, http.StatusCreated, response)
	default:
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func (s *HTTP) acceptInvitation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	var request struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if !decodeRequest(w, r, &request) {
		return
	}
	credentials, err := s.useCase.AcceptInvitation(r.Context(), request.Token, request.Password,
		httpx.RequestIDFromContext(r.Context()))
	if errors.Is(err, biz.ErrInvalidInvitation) || errors.Is(err, biz.ErrUserAlreadyExists) {
		w.Header().Set("Cache-Control", "no-store")
		httpx.ErrorRequest(w, r, http.StatusUnauthorized, "invalid_invitation")
		return
	}
	if writeIdentityError(w, r, err) {
		return
	}
	writeCredentials(w, http.StatusCreated, credentials)
}

func (s *HTTP) revokeInvitation(w http.ResponseWriter, r *http.Request, invitationID string) {
	if r.Method != http.MethodPost {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	principal, _ := security.PrincipalFromContext(r.Context())
	item, err := s.useCase.RevokeInvitation(r.Context(), principal, invitationID,
		httpx.RequestIDFromContext(r.Context()))
	if writeIdentityError(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, invitationResponse(item))
}

func invitationResponse(item biz.Invitation) map[string]any {
	response := map[string]any{
		"id": item.ID, "organization_id": item.OrganizationID, "email": item.Email,
		"status": item.Status, "version": item.Version, "invited_by": item.InvitedBy,
		"created_at": item.CreatedAt.UTC().Format(time.RFC3339),
		"expires_at": item.ExpiresAt.UTC().Format(time.RFC3339),
	}
	if !item.AcceptedAt.IsZero() {
		response["accepted_by"], response["accepted_at"] = item.AcceptedBy, item.AcceptedAt.UTC().Format(time.RFC3339)
	}
	if !item.RevokedAt.IsZero() {
		response["revoked_by"], response["revoked_at"] = item.RevokedBy, item.RevokedAt.UTC().Format(time.RFC3339)
	}
	return response
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

func (s *HTTP) sessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httpx.ErrorRequest(
			w,
			r,
			http.StatusMethodNotAllowed,
			"method_not_allowed",
		)
		return
	}
	principal, _ := security.PrincipalFromContext(r.Context())
	items, err := s.useCase.ListSessions(r.Context(), principal)
	if writeIdentityError(w, r, err) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	result := make([]map[string]any, len(items))
	for index, item := range items {
		result[index] = map[string]any{
			"id":         item.ID,
			"created_at": item.CreatedAt.UTC().Format(time.RFC3339),
			"expires_at": item.ExpiresAt.UTC().Format(time.RFC3339),
			"current":    item.ID == principal.SessionID,
		}
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": result})
}

func (s *HTTP) userSessions(w http.ResponseWriter, r *http.Request, userID string) {
	principal, _ := security.PrincipalFromContext(r.Context())
	switch r.Method {
	case http.MethodGet:
		items, err := s.useCase.ListUserSessions(r.Context(), principal, userID)
		if writeIdentityError(w, r, err) {
			return
		}
		result := make([]map[string]any, len(items))
		for index, item := range items {
			result[index] = map[string]any{
				"id": item.ID, "created_at": item.CreatedAt.UTC().Format(time.RFC3339),
				"expires_at": item.ExpiresAt.UTC().Format(time.RFC3339),
				"current":    item.ID == principal.SessionID,
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		httpx.JSON(w, http.StatusOK, map[string]any{"items": result})
	case http.MethodDelete:
		revoked, err := s.useCase.RevokeAllUserSessions(
			r.Context(), principal, userID, httpx.RequestIDFromContext(r.Context()),
		)
		if writeIdentityError(w, r, err) {
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		httpx.JSON(w, http.StatusOK, map[string]any{"revoked_sessions": revoked})
	default:
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func (s *HTTP) userSession(
	w http.ResponseWriter, r *http.Request, userID, sessionID string,
) {
	if r.Method != http.MethodDelete {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	principal, _ := security.PrincipalFromContext(r.Context())
	if err := s.useCase.RevokeUserSession(
		r.Context(), principal, userID, sessionID,
		httpx.RequestIDFromContext(r.Context()),
	); writeIdentityError(w, r, err) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *HTTP) session(
	w http.ResponseWriter,
	r *http.Request,
	sessionID string,
) {
	if r.Method != http.MethodDelete {
		httpx.ErrorRequest(
			w,
			r,
			http.StatusMethodNotAllowed,
			"method_not_allowed",
		)
		return
	}
	principal, _ := security.PrincipalFromContext(r.Context())
	err := s.useCase.RevokeSession(
		r.Context(),
		principal,
		sessionID,
		httpx.RequestIDFromContext(r.Context()),
	)
	if writeIdentityError(w, r, err) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
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
	case errors.Is(err, biz.ErrLoginRateLimited):
		var rateLimit *biz.LoginRateLimitError
		if errors.As(err, &rateLimit) {
			seconds := int64(
				(rateLimit.RetryAfter + time.Second - 1) /
					time.Second,
			)
			w.Header().Set(
				"Retry-After",
				strconv.FormatInt(max(seconds, 1), 10),
			)
		}
		httpx.ErrorRequest(
			w,
			r,
			http.StatusTooManyRequests,
			"login_rate_limited",
		)
	case errors.Is(err, biz.ErrInvalidEmail),
		errors.Is(err, biz.ErrInvalidName),
		errors.Is(err, biz.ErrInvalidPassword):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_identity")
	case errors.Is(err, biz.ErrUserAlreadyExists):
		httpx.ErrorRequest(w, r, http.StatusConflict, "user_already_exists")
	case errors.Is(err, biz.ErrInvalidInvitation):
		httpx.ErrorRequest(w, r, http.StatusConflict, "invalid_invitation_state")
	case errors.Is(err, biz.ErrCannotRevokeCurrent):
		httpx.ErrorRequest(w, r, http.StatusConflict, "cannot_revoke_current_session")
	case errors.Is(err, security.ErrForbidden):
		httpx.ErrorRequest(w, r, http.StatusForbidden, "forbidden")
	case errors.Is(err, biz.ErrNotFound):
		httpx.ErrorRequest(w, r, http.StatusNotFound, "not_found")
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
