package service

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/modules/terminal/biz"
	"github.com/owndock/owndock/internal/platform/httpx"
	"github.com/owndock/owndock/internal/platform/ingress"
	"github.com/owndock/owndock/internal/shared/security"
)

const ticketCookieName = "__Secure-owndock_terminal_ticket"

type HTTP struct {
	useCase *biz.UseCase
	wss     *TerminalWSS
}

func NewHTTP(
	useCase *biz.UseCase,
	observers ...TerminalConnectionObserver,
) *HTTP {
	return &HTTP{useCase: useCase, wss: NewTerminalWSS(useCase, observers...)}
}

func (s *HTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	segments := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(segments) == 4 && segments[0] == "api" && segments[1] == "v1" &&
		segments[2] == "terminal-sessions" && strings.HasSuffix(segments[3], ":connect") {
		s.wss.ServeHTTP(w, r, strings.TrimSuffix(segments[3], ":connect"))
		return
	}
	principal, ok := security.PrincipalFromContext(r.Context())
	if !ok {
		writeError(w, r, security.ErrUnauthenticated)
		return
	}
	switch {
	case len(segments) == 5 && isProjectPrefix(segments) && segments[4] == "terminal-policy":
		s.projectPolicy(w, r, principal, segments[3])
	case len(segments) == 6 && isProjectPrefix(segments) && segments[4] == "terminal-sessions" && segments[5] == "container":
		s.createContainer(w, r, principal, segments[3])
	case len(segments) == 3 && segments[0] == "api" && segments[1] == "v1" && segments[2] == "terminal-policy":
		s.organizationPolicy(w, r, principal)
	case len(segments) == 5 && segments[0] == "api" && segments[1] == "v1" && segments[2] == "managed-hosts" && segments[3] != "" && segments[4] == "terminal-sessions":
		s.createHost(w, r, principal, segments[3])
	case len(segments) == 4 && segments[0] == "api" && segments[1] == "v1" && segments[2] == "terminal-sessions" && strings.HasSuffix(segments[3], ":terminate"):
		s.terminate(w, r, principal, strings.TrimSuffix(segments[3], ":terminate"))
	case len(segments) == 4 && segments[0] == "api" && segments[1] == "v1" && segments[2] == "terminal-sessions" && segments[3] != "":
		s.getSession(w, r, principal, segments[3])
	default:
		httpx.ErrorRequest(w, r, http.StatusNotFound, "not_found")
	}
}

func isProjectPrefix(segments []string) bool {
	return segments[0] == "api" && segments[1] == "v1" && segments[2] == "projects" && segments[3] != ""
}

func (s *HTTP) projectPolicy(w http.ResponseWriter, r *http.Request, principal security.Principal, projectID string) {
	switch r.Method {
	case http.MethodGet:
		policy, err := s.useCase.GetProjectPolicy(r.Context(), principal, projectID)
		if writeError(w, r, err) {
			return
		}
		httpx.JSON(w, http.StatusOK, policyResponseFromDomain(policy))
	case http.MethodPut:
		input, expectedVersion, ok := decodePolicyRequest(w, r)
		if !ok {
			return
		}
		policy, err := s.useCase.SaveProjectPolicy(r.Context(), principal, projectID, input, expectedVersion, requestID(r))
		if writeError(w, r, err) {
			return
		}
		httpx.JSON(w, http.StatusOK, policyResponseFromDomain(policy))
	default:
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func (s *HTTP) organizationPolicy(w http.ResponseWriter, r *http.Request, principal security.Principal) {
	switch r.Method {
	case http.MethodGet:
		policy, err := s.useCase.GetOrganizationPolicy(r.Context(), principal)
		if writeError(w, r, err) {
			return
		}
		httpx.JSON(w, http.StatusOK, policyResponseFromDomain(policy))
	case http.MethodPut:
		input, expectedVersion, ok := decodePolicyRequest(w, r)
		if !ok {
			return
		}
		policy, err := s.useCase.SaveOrganizationPolicy(r.Context(), principal, input, expectedVersion, requestID(r))
		if writeError(w, r, err) {
			return
		}
		httpx.JSON(w, http.StatusOK, policyResponseFromDomain(policy))
	default:
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func (s *HTTP) createContainer(w http.ResponseWriter, r *http.Request, principal security.Principal, projectID string) {
	if r.Method != http.MethodPost {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	var request struct {
		DeploymentID string `json:"deployment_id"`
	}
	if !decodeRequest(w, r, &request) {
		return
	}
	clientIP, ok := trustedClientIP(r)
	if !ok {
		writeError(w, r, biz.ErrTerminalUnavailable)
		return
	}
	credential, err := s.useCase.CreateContainerSession(
		r.Context(), principal, projectID, request.DeploymentID, clientIP,
		r.UserAgent(), requestID(r),
	)
	if writeError(w, r, err) {
		return
	}
	writeCredential(w, credential)
}

func (s *HTTP) createHost(w http.ResponseWriter, r *http.Request, principal security.Principal, hostID string) {
	if r.Method != http.MethodPost {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	clientIP, ok := trustedClientIP(r)
	if !ok {
		writeError(w, r, biz.ErrTerminalUnavailable)
		return
	}
	credential, err := s.useCase.CreateHostSession(
		r.Context(), principal, hostID, clientIP, r.UserAgent(), requestID(r),
	)
	if writeError(w, r, err) {
		return
	}
	writeCredential(w, credential)
}

func (s *HTTP) getSession(w http.ResponseWriter, r *http.Request, principal security.Principal, sessionID string) {
	if r.Method != http.MethodGet {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	session, err := s.useCase.GetSession(r.Context(), principal, sessionID)
	if writeError(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, sessionResponseFromDomain(session))
}

func (s *HTTP) terminate(w http.ResponseWriter, r *http.Request, principal security.Principal, sessionID string) {
	if r.Method != http.MethodPost {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	session, err := s.useCase.TerminateSession(r.Context(), principal, sessionID, requestID(r))
	if writeError(w, r, err) {
		return
	}
	http.SetCookie(w, expiredTicketCookie(sessionID))
	httpx.JSON(w, http.StatusOK, sessionResponseFromDomain(session))
}

type policyRequest struct {
	Enabled               bool            `json:"enabled"`
	AllowedRoles          []security.Role `json:"allowed_roles"`
	EnvironmentStages     []string        `json:"environment_stages"`
	RuntimeTargetIDs      []string        `json:"runtime_target_ids"`
	ManagedHostIDs        []string        `json:"managed_host_ids"`
	IdleTimeout           string          `json:"idle_timeout"`
	MaximumDuration       string          `json:"maximum_duration"`
	MaximumPerUser        int             `json:"maximum_per_user"`
	MaximumPerTarget      int             `json:"maximum_per_target"`
	RevocationGracePeriod string          `json:"revocation_grace_period"`
	ExpectedVersion       uint64          `json:"expected_version"`
}

func decodePolicyRequest(w http.ResponseWriter, r *http.Request) (biz.PolicyInput, uint64, bool) {
	var request policyRequest
	if !decodeRequest(w, r, &request) {
		return biz.PolicyInput{}, 0, false
	}
	idle, idleErr := time.ParseDuration(request.IdleTimeout)
	maximum, maximumErr := time.ParseDuration(request.MaximumDuration)
	grace, graceErr := time.ParseDuration(request.RevocationGracePeriod)
	if idleErr != nil || maximumErr != nil || graceErr != nil {
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_terminal_policy")
		return biz.PolicyInput{}, 0, false
	}
	return biz.PolicyInput{
		Enabled: request.Enabled, AllowedRoles: request.AllowedRoles,
		EnvironmentStages: request.EnvironmentStages, RuntimeTargetIDs: request.RuntimeTargetIDs,
		ManagedHostIDs: request.ManagedHostIDs, IdleTimeout: idle, MaximumDuration: maximum,
		MaximumPerUser: request.MaximumPerUser, MaximumPerTarget: request.MaximumPerTarget,
		RevocationGracePeriod: grace,
	}, request.ExpectedVersion, true
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

func trustedClientIP(r *http.Request) (string, bool) {
	address, ok := ingress.ClientIPFromContext(r.Context())
	return address.String(), ok
}

func requestID(r *http.Request) string { return httpx.RequestIDFromContext(r.Context()) }

func writeCredential(w http.ResponseWriter, credential biz.Credential) {
	remaining := credential.ExpiresAt.Sub(credential.Session.CreatedAt)
	maxAge := max(1, int((remaining+time.Second-1)/time.Second))
	http.SetCookie(w, &http.Cookie{
		Name: ticketCookieName, Value: credential.Ticket,
		Path:   "/api/v1/terminal-sessions/" + credential.Session.ID + ":connect",
		MaxAge: maxAge, Expires: credential.ExpiresAt, HttpOnly: true, Secure: true,
		SameSite: http.SameSiteStrictMode,
	})
	w.Header().Set("Cache-Control", "no-store")
	httpx.JSON(w, http.StatusCreated, map[string]any{
		"session":           sessionResponseFromDomain(credential.Session),
		"ticket_expires_at": credential.ExpiresAt,
	})
}

func expiredTicketCookie(sessionID string) *http.Cookie {
	return &http.Cookie{
		Name: ticketCookieName, Value: "",
		Path:   "/api/v1/terminal-sessions/" + sessionID + ":connect",
		MaxAge: -1, Expires: time.Unix(1, 0), HttpOnly: true, Secure: true,
		SameSite: http.SameSiteStrictMode,
	}
}

func writeError(w http.ResponseWriter, r *http.Request, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, security.ErrUnauthenticated):
		w.Header().Set("WWW-Authenticate", "Bearer")
		httpx.ErrorRequest(w, r, http.StatusUnauthorized, "unauthenticated")
	case errors.Is(err, security.ErrForbidden), errors.Is(err, biz.ErrAccessDenied):
		httpx.ErrorRequest(w, r, http.StatusForbidden, "terminal_access_denied")
	case errors.Is(err, biz.ErrPolicyNotFound), errors.Is(err, biz.ErrSessionNotFound), errors.Is(err, biz.ErrTargetNotFound):
		httpx.ErrorRequest(w, r, http.StatusNotFound, "terminal_resource_not_found")
	case errors.Is(err, biz.ErrPolicyConflict), errors.Is(err, biz.ErrSessionConflict), errors.Is(err, biz.ErrSessionSlotConflict):
		httpx.ErrorRequest(w, r, http.StatusConflict, "terminal_resource_conflict")
	case errors.Is(err, biz.ErrSessionLimit):
		w.Header().Set("Retry-After", "30")
		httpx.ErrorRequest(w, r, http.StatusTooManyRequests, "terminal_session_limit_reached")
	case errors.Is(err, biz.ErrInvalidPolicy), errors.Is(err, biz.ErrInvalidSession):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_terminal_request")
	case errors.Is(err, biz.ErrTargetUnavailable):
		httpx.ErrorRequest(w, r, http.StatusConflict, "terminal_target_unavailable")
	case errors.Is(err, biz.ErrInvalidTicket):
		httpx.ErrorRequest(w, r, http.StatusUnauthorized, "terminal_ticket_invalid")
	default:
		httpx.ErrorRequest(w, r, http.StatusInternalServerError, "internal_error")
	}
	return true
}

type policyResponse struct {
	ID                    string          `json:"id"`
	Scope                 biz.PolicyScope `json:"scope"`
	OrganizationID        string          `json:"organization_id"`
	ProjectID             string          `json:"project_id,omitempty"`
	Enabled               bool            `json:"enabled"`
	AllowedRoles          []security.Role `json:"allowed_roles"`
	EnvironmentStages     []string        `json:"environment_stages"`
	RuntimeTargetIDs      []string        `json:"runtime_target_ids"`
	ManagedHostIDs        []string        `json:"managed_host_ids"`
	IdleTimeout           string          `json:"idle_timeout"`
	MaximumDuration       string          `json:"maximum_duration"`
	MaximumPerUser        int             `json:"maximum_per_user"`
	MaximumPerTarget      int             `json:"maximum_per_target"`
	RevocationGracePeriod string          `json:"revocation_grace_period"`
	Version               uint64          `json:"version"`
}

func policyResponseFromDomain(policy biz.AccessPolicy) policyResponse {
	return policyResponse{
		ID: policy.ID, Scope: policy.Scope, OrganizationID: policy.OrganizationID,
		ProjectID: policy.ProjectID, Enabled: policy.Enabled, AllowedRoles: policy.AllowedRoles,
		EnvironmentStages: nonNil(policy.EnvironmentStages), RuntimeTargetIDs: nonNil(policy.RuntimeTargetIDs),
		ManagedHostIDs: nonNil(policy.ManagedHostIDs), IdleTimeout: policy.IdleTimeout.String(),
		MaximumDuration: policy.MaximumDuration.String(), MaximumPerUser: policy.MaximumPerUser,
		MaximumPerTarget: policy.MaximumPerTarget, RevocationGracePeriod: policy.RevocationGracePeriod.String(),
		Version: policy.Version,
	}
}

type sessionResponse struct {
	ID              string            `json:"id"`
	OrganizationID  string            `json:"organization_id"`
	ProjectID       string            `json:"project_id,omitempty"`
	Kind            biz.Kind          `json:"kind"`
	ActorID         string            `json:"actor_id"`
	ManagedHostID   string            `json:"managed_host_id"`
	RuntimeTargetID string            `json:"runtime_target_id,omitempty"`
	DeploymentID    string            `json:"deployment_id,omitempty"`
	Status          biz.SessionStatus `json:"status"`
	CreatedAt       time.Time         `json:"created_at"`
	ConnectedAt     *time.Time        `json:"connected_at,omitempty"`
	LastActivityAt  time.Time         `json:"last_activity_at"`
	EndedAt         *time.Time        `json:"ended_at,omitempty"`
	IdleDeadline    time.Time         `json:"idle_deadline"`
	MaximumDeadline time.Time         `json:"maximum_deadline"`
	CloseReason     biz.CloseReason   `json:"close_reason,omitempty"`
	SafeErrorCode   string            `json:"safe_error_code,omitempty"`
	Version         uint64            `json:"version"`
}

func sessionResponseFromDomain(session biz.TerminalSession) sessionResponse {
	response := sessionResponse{
		ID: session.ID, OrganizationID: session.OrganizationID, ProjectID: session.ProjectID,
		Kind: session.Kind, ActorID: session.ActorID, ManagedHostID: session.ManagedHostID,
		RuntimeTargetID: session.RuntimeTargetID, DeploymentID: session.DeploymentID,
		Status: session.Status, CreatedAt: session.CreatedAt, LastActivityAt: session.LastActivityAt,
		IdleDeadline: session.IdleDeadline, MaximumDeadline: session.MaximumDeadline,
		CloseReason: session.CloseReason, SafeErrorCode: session.SafeErrorCode, Version: session.Version,
	}
	if !session.ConnectedAt.IsZero() {
		connected := session.ConnectedAt
		response.ConnectedAt = &connected
	}
	if !session.EndedAt.IsZero() {
		ended := session.EndedAt
		response.EndedAt = &ended
	}
	return response
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
