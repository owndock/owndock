package service

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/modules/managedhost/biz"
	"github.com/owndock/owndock/internal/platform/httpx"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/security"
)

type HTTP struct {
	useCase *biz.UseCase
}

func NewHTTP(useCase *biz.UseCase) *HTTP {
	return &HTTP{useCase: useCase}
}

func (s *HTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	segments := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(segments) == 4 &&
		segments[0] == "api" && segments[1] == "v1" &&
		segments[2] == "agent" && segments[3] == "enrollments:exchange" {
		s.exchangeEnrollment(w, r)
		return
	}
	principal, ok := security.PrincipalFromContext(r.Context())
	if !ok {
		writeError(w, r, security.ErrUnauthenticated)
		return
	}
	switch {
	case len(segments) == 3 &&
		segments[0] == "api" && segments[1] == "v1" && segments[2] == "managed-hosts":
		s.collection(w, r, principal)
	case len(segments) == 4 &&
		segments[0] == "api" && segments[1] == "v1" && segments[2] == "managed-hosts" &&
		strings.HasSuffix(segments[3], ":disable") &&
		strings.TrimSuffix(segments[3], ":disable") != "":
		s.disable(w, r, principal, strings.TrimSuffix(segments[3], ":disable"))
	case len(segments) == 4 &&
		segments[0] == "api" && segments[1] == "v1" && segments[2] == "managed-hosts" &&
		segments[3] != "":
		s.item(w, r, principal, segments[3])
	case len(segments) == 5 &&
		segments[0] == "api" && segments[1] == "v1" &&
		segments[2] == "managed-hosts" && segments[3] != "" &&
		segments[4] == "enrollments":
		s.createEnrollment(w, r, principal, segments[3])
	default:
		httpx.ErrorRequest(w, r, http.StatusNotFound, "not_found")
	}
}

func (s *HTTP) disable(
	w http.ResponseWriter,
	r *http.Request,
	principal security.Principal,
	hostID string,
) {
	if r.Method != http.MethodPost {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	item, err := s.useCase.Disable(
		r.Context(), principal, hostID, httpx.RequestIDFromContext(r.Context()),
	)
	if writeError(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, hostResponseFromDomain(item))
}

func (s *HTTP) createEnrollment(
	w http.ResponseWriter,
	r *http.Request,
	principal security.Principal,
	hostID string,
) {
	if r.Method != http.MethodPost {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	credential, err := s.useCase.CreateEnrollment(
		r.Context(), principal, hostID, httpx.RequestIDFromContext(r.Context()),
	)
	if writeError(w, r, err) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.JSON(w, http.StatusCreated, map[string]any{
		"enrollment_id":    credential.EnrollmentID,
		"managed_host_id":  credential.ManagedHostID,
		"enrollment_token": credential.Token,
		"expires_at":       credential.ExpiresAt,
	})
}

func (s *HTTP) exchangeEnrollment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	var request struct {
		EnrollmentToken string   `json:"enrollment_token"`
		InstanceID      string   `json:"instance_id"`
		AgentVersion    string   `json:"agent_version"`
		ProtocolVersion string   `json:"protocol_version"`
		Capabilities    []string `json:"capabilities"`
		CSRPEM          string   `json:"csr_pem"`
	}
	if !decodeRequest(w, r, &request) {
		return
	}
	credentials, err := s.useCase.ExchangeEnrollment(
		r.Context(),
		request.EnrollmentToken,
		request.InstanceID,
		request.AgentVersion,
		request.ProtocolVersion,
		request.Capabilities,
		[]byte(request.CSRPEM),
		httpx.RequestIDFromContext(r.Context()),
	)
	if writeError(w, r, err) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.JSON(w, http.StatusCreated, map[string]any{
		"agent_identity_id":      credentials.Identity.ID,
		"managed_host_id":        credentials.Identity.ManagedHostID,
		"certificate_pem":        string(credentials.CertificatePEM),
		"ca_certificate_pem":     string(credentials.CACertificatePEM),
		"certificate_expires_at": credentials.Identity.CertificateExpires,
	})
}

func (s *HTTP) collection(
	w http.ResponseWriter,
	r *http.Request,
	principal security.Principal,
) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.useCase.List(r.Context(), principal)
		if writeError(w, r, err) {
			return
		}
		responses := make([]hostResponse, len(items))
		for index, item := range items {
			responses[index] = hostResponseFromDomain(item)
		}
		httpx.JSON(w, http.StatusOK, map[string]any{"items": responses})
	case http.MethodPost:
		var request struct {
			Name           string             `json:"name"`
			ConnectionMode runtimeaccess.Mode `json:"connection_mode"`
			DirectSSHRef   string             `json:"direct_ssh_ref"`
		}
		if !decodeRequest(w, r, &request) {
			return
		}
		item, err := s.useCase.Create(
			r.Context(), principal, request.Name, request.ConnectionMode,
			request.DirectSSHRef, httpx.RequestIDFromContext(r.Context()),
		)
		if writeError(w, r, err) {
			return
		}
		httpx.JSON(w, http.StatusCreated, hostResponseFromDomain(item))
	default:
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func (s *HTTP) item(
	w http.ResponseWriter,
	r *http.Request,
	principal security.Principal,
	hostID string,
) {
	if r.Method != http.MethodGet {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	item, err := s.useCase.Get(r.Context(), principal, hostID)
	if writeError(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, hostResponseFromDomain(item))
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
		httpx.ErrorRequest(w, r, http.StatusNotFound, "managed_host_not_found")
	case errors.Is(err, biz.ErrDuplicateName):
		httpx.ErrorRequest(w, r, http.StatusConflict, "managed_host_name_conflict")
	case errors.Is(err, biz.ErrInvalidHost):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_managed_host")
	case errors.Is(err, biz.ErrInvalidEnrollment),
		errors.Is(err, biz.ErrInvalidAgentIdentity):
		httpx.ErrorRequest(w, r, http.StatusUnauthorized, "invalid_agent_enrollment")
	case errors.Is(err, biz.ErrEnrollmentNotAllowed):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "agent_enrollment_not_allowed")
	case errors.Is(err, biz.ErrEnrollmentUnavailable):
		httpx.ErrorRequest(w, r, http.StatusServiceUnavailable, "agent_enrollment_unavailable")
	default:
		httpx.ErrorRequest(w, r, http.StatusInternalServerError, "internal_error")
	}
	return true
}

type hostResponse struct {
	ID                        string             `json:"id"`
	OrganizationID            string             `json:"organization_id"`
	Name                      string             `json:"name"`
	Status                    biz.Status         `json:"status"`
	ConnectionMode            runtimeaccess.Mode `json:"connection_mode"`
	AgentIdentityID           string             `json:"agent_identity_id,omitempty"`
	AgentInstanceID           string             `json:"agent_instance_id,omitempty"`
	AgentCertificateExpiresAt *time.Time         `json:"agent_certificate_expires_at,omitempty"`
	DirectSSHRef              string             `json:"direct_ssh_ref,omitempty"`
	LastSeenAt                *time.Time         `json:"last_seen_at,omitempty"`
	AgentVersion              string             `json:"agent_version,omitempty"`
	ProtocolVersion           string             `json:"protocol_version,omitempty"`
	Capabilities              []string           `json:"capabilities"`
	CreatedBy                 string             `json:"created_by"`
	CreatedAt                 time.Time          `json:"created_at"`
	UpdatedAt                 time.Time          `json:"updated_at"`
}

func hostResponseFromDomain(item biz.ManagedHost) hostResponse {
	response := hostResponse{
		ID: item.ID, OrganizationID: item.OrganizationID, Name: item.Name,
		Status: item.Status, ConnectionMode: item.ConnectionMode,
		AgentIdentityID: item.AgentIdentityID, AgentInstanceID: item.AgentInstanceID,
		DirectSSHRef: item.DirectSSHRef, AgentVersion: item.AgentVersion,
		ProtocolVersion: item.ProtocolVersion, Capabilities: item.Capabilities,
		CreatedBy: item.CreatedBy, CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt,
	}
	if !item.AgentCertificateExpiresAt.IsZero() {
		expiresAt := item.AgentCertificateExpiresAt
		response.AgentCertificateExpiresAt = &expiresAt
	}
	if !item.LastSeenAt.IsZero() {
		lastSeenAt := item.LastSeenAt
		response.LastSeenAt = &lastSeenAt
	}
	return response
}
