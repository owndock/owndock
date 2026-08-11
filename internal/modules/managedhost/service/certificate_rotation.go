package service

import (
	"errors"
	"net/http"

	"github.com/owndock/owndock/internal/modules/managedhost/biz"
	"github.com/owndock/owndock/internal/platform/httpx"
)

type AgentCertificateRotationHTTP struct {
	useCase *biz.UseCase
}

func NewAgentCertificateRotationHTTP(useCase *biz.UseCase) *AgentCertificateRotationHTTP {
	return &AgentCertificateRotationHTTP{useCase: useCase}
}

func (h *AgentCertificateRotationHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if h.useCase == nil {
		httpx.ErrorRequest(w, r, http.StatusServiceUnavailable, "agent_certificate_rotation_unavailable")
		return
	}
	presented, err := agentCertificateIdentity(r)
	if err != nil {
		httpx.ErrorRequest(w, r, http.StatusUnauthorized, "invalid_agent_identity")
		return
	}
	var request struct {
		RotationID string `json:"rotation_id"`
		CSRPEM     string `json:"csr_pem"`
	}
	if !decodeRequest(w, r, &request) {
		return
	}
	credentials, err := h.useCase.RotateAgentCertificate(
		r.Context(), presented, request.RotationID, []byte(request.CSRPEM),
		httpx.RequestIDFromContext(r.Context()),
	)
	switch {
	case err == nil:
	case errors.Is(err, biz.ErrInvalidAgentIdentity):
		httpx.ErrorRequest(w, r, http.StatusUnauthorized, "invalid_agent_identity")
		return
	case errors.Is(err, biz.ErrAgentCertificateRotation):
		httpx.ErrorRequest(w, r, http.StatusServiceUnavailable, "agent_certificate_rotation_unavailable")
		return
	default:
		httpx.ErrorRequest(w, r, http.StatusInternalServerError, "internal_error")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.JSON(w, http.StatusCreated, map[string]any{
		"agent_identity_id":      credentials.Identity.ID,
		"managed_host_id":        credentials.Identity.ManagedHostID,
		"rotation_id":            request.RotationID,
		"certificate_pem":        string(credentials.CertificatePEM),
		"ca_certificate_pem":     string(credentials.CACertificatePEM),
		"certificate_expires_at": credentials.Identity.CertificateExpires,
	})
}
