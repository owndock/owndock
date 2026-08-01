package service

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/modules/build/biz"
	"github.com/owndock/owndock/internal/platform/httpx"
	"github.com/owndock/owndock/internal/shared/security"
)

type HTTP struct {
	useCase *biz.UseCase
}

func NewHTTP(useCase *biz.UseCase) *HTTP {
	return &HTTP{useCase: useCase}
}

func (s *HTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	principal, ok := security.PrincipalFromContext(r.Context())
	if !ok {
		writeError(w, r, security.ErrUnauthenticated)
		return
	}
	segments := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(segments) < 5 || len(segments) > 7 || segments[0] != "api" ||
		segments[1] != "v1" || segments[2] != "projects" || segments[3] == "" {
		httpx.ErrorRequest(w, r, http.StatusNotFound, "not_found")
		return
	}
	projectID := segments[3]
	switch {
	case len(segments) == 5 && segments[4] == "repository-credentials":
		s.credentials(w, r, principal, projectID)
	case len(segments) == 5 && segments[4] == "source-repositories":
		s.sources(w, r, principal, projectID)
	case len(segments) == 6 && segments[4] == "source-repositories" && segments[5] != "":
		s.source(w, r, principal, projectID, segments[5])
	case len(segments) == 7 && segments[4] == "source-repositories" &&
		segments[5] != "" && segments[6] == "probe":
		s.probeSource(w, r, principal, projectID, segments[5])
	default:
		httpx.ErrorRequest(w, r, http.StatusNotFound, "not_found")
	}
}

func (s *HTTP) probeSource(
	w http.ResponseWriter,
	r *http.Request,
	principal security.Principal,
	projectID, sourceID string,
) {
	if r.Method != http.MethodPost {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	item, err := s.useCase.ProbeSource(
		r.Context(), principal, projectID, sourceID,
		httpx.RequestIDFromContext(r.Context()),
	)
	if writeError(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, sourceResponseFromDomain(item))
}

func (s *HTTP) credentials(
	w http.ResponseWriter,
	r *http.Request,
	principal security.Principal,
	projectID string,
) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.useCase.ListCredentials(r.Context(), principal, projectID)
		if writeError(w, r, err) {
			return
		}
		responses := make([]credentialResponse, len(items))
		for index, item := range items {
			responses[index] = credentialResponseFromDomain(item)
		}
		httpx.JSON(w, http.StatusOK, map[string]any{"items": responses})
	case http.MethodPost:
		var request struct {
			Name                 string             `json:"name"`
			Type                 biz.CredentialType `json:"type"`
			Username             string             `json:"username"`
			SecretRef            string             `json:"secret_ref"`
			PublicKeyFingerprint string             `json:"public_key_fingerprint"`
		}
		if !decodeRequest(w, r, &request) {
			return
		}
		item, err := s.useCase.CreateCredential(
			r.Context(), principal, projectID, request.Name, request.Type,
			request.Username, request.SecretRef, request.PublicKeyFingerprint,
			httpx.RequestIDFromContext(r.Context()),
		)
		if writeError(w, r, err) {
			return
		}
		httpx.JSON(w, http.StatusCreated, credentialResponseFromDomain(item))
	default:
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func (s *HTTP) sources(
	w http.ResponseWriter,
	r *http.Request,
	principal security.Principal,
	projectID string,
) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.useCase.ListSources(r.Context(), principal, projectID)
		if writeError(w, r, err) {
			return
		}
		responses := make([]sourceResponse, len(items))
		for index, item := range items {
			responses[index] = sourceResponseFromDomain(item)
		}
		httpx.JSON(w, http.StatusOK, map[string]any{"items": responses})
	case http.MethodPost:
		var request struct {
			Name                  string `json:"name"`
			RepositoryURL         string `json:"repository_url"`
			DefaultBranch         string `json:"default_branch"`
			CredentialID          string `json:"credential_id"`
			SSHHostKeyFingerprint string `json:"ssh_host_key_fingerprint"`
		}
		if !decodeRequest(w, r, &request) {
			return
		}
		item, err := s.useCase.CreateSource(
			r.Context(), principal, projectID, request.Name, request.RepositoryURL,
			request.DefaultBranch, request.CredentialID,
			request.SSHHostKeyFingerprint,
			httpx.RequestIDFromContext(r.Context()),
		)
		if writeError(w, r, err) {
			return
		}
		httpx.JSON(w, http.StatusCreated, sourceResponseFromDomain(item))
	default:
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func (s *HTTP) source(
	w http.ResponseWriter,
	r *http.Request,
	principal security.Principal,
	projectID, sourceID string,
) {
	if r.Method != http.MethodGet {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	item, err := s.useCase.GetSource(r.Context(), principal, projectID, sourceID)
	if writeError(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, sourceResponseFromDomain(item))
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
		httpx.ErrorRequest(w, r, http.StatusNotFound, "not_found")
	case errors.Is(err, biz.ErrDuplicateName):
		httpx.ErrorRequest(w, r, http.StatusConflict, "name_conflict")
	case errors.Is(err, biz.ErrInvalidCredential):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_repository_credential")
	case errors.Is(err, biz.ErrInvalidSourceRepository):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_source_repository")
	case errors.Is(err, biz.ErrCredentialProtocolMismatch):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "repository_credential_protocol_mismatch")
	case errors.Is(err, biz.ErrSourceProbeUnavailable):
		httpx.ErrorRequest(w, r, http.StatusServiceUnavailable, "source_repository_probe_unavailable")
	default:
		httpx.ErrorRequest(w, r, http.StatusInternalServerError, "internal_error")
	}
	return true
}

type credentialResponse struct {
	ID                   string             `json:"id"`
	ProjectID            string             `json:"project_id"`
	Name                 string             `json:"name"`
	Type                 biz.CredentialType `json:"type"`
	Username             string             `json:"username,omitempty"`
	SecretConfigured     bool               `json:"secret_configured"`
	PublicKeyFingerprint string             `json:"public_key_fingerprint,omitempty"`
	Version              uint64             `json:"version"`
	CreatedBy            string             `json:"created_by"`
	CreatedAt            time.Time          `json:"created_at"`
}

func credentialResponseFromDomain(item biz.CredentialSummary) credentialResponse {
	return credentialResponse{
		ID: item.ID, ProjectID: item.ProjectID, Name: item.Name, Type: item.Type,
		Username: item.Username, SecretConfigured: item.SecretConfigured,
		PublicKeyFingerprint: item.PublicKeyFingerprint,
		Version:              item.Version, CreatedBy: item.CreatedBy, CreatedAt: item.CreatedAt,
	}
}

type sourceResponse struct {
	ID                    string                     `json:"id"`
	ProjectID             string                     `json:"project_id"`
	Name                  string                     `json:"name"`
	RepositoryURL         string                     `json:"repository_url"`
	Protocol              biz.RepositoryProtocol     `json:"protocol"`
	DefaultBranch         string                     `json:"default_branch"`
	CredentialID          string                     `json:"credential_id,omitempty"`
	SSHHostKeyFingerprint string                     `json:"ssh_host_key_fingerprint,omitempty"`
	Status                biz.SourceRepositoryStatus `json:"status"`
	LastProbedAt          *time.Time                 `json:"last_probed_at,omitempty"`
	CreatedBy             string                     `json:"created_by"`
	CreatedAt             time.Time                  `json:"created_at"`
	UpdatedAt             time.Time                  `json:"updated_at"`
}

func sourceResponseFromDomain(item biz.SourceRepository) sourceResponse {
	response := sourceResponse{
		ID: item.ID, ProjectID: item.ProjectID, Name: item.Name,
		RepositoryURL: item.RepositoryURL, Protocol: item.Protocol,
		DefaultBranch: item.DefaultBranch, CredentialID: item.CredentialID,
		SSHHostKeyFingerprint: item.SSHHostKeyFingerprint,
		Status:                item.Status, CreatedBy: item.CreatedBy,
		CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt,
	}
	if !item.LastProbedAt.IsZero() {
		lastProbedAt := item.LastProbedAt
		response.LastProbedAt = &lastProbedAt
	}
	return response
}
