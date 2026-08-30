package service

import (
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/modules/supplychain/biz"
	"github.com/owndock/owndock/internal/platform/httpx"
	"github.com/owndock/owndock/internal/shared/security"
)

type HTTP struct {
	useCase                *biz.UseCase
	trustPolicies          *biz.SignatureTrustPolicyUseCase
	signatureVerifications *biz.SignatureVerificationUseCase
	signingProfiles        *biz.SignatureSigningProfileUseCase
	vulnerabilityScans     *biz.VulnerabilityScanUseCase
	vulnerabilityWaivers   *biz.VulnerabilityWaiverUseCase
	deploymentPolicies     *biz.DeploymentPolicyUseCase
}

func (s *HTTP) WithDeploymentPolicies(useCase *biz.DeploymentPolicyUseCase) *HTTP {
	s.deploymentPolicies = useCase
	return s
}

func (s *HTTP) WithVulnerabilityWaivers(useCase *biz.VulnerabilityWaiverUseCase) *HTTP {
	s.vulnerabilityWaivers = useCase
	return s
}

func (s *HTTP) WithVulnerabilityScans(useCase *biz.VulnerabilityScanUseCase) *HTTP {
	s.vulnerabilityScans = useCase
	return s
}

func (s *HTTP) WithSignatureSigningProfiles(useCase *biz.SignatureSigningProfileUseCase) *HTTP {
	s.signingProfiles = useCase
	return s
}

func (s *HTTP) WithSignatureVerifications(useCase *biz.SignatureVerificationUseCase) *HTTP {
	s.signatureVerifications = useCase
	return s
}

func NewHTTP(useCase *biz.UseCase) *HTTP { return &HTTP{useCase: useCase} }

func (s *HTTP) WithSignatureTrustPolicies(useCase *biz.SignatureTrustPolicyUseCase) *HTTP {
	s.trustPolicies = useCase
	return s
}

func (s *HTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	principal, ok := security.PrincipalFromContext(r.Context())
	if !ok {
		writeError(w, r, security.ErrUnauthenticated)
		return
	}
	segments := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(segments) >= 5 && len(segments) <= 6 && segments[0] == "api" &&
		segments[1] == "v1" && segments[2] == "projects" && segments[3] != "" &&
		segments[4] == "deployment-policies" {
		s.serveDeploymentPolicies(w, r, principal, segments)
		return
	}
	if len(segments) >= 5 && len(segments) <= 6 && segments[0] == "api" &&
		segments[1] == "v1" && segments[2] == "projects" && segments[3] != "" &&
		segments[4] == "vulnerability-waivers" {
		s.serveVulnerabilityWaivers(w, r, principal, segments)
		return
	}
	if len(segments) >= 5 && len(segments) <= 6 && segments[0] == "api" &&
		segments[1] == "v1" && segments[2] == "projects" && segments[3] != "" &&
		segments[4] == "signature-trust-policies" {
		s.serveTrustPolicies(w, r, principal, segments)
		return
	}
	if len(segments) >= 5 && len(segments) <= 6 && segments[0] == "api" &&
		segments[1] == "v1" && segments[2] == "projects" && segments[3] != "" &&
		segments[4] == "signature-signing-profiles" {
		s.serveSigningProfiles(w, r, principal, segments)
		return
	}
	if len(segments) == 7 && segments[0] == "api" && segments[1] == "v1" &&
		segments[2] == "projects" && segments[3] != "" && segments[4] == "artifacts" &&
		segments[5] != "" && segments[6] == "signature-verifications" {
		s.serveSignatureVerificationSchedule(w, r, principal, segments[3], segments[5])
		return
	}
	if len(segments) == 7 && segments[0] == "api" && segments[1] == "v1" &&
		segments[2] == "projects" && segments[3] != "" && segments[4] == "artifacts" &&
		segments[5] != "" && segments[6] == "vulnerability-observation" {
		s.serveVulnerabilityObservation(w, r, principal, segments[3], segments[5])
		return
	}
	if len(segments) == 7 && segments[0] == "api" && segments[1] == "v1" &&
		segments[2] == "projects" && segments[3] != "" && segments[4] == "artifacts" &&
		segments[5] != "" && segments[6] == "vulnerability-scans" {
		s.serveVulnerabilityScanSchedule(w, r, principal, segments[3], segments[5])
		return
	}
	if len(segments) < 7 || len(segments) > 8 || segments[0] != "api" ||
		segments[1] != "v1" || segments[2] != "projects" || segments[3] == "" ||
		segments[4] != "artifacts" || segments[5] == "" ||
		(segments[6] != "evidence" && segments[6] != "verifications") {
		httpx.ErrorRequest(w, r, http.StatusNotFound, "not_found")
		return
	}
	if r.Method != http.MethodGet {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if segments[6] == "verifications" {
		if len(segments) != 7 || len(r.URL.Query()) != 0 {
			httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_artifact_evidence_query")
			return
		}
		items, err := s.useCase.ListEvidenceVerifications(r.Context(), principal, segments[3], segments[5])
		if writeError(w, r, err) {
			return
		}
		responses := make([]verificationResponse, len(items))
		for index := range items {
			responses[index] = verificationResponseFromDomain(items[index])
		}
		httpx.JSON(w, http.StatusOK, map[string]any{"items": responses})
		return
	}
	if len(r.URL.Query()) != 0 {
		httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_artifact_evidence_query")
		return
	}
	if len(segments) == 7 {
		items, err := s.useCase.ListEvidence(r.Context(), principal, segments[3], segments[5])
		if writeError(w, r, err) {
			return
		}
		responses := make([]evidenceResponse, len(items))
		for index := range items {
			responses[index] = responseFromDomain(items[index])
		}
		httpx.JSON(w, http.StatusOK, evidenceListResponse{Items: responses})
		return
	}
	if segments[7] == "" {
		httpx.ErrorRequest(w, r, http.StatusNotFound, "not_found")
		return
	}
	if evidenceID, download := strings.CutSuffix(segments[7], ":download"); download {
		if evidenceID == "" {
			httpx.ErrorRequest(w, r, http.StatusNotFound, "not_found")
			return
		}
		item, content, err := s.useCase.DownloadEvidence(
			r.Context(), principal, segments[3], segments[5], evidenceID,
		)
		if writeError(w, r, err) {
			return
		}
		filename := "owndock-" + strings.ReplaceAll(string(item.Kind), "_", "-") + "-" + item.ID + ".json"
		w.Header().Set("Content-Type", content.MediaType)
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": filename}))
		w.Header().Set("Content-Length", strconv.Itoa(len(content.Content)))
		w.Header().Set("ETag", `"`+content.Digest+`"`)
		w.Header().Set("X-OwnDock-Content-Digest", content.Digest)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content.Content)
		return
	}
	item, err := s.useCase.GetEvidence(r.Context(), principal, segments[3], segments[5], segments[7])
	if writeError(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, responseFromDomain(item))
}

type deploymentPolicyRequirementsRequest struct {
	RequireSBOM                  bool                      `json:"require_sbom"`
	RequireProvenance            bool                      `json:"require_provenance"`
	AllowedSignaturePolicyIDs    []string                  `json:"allowed_signature_policy_ids"`
	MaximumVulnerabilitySeverity biz.VulnerabilitySeverity `json:"maximum_vulnerability_severity"`
	MaximumScanAgeSeconds        int64                     `json:"maximum_scan_age_seconds"`
}

type deploymentPolicyRequest struct {
	Name            string                              `json:"name"`
	Scope           biz.DeploymentPolicyScope           `json:"scope"`
	EnvironmentID   string                              `json:"environment_id"`
	Mode            biz.DeploymentPolicyMode            `json:"mode"`
	Requirements    deploymentPolicyRequirementsRequest `json:"requirements"`
	Enabled         bool                                `json:"enabled"`
	ExpectedVersion uint64                              `json:"expected_version,omitempty"`
}

type deploymentPolicyRequirementsResponse struct {
	RequireSBOM                  bool                      `json:"require_sbom"`
	RequireProvenance            bool                      `json:"require_provenance"`
	AllowedSignaturePolicyIDs    []string                  `json:"allowed_signature_policy_ids"`
	MaximumVulnerabilitySeverity biz.VulnerabilitySeverity `json:"maximum_vulnerability_severity,omitempty"`
	MaximumScanAgeSeconds        int64                     `json:"maximum_scan_age_seconds,omitempty"`
}

type deploymentPolicyResponse struct {
	ID             string                               `json:"id"`
	OrganizationID string                               `json:"organization_id"`
	ProjectID      string                               `json:"project_id"`
	Name           string                               `json:"name"`
	Scope          biz.DeploymentPolicyScope            `json:"scope"`
	EnvironmentID  string                               `json:"environment_id,omitempty"`
	Mode           biz.DeploymentPolicyMode             `json:"mode"`
	Requirements   deploymentPolicyRequirementsResponse `json:"requirements"`
	Enabled        bool                                 `json:"enabled"`
	Version        uint64                               `json:"version"`
	CreatedBy      string                               `json:"created_by"`
	UpdatedBy      string                               `json:"updated_by"`
	CreatedAt      time.Time                            `json:"created_at"`
	UpdatedAt      time.Time                            `json:"updated_at"`
}

func (s *HTTP) serveDeploymentPolicies(w http.ResponseWriter, r *http.Request,
	principal security.Principal, segments []string) {
	if s.deploymentPolicies == nil {
		httpx.ErrorRequest(w, r, http.StatusServiceUnavailable, "deployment_policy_unavailable")
		return
	}
	projectID := segments[3]
	if len(segments) == 5 {
		switch r.Method {
		case http.MethodGet:
			if len(r.URL.Query()) != 0 {
				httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_deployment_policy")
				return
			}
			items, err := s.deploymentPolicies.List(r.Context(), principal, projectID)
			if writeError(w, r, err) {
				return
			}
			responses := make([]deploymentPolicyResponse, len(items))
			for index := range items {
				responses[index] = deploymentPolicyResponseFromDomain(items[index])
			}
			httpx.JSON(w, http.StatusOK, map[string]any{"items": responses})
		case http.MethodPost:
			request, ok := decodeDeploymentPolicyRequest(w, r)
			if !ok {
				return
			}
			if request.ExpectedVersion != 0 {
				httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_deployment_policy")
				return
			}
			input, err := request.domain()
			if err != nil {
				writeError(w, r, err)
				return
			}
			item, err := s.deploymentPolicies.Create(r.Context(), principal, projectID, input,
				r.Header.Get("X-Request-ID"))
			if writeError(w, r, err) {
				return
			}
			httpx.JSON(w, http.StatusCreated, deploymentPolicyResponseFromDomain(item))
		default:
			httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		}
		return
	}
	if segments[5] == "" {
		httpx.ErrorRequest(w, r, http.StatusNotFound, "not_found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		if len(r.URL.Query()) != 0 {
			httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_deployment_policy")
			return
		}
		item, err := s.deploymentPolicies.Get(r.Context(), principal, projectID, segments[5])
		if writeError(w, r, err) {
			return
		}
		httpx.JSON(w, http.StatusOK, deploymentPolicyResponseFromDomain(item))
	case http.MethodPatch:
		request, ok := decodeDeploymentPolicyRequest(w, r)
		if !ok {
			return
		}
		input, err := request.domain()
		if err != nil {
			writeError(w, r, err)
			return
		}
		item, err := s.deploymentPolicies.Update(r.Context(), principal, projectID, segments[5],
			request.ExpectedVersion, input, r.Header.Get("X-Request-ID"))
		if writeError(w, r, err) {
			return
		}
		httpx.JSON(w, http.StatusOK, deploymentPolicyResponseFromDomain(item))
	default:
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func decodeDeploymentPolicyRequest(w http.ResponseWriter, r *http.Request) (deploymentPolicyRequest, bool) {
	if r.Header.Get("Content-Type") != "application/json" {
		httpx.ErrorRequest(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return deploymentPolicyRequest{}, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32*1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request deploymentPolicyRequest
	if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) == nil {
		httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_deployment_policy")
		return deploymentPolicyRequest{}, false
	}
	return request, true
}

func (r deploymentPolicyRequest) domain() (biz.DeploymentPolicyInput, error) {
	if r.Requirements.MaximumScanAgeSeconds < 0 ||
		r.Requirements.MaximumScanAgeSeconds > int64(biz.MaximumDeploymentPolicyScanAge/time.Second) {
		return biz.DeploymentPolicyInput{}, biz.ErrInvalidDeploymentPolicy
	}
	return biz.DeploymentPolicyInput{Name: r.Name, Scope: r.Scope, EnvironmentID: r.EnvironmentID,
		Mode: r.Mode, Requirements: biz.DeploymentPolicyRequirements{
			RequireSBOM: r.Requirements.RequireSBOM, RequireProvenance: r.Requirements.RequireProvenance,
			AllowedSignaturePolicyIDs:    append([]string(nil), r.Requirements.AllowedSignaturePolicyIDs...),
			MaximumVulnerabilitySeverity: r.Requirements.MaximumVulnerabilitySeverity,
			MaximumScanAge:               time.Duration(r.Requirements.MaximumScanAgeSeconds) * time.Second,
		}, Enabled: r.Enabled}, nil
}

func deploymentPolicyResponseFromDomain(item biz.DeploymentPolicy) deploymentPolicyResponse {
	return deploymentPolicyResponse{ID: item.ID, OrganizationID: item.OrganizationID,
		ProjectID: item.ProjectID, Name: item.Name, Scope: item.Scope, EnvironmentID: item.EnvironmentID,
		Mode: item.Mode, Requirements: deploymentPolicyRequirementsResponse{
			RequireSBOM: item.Requirements.RequireSBOM, RequireProvenance: item.Requirements.RequireProvenance,
			AllowedSignaturePolicyIDs:    append([]string(nil), item.Requirements.AllowedSignaturePolicyIDs...),
			MaximumVulnerabilitySeverity: item.Requirements.MaximumVulnerabilitySeverity,
			MaximumScanAgeSeconds:        int64(item.Requirements.MaximumScanAge / time.Second),
		}, Enabled: item.Enabled, Version: item.Version, CreatedBy: item.CreatedBy, UpdatedBy: item.UpdatedBy,
		CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt}
}

func (s *HTTP) serveVulnerabilityScanSchedule(w http.ResponseWriter, r *http.Request,
	principal security.Principal, projectID, artifactID string) {
	if r.Method != http.MethodPost {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if len(r.URL.Query()) != 0 {
		httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_vulnerability_scan")
		return
	}
	if s.vulnerabilityScans == nil {
		httpx.ErrorRequest(w, r, http.StatusServiceUnavailable, "vulnerability_scan_unavailable")
		return
	}
	result, err := s.vulnerabilityScans.Schedule(r.Context(), principal, projectID, artifactID,
		r.Header.Get("Idempotency-Key"))
	if writeError(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusAccepted, map[string]any{"job_id": result.JobID, "scheduled": result.Scheduled})
}

type vulnerabilityCountsResponse struct {
	Unknown  uint64 `json:"unknown"`
	Low      uint64 `json:"low"`
	Medium   uint64 `json:"medium"`
	High     uint64 `json:"high"`
	Critical uint64 `json:"critical"`
	Total    uint64 `json:"total"`
	Fixable  uint64 `json:"fixable"`
}

type vulnerabilityObservationResponse struct {
	ID                    string                      `json:"id"`
	OrganizationID        string                      `json:"organization_id"`
	ProjectID             string                      `json:"project_id"`
	ArtifactID            string                      `json:"artifact_id"`
	SubjectDigest         string                      `json:"subject_digest"`
	EvidenceID            string                      `json:"evidence_id"`
	DescriptorDigest      string                      `json:"descriptor_digest"`
	Scanner               string                      `json:"scanner"`
	ScannerVersion        string                      `json:"scanner_version"`
	DatabaseSchemaVersion uint64                      `json:"database_schema_version"`
	DatabaseUpdatedAt     time.Time                   `json:"database_updated_at"`
	DatabaseDownloadedAt  time.Time                   `json:"database_downloaded_at"`
	ScannedAt             time.Time                   `json:"scanned_at"`
	FreshUntil            time.Time                   `json:"fresh_until"`
	Stale                 bool                        `json:"stale"`
	Counts                vulnerabilityCountsResponse `json:"counts"`
	HighestSeverity       biz.VulnerabilitySeverity   `json:"highest_severity"`
}

func (s *HTTP) serveVulnerabilityObservation(w http.ResponseWriter, r *http.Request,
	principal security.Principal, projectID, artifactID string) {
	if r.Method != http.MethodGet {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if len(r.URL.Query()) != 0 {
		httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_artifact_evidence_query")
		return
	}
	state, err := s.useCase.GetLatestVulnerabilityObservation(r.Context(), principal, projectID, artifactID)
	if writeError(w, r, err) {
		return
	}
	item := state.Observation
	httpx.JSON(w, http.StatusOK, vulnerabilityObservationResponse{ID: item.ID,
		OrganizationID: item.OrganizationID, ProjectID: item.ProjectID, ArtifactID: item.ArtifactID,
		SubjectDigest: item.SubjectDigest, EvidenceID: item.EvidenceID, DescriptorDigest: item.DescriptorDigest,
		Scanner: item.Scanner, ScannerVersion: item.ScannerVersion,
		DatabaseSchemaVersion: item.Database.SchemaVersion, DatabaseUpdatedAt: item.Database.UpdatedAt,
		DatabaseDownloadedAt: item.Database.DownloadedAt, ScannedAt: item.ScannedAt,
		FreshUntil: item.FreshUntil, Stale: state.Stale,
		Counts: vulnerabilityCountsResponse{Unknown: item.Counts.Unknown, Low: item.Counts.Low,
			Medium: item.Counts.Medium, High: item.Counts.High, Critical: item.Counts.Critical,
			Total: item.Counts.Total, Fixable: item.Counts.Fixable}, HighestSeverity: item.HighestSeverity})
}

type vulnerabilityWaiverRequest struct {
	Scope           biz.VulnerabilityWaiverScope `json:"scope"`
	ArtifactID      string                       `json:"artifact_id,omitempty"`
	VulnerabilityID string                       `json:"vulnerability_id"`
	Reason          string                       `json:"reason"`
	ExpiresAt       time.Time                    `json:"expires_at"`
}

type vulnerabilityWaiverRevokeRequest struct {
	Reason          string `json:"reason"`
	ExpectedVersion uint64 `json:"expected_version"`
}

type vulnerabilityWaiverResponse struct {
	ID               string                        `json:"id"`
	OrganizationID   string                        `json:"organization_id"`
	ProjectID        string                        `json:"project_id"`
	Scope            biz.VulnerabilityWaiverScope  `json:"scope"`
	ArtifactID       string                        `json:"artifact_id,omitempty"`
	SubjectDigest    string                        `json:"subject_digest,omitempty"`
	VulnerabilityID  string                        `json:"vulnerability_id"`
	Reason           string                        `json:"reason"`
	ApprovedBy       string                        `json:"approved_by"`
	ExpiresAt        time.Time                     `json:"expires_at"`
	Status           biz.VulnerabilityWaiverStatus `json:"status"`
	Version          uint64                        `json:"version"`
	CreatedAt        time.Time                     `json:"created_at"`
	RevokedAt        *time.Time                    `json:"revoked_at,omitempty"`
	RevokedBy        string                        `json:"revoked_by,omitempty"`
	RevocationReason string                        `json:"revocation_reason,omitempty"`
}

func (s *HTTP) serveVulnerabilityWaivers(w http.ResponseWriter, r *http.Request,
	principal security.Principal, segments []string) {
	if s.vulnerabilityWaivers == nil {
		httpx.ErrorRequest(w, r, http.StatusServiceUnavailable, "vulnerability_waiver_unavailable")
		return
	}
	projectID := segments[3]
	if len(segments) == 5 {
		switch r.Method {
		case http.MethodGet:
			query, ok := decodeVulnerabilityWaiverQuery(w, r)
			if !ok {
				return
			}
			page, err := s.vulnerabilityWaivers.List(r.Context(), principal, projectID, query)
			if writeError(w, r, err) {
				return
			}
			items := make([]vulnerabilityWaiverResponse, len(page.Items))
			for index := range page.Items {
				items[index] = s.vulnerabilityWaiverResponse(page.Items[index])
			}
			httpx.JSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": page.NextCursor})
		case http.MethodPost:
			request, ok := decodeVulnerabilityWaiverRequest(w, r)
			if !ok {
				return
			}
			item, err := s.vulnerabilityWaivers.Create(r.Context(), principal, projectID,
				biz.VulnerabilityWaiverInput{Scope: request.Scope, ArtifactID: request.ArtifactID,
					VulnerabilityID: request.VulnerabilityID, Reason: request.Reason,
					ExpiresAt: request.ExpiresAt}, httpx.RequestIDFromContext(r.Context()))
			if writeError(w, r, err) {
				return
			}
			httpx.JSON(w, http.StatusCreated, s.vulnerabilityWaiverResponse(item))
		default:
			httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		}
		return
	}
	waiverID, revoke := strings.CutSuffix(segments[5], ":revoke")
	if waiverID == "" {
		httpx.ErrorRequest(w, r, http.StatusNotFound, "not_found")
		return
	}
	if revoke {
		if r.Method != http.MethodPost {
			httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		request, ok := decodeVulnerabilityWaiverRevokeRequest(w, r)
		if !ok {
			return
		}
		item, err := s.vulnerabilityWaivers.Revoke(r.Context(), principal, projectID, waiverID,
			request.Reason, httpx.RequestIDFromContext(r.Context()), request.ExpectedVersion)
		if writeError(w, r, err) {
			return
		}
		httpx.JSON(w, http.StatusOK, s.vulnerabilityWaiverResponse(item))
		return
	}
	if r.Method != http.MethodGet {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if len(r.URL.Query()) != 0 {
		httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_vulnerability_waiver_query")
		return
	}
	item, err := s.vulnerabilityWaivers.Get(r.Context(), principal, projectID, waiverID)
	if writeError(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, s.vulnerabilityWaiverResponse(item))
}

func decodeVulnerabilityWaiverRequest(w http.ResponseWriter, r *http.Request) (vulnerabilityWaiverRequest, bool) {
	var request vulnerabilityWaiverRequest
	if !decodeVulnerabilityWaiverJSON(w, r, &request) {
		return vulnerabilityWaiverRequest{}, false
	}
	return request, true
}

func decodeVulnerabilityWaiverRevokeRequest(w http.ResponseWriter,
	r *http.Request) (vulnerabilityWaiverRevokeRequest, bool) {
	var request vulnerabilityWaiverRevokeRequest
	if !decodeVulnerabilityWaiverJSON(w, r, &request) {
		return vulnerabilityWaiverRevokeRequest{}, false
	}
	return request, true
}

func decodeVulnerabilityWaiverJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	if r.Header.Get("Content-Type") != "application/json" {
		httpx.ErrorRequest(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || decoder.Decode(&struct{}{}) == nil {
		httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_vulnerability_waiver")
		return false
	}
	return true
}

func decodeVulnerabilityWaiverQuery(w http.ResponseWriter, r *http.Request) (biz.VulnerabilityWaiverQuery, bool) {
	values := r.URL.Query()
	allowed := map[string]bool{"limit": true, "cursor": true, "vulnerability_id": true,
		"scope": true, "artifact_id": true, "status": true}
	for key, items := range values {
		if !allowed[key] || len(items) != 1 {
			httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_vulnerability_waiver_query")
			return biz.VulnerabilityWaiverQuery{}, false
		}
	}
	query := biz.VulnerabilityWaiverQuery{Cursor: values.Get("cursor"),
		VulnerabilityID: values.Get("vulnerability_id"),
		Scope:           biz.VulnerabilityWaiverScope(values.Get("scope")),
		ArtifactID:      values.Get("artifact_id"), ActiveOnly: true}
	if raw := values.Get("limit"); raw != "" {
		limit, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_vulnerability_waiver_query")
			return biz.VulnerabilityWaiverQuery{}, false
		}
		query.Limit = limit
	}
	switch values.Get("status") {
	case "", "active":
		query.ActiveOnly = true
	case "all":
		query.ActiveOnly = false
	default:
		httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_vulnerability_waiver_query")
		return biz.VulnerabilityWaiverQuery{}, false
	}
	return query, true
}

func (s *HTTP) vulnerabilityWaiverResponse(item biz.VulnerabilityWaiver) vulnerabilityWaiverResponse {
	response := vulnerabilityWaiverResponse{ID: item.ID, OrganizationID: item.OrganizationID,
		ProjectID: item.ProjectID, Scope: item.Scope, ArtifactID: item.ArtifactID,
		SubjectDigest: item.SubjectDigest, VulnerabilityID: item.VulnerabilityID,
		Reason: item.Reason, ApprovedBy: item.ApprovedBy, ExpiresAt: item.ExpiresAt,
		Status: s.vulnerabilityWaivers.CurrentStatus(item), Version: item.Version,
		CreatedAt: item.CreatedAt, RevokedBy: item.RevokedBy,
		RevocationReason: item.RevocationReason}
	if !item.RevokedAt.IsZero() {
		response.RevokedAt = &item.RevokedAt
	}
	return response
}

type signingProfileRequest struct {
	Name            string `json:"name"`
	KeyReference    string `json:"key_reference"`
	TrustPolicyID   string `json:"trust_policy_id"`
	Enabled         bool   `json:"enabled"`
	ExpectedVersion uint64 `json:"expected_version,omitempty"`
}

type signingProfileResponse struct {
	ID                      string                 `json:"id"`
	OrganizationID          string                 `json:"organization_id"`
	ProjectID               string                 `json:"project_id"`
	Name                    string                 `json:"name"`
	Provider                biz.SigningKeyProvider `json:"provider"`
	KeyReferenceFingerprint string                 `json:"key_reference_fingerprint"`
	TrustPolicyID           string                 `json:"trust_policy_id"`
	Enabled                 bool                   `json:"enabled"`
	Version                 uint64                 `json:"version"`
	CreatedAt               time.Time              `json:"created_at"`
	UpdatedAt               time.Time              `json:"updated_at"`
}

func (s *HTTP) serveSigningProfiles(w http.ResponseWriter, r *http.Request,
	principal security.Principal, segments []string) {
	if s.signingProfiles == nil {
		httpx.ErrorRequest(w, r, http.StatusServiceUnavailable, "signature_signing_profile_unavailable")
		return
	}
	projectID := segments[3]
	if len(segments) == 5 {
		switch r.Method {
		case http.MethodGet:
			if len(r.URL.Query()) != 0 {
				httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_signature_signing_profile")
				return
			}
			items, err := s.signingProfiles.List(r.Context(), principal, projectID)
			if writeError(w, r, err) {
				return
			}
			responses := make([]signingProfileResponse, len(items))
			for i := range items {
				responses[i] = signingProfileResponseFromDomain(items[i])
			}
			httpx.JSON(w, http.StatusOK, map[string]any{"items": responses})
		case http.MethodPost:
			input, ok := decodeSigningProfileRequest(w, r)
			if !ok {
				return
			}
			item, err := s.signingProfiles.Create(r.Context(), principal, projectID, input.domain())
			if writeError(w, r, err) {
				return
			}
			httpx.JSON(w, http.StatusCreated, signingProfileResponseFromDomain(item))
		default:
			httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		}
		return
	}
	if segments[5] == "" {
		httpx.ErrorRequest(w, r, http.StatusNotFound, "not_found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		if len(r.URL.Query()) != 0 {
			httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_signature_signing_profile")
			return
		}
		item, err := s.signingProfiles.Get(r.Context(), principal, projectID, segments[5])
		if writeError(w, r, err) {
			return
		}
		httpx.JSON(w, http.StatusOK, signingProfileResponseFromDomain(item))
	case http.MethodPatch:
		input, ok := decodeSigningProfileRequest(w, r)
		if !ok {
			return
		}
		item, err := s.signingProfiles.Update(r.Context(), principal, projectID, segments[5], input.ExpectedVersion, input.domain())
		if writeError(w, r, err) {
			return
		}
		httpx.JSON(w, http.StatusOK, signingProfileResponseFromDomain(item))
	default:
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func decodeSigningProfileRequest(w http.ResponseWriter, r *http.Request) (signingProfileRequest, bool) {
	if r.Header.Get("Content-Type") != "application/json" {
		httpx.ErrorRequest(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return signingProfileRequest{}, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request signingProfileRequest
	if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) == nil {
		httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_signature_signing_profile")
		return signingProfileRequest{}, false
	}
	return request, true
}

func (r signingProfileRequest) domain() biz.SignatureSigningProfileInput {
	return biz.SignatureSigningProfileInput{Name: r.Name, KeyReference: r.KeyReference,
		TrustPolicyID: r.TrustPolicyID, Enabled: r.Enabled}
}

func signingProfileResponseFromDomain(item biz.SignatureSigningProfile) signingProfileResponse {
	return signingProfileResponse{ID: item.ID, OrganizationID: item.OrganizationID, ProjectID: item.ProjectID,
		Name: item.Name, Provider: item.Provider, KeyReferenceFingerprint: item.KeyReferenceFingerprint,
		TrustPolicyID: item.TrustPolicyID, Enabled: item.Enabled, Version: item.Version,
		CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt}
}

type signatureVerificationRequest struct {
	PolicyID string `json:"policy_id"`
}

func (s *HTTP) serveSignatureVerificationSchedule(w http.ResponseWriter, r *http.Request,
	principal security.Principal, projectID, artifactID string) {
	if r.Method != http.MethodPost {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if s.signatureVerifications == nil {
		httpx.ErrorRequest(w, r, http.StatusServiceUnavailable, "signature_verification_unavailable")
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		httpx.ErrorRequest(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request signatureVerificationRequest
	if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) == nil {
		httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_signature_verification")
		return
	}
	result, err := s.signatureVerifications.Schedule(r.Context(), principal, projectID, artifactID,
		request.PolicyID, r.Header.Get("Idempotency-Key"))
	if writeError(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusAccepted, map[string]any{"job_id": result.JobID,
		"policy_id": result.PolicyID, "policy_version": result.PolicyVersion, "scheduled": result.Scheduled})
}

type trustPolicyRequest struct {
	Name                string                 `json:"name"`
	Mode                biz.SignatureTrustMode `json:"mode"`
	PublicKeyPEM        string                 `json:"public_key_pem"`
	TrustedRootID       string                 `json:"trusted_root_id"`
	TrustedRootHash     string                 `json:"trusted_root_hash"`
	CertificateIdentity string                 `json:"certificate_identity"`
	OIDCIssuer          string                 `json:"oidc_issuer"`
	Enabled             bool                   `json:"enabled"`
	ExpectedVersion     uint64                 `json:"expected_version,omitempty"`
}

type trustPolicyResponse struct {
	ID                   string                 `json:"id"`
	OrganizationID       string                 `json:"organization_id"`
	ProjectID            string                 `json:"project_id"`
	Name                 string                 `json:"name"`
	Mode                 biz.SignatureTrustMode `json:"mode"`
	PublicKeyFingerprint string                 `json:"public_key_fingerprint,omitempty"`
	TrustedRootID        string                 `json:"trusted_root_id,omitempty"`
	TrustedRootHash      string                 `json:"trusted_root_hash,omitempty"`
	CertificateIdentity  string                 `json:"certificate_identity,omitempty"`
	OIDCIssuer           string                 `json:"oidc_issuer,omitempty"`
	Enabled              bool                   `json:"enabled"`
	Version              uint64                 `json:"version"`
	CreatedAt            time.Time              `json:"created_at"`
	UpdatedAt            time.Time              `json:"updated_at"`
}

func (s *HTTP) serveTrustPolicies(w http.ResponseWriter, r *http.Request,
	principal security.Principal, segments []string) {
	if s.trustPolicies == nil {
		httpx.ErrorRequest(w, r, http.StatusServiceUnavailable, "signature_trust_policy_unavailable")
		return
	}
	projectID := segments[3]
	if len(segments) == 5 {
		switch r.Method {
		case http.MethodGet:
			if len(r.URL.Query()) != 0 {
				httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_signature_trust_policy")
				return
			}
			items, err := s.trustPolicies.List(r.Context(), principal, projectID)
			if writeError(w, r, err) {
				return
			}
			responses := make([]trustPolicyResponse, len(items))
			for i := range items {
				responses[i] = trustPolicyResponseFromDomain(items[i])
			}
			httpx.JSON(w, http.StatusOK, map[string]any{"items": responses})
		case http.MethodPost:
			input, ok := decodeTrustPolicyRequest(w, r)
			if !ok {
				return
			}
			item, err := s.trustPolicies.Create(r.Context(), principal, projectID, input.domain())
			if writeError(w, r, err) {
				return
			}
			httpx.JSON(w, http.StatusCreated, trustPolicyResponseFromDomain(item))
		default:
			httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		}
		return
	}
	if segments[5] == "" {
		httpx.ErrorRequest(w, r, http.StatusNotFound, "not_found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		if len(r.URL.Query()) != 0 {
			httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_signature_trust_policy")
			return
		}
		item, err := s.trustPolicies.Get(r.Context(), principal, projectID, segments[5])
		if writeError(w, r, err) {
			return
		}
		httpx.JSON(w, http.StatusOK, trustPolicyResponseFromDomain(item))
	case http.MethodPatch:
		input, ok := decodeTrustPolicyRequest(w, r)
		if !ok {
			return
		}
		item, err := s.trustPolicies.Update(r.Context(), principal, projectID, segments[5],
			input.ExpectedVersion, input.domain())
		if writeError(w, r, err) {
			return
		}
		httpx.JSON(w, http.StatusOK, trustPolicyResponseFromDomain(item))
	default:
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func decodeTrustPolicyRequest(w http.ResponseWriter, r *http.Request) (trustPolicyRequest, bool) {
	if r.Header.Get("Content-Type") != "application/json" {
		httpx.ErrorRequest(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return trustPolicyRequest{}, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 128*1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request trustPolicyRequest
	if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) == nil {
		httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_signature_trust_policy")
		return trustPolicyRequest{}, false
	}
	return request, true
}

func (r trustPolicyRequest) domain() biz.SignatureTrustPolicyInput {
	return biz.SignatureTrustPolicyInput{Name: r.Name, Mode: r.Mode, PublicKeyPEM: r.PublicKeyPEM,
		TrustedRootID: r.TrustedRootID, TrustedRootHash: r.TrustedRootHash,
		CertificateIdentity: r.CertificateIdentity, OIDCIssuer: r.OIDCIssuer, Enabled: r.Enabled}
}

func trustPolicyResponseFromDomain(item biz.SignatureTrustPolicy) trustPolicyResponse {
	return trustPolicyResponse{ID: item.ID, OrganizationID: item.OrganizationID, ProjectID: item.ProjectID,
		Name: item.Name, Mode: item.Mode, PublicKeyFingerprint: item.PublicKeyFingerprint,
		TrustedRootID: item.TrustedRootID, TrustedRootHash: item.TrustedRootHash,
		CertificateIdentity: item.CertificateIdentity, OIDCIssuer: item.OIDCIssuer,
		Enabled: item.Enabled, Version: item.Version, CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt}
}

type evidenceListResponse struct {
	Items []evidenceResponse `json:"items"`
}

type evidenceResponse struct {
	ID                 string                 `json:"id"`
	OrganizationID     string                 `json:"organization_id"`
	ProjectID          string                 `json:"project_id"`
	ArtifactID         string                 `json:"artifact_id"`
	SubjectDigest      string                 `json:"subject_digest"`
	Kind               biz.EvidenceKind       `json:"kind"`
	MediaType          string                 `json:"media_type"`
	FormatVersion      string                 `json:"format_version"`
	PredicateType      string                 `json:"predicate_type,omitempty"`
	Producer           string                 `json:"producer"`
	RegistryRepository string                 `json:"registry_repository"`
	DescriptorDigest   string                 `json:"descriptor_digest"`
	VerificationStatus biz.VerificationStatus `json:"verification_status"`
	CreatedAt          time.Time              `json:"created_at"`
}

type verificationResponse struct {
	ID                    string                 `json:"id"`
	OrganizationID        string                 `json:"organization_id"`
	ProjectID             string                 `json:"project_id"`
	ArtifactID            string                 `json:"artifact_id"`
	SubjectDigest         string                 `json:"subject_digest"`
	PolicyID              string                 `json:"policy_id"`
	PolicyVersion         uint64                 `json:"policy_version"`
	SigningProfileID      string                 `json:"signing_profile_id,omitempty"`
	SigningProfileVersion uint64                 `json:"signing_profile_version,omitempty"`
	SigningKeyProvider    biz.SigningKeyProvider `json:"signing_key_provider,omitempty"`
	SigningKeyFingerprint string                 `json:"signing_key_fingerprint,omitempty"`
	TrustMode             biz.SignatureTrustMode `json:"trust_mode"`
	TrustRootHash         string                 `json:"trust_root_hash"`
	SignerIdentity        string                 `json:"signer_identity,omitempty"`
	OIDCIssuer            string                 `json:"oidc_issuer,omitempty"`
	BundleSetDigest       string                 `json:"bundle_set_digest"`
	Verifier              string                 `json:"verifier"`
	VerifierVersion       string                 `json:"verifier_version"`
	VerificationStatus    biz.VerificationStatus `json:"verification_status"`
	CreatedAt             time.Time              `json:"created_at"`
}

func verificationResponseFromDomain(item biz.EvidenceVerification) verificationResponse {
	return verificationResponse{ID: item.ID, OrganizationID: item.OrganizationID, ProjectID: item.ProjectID,
		ArtifactID: item.ArtifactID, SubjectDigest: item.SubjectDigest, PolicyID: item.PolicyID,
		PolicyVersion: item.PolicyVersion, TrustMode: item.TrustMode, TrustRootHash: item.TrustRootHash,
		SigningProfileID: item.SigningProfileID, SigningProfileVersion: item.SigningProfileVersion,
		SigningKeyProvider: item.SigningKeyProvider, SigningKeyFingerprint: item.SigningKeyFingerprint,
		SignerIdentity: item.SignerIdentity, OIDCIssuer: item.OIDCIssuer, BundleSetDigest: item.BundleSetDigest,
		Verifier: item.Verifier, VerifierVersion: item.VerifierVersion,
		VerificationStatus: item.VerificationStatus, CreatedAt: item.CreatedAt}
}

func responseFromDomain(item biz.Evidence) evidenceResponse {
	return evidenceResponse{
		ID: item.ID, OrganizationID: item.OrganizationID, ProjectID: item.ProjectID,
		ArtifactID: item.ArtifactID, SubjectDigest: item.SubjectDigest, Kind: item.Kind,
		MediaType: item.MediaType, FormatVersion: item.FormatVersion,
		PredicateType: item.PredicateType, Producer: item.Producer,
		RegistryRepository: item.RegistryRepository, DescriptorDigest: item.DescriptorDigest,
		VerificationStatus: item.VerificationStatus, CreatedAt: item.CreatedAt,
	}
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
	case errors.Is(err, biz.ErrInvalidEvidence):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_artifact_evidence")
	case errors.Is(err, biz.ErrInvalidSignatureTrustPolicy):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_signature_trust_policy")
	case errors.Is(err, biz.ErrInvalidEvidenceJob), errors.Is(err, biz.ErrInvalidSignatureTrust),
		errors.Is(err, biz.ErrInvalidSignatureVerificationRequest):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_signature_verification")
	case errors.Is(err, biz.ErrInvalidVulnerabilityScanRequest):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_vulnerability_scan")
	case errors.Is(err, biz.ErrInvalidVulnerabilityWaiver):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_vulnerability_waiver")
	case errors.Is(err, biz.ErrVulnerabilityWaiverConflict):
		httpx.ErrorRequest(w, r, http.StatusConflict, "vulnerability_waiver_conflict")
	case errors.Is(err, biz.ErrInvalidDeploymentPolicy):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_deployment_policy")
	case errors.Is(err, biz.ErrDeploymentPolicyConflict):
		httpx.ErrorRequest(w, r, http.StatusConflict, "deployment_policy_conflict")
	case errors.Is(err, biz.ErrSignatureTrustPolicyConflict):
		httpx.ErrorRequest(w, r, http.StatusConflict, "signature_trust_policy_conflict")
	case errors.Is(err, biz.ErrInvalidSigningProfile), errors.Is(err, biz.ErrInvalidSigningKey):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_signature_signing_profile")
	case errors.Is(err, biz.ErrSigningProfileConflict):
		httpx.ErrorRequest(w, r, http.StatusConflict, "signature_signing_profile_conflict")
	case errors.Is(err, biz.ErrUnavailable):
		httpx.ErrorRequest(w, r, http.StatusServiceUnavailable, "artifact_evidence_unavailable")
	case errors.Is(err, biz.ErrEvidenceContentTooLarge), errors.Is(err, biz.ErrEvidenceIntegrity),
		errors.Is(err, biz.ErrRegistryAuthentication), errors.Is(err, biz.ErrInvalidRegistryResponse):
		httpx.ErrorRequest(w, r, http.StatusServiceUnavailable, "artifact_evidence_content_unavailable")
	default:
		httpx.ErrorRequest(w, r, http.StatusInternalServerError, "internal_error")
	}
	return true
}
