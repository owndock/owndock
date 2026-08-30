package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/supplychain/biz"
	"github.com/owndock/owndock/internal/shared/security"
)

type projectLookupStub struct{}

func (projectLookupStub) ProjectExists(context.Context, string, string) (bool, error) {
	return true, nil
}

type artifactLookupStub struct{}

func (artifactLookupStub) ResolveArtifact(context.Context, string, string, string) (biz.ArtifactSubject, error) {
	return biz.ArtifactSubject{
		ID: "artifact-1", OrganizationID: "organization-1", ProjectID: "project-1",
		SubjectDigest:      "sha256:" + strings.Repeat("a", 64),
		RegistryRepository: "registry.example.com/team/api", RegistryCredentialID: "registry-1",
	}, nil
}

type evidenceRepositoryStub struct{ item biz.Evidence }

func (s evidenceRepositoryStub) ListEvidence(context.Context, string, string) ([]biz.Evidence, error) {
	return []biz.Evidence{s.item}, nil
}
func (s evidenceRepositoryStub) GetEvidence(context.Context, string, string, string) (biz.Evidence, error) {
	return s.item, nil
}
func (s evidenceRepositoryStub) CreateEvidence(_ context.Context, item biz.Evidence) (biz.Evidence, error) {
	return item, nil
}

type evidenceContentReaderStub struct{ content biz.EvidenceContent }
type evidenceVerificationRepositoryStub struct{ items []biz.EvidenceVerification }
type vulnerabilityObservationRepositoryStub struct{ item biz.VulnerabilityObservation }
type vulnerabilityJobCreatorStub struct{ item biz.EvidenceJob }

type vulnerabilityWaiverRepositoryStub struct {
	items map[string]biz.VulnerabilityWaiver
}

type deploymentPolicyEnvironmentLookupStub struct{ stages map[string]string }

func (s deploymentPolicyEnvironmentLookupStub) EnvironmentStage(_ context.Context,
	projectID, environmentID string) (string, error) {
	stage, ok := s.stages[projectID+"/"+environmentID]
	if !ok {
		return "", biz.ErrNotFound
	}
	return stage, nil
}

type deploymentPolicyRepositoryStub struct {
	items map[string]biz.DeploymentPolicy
}

func (s *deploymentPolicyRepositoryStub) CreateDeploymentPolicy(_ context.Context,
	item biz.DeploymentPolicy) (biz.DeploymentPolicy, error) {
	if s.items == nil {
		s.items = make(map[string]biz.DeploymentPolicy)
	}
	s.items[item.ID] = item
	return item, nil
}

func (s *deploymentPolicyRepositoryStub) ListDeploymentPolicies(_ context.Context,
	organizationID, projectID string) ([]biz.DeploymentPolicy, error) {
	items := []biz.DeploymentPolicy{}
	for _, item := range s.items {
		if item.OrganizationID == organizationID && item.ProjectID == projectID {
			items = append(items, item)
		}
	}
	return items, nil
}

func (s *deploymentPolicyRepositoryStub) GetDeploymentPolicy(_ context.Context,
	organizationID, projectID, policyID string) (biz.DeploymentPolicy, error) {
	item, ok := s.items[policyID]
	if !ok || item.OrganizationID != organizationID || item.ProjectID != projectID {
		return biz.DeploymentPolicy{}, biz.ErrNotFound
	}
	return item, nil
}

func (s *deploymentPolicyRepositoryStub) SaveDeploymentPolicy(_ context.Context,
	item biz.DeploymentPolicy, expectedVersion uint64) (biz.DeploymentPolicy, error) {
	current, ok := s.items[item.ID]
	if !ok || current.Version != expectedVersion {
		return biz.DeploymentPolicy{}, biz.ErrDeploymentPolicyConflict
	}
	s.items[item.ID] = item
	return item, nil
}

func (s *vulnerabilityWaiverRepositoryStub) CreateVulnerabilityWaiver(_ context.Context,
	item biz.VulnerabilityWaiver) (biz.VulnerabilityWaiver, error) {
	if s.items == nil {
		s.items = make(map[string]biz.VulnerabilityWaiver)
	}
	s.items[item.ID] = item
	return item, nil
}

func (s *vulnerabilityWaiverRepositoryStub) ListVulnerabilityWaivers(_ context.Context,
	organizationID, projectID string, query biz.VulnerabilityWaiverQuery) (biz.VulnerabilityWaiverPage, error) {
	page := biz.VulnerabilityWaiverPage{Items: []biz.VulnerabilityWaiver{}}
	for _, item := range s.items {
		if item.OrganizationID == organizationID && item.ProjectID == projectID &&
			(!query.ActiveOnly || item.Status(query.ActiveAt) == biz.VulnerabilityWaiverActive) {
			page.Items = append(page.Items, item)
		}
	}
	return page, nil
}

func (s *vulnerabilityWaiverRepositoryStub) GetVulnerabilityWaiver(_ context.Context,
	organizationID, projectID, waiverID string) (biz.VulnerabilityWaiver, error) {
	item, ok := s.items[waiverID]
	if !ok || item.OrganizationID != organizationID || item.ProjectID != projectID {
		return biz.VulnerabilityWaiver{}, biz.ErrNotFound
	}
	return item, nil
}

func (s *vulnerabilityWaiverRepositoryStub) SaveVulnerabilityWaiver(_ context.Context,
	item biz.VulnerabilityWaiver, expectedVersion uint64) (biz.VulnerabilityWaiver, error) {
	current, ok := s.items[item.ID]
	if !ok || current.Version != expectedVersion {
		return biz.VulnerabilityWaiver{}, biz.ErrVulnerabilityWaiverConflict
	}
	s.items[item.ID] = item
	return item, nil
}

func (s *vulnerabilityJobCreatorStub) CreateEvidenceJob(_ context.Context,
	item biz.EvidenceJob) (biz.EvidenceJob, error) {
	s.item = item
	return item, nil
}

func (s vulnerabilityObservationRepositoryStub) GetLatestVulnerabilityObservation(
	context.Context, string, string) (biz.VulnerabilityObservation, error) {
	return s.item, nil
}

func (s evidenceVerificationRepositoryStub) ListEvidenceVerifications(context.Context, string, string) ([]biz.EvidenceVerification, error) {
	return s.items, nil
}

type trustPolicyRepositoryStub struct {
	items map[string]biz.SignatureTrustPolicy
}

func (s *trustPolicyRepositoryStub) CreateSignatureTrustPolicy(_ context.Context,
	item biz.SignatureTrustPolicy) (biz.SignatureTrustPolicy, error) {
	s.items[item.ID] = item
	return item, nil
}
func (s *trustPolicyRepositoryStub) ListSignatureTrustPolicies(_ context.Context,
	projectID string) ([]biz.SignatureTrustPolicy, error) {
	items := make([]biz.SignatureTrustPolicy, 0, len(s.items))
	for _, item := range s.items {
		if item.ProjectID == projectID {
			items = append(items, item)
		}
	}
	return items, nil
}
func (s *trustPolicyRepositoryStub) GetSignatureTrustPolicy(_ context.Context,
	projectID, policyID string) (biz.SignatureTrustPolicy, error) {
	item, ok := s.items[policyID]
	if !ok || item.ProjectID != projectID {
		return biz.SignatureTrustPolicy{}, biz.ErrNotFound
	}
	return item, nil
}
func (s *trustPolicyRepositoryStub) SaveSignatureTrustPolicy(_ context.Context,
	item biz.SignatureTrustPolicy, expected uint64) (biz.SignatureTrustPolicy, error) {
	current, ok := s.items[item.ID]
	if !ok {
		return biz.SignatureTrustPolicy{}, biz.ErrNotFound
	}
	if current.Version != expected {
		return biz.SignatureTrustPolicy{}, biz.ErrSignatureTrustPolicyConflict
	}
	s.items[item.ID] = item
	return item, nil
}

func (s evidenceContentReaderStub) ReadEvidence(context.Context,
	biz.ArtifactSubject, biz.Evidence) (biz.EvidenceContent, error) {
	return s.content, nil
}

func TestHTTPManagesRestrictedDeploymentPolicies(t *testing.T) {
	now := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)
	repository := &deploymentPolicyRepositoryStub{}
	useCase, err := biz.NewDeploymentPolicyUseCase(projectLookupStub{},
		deploymentPolicyEnvironmentLookupStub{stages: map[string]string{
			"project-1/production-1": "production",
		}}, repository, func() (string, error) { return "policy-1", nil }, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHTTP(nil).WithDeploymentPolicies(useCase)
	maintainer := security.Principal{UserID: "maintainer-1", OrganizationID: "organization-1",
		SessionID: "session-1", Role: security.RoleMaintainer}
	requestBody := `{"name":"Release baseline","scope":"project","environment_id":"",` +
		`"mode":"enforced","requirements":{"require_sbom":true,"require_provenance":true,` +
		`"allowed_signature_policy_ids":["trust-1"],"maximum_vulnerability_severity":"high",` +
		`"maximum_scan_age_seconds":3600},"enabled":true}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/projects/project-1/deployment-policies",
		strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(security.WithPrincipal(request.Context(), maintainer))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || !strings.Contains(response.Body.String(), `"version":1`) ||
		!strings.Contains(response.Body.String(), `"maximum_scan_age_seconds":3600`) {
		t.Fatalf("create deployment policy = %d %s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, "/api/v1/projects/project-1/deployment-policies/policy-1", nil)
	request = request.WithContext(security.WithPrincipal(request.Context(), maintainer))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"scope":"project"`) {
		t.Fatalf("get deployment policy = %d %s", response.Code, response.Body.String())
	}

	updateBody := strings.Replace(requestBody, `"Release baseline"`, `"Updated baseline"`, 1)
	updateBody = strings.TrimSuffix(updateBody, "}") + `,"expected_version":1}`
	request = httptest.NewRequest(http.MethodPatch,
		"/api/v1/projects/project-1/deployment-policies/policy-1", strings.NewReader(updateBody))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(security.WithPrincipal(request.Context(), maintainer))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"version":2`) ||
		!strings.Contains(response.Body.String(), `"name":"Updated baseline"`) {
		t.Fatalf("update deployment policy = %d %s", response.Code, response.Body.String())
	}

	unsafeProduction := `{"name":"Unsafe","scope":"environment","environment_id":"production-1",` +
		`"mode":"advisory","requirements":{"require_sbom":true,"require_provenance":false,` +
		`"allowed_signature_policy_ids":[],"maximum_vulnerability_severity":"",` +
		`"maximum_scan_age_seconds":0},"enabled":true}`
	request = httptest.NewRequest(http.MethodPost, "/api/v1/projects/project-1/deployment-policies",
		strings.NewReader(unsafeProduction))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(security.WithPrincipal(request.Context(), maintainer))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("unsafe production policy = %d %s", response.Code, response.Body.String())
	}

	viewer := maintainer
	viewer.Role = security.RoleViewer
	request = httptest.NewRequest(http.MethodPost, "/api/v1/projects/project-1/deployment-policies",
		strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(security.WithPrincipal(request.Context(), viewer))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("viewer create deployment policy = %d %s", response.Code, response.Body.String())
	}
}

func TestHTTPListsAndGetsSafeEvidenceMetadata(t *testing.T) {
	item, err := biz.NewEvidence(biz.EvidenceInput{
		ID: "evidence-1", OrganizationID: "organization-1", ProjectID: "project-1",
		ArtifactID: "artifact-1", SubjectDigest: "sha256:" + strings.Repeat("a", 64),
		Kind: biz.EvidenceKindSBOM, MediaType: "application/vnd.cyclonedx+json",
		FormatVersion: "1.6", Producer: "worker/1.0.0",
		RegistryRepository: "registry.example.com/team/api",
		DescriptorDigest:   "sha256:" + strings.Repeat("b", 64),
		VerificationStatus: biz.VerificationVerified, CreatedAt: time.Unix(100, 0),
	})
	if err != nil {
		t.Fatalf("NewEvidence() error = %v", err)
	}
	useCase, _ := biz.NewUseCase(projectLookupStub{}, artifactLookupStub{}, evidenceRepositoryStub{item: item})
	handler := NewHTTP(useCase)
	principal := security.Principal{UserID: "user-1", OrganizationID: "organization-1", SessionID: "session-1", Role: security.RoleViewer}
	for _, target := range []string{
		"/api/v1/projects/project-1/artifacts/artifact-1/evidence",
		"/api/v1/projects/project-1/artifacts/artifact-1/evidence/evidence-1",
	} {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		request = request.WithContext(security.WithPrincipal(request.Context(), principal))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"subject_digest":"sha256:`) ||
			strings.Contains(response.Body.String(), "secret") {
			t.Fatalf("GET %s = %d %s", target, response.Code, response.Body.String())
		}
	}
}

func TestHTTPDownloadsVerifiedEvidenceWithSafeHeaders(t *testing.T) {
	item, err := biz.NewEvidence(biz.EvidenceInput{
		ID: "evidence-1", OrganizationID: "organization-1", ProjectID: "project-1",
		ArtifactID: "artifact-1", SubjectDigest: "sha256:" + strings.Repeat("a", 64),
		Kind: biz.EvidenceKindProvenance, MediaType: biz.SLSAProvenanceMediaType,
		FormatVersion: biz.SLSAProvenanceFormatVersion, PredicateType: biz.SLSAProvenancePredicateV1,
		Producer: "owndock-build-worker/0.1.0", RegistryRepository: "registry.example.com/team/api",
		DescriptorDigest:   "sha256:" + strings.Repeat("b", 64),
		VerificationStatus: biz.VerificationUnverified, CreatedAt: time.Unix(100, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	content := []byte(`{"_type":"https://in-toto.io/Statement/v1"}`)
	useCase, _ := biz.NewUseCase(projectLookupStub{}, artifactLookupStub{}, evidenceRepositoryStub{item: item})
	useCase.WithContentReader(evidenceContentReaderStub{content: biz.EvidenceContent{
		Content: content, MediaType: biz.SLSAProvenanceMediaType,
		Digest: "sha256:" + strings.Repeat("c", 64),
	}})
	handler := NewHTTP(useCase)
	request := httptest.NewRequest(http.MethodGet,
		"/api/v1/projects/project-1/artifacts/artifact-1/evidence/evidence-1:download", nil)
	request = request.WithContext(security.WithPrincipal(request.Context(), security.Principal{
		UserID: "user-1", OrganizationID: "organization-1", SessionID: "session-1", Role: security.RoleViewer,
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != string(content) ||
		response.Header().Get("Content-Type") != biz.SLSAProvenanceMediaType ||
		response.Header().Get("X-OwnDock-Content-Digest") != "sha256:"+strings.Repeat("c", 64) ||
		!strings.Contains(response.Header().Get("Content-Disposition"), "owndock-provenance-evidence-1.json") {
		t.Fatalf("download response = %d %#v %s", response.Code, response.Header(), response.Body.String())
	}
}

func TestHTTPListsSignatureVerificationSummaries(t *testing.T) {
	useCase, _ := biz.NewUseCase(projectLookupStub{}, artifactLookupStub{}, evidenceRepositoryStub{})
	useCase.WithVerificationRepository(evidenceVerificationRepositoryStub{items: []biz.EvidenceVerification{{
		ID: "verification-1", OrganizationID: "organization-1", ProjectID: "project-1",
		ArtifactID: "artifact-1", SubjectDigest: "sha256:" + strings.Repeat("a", 64),
		PolicyID: "policy-1", PolicyVersion: 2, TrustMode: biz.SignatureTrustKeyless,
		TrustRootHash:  "sha256:" + strings.Repeat("b", 64),
		SignerIdentity: "https://git.example.com/team/api/.ci/release@refs/tags/v1.0.0",
		OIDCIssuer:     "https://issuer.example.com", BundleSetDigest: "sha256:" + strings.Repeat("c", 64),
		Verifier: "cosign", VerifierVersion: "3.0.6", VerificationStatus: biz.VerificationVerified,
		CreatedAt: time.Unix(100, 0),
	}}})
	handler := NewHTTP(useCase)
	request := httptest.NewRequest(http.MethodGet,
		"/api/v1/projects/project-1/artifacts/artifact-1/verifications", nil)
	request = request.WithContext(security.WithPrincipal(request.Context(), security.Principal{
		UserID: "user-1", OrganizationID: "organization-1", SessionID: "session-1", Role: security.RoleViewer}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"policy_version":2`) ||
		strings.Contains(response.Body.String(), "PUBLIC KEY") {
		t.Fatalf("verification list = %d %s", response.Code, response.Body.String())
	}
}

func TestHTTPReturnsBoundedLatestVulnerabilityObservationAndStaleState(t *testing.T) {
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	observation, err := biz.NewVulnerabilityObservation(biz.VulnerabilityObservation{
		ID: "vulnerability-observation-1", OrganizationID: "organization-1", ProjectID: "project-1",
		ArtifactID: "artifact-1", EvidenceID: "evidence-1",
		SubjectDigest: "sha256:" + strings.Repeat("a", 64), DescriptorDigest: "sha256:" + strings.Repeat("b", 64),
		Scanner: "trivy", ScannerVersion: "0.74.0",
		Database: biz.VulnerabilityDatabase{SchemaVersion: 2, UpdatedAt: now.Add(-4 * time.Hour),
			DownloadedAt: now.Add(-3 * time.Hour), NextUpdate: now.Add(-time.Hour)},
		ScannedAt: now.Add(-2 * time.Hour), FreshUntil: now.Add(-time.Hour),
		Counts:          biz.VulnerabilityCounts{High: 2, Total: 2, Fixable: 1},
		HighestSeverity: biz.VulnerabilitySeverityHigh})
	if err != nil {
		t.Fatal(err)
	}
	useCase, _ := biz.NewUseCase(projectLookupStub{}, artifactLookupStub{}, evidenceRepositoryStub{})
	useCase.WithVulnerabilityObservations(vulnerabilityObservationRepositoryStub{item: observation},
		func() time.Time { return now })
	handler := NewHTTP(useCase)
	request := httptest.NewRequest(http.MethodGet,
		"/api/v1/projects/project-1/artifacts/artifact-1/vulnerability-observation", nil)
	request = request.WithContext(security.WithPrincipal(request.Context(), security.Principal{
		UserID: "user-1", OrganizationID: "organization-1", SessionID: "session-1", Role: security.RoleViewer}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"stale":true`) ||
		!strings.Contains(response.Body.String(), `"highest_severity":"high"`) ||
		!strings.Contains(response.Body.String(), `"fixable":1`) || strings.Contains(response.Body.String(), "VulnerabilityID") {
		t.Fatalf("observation = %d %s", response.Code, response.Body.String())
	}
}

func TestHTTPSchedulesManualVulnerabilityRescanWithIdempotencyKey(t *testing.T) {
	jobs := &vulnerabilityJobCreatorStub{}
	useCase, _ := biz.NewUseCase(projectLookupStub{}, artifactLookupStub{}, evidenceRepositoryStub{})
	scans, err := biz.NewVulnerabilityScanUseCase(artifactLookupStub{}, jobs,
		func() (string, error) { return "audit-1", nil }, func() time.Time { return time.Unix(100, 0) })
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHTTP(useCase).WithVulnerabilityScans(scans)
	request := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/project-1/artifacts/artifact-1/vulnerability-scans", nil)
	request.Header.Set("Idempotency-Key", "manual-scan-1")
	request = request.WithContext(security.WithPrincipal(request.Context(), security.Principal{
		UserID: "user-1", OrganizationID: "organization-1", SessionID: "session-1", Role: security.RoleDeveloper}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || !strings.Contains(response.Body.String(), `"scheduled":true`) ||
		jobs.item.Kind != biz.EvidenceKindVulnerabilityReport {
		t.Fatalf("rescan = %d %s job=%+v", response.Code, response.Body.String(), jobs.item)
	}
}

func TestHTTPVulnerabilityWaiverLifecycleIsBoundedAndRoleProtected(t *testing.T) {
	now := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)
	repository := &vulnerabilityWaiverRepositoryStub{}
	waivers, err := biz.NewVulnerabilityWaiverUseCase(projectLookupStub{}, artifactLookupStub{}, repository,
		func() (string, error) { return "waiver-1", nil }, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	evidence, _ := biz.NewUseCase(projectLookupStub{}, artifactLookupStub{}, evidenceRepositoryStub{})
	handler := NewHTTP(evidence).WithVulnerabilityWaivers(waivers)
	maintainer := security.Principal{UserID: "maintainer-1", OrganizationID: "organization-1",
		SessionID: "session-1", Role: security.RoleMaintainer}
	createBody := `{"scope":"artifact","artifact_id":"artifact-1","vulnerability_id":"cve-2026-12345",` +
		`"reason":"The vulnerable path is disabled.","expires_at":"` + now.Add(24*time.Hour).Format(time.RFC3339) + `"}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/projects/project-1/vulnerability-waivers",
		strings.NewReader(createBody))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(security.WithPrincipal(request.Context(), maintainer))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || !strings.Contains(response.Body.String(), `"status":"active"`) ||
		!strings.Contains(response.Body.String(), `"vulnerability_id":"CVE-2026-12345"`) ||
		!strings.Contains(response.Body.String(), `"subject_digest":"sha256:`) ||
		!strings.Contains(response.Body.String(), `"approved_by":"maintainer-1"`) {
		t.Fatalf("create waiver = %d %s", response.Code, response.Body.String())
	}
	viewer := maintainer
	viewer.UserID, viewer.Role = "viewer-1", security.RoleViewer
	request = httptest.NewRequest(http.MethodGet,
		"/api/v1/projects/project-1/vulnerability-waivers?status=active&limit=50", nil)
	request = request.WithContext(security.WithPrincipal(request.Context(), viewer))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"next_cursor":""`) ||
		!strings.Contains(response.Body.String(), `"waiver-1"`) {
		t.Fatalf("list waivers = %d %s", response.Code, response.Body.String())
	}
	developer := maintainer
	developer.UserID, developer.Role = "developer-1", security.RoleDeveloper
	request = httptest.NewRequest(http.MethodPost, "/api/v1/projects/project-1/vulnerability-waivers",
		strings.NewReader(createBody))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(security.WithPrincipal(request.Context(), developer))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("developer create waiver = %d %s", response.Code, response.Body.String())
	}
	revokeBody := `{"reason":"Patched image deployed.","expected_version":1}`
	request = httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/project-1/vulnerability-waivers/waiver-1:revoke", strings.NewReader(revokeBody))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(security.WithPrincipal(request.Context(), maintainer))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"status":"revoked"`) ||
		!strings.Contains(response.Body.String(), `"revocation_reason":"Patched image deployed."`) {
		t.Fatalf("revoke waiver = %d %s", response.Code, response.Body.String())
	}
}

func TestHTTPRejectsInvalidVulnerabilityWaiverQueriesAndPermanentApproval(t *testing.T) {
	now := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)
	repository := &vulnerabilityWaiverRepositoryStub{}
	waivers, _ := biz.NewVulnerabilityWaiverUseCase(projectLookupStub{}, artifactLookupStub{}, repository,
		func() (string, error) { return "waiver-1", nil }, func() time.Time { return now })
	evidence, _ := biz.NewUseCase(projectLookupStub{}, artifactLookupStub{}, evidenceRepositoryStub{})
	handler := NewHTTP(evidence).WithVulnerabilityWaivers(waivers)
	principal := security.Principal{UserID: "maintainer-1", OrganizationID: "organization-1",
		SessionID: "session-1", Role: security.RoleMaintainer}
	for _, target := range []string{
		"/api/v1/projects/project-1/vulnerability-waivers?unknown=true",
		"/api/v1/projects/project-1/vulnerability-waivers?status=expired",
		"/api/v1/projects/project-1/vulnerability-waivers?limit=101",
	} {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		request = request.WithContext(security.WithPrincipal(request.Context(), principal))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest && response.Code != http.StatusUnprocessableEntity {
			t.Fatalf("GET %s = %d %s", target, response.Code, response.Body.String())
		}
	}
	body := `{"scope":"project","vulnerability_id":"CVE-2026-12345","reason":"No expiry",` +
		`"expires_at":"` + now.Add(181*24*time.Hour).Format(time.RFC3339) + `"}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/projects/project-1/vulnerability-waivers",
		strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(security.WithPrincipal(request.Context(), principal))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("permanent waiver = %d %s", response.Code, response.Body.String())
	}
}

func TestHTTPRejectsUnknownQueriesAndWrites(t *testing.T) {
	useCase, _ := biz.NewUseCase(projectLookupStub{}, artifactLookupStub{}, evidenceRepositoryStub{})
	handler := NewHTTP(useCase)
	principal := security.Principal{UserID: "user-1", OrganizationID: "organization-1", SessionID: "session-1", Role: security.RoleViewer}
	for _, test := range []struct {
		method, target string
		status         int
	}{
		{http.MethodGet, "/api/v1/projects/project-1/artifacts/artifact-1/evidence?raw=true", http.StatusBadRequest},
		{http.MethodPost, "/api/v1/projects/project-1/artifacts/artifact-1/evidence", http.StatusMethodNotAllowed},
	} {
		request := httptest.NewRequest(test.method, test.target, nil)
		request = request.WithContext(security.WithPrincipal(request.Context(), principal))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.status {
			t.Fatalf("%s %s = %d", test.method, test.target, response.Code)
		}
	}
}

func TestHTTPRejectsUnauthenticatedAndUnknownPaths(t *testing.T) {
	useCase, _ := biz.NewUseCase(projectLookupStub{}, artifactLookupStub{}, evidenceRepositoryStub{})
	handler := NewHTTP(useCase)
	unauthenticated := httptest.NewRecorder()
	handler.ServeHTTP(unauthenticated, httptest.NewRequest(
		http.MethodGet, "/api/v1/projects/project-1/artifacts/artifact-1/evidence", nil,
	))
	if unauthenticated.Code != http.StatusUnauthorized || unauthenticated.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("unauthenticated = %d %#v", unauthenticated.Code, unauthenticated.Header())
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/projects/project-1/artifacts/artifact-1/raw", nil)
	request = request.WithContext(security.WithPrincipal(request.Context(), security.Principal{
		UserID: "user-1", OrganizationID: "organization-1", SessionID: "session-1", Role: security.RoleViewer,
	}))
	unknown := httptest.NewRecorder()
	handler.ServeHTTP(unknown, request)
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown path = %d", unknown.Code)
	}
}

func TestHTTPSignatureTrustPolicyLifecycleDoesNotReturnPublicKey(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	repository := &trustPolicyRepositoryStub{items: make(map[string]biz.SignatureTrustPolicy)}
	useCase, err := biz.NewSignatureTrustPolicyUseCase(projectLookupStub{}, repository,
		func() (string, error) { return "policy-1", nil }, func() time.Time { return time.Unix(100, 0) })
	if err != nil {
		t.Fatal(err)
	}
	evidenceUseCase, _ := biz.NewUseCase(projectLookupStub{}, artifactLookupStub{}, evidenceRepositoryStub{})
	handler := NewHTTP(evidenceUseCase).WithSignatureTrustPolicies(useCase)
	principal := security.Principal{UserID: "user-1", OrganizationID: "organization-1",
		SessionID: "session-1", Role: security.RoleMaintainer}
	body := `{"name":"Release signer","mode":"public_key","public_key_pem":` +
		strconv.Quote(publicKey) + `,"enabled":true}`
	request := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/project-1/signature-trust-policies", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(security.WithPrincipal(request.Context(), principal))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || strings.Contains(response.Body.String(), "BEGIN PUBLIC KEY") ||
		!strings.Contains(response.Body.String(), `"public_key_fingerprint":"sha256:`) {
		t.Fatalf("create policy = %d %s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet,
		"/api/v1/projects/project-1/signature-trust-policies/policy-1", nil)
	request = request.WithContext(security.WithPrincipal(request.Context(), principal))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "BEGIN PUBLIC KEY") {
		t.Fatalf("get policy = %d %s", response.Code, response.Body.String())
	}
}
