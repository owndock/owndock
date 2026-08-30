package data

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	deploymentbiz "github.com/owndock/owndock/internal/modules/deployment/biz"
	"github.com/owndock/owndock/internal/modules/supplychain/biz"
)

type admissionReleaseLookupStub struct {
	stage      string
	artifactID string
	err        error
}

func (s admissionReleaseLookupStub) EnvironmentStage(context.Context, string, string) (string, error) {
	return s.stage, s.err
}
func (s admissionReleaseLookupStub) ReleaseSourceArtifactID(context.Context,
	string, string, string) (string, error) {
	return s.artifactID, s.err
}

type admissionArtifactLookupStub struct {
	subject biz.ArtifactSubject
	err     error
}

func (s admissionArtifactLookupStub) ResolveArtifact(context.Context,
	string, string, string) (biz.ArtifactSubject, error) {
	return s.subject, s.err
}

type admissionPolicyRepositoryStub struct{ items []biz.DeploymentPolicy }

func (s admissionPolicyRepositoryStub) CreateDeploymentPolicy(context.Context,
	biz.DeploymentPolicy) (biz.DeploymentPolicy, error) {
	return biz.DeploymentPolicy{}, errors.New("not implemented")
}
func (s admissionPolicyRepositoryStub) ListDeploymentPolicies(context.Context,
	string, string) ([]biz.DeploymentPolicy, error) {
	return append([]biz.DeploymentPolicy{}, s.items...), nil
}
func (s admissionPolicyRepositoryStub) GetDeploymentPolicy(context.Context,
	string, string, string) (biz.DeploymentPolicy, error) {
	return biz.DeploymentPolicy{}, biz.ErrNotFound
}
func (s admissionPolicyRepositoryStub) SaveDeploymentPolicy(context.Context,
	biz.DeploymentPolicy, uint64) (biz.DeploymentPolicy, error) {
	return biz.DeploymentPolicy{}, errors.New("not implemented")
}

type admissionEvidenceRepositoryStub struct{ items []biz.Evidence }

func (s admissionEvidenceRepositoryStub) ListEvidence(context.Context, string, string) ([]biz.Evidence, error) {
	return append([]biz.Evidence{}, s.items...), nil
}
func (s admissionEvidenceRepositoryStub) GetEvidence(context.Context, string, string, string) (biz.Evidence, error) {
	return biz.Evidence{}, biz.ErrNotFound
}
func (s admissionEvidenceRepositoryStub) CreateEvidence(context.Context, biz.Evidence) (biz.Evidence, error) {
	return biz.Evidence{}, errors.New("not implemented")
}

type admissionContentReaderStub struct {
	content map[string]biz.EvidenceContent
	err     map[string]error
}

func (s admissionContentReaderStub) ReadEvidence(_ context.Context, _ biz.ArtifactSubject,
	evidence biz.Evidence) (biz.EvidenceContent, error) {
	if err := s.err[evidence.ID]; err != nil {
		return biz.EvidenceContent{}, err
	}
	item, ok := s.content[evidence.ID]
	if !ok {
		return biz.EvidenceContent{}, biz.ErrUnavailable
	}
	return item, nil
}

type admissionVerificationRepositoryStub struct{ items []biz.EvidenceVerification }

func (s admissionVerificationRepositoryStub) ListEvidenceVerifications(context.Context,
	string, string) ([]biz.EvidenceVerification, error) {
	return append([]biz.EvidenceVerification{}, s.items...), nil
}

type admissionTrustPolicyRepositoryStub struct {
	items map[string]biz.SignatureTrustPolicy
}

func (s admissionTrustPolicyRepositoryStub) CreateSignatureTrustPolicy(context.Context,
	biz.SignatureTrustPolicy) (biz.SignatureTrustPolicy, error) {
	return biz.SignatureTrustPolicy{}, errors.New("not implemented")
}
func (s admissionTrustPolicyRepositoryStub) ListSignatureTrustPolicies(context.Context,
	string) ([]biz.SignatureTrustPolicy, error) {
	return nil, nil
}
func (s admissionTrustPolicyRepositoryStub) GetSignatureTrustPolicy(_ context.Context,
	_ string, policyID string) (biz.SignatureTrustPolicy, error) {
	item, ok := s.items[policyID]
	if !ok {
		return biz.SignatureTrustPolicy{}, biz.ErrNotFound
	}
	return item, nil
}
func (s admissionTrustPolicyRepositoryStub) SaveSignatureTrustPolicy(context.Context,
	biz.SignatureTrustPolicy, uint64) (biz.SignatureTrustPolicy, error) {
	return biz.SignatureTrustPolicy{}, errors.New("not implemented")
}

type admissionVulnerabilityRepositoryStub struct{ item biz.VulnerabilityObservation }

func (s admissionVulnerabilityRepositoryStub) GetLatestVulnerabilityObservation(context.Context,
	string, string) (biz.VulnerabilityObservation, error) {
	if s.item.ID == "" {
		return biz.VulnerabilityObservation{}, biz.ErrNotFound
	}
	return s.item, nil
}

type admissionWaiverRepositoryStub struct{ items []biz.VulnerabilityWaiver }

func (s admissionWaiverRepositoryStub) ListApplicableVulnerabilityWaivers(context.Context,
	string, string, string, string, time.Time) ([]biz.VulnerabilityWaiver, error) {
	return append([]biz.VulnerabilityWaiver{}, s.items...), nil
}

type admissionFixture struct {
	now          time.Time
	subject      biz.ArtifactSubject
	policy       biz.DeploymentPolicy
	evidence     []biz.Evidence
	content      map[string]biz.EvidenceContent
	trustPolicy  biz.SignatureTrustPolicy
	verification biz.EvidenceVerification
	observation  biz.VulnerabilityObservation
	waiver       biz.VulnerabilityWaiver
}

func newAdmissionFixture(t *testing.T) admissionFixture {
	t.Helper()
	now := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)
	subject := biz.ArtifactSubject{ID: "artifact-1", OrganizationID: "organization-1",
		ProjectID: "project-1", SubjectDigest: "sha256:" + strings.Repeat("a", 64),
		RegistryRepository: "registry.example.com/team/api", RegistryCredentialID: "registry-1"}
	policy, err := biz.NewDeploymentPolicy(biz.DeploymentPolicyInput{ID: "admission-policy-1",
		OrganizationID: subject.OrganizationID, ProjectID: subject.ProjectID, Name: "Release baseline",
		Scope: biz.DeploymentPolicyScopeProject, Mode: biz.DeploymentPolicyEnforced,
		Requirements: biz.DeploymentPolicyRequirements{RequireSBOM: true, RequireProvenance: true,
			AllowedSignaturePolicyIDs:    []string{"trust-policy-1"},
			MaximumVulnerabilitySeverity: biz.VulnerabilitySeverityMedium,
			MaximumScanAge:               24 * time.Hour},
		Enabled: true, Version: 1, CreatedBy: "maintainer-1", UpdatedBy: "maintainer-1",
		CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	trustPolicy, err := biz.NewSignatureTrustPolicy(biz.SignatureTrustPolicyInput{
		ID: "trust-policy-1", OrganizationID: subject.OrganizationID, ProjectID: subject.ProjectID,
		Name: "Release signer", Mode: biz.SignatureTrustKeyless, TrustedRootID: "offline-root-1",
		TrustedRootHash:     "sha256:" + strings.Repeat("b", 64),
		CertificateIdentity: "https://git.example.com/team/api/.ci/release@refs/tags/v1.0.0",
		OIDCIssuer:          "https://issuer.example.com", Enabled: true, Version: 1,
		CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	verification, err := biz.NewEvidenceVerification(biz.EvidenceVerification{ID: "verification-1",
		OrganizationID: subject.OrganizationID, ProjectID: subject.ProjectID, ArtifactID: subject.ID,
		SubjectDigest: subject.SubjectDigest, PolicyID: trustPolicy.ID, PolicyVersion: trustPolicy.Version,
		TrustMode: trustPolicy.Mode, TrustRootHash: trustPolicy.TrustedRootHash,
		SignerIdentity: trustPolicy.CertificateIdentity, OIDCIssuer: trustPolicy.OIDCIssuer,
		BundleSetDigest: "sha256:" + strings.Repeat("c", 64), Verifier: "cosign", VerifierVersion: "3.0.6",
		VerificationStatus: biz.VerificationVerified, CreatedAt: now.Add(-30 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	createdAt := now.Add(-time.Hour)
	newEvidence := func(id string, kind biz.EvidenceKind, mediaType, formatVersion,
		predicateType, descriptorCharacter string) biz.Evidence {
		item, evidenceErr := biz.NewEvidence(biz.EvidenceInput{ID: id,
			OrganizationID: subject.OrganizationID, ProjectID: subject.ProjectID, ArtifactID: subject.ID,
			SubjectDigest: subject.SubjectDigest, Kind: kind, MediaType: mediaType,
			FormatVersion: formatVersion, PredicateType: predicateType, Producer: "integration/1.0.0",
			RegistryRepository: subject.RegistryRepository,
			DescriptorDigest:   "sha256:" + strings.Repeat(descriptorCharacter, 64),
			VerificationStatus: biz.VerificationUnverified, CreatedAt: createdAt})
		if evidenceErr != nil {
			t.Fatal(evidenceErr)
		}
		return item
	}
	sbom := newEvidence("evidence-sbom", biz.EvidenceKindSBOM, biz.CycloneDXJSONMediaType,
		biz.CycloneDXVersion16, "", "d")
	provenance := newEvidence("evidence-provenance", biz.EvidenceKindProvenance, biz.SLSAProvenanceMediaType,
		biz.SLSAProvenanceFormatVersion, biz.SLSAProvenancePredicateV1, "e")
	vulnerability := newEvidence("evidence-vulnerability", biz.EvidenceKindVulnerabilityReport,
		biz.TrivyReportMediaType, biz.TrivyReportFormatVersion, "", "f")
	report := []byte(fmt.Sprintf(`{"SchemaVersion":2,"CreatedAt":%q,"ArtifactName":%q,"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2026-1111","Severity":"HIGH","FixedVersion":""},{"VulnerabilityID":"CVE-2026-2222","Severity":"MEDIUM","FixedVersion":"1.2.3"}]}]}`,
		createdAt.Format(time.RFC3339), subject.RegistryRepository+"@"+subject.SubjectDigest))
	observation, err := biz.NewVulnerabilityObservation(biz.VulnerabilityObservation{
		ID: "observation-1", OrganizationID: subject.OrganizationID, ProjectID: subject.ProjectID,
		ArtifactID: subject.ID, SubjectDigest: subject.SubjectDigest, EvidenceID: vulnerability.ID,
		DescriptorDigest: vulnerability.DescriptorDigest, Scanner: "trivy", ScannerVersion: PinnedTrivyVersion,
		Database: biz.VulnerabilityDatabase{SchemaVersion: 2, UpdatedAt: now.Add(-2 * time.Hour),
			DownloadedAt: now.Add(-90 * time.Minute), NextUpdate: now.Add(6 * time.Hour)},
		ScannedAt: createdAt, FreshUntil: now.Add(5 * time.Hour),
		Counts:          biz.VulnerabilityCounts{High: 1, Medium: 1, Total: 2, Fixable: 1},
		HighestSeverity: biz.VulnerabilitySeverityHigh})
	if err != nil {
		t.Fatal(err)
	}
	waiver, err := biz.NewVulnerabilityWaiver(biz.VulnerabilityWaiverInput{ID: "waiver-1",
		OrganizationID: subject.OrganizationID, ProjectID: subject.ProjectID,
		Scope: biz.VulnerabilityWaiverScopeProject, VulnerabilityID: "CVE-2026-1111",
		Reason: "The vulnerable path is disabled.", ApprovedBy: "maintainer-1",
		ExpiresAt: now.Add(24 * time.Hour), Version: 1, CreatedAt: now.Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return admissionFixture{now: now, subject: subject, policy: policy,
		evidence: []biz.Evidence{sbom, provenance, vulnerability},
		content: map[string]biz.EvidenceContent{
			sbom.ID: {Content: []byte(`{"bomFormat":"CycloneDX"}`), MediaType: sbom.MediaType,
				Digest: "sha256:" + strings.Repeat("1", 64)},
			provenance.ID: {Content: []byte(`{"_type":"https://in-toto.io/Statement/v1"}`),
				MediaType: provenance.MediaType, Digest: "sha256:" + strings.Repeat("2", 64)},
			vulnerability.ID: {Content: report, MediaType: vulnerability.MediaType,
				Digest: "sha256:" + strings.Repeat("3", 64)},
		}, trustPolicy: trustPolicy, verification: verification, observation: observation, waiver: waiver}
}

func (f admissionFixture) evaluator(t *testing.T, stage string,
	policies []biz.DeploymentPolicy) *DeploymentAdmissionEvaluator {
	t.Helper()
	evaluator, err := NewDeploymentAdmissionEvaluator(DeploymentAdmissionOptions{
		Releases:  admissionReleaseLookupStub{stage: stage, artifactID: f.subject.ID},
		Artifacts: admissionArtifactLookupStub{subject: f.subject}, Policies: admissionPolicyRepositoryStub{items: policies},
		Evidence:        admissionEvidenceRepositoryStub{items: f.evidence},
		Content:         admissionContentReaderStub{content: f.content, err: map[string]error{}},
		Verifications:   admissionVerificationRepositoryStub{items: []biz.EvidenceVerification{f.verification}},
		TrustPolicies:   admissionTrustPolicyRepositoryStub{items: map[string]biz.SignatureTrustPolicy{f.trustPolicy.ID: f.trustPolicy}},
		Vulnerabilities: admissionVulnerabilityRepositoryStub{item: f.observation},
		Waivers:         admissionWaiverRepositoryStub{items: []biz.VulnerabilityWaiver{f.waiver}},
		Now:             func() time.Time { return f.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return evaluator
}

func admissionRequest() deploymentbiz.AdmissionRequest {
	return deploymentbiz.AdmissionRequest{OrganizationID: "organization-1", ProjectID: "project-1",
		ReleaseID: "release-1", ApplicationID: "application-1", EnvironmentID: "environment-1"}
}

func TestDeploymentAdmissionFreezesVerifiedEvidenceAndExactWaiver(t *testing.T) {
	fixture := newAdmissionFixture(t)
	snapshot, err := fixture.evaluator(t, "production", []biz.DeploymentPolicy{fixture.policy}).
		EvaluateAdmission(t.Context(), admissionRequest())
	if err != nil || snapshot.Decision != deploymentbiz.AdmissionAdmitted || snapshot.EvaluationDigest == "" ||
		len(snapshot.Policies) != 1 || snapshot.Policies[0].Mode != "enforced" ||
		len(snapshot.Evidence) != 3 || len(snapshot.Verifications) != 1 || len(snapshot.Waivers) != 1 ||
		snapshot.Vulnerability == nil || snapshot.Vulnerability.RemainingCounts.Medium != 1 ||
		snapshot.Vulnerability.RemainingCounts.High != 0 || snapshot.Vulnerability.HighestRemaining != "medium" {
		t.Fatalf("EvaluateAdmission() = %+v, %v", snapshot, err)
	}
	if snapshot.Validate() != nil {
		t.Fatalf("snapshot validation failed: %v", snapshot.Validate())
	}
}

func TestDeploymentAdmissionFailsClosedInProductionAndWarnsDevelopment(t *testing.T) {
	fixture := newAdmissionFixture(t)
	fixture.evidence = fixture.evidence[1:]
	production, err := fixture.evaluator(t, "production", []biz.DeploymentPolicy{fixture.policy}).
		EvaluateAdmission(t.Context(), admissionRequest())
	if !errors.Is(err, deploymentbiz.ErrAdmissionDenied) || production.Decision != deploymentbiz.AdmissionDenied ||
		len(production.Violations) == 0 || production.Violations[0].Code != deploymentbiz.AdmissionSBOMMissing {
		t.Fatalf("production admission = %+v, %v", production, err)
	}
	development, err := fixture.evaluator(t, "development", []biz.DeploymentPolicy{fixture.policy}).
		EvaluateAdmission(t.Context(), admissionRequest())
	if err != nil || development.Decision != deploymentbiz.AdmissionAdmittedWithWarning ||
		development.Policies[0].Mode != "advisory" {
		t.Fatalf("development admission = %+v, %v", development, err)
	}
}

func TestDeploymentAdmissionRejectsReportObservationDrift(t *testing.T) {
	fixture := newAdmissionFixture(t)
	fixture.observation.Counts = biz.VulnerabilityCounts{High: 2, Total: 2}
	fixture.observation.HighestSeverity = biz.VulnerabilitySeverityHigh
	snapshot, err := fixture.evaluator(t, "production", []biz.DeploymentPolicy{fixture.policy}).
		EvaluateAdmission(t.Context(), admissionRequest())
	if !errors.Is(err, deploymentbiz.ErrAdmissionDenied) || snapshot.Decision != deploymentbiz.AdmissionDenied {
		t.Fatalf("drifted admission = %+v, %v", snapshot, err)
	}
	found := false
	for _, violation := range snapshot.Violations {
		found = found || violation.Code == deploymentbiz.AdmissionVulnerabilityIntegrity
	}
	if !found {
		t.Fatalf("drift violation missing: %+v", snapshot.Violations)
	}
}

func TestDeploymentAdmissionWithoutEnabledPolicyStillFreezesEvaluation(t *testing.T) {
	fixture := newAdmissionFixture(t)
	snapshot, err := fixture.evaluator(t, "staging", nil).EvaluateAdmission(t.Context(), admissionRequest())
	if err != nil || snapshot.Decision != deploymentbiz.AdmissionNotConfigured ||
		len(snapshot.Policies) != 0 || snapshot.EvaluationDigest == "" || snapshot.Validate() != nil {
		t.Fatalf("unconfigured admission = %+v, %v", snapshot, err)
	}
}
