package biz

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/shared/security"
)

type signatureArtifactLookupStub struct{ subject ArtifactSubject }

func (s signatureArtifactLookupStub) ResolveArtifact(context.Context, string, string, string) (ArtifactSubject, error) {
	return s.subject, nil
}

type signatureJobCreatorStub struct {
	job       EvidenceJob
	duplicate bool
}

func (s *signatureJobCreatorStub) CreateEvidenceJob(_ context.Context, item EvidenceJob) (EvidenceJob, error) {
	if s.duplicate {
		return s.job, ErrDuplicate
	}
	s.job, s.duplicate = item, true
	return item, nil
}

func TestSignatureVerificationUseCaseFreezesPolicyAndIsIdempotent(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	policy, err := NewSignatureTrustPolicy(SignatureTrustPolicyInput{ID: "policy-1",
		OrganizationID: "organization-1", ProjectID: "project-1", Name: "release signer",
		Mode: SignatureTrustKeyless, TrustedRootID: "offline-root-1",
		TrustedRootHash:     "sha256:" + strings.Repeat("b", 64),
		CertificateIdentity: "https://git.example.com/team/api/.ci/release@refs/tags/v1.0.0",
		OIDCIssuer:          "https://issuer.example.com", Enabled: true, Version: 4, CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	policies := &signaturePolicyRepositoryStub{items: map[string]SignatureTrustPolicy{policy.ID: policy}}
	jobs := &signatureJobCreatorStub{}
	useCase, err := NewSignatureVerificationUseCase(signatureArtifactLookupStub{subject: ArtifactSubject{
		ID: "artifact-1", OrganizationID: "organization-1", ProjectID: "project-1",
		SubjectDigest:      "sha256:" + strings.Repeat("a", 64),
		RegistryRepository: "registry.example.com/team/api", RegistryCredentialID: "registry-1",
	}}, policies, jobs, func() (string, error) { return "audit-1", nil }, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	developer := security.Principal{UserID: "developer-1", OrganizationID: "organization-1",
		SessionID: "session-1", Role: security.RoleDeveloper}
	first, err := useCase.Schedule(t.Context(), developer, "project-1", "artifact-1", "policy-1", "request-1")
	if err != nil || !first.Scheduled || jobs.job.Signature.PolicyVersion != 4 ||
		jobs.job.ID != SignatureVerificationIdempotencyKey("artifact-1", "policy-1", 4, "request-1") {
		t.Fatalf("first schedule = %+v job=%+v err=%v", first, jobs.job, err)
	}
	second, err := useCase.Schedule(t.Context(), developer, "project-1", "artifact-1", "policy-1", "request-1")
	if err != nil || second.Scheduled || second.JobID != first.JobID {
		t.Fatalf("duplicate schedule = %+v, %v", second, err)
	}
	viewer := developer
	viewer.Role = security.RoleViewer
	jobs.duplicate = false
	retry, err := useCase.Schedule(t.Context(), developer, "project-1", "artifact-1", "policy-1", "request-2")
	if err != nil || !retry.Scheduled || retry.JobID == first.JobID {
		t.Fatalf("retry schedule = %+v, %v", retry, err)
	}
	if _, err := useCase.Schedule(t.Context(), viewer, "project-1", "artifact-1", "policy-1", "request-3"); !errors.Is(err, security.ErrForbidden) {
		t.Fatalf("viewer schedule error = %v", err)
	}
	if _, err := useCase.Schedule(t.Context(), developer, "project-1", "artifact-1", "policy-1", "bad request"); !errors.Is(err, ErrInvalidSignatureVerificationRequest) {
		t.Fatalf("invalid idempotency key error = %v", err)
	}
}
