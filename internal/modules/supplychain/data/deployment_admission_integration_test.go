package data

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	buildbiz "github.com/owndock/owndock/internal/modules/build/biz"
	deploymentbiz "github.com/owndock/owndock/internal/modules/deployment/biz"
	"github.com/owndock/owndock/internal/modules/supplychain/biz"
)

func TestDeploymentAdmissionFailsClosedWithRealRegistry(t *testing.T) {
	if os.Getenv("OWNDOCK_RUN_SUPPLY_CHAIN_INTEGRATION") != "1" {
		t.Skip("set OWNDOCK_RUN_SUPPLY_CHAIN_INTEGRATION=1 to run the Deployment admission Registry integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	containerName := fmt.Sprintf("owndock-admission-registry-%d", time.Now().UnixNano())
	runDockerCommand(t, ctx, "run", "--detach", "--name", containerName,
		"--publish", "127.0.0.1::5000", pinnedRegistryImage)
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()
		_ = exec.CommandContext(cleanupContext, "docker", "rm", "--force", containerName).Run()
	})
	port := strings.TrimSpace(runDockerCommand(t, ctx, "port", containerName, "5000/tcp"))
	base := "http://" + port
	waitForRegistry(t, ctx, base, nil)
	repository := strings.TrimPrefix(base, "http://") + "/admission/api"
	subjectDigest := createUnsignedRegistrySubject(t, ctx, base, "admission/api", "release", "amd64")
	otherSubjectDigest := createUnsignedRegistrySubject(t, ctx, base, "admission/api", "other", "arm64")
	artifactProber := mustNewOCIArtifactProber(t, OCIArtifactProberOptions{AllowPlainHTTP: true})
	if err := artifactProber.ProbeArtifact(ctx, "project-1", "registry-1", repository,
		subjectDigest); err != nil {
		t.Fatalf("probe external Artifact digest: %v", err)
	}

	document, err := biz.NewCycloneDX16Document([]byte(
		`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]}`), 4096)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := NewORASPublisher(ORASPublisherOptions{AllowPlainHTTP: true, MaxDocumentBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	published, err := publisher.PublishSBOM(ctx, biz.SBOMPublication{ProjectID: "project-1",
		RegistryCredentialID: "registry-1",
		RegistryRepository:   repository, SubjectDigest: subjectDigest, Document: document,
		CreatedAt: time.Unix(100, 0)})
	if err != nil {
		t.Fatal(err)
	}
	otherPublished, err := publisher.PublishSBOM(ctx, biz.SBOMPublication{ProjectID: "project-1",
		RegistryCredentialID: "registry-1",
		RegistryRepository:   repository, SubjectDigest: otherSubjectDigest, Document: document,
		CreatedAt: time.Unix(101, 0)})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)
	subject := biz.ArtifactSubject{ID: "artifact-1", OrganizationID: "organization-1",
		ProjectID: "project-1", SubjectDigest: subjectDigest, RegistryRepository: repository}
	policy, err := biz.NewDeploymentPolicy(biz.DeploymentPolicyInput{ID: "policy-1",
		OrganizationID: subject.OrganizationID, ProjectID: subject.ProjectID, Name: "Production baseline",
		Scope: biz.DeploymentPolicyScopeProject, Mode: biz.DeploymentPolicyEnforced,
		Requirements: biz.DeploymentPolicyRequirements{RequireSBOM: true}, Enabled: true, Version: 1,
		CreatedBy: "maintainer-1", UpdatedBy: "maintainer-1", CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	newEvidence := func(descriptorDigest string) biz.Evidence {
		item, evidenceErr := biz.NewEvidence(biz.EvidenceInput{ID: "sbom-1",
			OrganizationID: subject.OrganizationID, ProjectID: subject.ProjectID, ArtifactID: subject.ID,
			SubjectDigest: subject.SubjectDigest, Kind: biz.EvidenceKindSBOM,
			MediaType: biz.CycloneDXJSONMediaType, FormatVersion: biz.CycloneDXVersion16,
			Producer: "syft/1.50.0", RegistryRepository: repository,
			DescriptorDigest: descriptorDigest, VerificationStatus: biz.VerificationUnverified,
			CreatedAt: now})
		if evidenceErr != nil {
			t.Fatal(evidenceErr)
		}
		return item
	}
	reader, err := NewOCIContentReader(OCIContentReaderOptions{AllowPlainHTTP: true, MaxDocumentBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	newEvaluator := func(evidence biz.Evidence) *DeploymentAdmissionEvaluator {
		evaluator, evaluatorErr := NewDeploymentAdmissionEvaluator(DeploymentAdmissionOptions{
			Releases:  admissionReleaseLookupStub{stage: "production", artifactID: subject.ID},
			Artifacts: admissionArtifactLookupStub{subject: subject},
			Policies:  admissionPolicyRepositoryStub{items: []biz.DeploymentPolicy{policy}},
			Evidence:  admissionEvidenceRepositoryStub{items: []biz.Evidence{evidence}}, Content: reader,
			Verifications:   admissionVerificationRepositoryStub{},
			TrustPolicies:   admissionTrustPolicyRepositoryStub{items: map[string]biz.SignatureTrustPolicy{}},
			Vulnerabilities: admissionVulnerabilityRepositoryStub{}, Waivers: admissionWaiverRepositoryStub{},
			Now: func() time.Time { return now },
		})
		if evaluatorErr != nil {
			t.Fatal(evaluatorErr)
		}
		return evaluator
	}
	request := deploymentbiz.AdmissionRequest{OrganizationID: subject.OrganizationID,
		ProjectID: subject.ProjectID, ReleaseID: "release-1", ApplicationID: "application-1",
		EnvironmentID: "production"}
	admitted, err := newEvaluator(newEvidence(published.Digest)).EvaluateAdmission(ctx, request)
	if err != nil || admitted.Decision != deploymentbiz.AdmissionAdmitted || admitted.Validate() != nil ||
		len(admitted.Evidence) != 1 || admitted.Evidence[0].ContentDigest != document.ContentDigest {
		t.Fatalf("real Registry admission = %+v, %v", admitted, err)
	}

	assertAdmissionDeniedWithViolation(t,
		newEvaluator(newEvidence(otherPublished.Digest)), ctx, request, deploymentbiz.AdmissionEvidenceUnavailable)
	runDockerCommand(t, ctx, "stop", containerName)
	if err := artifactProber.ProbeArtifact(ctx, "project-1", "registry-1", repository,
		subjectDigest); !errors.Is(err, buildbiz.ErrArtifactRegistryUnavailable) {
		t.Fatalf("offline external Artifact probe error = %v", err)
	}
	assertAdmissionDeniedWithViolation(t,
		newEvaluator(newEvidence(published.Digest)), ctx, request, deploymentbiz.AdmissionEvidenceUnavailable)
}

func assertAdmissionDeniedWithViolation(t *testing.T, evaluator *DeploymentAdmissionEvaluator,
	ctx context.Context, request deploymentbiz.AdmissionRequest, code deploymentbiz.AdmissionViolationCode) {
	t.Helper()
	_, err := evaluator.EvaluateAdmission(ctx, request)
	if !errors.Is(err, deploymentbiz.ErrAdmissionDenied) {
		t.Fatalf("admission error = %v, want denied", err)
	}
	var denied deploymentbiz.AdmissionDeniedError
	if !errors.As(err, &denied) || denied.Snapshot.Decision != deploymentbiz.AdmissionDenied ||
		denied.Snapshot.Validate() != nil {
		t.Fatalf("denied snapshot = %+v, error = %v", denied.Snapshot, err)
	}
	for _, violation := range denied.Snapshot.Violations {
		if violation.Code == code {
			return
		}
	}
	t.Fatalf("denied violations = %+v, want %s", denied.Snapshot.Violations, code)
}
