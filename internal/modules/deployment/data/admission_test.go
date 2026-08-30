package data

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/deployment/biz"
)

func TestDeploymentDocumentPreservesAndValidatesAdmissionSnapshot(t *testing.T) {
	now := time.Date(2026, 8, 29, 10, 0, 0, 123456789, time.UTC)
	snapshot, err := (biz.AdmissionSnapshot{EvaluatedAt: now, EnvironmentStage: "production",
		ArtifactID: "artifact-1", SubjectDigest: "sha256:" + strings.Repeat("a", 64),
		Policies: []biz.AdmissionPolicySnapshot{{ID: "policy-1", Version: 3, Scope: "project",
			Mode: "enforced", Requirements: biz.AdmissionRequirementsSnapshot{RequireSBOM: true,
				AllowedSignaturePolicyIDs: []string{}}}},
		Evidence: []biz.AdmissionEvidenceSnapshot{{ID: "evidence-1", Kind: "sbom",
			DescriptorDigest: "sha256:" + strings.Repeat("b", 64),
			ContentDigest:    "sha256:" + strings.Repeat("c", 64)}},
		Verifications: []biz.AdmissionVerificationSnapshot{}, Waivers: []biz.AdmissionWaiverSnapshot{},
		Violations: []biz.AdmissionViolation{}, Decision: biz.AdmissionAdmitted}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	item, err := biz.NewFormal("deployment-1", "project-1", "release-1", "application-1",
		"environment-1", "target-1", "idempotency-1", now)
	if err != nil {
		t.Fatal(err)
	}
	item.OrganizationID, item.Admission = "organization-1", snapshot
	document := deploymentDocumentFromDomain(item)
	restored, err := document.domain()
	if err != nil || restored.Admission.EvaluationDigest != snapshot.EvaluationDigest ||
		restored.Admission.Policies[0].Version != 3 || restored.Admission.Validate() != nil {
		t.Fatalf("round trip = %+v, %v", restored, err)
	}
	document.Admission.EvaluationDigest = "sha256:" + strings.Repeat("f", 64)
	if _, err := document.domain(); !errors.Is(err, biz.ErrAdmissionUnavailable) {
		t.Fatalf("corrupt admission error = %v", err)
	}
}
