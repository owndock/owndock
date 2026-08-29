package data

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/supplychain/biz"
)

func TestOCIContentReaderRejectsUnsafeLimitsAndMismatchedIdentityBeforeNetwork(t *testing.T) {
	if _, err := NewOCIContentReader(OCIContentReaderOptions{MaxDocumentBytes: 1}); !errors.Is(err, biz.ErrInvalidEvidence) {
		t.Fatalf("invalid limit error = %v", err)
	}
	reader, err := NewOCIContentReader(OCIContentReaderOptions{
		AllowPlainHTTP: true, MaxDocumentBytes: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	subject := biz.ArtifactSubject{
		ID: "artifact-1", OrganizationID: "organization-1", ProjectID: "project-1",
		SubjectDigest:      "sha256:" + strings.Repeat("a", 64),
		RegistryRepository: "127.0.0.1:5000/team/api", RegistryCredentialID: "registry-1",
	}
	evidence, err := biz.NewEvidence(biz.EvidenceInput{
		ID: "sbom-1", OrganizationID: subject.OrganizationID, ProjectID: subject.ProjectID,
		ArtifactID: "different-artifact", SubjectDigest: subject.SubjectDigest,
		Kind: biz.EvidenceKindSBOM, MediaType: biz.CycloneDXJSONMediaType,
		FormatVersion: biz.CycloneDXVersion16, Producer: "syft/1.50.0",
		RegistryRepository: subject.RegistryRepository,
		DescriptorDigest:   "sha256:" + strings.Repeat("b", 64),
		VerificationStatus: biz.VerificationUnverified, CreatedAt: time.Unix(100, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadEvidence(t.Context(), subject, evidence); !errors.Is(err, biz.ErrInvalidEvidence) {
		t.Fatalf("mismatched identity error = %v", err)
	}
}

func TestEvidenceDownloadValidationAndBoundsFailClosed(t *testing.T) {
	content, err := readBounded(io.NopCloser(strings.NewReader("12345")), 4)
	if !errors.Is(err, biz.ErrEvidenceContentTooLarge) || content != nil {
		t.Fatalf("readBounded() = %q, %v", content, err)
	}
	sbom := biz.Evidence{
		Kind: biz.EvidenceKindSBOM, MediaType: biz.CycloneDXJSONMediaType,
		FormatVersion: biz.CycloneDXVersion16,
	}
	if err := validateDownloadedEvidence([]byte(`{"bomFormat":"CycloneDX"}`), sbom, 4096); !errors.Is(err, biz.ErrEvidenceIntegrity) {
		t.Fatalf("invalid SBOM error = %v", err)
	}
	unsupported := biz.Evidence{Kind: biz.EvidenceKindSignature}
	if err := validateDownloadedEvidence([]byte(`{}`), unsupported, 4096); !errors.Is(err, biz.ErrUnavailable) {
		t.Fatalf("unsupported evidence error = %v", err)
	}
}
