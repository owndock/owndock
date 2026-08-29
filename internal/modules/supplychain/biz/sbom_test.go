package biz

import (
	"errors"
	"strings"
	"testing"
)

func TestSBOMRequestRequiresExactDigestAndCycloneDX16(t *testing.T) {
	request := SBOMRequest{
		ProjectID: "project-1", RegistryCredentialID: "registry-1",
		RegistryRepository: "registry.example.com/team/api",
		SubjectDigest:      "sha256:" + strings.Repeat("a", 64),
		FormatVersion:      CycloneDXVersion16,
	}
	if err := request.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if !strings.Contains(request.CanonicalSubject(), "@sha256:") {
		t.Fatalf("CanonicalSubject() = %q", request.CanonicalSubject())
	}
	request.FormatVersion = "latest"
	if err := request.Validate(); !errors.Is(err, ErrInvalidEvidenceJob) {
		t.Fatalf("floating format Validate() error = %v", err)
	}
	request.FormatVersion, request.SubjectDigest = CycloneDXVersion16, "tag:latest"
	if err := request.Validate(); !errors.Is(err, ErrInvalidEvidenceJob) {
		t.Fatalf("moving subject Validate() error = %v", err)
	}
}

func TestNewCycloneDX16DocumentValidatesAndHashesBoundedContent(t *testing.T) {
	content := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","name":"example"}]}`)
	document, err := NewCycloneDX16Document(content, 4096)
	if err != nil || document.MediaType != CycloneDXJSONMediaType ||
		document.FormatVersion != CycloneDXVersion16 || !strings.HasPrefix(document.ContentDigest, "sha256:") {
		t.Fatalf("NewCycloneDX16Document() = %+v, %v", document, err)
	}
	content[0] = 'x'
	if document.Content[0] != '{' {
		t.Fatal("SBOM content aliases caller memory")
	}
	for _, invalid := range [][]byte{
		[]byte(`not-json`),
		[]byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1}`),
		[]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":0}`),
		[]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"","name":"x"}]}`),
	} {
		if _, err := NewCycloneDX16Document(invalid, 4096); !errors.Is(err, ErrInvalidSBOM) {
			t.Fatalf("invalid document %q error = %v", invalid, err)
		}
	}
	if _, err := NewCycloneDX16Document([]byte(`{}`), 1); !errors.Is(err, ErrSBOMTooLarge) {
		t.Fatalf("oversized document error = %v", err)
	}
}
