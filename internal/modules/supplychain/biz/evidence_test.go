package biz

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/shared/security"
)

func validEvidenceInput() EvidenceInput {
	return EvidenceInput{
		ID: "evidence-1", OrganizationID: "organization-1", ProjectID: "project-1",
		ArtifactID: "artifact-1", SubjectDigest: "sha256:" + strings.Repeat("a", 64),
		Kind: EvidenceKindSBOM, MediaType: "application/vnd.cyclonedx+json",
		FormatVersion: "1.6", Producer: "owndock-evidence-worker/1.0.0",
		RegistryRepository: "registry.example.com/team/api",
		DescriptorDigest:   "sha256:" + strings.Repeat("b", 64),
		VerificationStatus: VerificationVerified, CreatedAt: time.Unix(100, 0),
	}
}

func TestNewEvidenceNormalizesAndValidatesBoundedIndex(t *testing.T) {
	item, err := NewEvidence(validEvidenceInput())
	if err != nil {
		t.Fatalf("NewEvidence() error = %v", err)
	}
	if item.SubjectDigest == item.DescriptorDigest || item.CreatedAt.Location() != time.UTC {
		t.Fatalf("evidence = %+v", item)
	}
	invalid := []func(*EvidenceInput){
		func(v *EvidenceInput) { v.SubjectDigest = "latest" },
		func(v *EvidenceInput) { v.DescriptorDigest = "sha512:" + strings.Repeat("a", 128) },
		func(v *EvidenceInput) { v.RegistryRepository += ":latest" },
		func(v *EvidenceInput) { v.MediaType = "Application/JSON" },
		func(v *EvidenceInput) { v.PredicateType = "http://unsafe.example/predicate" },
		func(v *EvidenceInput) { v.VerificationStatus = "trusted" },
	}
	for index, mutate := range invalid {
		input := validEvidenceInput()
		mutate(&input)
		if _, err := NewEvidence(input); !errors.Is(err, ErrInvalidEvidence) {
			t.Errorf("invalid[%d] error = %v", index, err)
		}
	}
}

func TestEvidenceEnumsAndConstructorDependenciesFailClosed(t *testing.T) {
	for _, kind := range []EvidenceKind{
		EvidenceKindSBOM, EvidenceKindProvenance, EvidenceKindSignature,
		EvidenceKindVulnerabilityReport,
	} {
		if !kind.Valid() {
			t.Errorf("kind %q is not valid", kind)
		}
	}
	if EvidenceKind("unknown").Valid() || VerificationStatus("trusted").Valid() {
		t.Fatal("unknown evidence enum was accepted")
	}
	if _, err := NewUseCase(nil, artifactLookupStub{}, &repositoryStub{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("NewUseCase(nil) error = %v", err)
	}
}

type projectLookupStub struct{ exists bool }

func (s projectLookupStub) ProjectExists(context.Context, string, string) (bool, error) {
	return s.exists, nil
}

type artifactLookupStub struct{ err error }

func (s artifactLookupStub) ResolveArtifact(context.Context, string, string, string) (ArtifactSubject, error) {
	return ArtifactSubject{ID: "artifact-1"}, s.err
}

type repositoryStub struct{ items []Evidence }

func (s *repositoryStub) ListEvidence(context.Context, string, string) ([]Evidence, error) {
	return s.items, nil
}
func (s *repositoryStub) GetEvidence(context.Context, string, string, string) (Evidence, error) {
	if len(s.items) == 0 {
		return Evidence{}, ErrNotFound
	}
	return s.items[0], nil
}
func (s *repositoryStub) CreateEvidence(_ context.Context, item Evidence) (Evidence, error) {
	return item, nil
}

func TestUseCaseRequiresProjectArtifactAndReadPermission(t *testing.T) {
	item, _ := NewEvidence(validEvidenceInput())
	principal := security.Principal{UserID: "user-1", OrganizationID: "organization-1", SessionID: "session-1", Role: security.RoleViewer}
	repository := &repositoryStub{items: []Evidence{item}}
	useCase, err := NewUseCase(projectLookupStub{exists: true}, artifactLookupStub{}, repository)
	if err != nil {
		t.Fatalf("NewUseCase() error = %v", err)
	}
	items, err := useCase.ListEvidence(t.Context(), principal, "project-1", "artifact-1")
	if err != nil || len(items) != 1 {
		t.Fatalf("ListEvidence() = %+v, %v", items, err)
	}
	if _, err := useCase.ListEvidence(t.Context(), security.Principal{}, "project-1", "artifact-1"); !errors.Is(err, security.ErrUnauthenticated) {
		t.Fatalf("unauthenticated error = %v", err)
	}
	missingProject, _ := NewUseCase(projectLookupStub{}, artifactLookupStub{}, repository)
	if _, err := missingProject.ListEvidence(t.Context(), principal, "project-1", "artifact-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing project error = %v", err)
	}
	missingArtifact, _ := NewUseCase(projectLookupStub{exists: true}, artifactLookupStub{err: ErrNotFound}, repository)
	if _, err := missingArtifact.ListEvidence(t.Context(), principal, "project-1", "artifact-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing artifact error = %v", err)
	}
	if _, err := useCase.GetEvidence(t.Context(), principal, "project-1", "artifact-1", "invalid/id"); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("invalid evidence ID error = %v", err)
	}
	if got, err := useCase.GetEvidence(t.Context(), principal, "project-1", "artifact-1", "evidence-1"); err != nil || got.ID != item.ID {
		t.Fatalf("GetEvidence() = %+v, %v", got, err)
	}
}
