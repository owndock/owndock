package biz

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/shared/runtimespec"
	"github.com/owndock/owndock/internal/shared/security"
	"github.com/owndock/owndock/internal/shared/transaction"
)

type externalArtifactStore struct {
	items map[string]Artifact
}

func (s *externalArtifactStore) ListArtifacts(_ context.Context, projectID string) ([]Artifact, error) {
	var result []Artifact
	for _, item := range s.items {
		if item.ProjectID == projectID {
			result = append(result, item)
		}
	}
	return result, nil
}

func (s *externalArtifactStore) GetArtifact(_ context.Context, projectID, artifactID string) (Artifact, error) {
	item, ok := s.items[artifactID]
	if !ok || item.ProjectID != projectID {
		return Artifact{}, ErrNotFound
	}
	return item, nil
}

func (s *externalArtifactStore) GetArtifactByBuild(_ context.Context, buildID string) (Artifact, error) {
	for _, item := range s.items {
		if item.BuildID == buildID && buildID != "" {
			return item, nil
		}
	}
	return Artifact{}, ErrNotFound
}

func (s *externalArtifactStore) GetArtifactByRegistrationKey(_ context.Context,
	projectID, key string) (Artifact, error) {
	for _, item := range s.items {
		if item.ProjectID == projectID && item.RegistrationKey == key && key != "" {
			return item, nil
		}
	}
	return Artifact{}, ErrNotFound
}

func (s *externalArtifactStore) CreateArtifact(_ context.Context, item Artifact) (Artifact, error) {
	if _, ok := s.items[item.ID]; ok {
		return Artifact{}, ErrDuplicateArtifact
	}
	for _, existing := range s.items {
		if existing.ProjectID == item.ProjectID && existing.RegistrationKey != "" &&
			existing.RegistrationKey == item.RegistrationKey {
			return Artifact{}, ErrDuplicateArtifact
		}
	}
	s.items[item.ID] = item
	return item, nil
}

func (s *externalArtifactStore) NextPendingArtifact(context.Context) (Artifact, bool, error) {
	return Artifact{}, false, nil
}

func (s *externalArtifactStore) SaveArtifactRelease(_ context.Context, item Artifact,
	expected uint64) (Artifact, error) {
	current, ok := s.items[item.ID]
	if !ok {
		return Artifact{}, ErrNotFound
	}
	if current.Version != expected {
		return Artifact{}, ErrVersionConflict
	}
	item.Version = expected + 1
	s.items[item.ID] = item
	return item, nil
}

type artifactEvidenceSchedulerStub struct {
	calls int
	item  Artifact
	err   error
}

func (s *artifactEvidenceSchedulerStub) EnsureArtifactEvidence(_ context.Context, item Artifact) error {
	s.calls++
	s.item = item
	return s.err
}

type artifactAvailabilityProbeStub struct {
	calls        int
	projectID    string
	credentialID string
	repository   string
	digest       string
	err          error
}

type externalArtifactReleaseCreatorStub struct {
	request ArtifactReleaseRequest
	calls   int
}

func (s *externalArtifactReleaseCreatorStub) CreateArtifactRelease(_ context.Context,
	request ArtifactReleaseRequest) (string, error) {
	s.calls++
	s.request = request
	return "external-release-1", nil
}

func (s *artifactAvailabilityProbeStub) ProbeArtifact(_ context.Context, projectID, credentialID,
	repository, digest string) error {
	s.calls++
	s.projectID, s.credentialID, s.repository, s.digest = projectID, credentialID, repository, digest
	return s.err
}

func TestUseCaseRegistersExternalArtifactIdempotently(t *testing.T) {
	artifacts := &externalArtifactStore{items: map[string]Artifact{}}
	evidence, probe, audit := &artifactEvidenceSchedulerStub{}, &artifactAvailabilityProbeStub{}, &auditStub{}
	sequence := 0
	references := configurationReferencesStub{applicationExists: true, registryServer: "registry.example.com"}
	useCase := NewUseCase(projectLookupStub{exists: true}, newRepositoryStub(),
		transaction.Passthrough{}, audit, func() (string, error) {
			sequence++
			return fmt.Sprintf("generated-%d", sequence), nil
		}, func() time.Time { return time.Unix(300, 0).UTC() }).
		WithConfigurationReferences(references, references).
		WithArtifactReleases(artifacts, nil).
		WithExternalArtifactRegistration(evidence, probe)
	input := ExternalArtifactInput{
		ApplicationID: "application-1", RegistryCredentialID: "registry-1",
		ImageDigest:    "registry.example.com/team/api@sha256:" + strings.Repeat("c", 64),
		TargetPlatform: BuildPlatformLinuxAMD64, Producer: "github-actions/team/api",
		RegistrationKey: "delivery-123",
	}
	created, err := useCase.RegisterExternalArtifact(t.Context(),
		testPrincipal(security.RoleDeveloper), "project-1", input, "request-1")
	if err != nil {
		t.Fatal(err)
	}
	if created.Origin != ArtifactOriginExternal || created.ProducerVerification != ArtifactProducerDeclared ||
		created.BuildID != "" || evidence.calls != 1 || evidence.item.ID != created.ID || probe.calls != 1 ||
		probe.projectID != "project-1" || probe.credentialID != "registry-1" ||
		probe.repository != "registry.example.com/team/api" ||
		probe.digest != "sha256:"+strings.Repeat("c", 64) || len(audit.events) != 1 ||
		audit.events[0].Action != "artifact.register_external" {
		t.Fatalf("created=%+v evidence=%+v probe=%+v audit=%+v", created, evidence, probe, audit.events)
	}
	replayed, err := useCase.RegisterExternalArtifact(t.Context(),
		testPrincipal(security.RoleDeveloper), "project-1", input, "request-2")
	if err != nil || replayed.ID != created.ID || evidence.calls != 1 || probe.calls != 1 || len(audit.events) != 1 {
		t.Fatalf("replay=%+v err=%v evidence=%d probe=%d audit=%d",
			replayed, err, evidence.calls, probe.calls, len(audit.events))
	}
	changed := input
	changed.Producer = "gitlab-ci/team/api"
	if _, err := useCase.RegisterExternalArtifact(t.Context(),
		testPrincipal(security.RoleDeveloper), "project-1", changed, "request-3"); !errors.Is(err, ErrIdempotencyMismatch) {
		t.Fatalf("changed idempotent request error = %v", err)
	}
}

func TestUseCaseExternalArtifactFailsClosedBeforePersistence(t *testing.T) {
	for name, testCase := range map[string]struct {
		expected  error
		configure func(*configurationReferencesStub, *artifactEvidenceSchedulerStub, *artifactAvailabilityProbeStub)
	}{
		"registry mismatch": {ErrRegistryMismatch, func(references *configurationReferencesStub,
			_ *artifactEvidenceSchedulerStub, _ *artifactAvailabilityProbeStub) {
			references.registryServer = "registry.other.example"
		}},
		"probe unavailable": {ErrArtifactRegistryUnavailable, func(_ *configurationReferencesStub,
			_ *artifactEvidenceSchedulerStub, probe *artifactAvailabilityProbeStub) {
			probe.err = ErrArtifactRegistryUnavailable
		}},
		"evidence unavailable": {ErrArtifactRegistrationUnavailable, func(_ *configurationReferencesStub,
			evidence *artifactEvidenceSchedulerStub, _ *artifactAvailabilityProbeStub) {
			evidence.err = errors.New("evidence storage failed")
		}},
	} {
		t.Run(name, func(t *testing.T) {
			artifacts := &externalArtifactStore{items: map[string]Artifact{}}
			evidence, probe := &artifactEvidenceSchedulerStub{}, &artifactAvailabilityProbeStub{}
			references := configurationReferencesStub{applicationExists: true, registryServer: "registry.example.com"}
			testCase.configure(&references, evidence, probe)
			useCase := NewUseCase(projectLookupStub{exists: true}, newRepositoryStub(),
				transaction.Passthrough{}, &auditStub{}, func() (string, error) { return "generated-1", nil },
				func() time.Time { return time.Unix(300, 0) }).WithConfigurationReferences(references, references).
				WithArtifactReleases(artifacts, nil).WithExternalArtifactRegistration(evidence, probe)
			_, err := useCase.RegisterExternalArtifact(t.Context(), testPrincipal(security.RoleDeveloper),
				"project-1", ExternalArtifactInput{
					ApplicationID: "application-1", RegistryCredentialID: "registry-1",
					ImageDigest:    "registry.example.com/team/api@sha256:" + strings.Repeat("d", 64),
					TargetPlatform: BuildPlatformLinuxAMD64, Producer: "external-ci",
					RegistrationKey: "delivery-123",
				}, "request-1")
			if !errors.Is(err, testCase.expected) {
				t.Fatalf("RegisterExternalArtifact() error = %v, want %v", err, testCase.expected)
			}
		})
	}
}

func TestUseCaseCreatesReleaseFromExternalArtifactWithoutInventingBuild(t *testing.T) {
	item, err := NewExternalArtifact(ExternalArtifactInput{
		ID: "external-artifact-1", OrganizationID: "organization-1", ProjectID: "project-1",
		ApplicationID: "application-1", RegistryCredentialID: "registry-1",
		ImageDigest:    "registry.example.com/team/api@sha256:" + strings.Repeat("e", 64),
		TargetPlatform: BuildPlatformLinuxAMD64, Producer: "github-actions/team/api",
		RegistrationKey: "delivery-123", ReleaseRuntimeSpec: runtimespec.Spec{
			Ports: []runtimespec.Port{{Name: "http", ContainerPort: 8080}},
		}, CreatedAt: time.Unix(300, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	artifacts := &externalArtifactStore{items: map[string]Artifact{item.ID: item}}
	creator, audit := &externalArtifactReleaseCreatorStub{}, &auditStub{}
	sequence := 0
	useCase := NewUseCase(projectLookupStub{exists: true}, newRepositoryStub(),
		transaction.Passthrough{}, audit, func() (string, error) {
			sequence++
			return fmt.Sprintf("release-audit-%d", sequence), nil
		}, func() time.Time { return time.Unix(400, 0) }).WithArtifactReleases(artifacts, creator)
	released, err := useCase.CreateReleaseFromArtifact(t.Context(),
		testPrincipal(security.RoleDeveloper), item.ProjectID, item.ID, runtimespec.Spec{}, "request-1")
	if err != nil {
		t.Fatal(err)
	}
	if released.ReleaseStatus != ArtifactReleaseCreated || released.ReleaseID != "external-release-1" ||
		creator.calls != 1 || creator.request.ArtifactID != item.ID || creator.request.BuildID != "" ||
		creator.request.BuildConfigurationID != "" || len(creator.request.AutomaticDeployments) != 0 ||
		len(creator.request.RuntimeSpec.Ports) != 1 || creator.request.RuntimeSpec.Ports[0].ContainerPort != 8080 ||
		len(audit.events) != 1 || audit.events[0].Action != "artifact.release_created" {
		t.Fatalf("released=%+v creator=%+v audit=%+v", released, creator, audit.events)
	}
}
