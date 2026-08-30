package data

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/supplychain/biz"
)

type registryCredentialProviderProbe struct {
	credential biz.RegistryCredential
	err        error
}

func (p registryCredentialProviderProbe) ResolveRegistryCredential(
	context.Context, string, string, string,
) (biz.RegistryCredential, error) {
	return biz.RegistryCredential{
		AuthenticationMode: p.credential.AuthenticationMode,
		Username:           p.credential.Username,
		Password:           append([]byte(nil), p.credential.Password...),
	}, p.err
}

func orasPublicationFixture(t *testing.T, repository string) biz.SBOMPublication {
	t.Helper()
	document, err := biz.NewCycloneDX16Document(
		[]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]}`), 4096,
	)
	if err != nil {
		t.Fatal(err)
	}
	return biz.SBOMPublication{
		ProjectID: "project-1", RegistryCredentialID: "registry-1",
		RegistryRepository: repository, SubjectDigest: "sha256:" + strings.Repeat("a", 64),
		Document: document, CreatedAt: time.Unix(100, 0),
	}
}

func provenancePublicationFixture(t *testing.T, repository, subjectDigest string) biz.ProvenancePublication {
	t.Helper()
	recipe := biz.ProvenanceRecipe{
		BuildID: "build-1", ApplicationID: "application-1",
		SourceURI: "git+https://git.example.com/team/api.git",
		SourceRef: "refs/heads/main", CommitSHA: strings.Repeat("b", 40),
		ConfigurationID: "configuration-1", ConfigurationVersion: 7,
		DockerfilePath: "Dockerfile", ContextPath: ".", TargetPlatform: "linux/amd64",
		CPUMilli: 2000, MemoryBytes: 2 * 1024 * 1024 * 1024,
		DiskBytes: 10 * 1024 * 1024 * 1024, TimeoutSeconds: 1800,
		BuilderID:      biz.OwnDockBuildKitBuilderIDV1,
		BuilderVersion: "0.1.0", BuilderCommit: strings.Repeat("c", 40),
		BuildKitVersion: "v0.31.2",
		BuildKitImage:   "moby/buildkit:v0.31.2-rootless@sha256:" + strings.Repeat("d", 64),
		FrontendImage:   "docker/dockerfile:1.25.0@sha256:" + strings.Repeat("e", 64),
		StartedAt:       time.Unix(100, 0).UTC(), FinishedAt: time.Unix(200, 0).UTC(),
	}
	generator, err := NewSLSAProvenanceGenerator(64 * 1024)
	if err != nil {
		t.Fatal(err)
	}
	document, err := generator.GenerateProvenance(t.Context(), biz.ProvenanceRequest{
		RegistryRepository: repository, SubjectDigest: subjectDigest, Recipe: recipe,
	})
	if err != nil {
		t.Fatal(err)
	}
	return biz.ProvenancePublication{
		ProjectID: "project-1", RegistryCredentialID: "registry-1",
		RegistryRepository: repository, SubjectDigest: subjectDigest,
		Document: document, CreatedAt: time.Unix(200, 0),
	}
}

func TestORASPublisherRejectsUnsafeConfigurationAndPublication(t *testing.T) {
	if _, err := NewORASPublisher(ORASPublisherOptions{MaxDocumentBytes: 1}); !errors.Is(err, biz.ErrInvalidEvidenceJob) {
		t.Fatalf("invalid limit error = %v", err)
	}
	publisher, err := NewORASPublisher(ORASPublisherOptions{AllowPlainHTTP: true, MaxDocumentBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	if publisher.String() != "oras-go/2.6.2" {
		t.Fatalf("String() = %q", publisher.String())
	}
	if _, err := publisher.PublishSBOM(t.Context(), orasPublicationFixture(t, "registry.example.com/team/api")); !errors.Is(err, biz.ErrInvalidEvidenceJob) {
		t.Fatalf("plain remote Registry error = %v", err)
	}
	invalid := orasPublicationFixture(t, "127.0.0.1:5000/team/api")
	invalid.Document.ContentDigest = "sha256:" + strings.Repeat("b", 64)
	if _, err := publisher.PublishSBOM(t.Context(), invalid); !errors.Is(err, biz.ErrInvalidSBOM) {
		t.Fatalf("mismatched SBOM digest error = %v", err)
	}
	provenance := provenancePublicationFixture(t, "127.0.0.1:5000/team/api",
		"sha256:"+strings.Repeat("a", 64))
	provenance.Document.ContentDigest = "sha256:" + strings.Repeat("f", 64)
	if _, err := publisher.PublishProvenance(t.Context(), provenance); !errors.Is(err, biz.ErrInvalidProvenance) {
		t.Fatalf("mismatched provenance digest error = %v", err)
	}
}

func TestORASPublisherFailsClosedBeforeNetworkWhenCredentialCannotResolve(t *testing.T) {
	publisher, err := NewORASPublisher(ORASPublisherOptions{
		AllowPlainHTTP: true, MaxDocumentBytes: 4096,
		Credentials: registryCredentialProviderProbe{err: errors.New("secret provider detail")},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = publisher.PublishSBOM(t.Context(), orasPublicationFixture(t, "127.0.0.1:1/team/api"))
	if !errors.Is(err, biz.ErrRegistryAuthentication) || strings.Contains(err.Error(), "secret provider detail") {
		t.Fatalf("credential error = %v", err)
	}
}
