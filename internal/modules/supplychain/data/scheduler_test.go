package data

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	buildbiz "github.com/owndock/owndock/internal/modules/build/biz"
	"github.com/owndock/owndock/internal/modules/supplychain/biz"
)

type evidenceJobCreatorStub struct {
	job  biz.EvidenceJob
	jobs []biz.EvidenceJob
	err  error
}

func (s *evidenceJobCreatorStub) CreateEvidenceJob(
	_ context.Context, job biz.EvidenceJob,
) (biz.EvidenceJob, error) {
	s.job = job
	s.jobs = append(s.jobs, job)
	return job, s.err
}

type provenanceBuildLookupStub struct {
	build  buildbiz.Build
	source buildbiz.SourceRepository
	err    error
}

type signaturePolicyListerStub struct {
	policies []biz.SignatureTrustPolicy
	err      error
}
type signingProfileListerStub struct {
	profiles []biz.SignatureSigningProfile
	err      error
}

func (s signingProfileListerStub) ListSignatureSigningProfiles(context.Context, string) ([]biz.SignatureSigningProfile, error) {
	return s.profiles, s.err
}

func (s signaturePolicyListerStub) ListSignatureTrustPolicies(context.Context, string) ([]biz.SignatureTrustPolicy, error) {
	return s.policies, s.err
}

func (s provenanceBuildLookupStub) GetBuild(context.Context, string, string) (buildbiz.Build, error) {
	return s.build, s.err
}

func (s provenanceBuildLookupStub) GetSource(context.Context, string, string) (buildbiz.SourceRepository, error) {
	return s.source, s.err
}

func TestArtifactEvidenceSchedulerCreatesStableSBOMJob(t *testing.T) {
	creator := &evidenceJobCreatorStub{}
	scheduler := NewArtifactEvidenceScheduler(
		creator, func() (string, error) { return "job-1", nil },
		func() time.Time { return time.Unix(200, 0) },
	)
	artifact := buildbiz.Artifact{
		ID: "artifact-1", OrganizationID: "organization-1", ProjectID: "project-1",
		RegistryCredentialID: "registry-1", ImageRepository: "registry.example.com/team/api",
		ImageDigest: "registry.example.com/team/api@sha256:" + strings.Repeat("a", 64),
	}
	if err := scheduler.EnsureArtifactEvidence(t.Context(), artifact); err != nil {
		t.Fatalf("EnsureArtifactEvidence() error = %v", err)
	}
	job := creator.job
	if job.ID != "job-1" || job.ArtifactID != artifact.ID ||
		job.SubjectDigest != "sha256:"+strings.Repeat("a", 64) ||
		job.Kind != biz.EvidenceKindSBOM || job.FormatVersion != "1.6" ||
		job.Producer != "syft/1.50.0" || !strings.HasPrefix(job.IdempotencyKey, "sbom-") {
		t.Fatalf("scheduled job = %+v", job)
	}
	firstKey := job.IdempotencyKey
	if err := scheduler.EnsureArtifactEvidence(t.Context(), artifact); err != nil ||
		creator.job.IdempotencyKey != firstKey {
		t.Fatalf("stable retry = %+v, %v", creator.job, err)
	}
}

func TestArtifactEvidenceSchedulerCreatesStableVulnerabilityJobWhenEnabled(t *testing.T) {
	creator := &evidenceJobCreatorStub{}
	ids := []string{"sbom-job-1", "vulnerability-job-1"}
	scheduler := NewArtifactEvidenceScheduler(creator, func() (string, error) {
		id := ids[0]
		ids = ids[1:]
		return id, nil
	}, func() time.Time { return time.Unix(210, 0).UTC() }).WithVulnerabilityScanning()
	artifact := buildbiz.Artifact{ID: "artifact-1", OrganizationID: "organization-1", ProjectID: "project-1",
		RegistryCredentialID: "registry-1", ImageRepository: "registry.example.com/team/api",
		ImageDigest: "registry.example.com/team/api@sha256:" + strings.Repeat("a", 64)}
	if err := scheduler.EnsureArtifactEvidence(t.Context(), artifact); err != nil {
		t.Fatal(err)
	}
	if len(creator.jobs) != 2 || creator.jobs[1].ID != "vulnerability-job-1" ||
		creator.jobs[1].Kind != biz.EvidenceKindVulnerabilityReport ||
		creator.jobs[1].FormatVersion != biz.TrivyReportFormatVersion ||
		creator.jobs[1].Producer != "trivy/"+PinnedTrivyVersion ||
		!strings.HasPrefix(creator.jobs[1].IdempotencyKey, "vulnerability-") {
		t.Fatalf("jobs = %+v", creator.jobs)
	}
}

func TestArtifactEvidenceSchedulerFreezesSLSAProvenanceRecipe(t *testing.T) {
	creator := &evidenceJobCreatorStub{}
	ids := []string{"sbom-job-1", "provenance-job-1"}
	scheduler := NewArtifactEvidenceScheduler(creator, func() (string, error) {
		id := ids[0]
		ids = ids[1:]
		return id, nil
	}, func() time.Time { return time.Unix(210, 0).UTC() }).WithProvenance(
		provenanceBuildLookupStub{
			build: buildbiz.Build{
				ID: "build-1", ProjectID: "project-1", ApplicationID: "application-1",
				Revision: buildbiz.SourceRevision{
					SourceRepositoryID: "source-1", Ref: "refs/heads/main",
					CommitSHA: strings.Repeat("b", 40),
				},
				Configuration: buildbiz.BuildConfigurationSnapshot{
					ConfigurationID: "configuration-1", ConfigurationVersion: 7,
					SourceRepositoryID: "source-1", DockerfilePath: "deploy/Dockerfile",
					ContextPath: ".", TargetPlatform: buildbiz.BuildPlatformLinuxAMD64,
					Resources: buildbiz.BuildResources{
						CPUMilli: 2000, MemoryBytes: 2 * 1024 * 1024 * 1024,
						DiskBytes: 10 * 1024 * 1024 * 1024,
					},
					TimeoutSeconds: 1800,
				},
				StartedAt: time.Unix(100, 0).UTC(),
			},
			source: buildbiz.SourceRepository{
				ID: "source-1", ProjectID: "project-1",
				RepositoryURL: "git@code.example.com:team/api.git",
			},
		},
		ProvenanceBuilderIdentity{
			BuilderID:      biz.OwnDockBuildKitBuilderIDV1,
			BuilderVersion: "0.1.0", BuilderCommit: strings.Repeat("c", 40),
			BuildKitVersion: "v0.31.2",
			BuildKitImage:   "moby/buildkit:v0.31.2-rootless@sha256:" + strings.Repeat("d", 64),
			FrontendImage:   "docker/dockerfile:1.25.0@sha256:" + strings.Repeat("e", 64),
		},
	)
	artifact := buildbiz.Artifact{
		ID: "artifact-1", OrganizationID: "organization-1", ProjectID: "project-1",
		ApplicationID: "application-1", BuildID: "build-1",
		RegistryCredentialID: "registry-1", ImageRepository: "registry.example.com/team/api",
		ImageDigest: "registry.example.com/team/api@sha256:" + strings.Repeat("a", 64),
		CreatedAt:   time.Unix(200, 0).UTC(),
	}
	if err := scheduler.EnsureArtifactEvidence(t.Context(), artifact); err != nil {
		t.Fatalf("EnsureArtifactEvidence() error = %v", err)
	}
	if len(creator.jobs) != 2 || creator.jobs[0].Kind != biz.EvidenceKindSBOM ||
		creator.jobs[1].Kind != biz.EvidenceKindProvenance {
		t.Fatalf("scheduled jobs = %+v", creator.jobs)
	}
	job := creator.jobs[1]
	if job.FormatVersion != biz.SLSAProvenanceFormatVersion ||
		job.Provenance.SourceURI != "git+ssh://code.example.com/team/api.git" ||
		job.Provenance.CommitSHA != strings.Repeat("b", 40) ||
		job.Provenance.FinishedAt != artifact.CreatedAt ||
		!strings.HasPrefix(job.IdempotencyKey, "provenance-") {
		t.Fatalf("provenance job = %+v", job)
	}
}

func TestArtifactEvidenceSchedulerTreatsDuplicateAsSuccessAndFailsClosed(t *testing.T) {
	creator := &evidenceJobCreatorStub{err: biz.ErrDuplicate}
	scheduler := NewArtifactEvidenceScheduler(
		creator, func() (string, error) { return "job-1", nil }, time.Now,
	)
	artifact := buildbiz.Artifact{
		ID: "artifact-1", OrganizationID: "organization-1", ProjectID: "project-1",
		RegistryCredentialID: "registry-1", ImageRepository: "registry.example.com/team/api",
		ImageDigest: "registry.example.com/team/api@sha256:" + strings.Repeat("a", 64),
	}
	if err := scheduler.EnsureArtifactEvidence(t.Context(), artifact); err != nil {
		t.Fatalf("duplicate scheduling error = %v", err)
	}
	artifact.ImageDigest = "malformed"
	if err := scheduler.EnsureArtifactEvidence(t.Context(), artifact); !errors.Is(err, biz.ErrInvalidEvidenceJob) {
		t.Fatalf("malformed Artifact error = %v", err)
	}
	if err := (*ArtifactEvidenceScheduler)(nil).EnsureArtifactEvidence(t.Context(), artifact); !errors.Is(err, biz.ErrUnavailable) {
		t.Fatalf("nil scheduler error = %v", err)
	}
}

func TestArtifactEvidenceSchedulerFreezesEnabledSignaturePolicyVersion(t *testing.T) {
	creator := &evidenceJobCreatorStub{}
	ids := []string{"sbom-job-1", "signature-job-1"}
	now := time.Unix(300, 0).UTC()
	policy, err := biz.NewSignatureTrustPolicy(biz.SignatureTrustPolicyInput{
		ID: "policy-1", OrganizationID: "organization-1", ProjectID: "project-1", Name: "release signer",
		Mode: biz.SignatureTrustKeyless, TrustedRootID: "offline-root-1",
		TrustedRootHash:     "sha256:" + strings.Repeat("b", 64),
		CertificateIdentity: "https://git.example.com/team/api/.ci/release@refs/tags/v1.0.0",
		OIDCIssuer:          "https://issuer.example.com", Enabled: true, Version: 7, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	scheduler := NewArtifactEvidenceScheduler(creator, func() (string, error) {
		id := ids[0]
		ids = ids[1:]
		return id, nil
	}, func() time.Time { return now }).WithSignatureTrustPolicies(signaturePolicyListerStub{policies: []biz.SignatureTrustPolicy{policy}})
	artifact := buildbiz.Artifact{ID: "artifact-1", OrganizationID: "organization-1", ProjectID: "project-1",
		RegistryCredentialID: "registry-1", ImageRepository: "registry.example.com/team/api",
		ImageDigest: "registry.example.com/team/api@sha256:" + strings.Repeat("a", 64)}
	if err := scheduler.EnsureArtifactEvidence(t.Context(), artifact); err != nil {
		t.Fatal(err)
	}
	if len(creator.jobs) != 2 || creator.jobs[1].Kind != biz.EvidenceKindSignature ||
		creator.jobs[1].Signature.PolicyID != policy.ID || creator.jobs[1].Signature.PolicyVersion != 7 ||
		!strings.HasPrefix(creator.jobs[1].IdempotencyKey, "signature-") {
		t.Fatalf("scheduled jobs = %+v", creator.jobs)
	}
}

func TestArtifactEvidenceSchedulerFreezesKMSProfileAndSkipsPrematureVerify(t *testing.T) {
	creator := &evidenceJobCreatorStub{}
	ids := []string{"sbom-job-1"}
	now := time.Unix(400, 0).UTC()
	publicKey := signatureVerificationFixture(t).Trust.PublicKeyPEM
	policy, err := biz.NewSignatureTrustPolicy(biz.SignatureTrustPolicyInput{ID: "policy-1",
		OrganizationID: "organization-1", ProjectID: "project-1", Name: "KMS public key",
		Mode: biz.SignatureTrustPublicKey, PublicKeyPEM: string(publicKey), Enabled: true,
		Version: 2, CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := biz.NewSignatureSigningProfile(biz.SignatureSigningProfileInput{ID: "profile-1",
		OrganizationID: "organization-1", ProjectID: "project-1", Name: "Vault signer",
		KeyReference: "hashivault://release-signing-key", TrustPolicyID: policy.ID, Enabled: true,
		Version: 3, CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	scheduler := NewArtifactEvidenceScheduler(creator, func() (string, error) {
		id := ids[0]
		ids = ids[1:]
		return id, nil
	}, func() time.Time { return now }).WithSignatureTrustPolicies(
		signaturePolicyListerStub{policies: []biz.SignatureTrustPolicy{policy}}).
		WithSignatureSigningProfiles(signingProfileListerStub{profiles: []biz.SignatureSigningProfile{profile}})
	artifact := buildbiz.Artifact{ID: "artifact-1", OrganizationID: "organization-1", ProjectID: "project-1",
		RegistryCredentialID: "registry-1", ImageRepository: "registry.example.com/team/api",
		ImageDigest: "registry.example.com/team/api@sha256:" + strings.Repeat("a", 64)}
	if err := scheduler.EnsureArtifactEvidence(t.Context(), artifact); err != nil {
		t.Fatal(err)
	}
	if len(creator.jobs) != 2 || creator.jobs[1].SignatureOperation != biz.SignatureOperationSignAndVerify ||
		creator.jobs[1].Signing.ProfileVersion != 3 || creator.jobs[1].Signing.TrustPolicyID != policy.ID {
		t.Fatalf("scheduled sign-and-verify jobs = %+v", creator.jobs)
	}
}
