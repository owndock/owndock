package data

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/distribution/reference"
	buildbiz "github.com/owndock/owndock/internal/modules/build/biz"
	"github.com/owndock/owndock/internal/modules/supplychain/biz"
)

type provenanceBuildLookup interface {
	GetBuild(context.Context, string, string) (buildbiz.Build, error)
	GetSource(context.Context, string, string) (buildbiz.SourceRepository, error)
}

type ProvenanceBuilderIdentity struct {
	BuilderID       string
	BuilderVersion  string
	BuilderCommit   string
	BuildKitVersion string
	BuildKitImage   string
	FrontendImage   string
}

type evidenceJobCreator interface {
	CreateEvidenceJob(context.Context, biz.EvidenceJob) (biz.EvidenceJob, error)
}

type enabledSignatureTrustPolicyLister interface {
	ListSignatureTrustPolicies(context.Context, string) ([]biz.SignatureTrustPolicy, error)
}

type enabledSignatureSigningProfileLister interface {
	ListSignatureSigningProfiles(context.Context, string) ([]biz.SignatureSigningProfile, error)
}

type ArtifactEvidenceScheduler struct {
	jobs                  evidenceJobCreator
	newID                 func() (string, error)
	now                   func() time.Time
	builds                provenanceBuildLookup
	builder               ProvenanceBuilderIdentity
	trustPolicies         enabledSignatureTrustPolicyLister
	signingProfiles       enabledSignatureSigningProfileLister
	vulnerabilityScanning bool
}

func (s *ArtifactEvidenceScheduler) WithVulnerabilityScanning() *ArtifactEvidenceScheduler {
	s.vulnerabilityScanning = true
	return s
}

func (s *ArtifactEvidenceScheduler) WithSignatureSigningProfiles(
	profiles enabledSignatureSigningProfileLister,
) *ArtifactEvidenceScheduler {
	s.signingProfiles = profiles
	return s
}

func (s *ArtifactEvidenceScheduler) WithSignatureTrustPolicies(
	policies enabledSignatureTrustPolicyLister,
) *ArtifactEvidenceScheduler {
	s.trustPolicies = policies
	return s
}

func (s *ArtifactEvidenceScheduler) WithProvenance(
	builds provenanceBuildLookup,
	builder ProvenanceBuilderIdentity,
) *ArtifactEvidenceScheduler {
	s.builds, s.builder = builds, builder
	return s
}

func NewArtifactEvidenceScheduler(
	jobs evidenceJobCreator,
	newID func() (string, error),
	now func() time.Time,
) *ArtifactEvidenceScheduler {
	return &ArtifactEvidenceScheduler{jobs: jobs, newID: newID, now: now}
}

// EnsureArtifactEvidence is called in the same MongoDB transaction that
// publishes the Artifact. A stable idempotency key makes transaction retries
// and worker restarts safe without coupling Build to Evidence Job fields.
func (s *ArtifactEvidenceScheduler) EnsureArtifactEvidence(
	ctx context.Context,
	artifact buildbiz.Artifact,
) error {
	if s == nil || s.jobs == nil || s.newID == nil || s.now == nil {
		return biz.ErrUnavailable
	}
	named, err := reference.ParseNormalizedNamed(strings.TrimSpace(artifact.ImageDigest))
	canonical, ok := named.(reference.Canonical)
	if err != nil || !ok || canonical.Name() != artifact.ImageRepository {
		return biz.ErrInvalidEvidenceJob
	}
	jobID, err := s.newID()
	if err != nil {
		return err
	}
	keyDigest := sha256.Sum256([]byte(
		artifact.ID + "\x00sbom\x00cyclonedx-1.6\x00syft-" + PinnedSyftVersion,
	))
	job, err := biz.NewEvidenceJob(biz.EvidenceJobInput{
		ID: jobID, OrganizationID: artifact.OrganizationID, ProjectID: artifact.ProjectID,
		ArtifactID: artifact.ID, SubjectDigest: canonical.Digest().String(),
		RegistryRepository:   artifact.ImageRepository,
		RegistryCredentialID: artifact.RegistryCredentialID,
		Kind:                 biz.EvidenceKindSBOM,
		FormatVersion:        biz.CycloneDXVersion16,
		Producer:             "syft/" + PinnedSyftVersion,
		IdempotencyKey:       "sbom-" + hex.EncodeToString(keyDigest[:]),
		CreatedAt:            s.now().UTC(),
	})
	if err != nil {
		return err
	}
	if _, err = s.jobs.CreateEvidenceJob(ctx, job); err != nil && !errors.Is(err, biz.ErrDuplicate) {
		return err
	}
	if s.vulnerabilityScanning {
		if err := s.ensureVulnerabilityScan(ctx, artifact, canonical.Digest().String()); err != nil {
			return err
		}
	}
	if err := s.ensureSignatureVerification(ctx, artifact, canonical.Digest().String()); err != nil {
		return err
	}
	if s.builds == nil {
		return nil
	}
	return s.ensureProvenance(ctx, artifact, canonical.Digest().String())
}

func (s *ArtifactEvidenceScheduler) ensureVulnerabilityScan(ctx context.Context,
	artifact buildbiz.Artifact, subjectDigest string) error {
	jobID, err := s.newID()
	if err != nil {
		return err
	}
	keyDigest := sha256.Sum256([]byte(artifact.ID + "\x00vulnerability\x00trivy-" + PinnedTrivyVersion))
	job, err := biz.NewEvidenceJob(biz.EvidenceJobInput{ID: jobID,
		OrganizationID: artifact.OrganizationID, ProjectID: artifact.ProjectID, ArtifactID: artifact.ID,
		SubjectDigest: subjectDigest, RegistryRepository: artifact.ImageRepository,
		RegistryCredentialID: artifact.RegistryCredentialID, Kind: biz.EvidenceKindVulnerabilityReport,
		FormatVersion: biz.TrivyReportFormatVersion, Producer: "trivy/" + PinnedTrivyVersion,
		IdempotencyKey: "vulnerability-" + hex.EncodeToString(keyDigest[:]), CreatedAt: s.now().UTC()})
	if err != nil {
		return err
	}
	if _, err = s.jobs.CreateEvidenceJob(ctx, job); errors.Is(err, biz.ErrDuplicate) {
		return nil
	}
	return err
}

func (s *ArtifactEvidenceScheduler) ensureSignatureVerification(ctx context.Context,
	artifact buildbiz.Artifact, subjectDigest string) error {
	if s.trustPolicies == nil {
		return nil
	}
	policies, err := s.trustPolicies.ListSignatureTrustPolicies(ctx, artifact.ProjectID)
	if err != nil {
		return err
	}
	profilesByPolicy := map[string]biz.SignatureSigningProfile{}
	if s.signingProfiles != nil {
		profiles, profileErr := s.signingProfiles.ListSignatureSigningProfiles(ctx, artifact.ProjectID)
		if profileErr != nil {
			return profileErr
		}
		for _, profile := range profiles {
			if !profile.Enabled {
				continue
			}
			if _, duplicate := profilesByPolicy[profile.TrustPolicyID]; duplicate {
				return biz.ErrInvalidSigningProfile
			}
			profilesByPolicy[profile.TrustPolicyID] = profile
		}
	}
	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}
		snapshot, snapshotErr := policy.Snapshot()
		if snapshotErr != nil {
			return snapshotErr
		}
		operation := biz.SignatureOperationVerify
		idempotencyKey := biz.SignatureVerificationIdempotencyKey(artifact.ID, policy.ID, policy.Version, "automatic")
		var signing biz.SignatureSigningSnapshot
		if profile, found := profilesByPolicy[policy.ID]; found {
			if policy.Mode != biz.SignatureTrustPublicKey {
				return biz.ErrInvalidSigningProfile
			}
			signing, err = profile.Snapshot()
			if err != nil {
				return err
			}
			operation = biz.SignatureOperationSignAndVerify
			idempotencyKey = biz.SignatureSigningIdempotencyKey(artifact.ID, signing, snapshot)
		}
		job, jobErr := biz.NewEvidenceJob(biz.EvidenceJobInput{
			ID: idempotencyKey, OrganizationID: artifact.OrganizationID, ProjectID: artifact.ProjectID,
			ArtifactID: artifact.ID, SubjectDigest: subjectDigest,
			RegistryRepository: artifact.ImageRepository, RegistryCredentialID: artifact.RegistryCredentialID,
			Kind: biz.EvidenceKindSignature, FormatVersion: biz.CosignSignatureFormatV03,
			Producer: biz.CosignVerifierProducerV306, Signature: snapshot,
			SignatureOperation: operation, Signing: signing,
			IdempotencyKey: idempotencyKey,
			CreatedAt:      s.now().UTC(),
		})
		if jobErr != nil {
			return jobErr
		}
		if _, jobErr = s.jobs.CreateEvidenceJob(ctx, job); jobErr != nil && !errors.Is(jobErr, biz.ErrDuplicate) {
			return jobErr
		}
	}
	return nil
}

func (s *ArtifactEvidenceScheduler) ensureProvenance(ctx context.Context,
	artifact buildbiz.Artifact, subjectDigest string) error {
	build, err := s.builds.GetBuild(ctx, artifact.ProjectID, artifact.BuildID)
	if err != nil {
		return err
	}
	source, err := s.builds.GetSource(ctx, artifact.ProjectID, build.Revision.SourceRepositoryID)
	if err != nil {
		return err
	}
	sourceURI, err := provenanceSourceURI(source.RepositoryURL)
	if err != nil {
		return biz.ErrInvalidEvidenceJob
	}
	jobID, err := s.newID()
	if err != nil {
		return err
	}
	recipe := biz.ProvenanceRecipe{
		BuildID: build.ID, ApplicationID: build.ApplicationID,
		SourceURI: sourceURI, SourceRef: build.Revision.Ref, CommitSHA: build.Revision.CommitSHA,
		ConfigurationID:      build.Configuration.ConfigurationID,
		ConfigurationVersion: build.Configuration.ConfigurationVersion,
		DockerfilePath:       build.Configuration.DockerfilePath, ContextPath: build.Configuration.ContextPath,
		TargetPlatform: string(build.Configuration.TargetPlatform),
		CPUMilli:       build.Configuration.Resources.CPUMilli,
		MemoryBytes:    build.Configuration.Resources.MemoryBytes,
		DiskBytes:      build.Configuration.Resources.DiskBytes,
		TimeoutSeconds: build.Configuration.TimeoutSeconds,
		BuilderID:      s.builder.BuilderID, BuilderVersion: s.builder.BuilderVersion,
		BuilderCommit: s.builder.BuilderCommit, BuildKitVersion: s.builder.BuildKitVersion,
		BuildKitImage: s.builder.BuildKitImage, FrontendImage: s.builder.FrontendImage,
		StartedAt: build.StartedAt, FinishedAt: artifact.CreatedAt,
	}
	keyInput, err := json.Marshal(recipe)
	if err != nil {
		return biz.ErrInvalidEvidenceJob
	}
	keyDigest := sha256.Sum256(append([]byte(artifact.ID+"\x00provenance\x00"), keyInput...))
	job, err := biz.NewEvidenceJob(biz.EvidenceJobInput{
		ID: jobID, OrganizationID: artifact.OrganizationID, ProjectID: artifact.ProjectID,
		ArtifactID: artifact.ID, SubjectDigest: subjectDigest,
		RegistryRepository: artifact.ImageRepository, RegistryCredentialID: artifact.RegistryCredentialID,
		Kind: biz.EvidenceKindProvenance, FormatVersion: biz.SLSAProvenanceFormatVersion,
		Producer:   "owndock-build-worker/" + strings.TrimSpace(s.builder.BuilderVersion),
		Provenance: recipe, IdempotencyKey: "provenance-" + hex.EncodeToString(keyDigest[:]),
		CreatedAt: s.now().UTC(),
	})
	if err != nil {
		return err
	}
	if _, err = s.jobs.CreateEvidenceJob(ctx, job); errors.Is(err, biz.ErrDuplicate) {
		return nil
	}
	return err
}

func provenanceSourceURI(repositoryURL string) (string, error) {
	value := strings.TrimSpace(repositoryURL)
	if strings.HasPrefix(value, "https://") {
		return "git+" + value, nil
	}
	if strings.HasPrefix(value, "ssh://") {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Host == "" {
			return "", biz.ErrInvalidEvidenceJob
		}
		parsed.User = nil
		parsed.Scheme = "git+ssh"
		return parsed.String(), nil
	}
	match := scpLikeSourcePattern.FindStringSubmatch(value)
	if match == nil {
		return "", biz.ErrInvalidEvidenceJob
	}
	return "git+ssh://" + match[2] + "/" + strings.TrimPrefix(match[3], "/"), nil
}

var scpLikeSourcePattern = regexp.MustCompile(`^([^@]+)@([^:]+):(.+)$`)
