package data

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/supplychain/biz"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func TestEvidenceDocumentRejectsMalformedPersistedData(t *testing.T) {
	document := evidenceDocument{
		ID: "evidence-1", OrganizationID: "organization-1", ProjectID: "project-1",
		ArtifactID: "artifact-1", SubjectDigest: "sha256:" + strings.Repeat("a", 64),
		Kind: biz.EvidenceKindSBOM, MediaType: "application/vnd.cyclonedx+json",
		FormatVersion: "1.6", Producer: "worker/1.0.0",
		RegistryRepository: "registry.example.com/team/api",
		DescriptorDigest:   "not-a-digest", VerificationStatus: biz.VerificationVerified,
		CreatedAt: time.Unix(100, 0),
	}
	if _, err := document.domain(); !errors.Is(err, biz.ErrInvalidEvidence) {
		t.Fatalf("domain() error = %v", err)
	}
}

func TestProvenanceEvidenceJobBSONRoundTrip(t *testing.T) {
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
	item, err := biz.NewEvidenceJob(biz.EvidenceJobInput{
		ID: "provenance-job-1", OrganizationID: "organization-1", ProjectID: "project-1",
		ArtifactID: "artifact-1", SubjectDigest: "sha256:" + strings.Repeat("a", 64),
		RegistryRepository: "registry.example.com/team/api", RegistryCredentialID: "registry-1",
		Kind: biz.EvidenceKindProvenance, FormatVersion: biz.SLSAProvenanceFormatVersion,
		Producer: "owndock-build-worker/0.1.0", Provenance: recipe, CreatedAt: time.Unix(200, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := bson.Marshal(evidenceJobDocumentFromDomain(item))
	if err != nil {
		t.Fatal(err)
	}
	var persisted evidenceJobDocument
	if err := bson.Unmarshal(encoded, &persisted); err != nil {
		t.Fatal(err)
	}
	restored, err := persisted.domain()
	if err != nil || restored.Provenance != recipe {
		t.Fatalf("provenance BSON round trip = %+v, %v", restored.Provenance, err)
	}
}

func TestEvidenceJobDocumentRoundTripAndRejectsMalformedData(t *testing.T) {
	item, err := biz.NewEvidenceJob(biz.EvidenceJobInput{
		ID: "evidence-job-1", OrganizationID: "organization-1", ProjectID: "project-1",
		ArtifactID: "artifact-1", SubjectDigest: "sha256:" + strings.Repeat("a", 64),
		RegistryRepository: "registry.example.com/team/api", Kind: biz.EvidenceKindSBOM,
		RegistryCredentialID: "registry-1",
		FormatVersion:        "1.6", Producer: "owndock-evidence-worker/1.0.0",
		CreatedAt: time.Unix(100, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := item.Acquire(biz.EvidenceClaim{
		WorkerID: "worker-1", Now: time.Unix(110, 0), ExpiresAt: time.Unix(140, 0),
	}); err != nil {
		t.Fatal(err)
	}
	item.Version++
	document := evidenceJobDocumentFromDomain(item)
	restored, err := document.domain()
	if err != nil || restored.Lease.Generation != 1 || restored.Version != 2 {
		t.Fatalf("EvidenceJob round trip = %+v, %v", restored, err)
	}
	document.Status = "invented"
	if _, err := document.domain(); !errors.Is(err, biz.ErrInvalidEvidenceJob) {
		t.Fatalf("malformed EvidenceJob error = %v", err)
	}
}

func TestSignAndVerifyJobAndSigningProfileBSONRoundTrip(t *testing.T) {
	now := time.Unix(300, 0).UTC()
	publicKey := signatureVerificationFixture(t).Trust.PublicKeyPEM
	policy, err := biz.NewSignatureTrustPolicy(biz.SignatureTrustPolicyInput{ID: "policy-1",
		OrganizationID: "organization-1", ProjectID: "project-1", Name: "KMS key",
		Mode: biz.SignatureTrustPublicKey, PublicKeyPEM: string(publicKey), Enabled: true,
		Version: 2, CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	trust, _ := policy.Snapshot()
	profile, err := biz.NewSignatureSigningProfile(biz.SignatureSigningProfileInput{ID: "profile-1",
		OrganizationID: "organization-1", ProjectID: "project-1", Name: "Vault signer",
		KeyReference: "hashivault://release-key", TrustPolicyID: policy.ID, Enabled: true,
		Version: 3, CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	signing, _ := profile.Snapshot()
	job, err := biz.NewEvidenceJob(biz.EvidenceJobInput{ID: "signature-job-1",
		OrganizationID: "organization-1", ProjectID: "project-1", ArtifactID: "artifact-1",
		SubjectDigest: "sha256:" + strings.Repeat("a", 64), RegistryRepository: "registry.example.com/team/api",
		RegistryCredentialID: "registry-1", Kind: biz.EvidenceKindSignature,
		FormatVersion: biz.CosignSignatureFormatV03, Producer: biz.CosignVerifierProducerV306,
		Signature: trust, SignatureOperation: biz.SignatureOperationSignAndVerify, Signing: signing, CreatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	document := evidenceJobDocumentFromDomain(job)
	restored, err := document.domain()
	if err != nil || restored.Signing != signing || restored.SignatureOperation != biz.SignatureOperationSignAndVerify {
		t.Fatalf("signing job round trip = %+v, %v", restored, err)
	}
	profileDocument := signingProfileDocumentFromDomain(profile)
	restoredProfile, err := profileDocument.domain()
	if err != nil || restoredProfile.KeyReferenceFingerprint != profile.KeyReferenceFingerprint {
		t.Fatalf("signing profile round trip = %+v, %v", restoredProfile, err)
	}
	profileDocument.KeyReferenceFingerprint = "sha256:" + strings.Repeat("f", 64)
	if _, err := profileDocument.domain(); !errors.Is(err, biz.ErrInvalidSigningProfile) {
		t.Fatalf("corrupt signing profile error = %v", err)
	}
}
