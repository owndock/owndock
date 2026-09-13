package data

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/modules/supplychain/biz"
	"github.com/owndock/owndock/internal/platform/mongotx"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func (r *MongoRepository) CreateEvidenceJob(ctx context.Context, item biz.EvidenceJob) (biz.EvidenceJob, error) {
	if err := item.Validate(); err != nil || item.Status != biz.EvidenceJobQueued || item.Lease.Owner != "" {
		return biz.EvidenceJob{}, biz.ErrInvalidEvidenceJob
	}
	if _, err := r.jobs.InsertOne(ctx, evidenceJobDocumentFromDomain(item)); mongo.IsDuplicateKeyError(err) {
		var duplicate evidenceJobDocument
		findErr := r.jobs.FindOne(ctx, bson.D{{Key: "organization_id", Value: item.OrganizationID},
			{Key: "project_id", Value: item.ProjectID}, {Key: "$or", Value: bson.A{
				bson.D{{Key: "idempotency_key", Value: item.IdempotencyKey}},
				bson.D{{Key: "artifact_id", Value: item.ArtifactID}, {Key: "kind", Value: item.Kind},
					{Key: "active", Value: true}},
			}}}).Decode(&duplicate)
		if findErr == nil {
			existing, decodeErr := duplicate.domain()
			if decodeErr != nil {
				return biz.EvidenceJob{}, decodeErr
			}
			return existing, biz.ErrDuplicate
		}
		return biz.EvidenceJob{}, biz.ErrDuplicate
	} else if err != nil {
		return biz.EvidenceJob{}, fmt.Errorf("insert evidence job: %w", err)
	}
	return item, nil
}

func (r *MongoRepository) ClaimNextEvidenceJob(ctx context.Context, claim biz.EvidenceClaim) (biz.EvidenceJob, bool, error) {
	if err := claim.Validate(); err != nil {
		return biz.EvidenceJob{}, false, err
	}
	leaseAvailable := bson.D{{Key: "$or", Value: bson.A{
		bson.D{{Key: "lease.expires_at", Value: bson.D{{Key: "$lte", Value: claim.Now.UTC()}}}},
		bson.D{{Key: "lease.expires_at", Value: bson.D{{Key: "$exists", Value: false}}}},
		bson.D{{Key: "lease.owner", Value: ""}},
	}}}
	update := bson.D{
		{Key: "$set", Value: bson.D{
			{Key: "lease.owner", Value: claim.WorkerID},
			{Key: "lease.expires_at", Value: claim.ExpiresAt.UTC()},
			{Key: "updated_at", Value: claim.Now.UTC()},
		}},
		{Key: "$inc", Value: bson.D{{Key: "lease.generation", Value: 1}, {Key: "version", Value: 1}}},
	}
	for _, status := range []biz.EvidenceJobStatus{
		biz.EvidenceJobPublishing, biz.EvidenceJobVerifying, biz.EvidenceJobGenerating, biz.EvidenceJobQueued,
	} {
		var document evidenceJobDocument
		filter := append(append(bson.D{}, leaseAvailable...), bson.E{Key: "status", Value: status})
		if len(claim.Kinds) > 0 {
			filter = append(filter, bson.E{Key: "kind", Value: bson.D{{Key: "$in", Value: claim.Kinds}}})
		}
		err := r.jobs.FindOneAndUpdate(ctx, filter, update, options.FindOneAndUpdate().
			SetSort(bson.D{{Key: "created_at", Value: 1}, {Key: "_id", Value: 1}}).
			SetReturnDocument(options.After)).Decode(&document)
		if err == nil {
			item, domainErr := document.domain()
			return item, domainErr == nil, domainErr
		}
		if !errors.Is(err, mongo.ErrNoDocuments) {
			return biz.EvidenceJob{}, false, fmt.Errorf("claim evidence job: %w", err)
		}
	}
	return biz.EvidenceJob{}, false, nil
}

func (r *MongoRepository) RenewEvidenceJobLease(ctx context.Context, jobID, workerID string,
	generation, expectedVersion uint64, now, expiresAt time.Time) (biz.EvidenceJob, error) {
	if !validEvidenceQueueIdentity(jobID, workerID) || generation == 0 || now.IsZero() || !expiresAt.After(now) {
		return biz.EvidenceJob{}, biz.ErrInvalidEvidenceJob
	}
	var document evidenceJobDocument
	err := r.jobs.FindOneAndUpdate(ctx, activeEvidenceFence(jobID, workerID, generation, expectedVersion, now), bson.D{
		{Key: "$set", Value: bson.D{{Key: "lease.expires_at", Value: expiresAt.UTC()}, {Key: "updated_at", Value: now.UTC()}}},
		{Key: "$inc", Value: bson.D{{Key: "version", Value: 1}}},
	}, options.FindOneAndUpdate().SetReturnDocument(options.After)).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return biz.EvidenceJob{}, biz.ErrEvidenceLeaseExpired
	}
	if err != nil {
		return biz.EvidenceJob{}, fmt.Errorf("renew evidence job lease: %w", err)
	}
	return document.domain()
}

func (r *MongoRepository) SaveClaimedEvidenceJob(ctx context.Context, item biz.EvidenceJob,
	expectedVersion uint64, workerID string, generation uint64, now time.Time) (biz.EvidenceJob, error) {
	if err := item.Validate(); err != nil || !validEvidenceQueueIdentity(item.ID, workerID) ||
		generation == 0 || now.IsZero() || (!item.Terminal() &&
		(item.Lease.Owner != workerID || item.Lease.Generation != generation || !item.Lease.Active(now))) {
		return biz.EvidenceJob{}, biz.ErrEvidenceLeaseExpired
	}
	item.Version = expectedVersion + 1
	result, err := r.jobs.ReplaceOne(ctx, activeEvidenceFence(item.ID, workerID, generation, expectedVersion, now),
		evidenceJobDocumentFromDomain(item))
	if err != nil {
		return biz.EvidenceJob{}, fmt.Errorf("save claimed evidence job: %w", err)
	}
	if result.ModifiedCount != 1 {
		return biz.EvidenceJob{}, biz.ErrEvidenceLeaseExpired
	}
	return item, nil
}

func (r *MongoRepository) ValidateEvidenceFence(ctx context.Context, jobID, workerID string,
	generation uint64, now time.Time) error {
	if !validEvidenceQueueIdentity(jobID, workerID) || generation == 0 || now.IsZero() {
		return biz.ErrInvalidEvidenceJob
	}
	err := r.jobs.FindOne(ctx, bson.D{
		{Key: "_id", Value: jobID}, {Key: "lease.owner", Value: workerID},
		{Key: "lease.generation", Value: generation},
		{Key: "lease.expires_at", Value: bson.D{{Key: "$gt", Value: now.UTC()}}},
		{Key: "status", Value: bson.D{{Key: "$in", Value: bson.A{
			biz.EvidenceJobQueued, biz.EvidenceJobGenerating, biz.EvidenceJobPublishing, biz.EvidenceJobVerifying,
		}}}},
	}, options.FindOne().SetProjection(bson.D{{Key: "_id", Value: 1}})).Err()
	if errors.Is(err, mongo.ErrNoDocuments) {
		return biz.ErrEvidenceLeaseExpired
	}
	if err != nil {
		return fmt.Errorf("validate evidence job fence: %w", err)
	}
	return nil
}

// PublishClaimedEvidence atomically records the immutable Evidence index and
// completes its job. Registry content must already have been uploaded by exact
// digest; an expired Worker can leave an unindexed blob but cannot claim it.
func (r *MongoRepository) PublishClaimedEvidence(ctx context.Context, item biz.EvidenceJob,
	evidence biz.Evidence, expectedVersion uint64, workerID string, generation uint64,
	now time.Time) (biz.EvidenceJob, biz.Evidence, error) {
	if err := validateEvidencePublication(item, evidence, workerID, generation, now); err != nil {
		return biz.EvidenceJob{}, biz.Evidence{}, err
	}
	item.Version = expectedVersion + 1
	session, err := r.client.StartSession()
	if err != nil {
		return biz.EvidenceJob{}, biz.Evidence{}, fmt.Errorf("start evidence publication session: %w", err)
	}
	defer session.EndSession(ctx)
	_, err = session.WithTransaction(ctx, func(transactionContext context.Context) (any, error) {
		if _, insertErr := r.evidence.InsertOne(transactionContext, documentFromDomain(evidence)); insertErr != nil {
			if mongo.IsDuplicateKeyError(insertErr) {
				return nil, biz.ErrDuplicate
			}
			return nil, fmt.Errorf("insert published evidence: %w", insertErr)
		}
		result, replaceErr := r.jobs.ReplaceOne(transactionContext,
			activeEvidenceFence(item.ID, workerID, generation, expectedVersion, now),
			evidenceJobDocumentFromDomain(item))
		if replaceErr != nil {
			return nil, fmt.Errorf("complete evidence job: %w", replaceErr)
		}
		if result.ModifiedCount != 1 {
			return nil, biz.ErrEvidenceLeaseExpired
		}
		return nil, nil
	}, mongotx.Options())
	if err != nil {
		return biz.EvidenceJob{}, biz.Evidence{}, err
	}
	return item, evidence, nil
}

func validateEvidencePublication(item biz.EvidenceJob, evidence biz.Evidence,
	workerID string, generation uint64, now time.Time) error {
	if err := item.Validate(); err != nil || item.Status != biz.EvidenceJobSucceeded ||
		!validEvidenceQueueIdentity(item.ID, workerID) || generation == 0 || now.IsZero() {
		return biz.ErrInvalidEvidenceJob
	}
	normalized, err := biz.NewEvidence(inputFromDomain(evidence))
	if err != nil {
		return err
	}
	if normalized.OrganizationID != item.OrganizationID || normalized.ProjectID != item.ProjectID ||
		normalized.ArtifactID != item.ArtifactID || normalized.SubjectDigest != item.SubjectDigest ||
		normalized.RegistryRepository != item.RegistryRepository || normalized.Kind != item.Kind ||
		normalized.FormatVersion != item.FormatVersion || normalized.Producer != item.Producer {
		return biz.ErrInvalidEvidence
	}
	return nil
}

func activeEvidenceFence(jobID, workerID string, generation, version uint64, now time.Time) bson.D {
	return bson.D{
		{Key: "_id", Value: jobID}, {Key: "version", Value: version},
		{Key: "lease.owner", Value: workerID}, {Key: "lease.generation", Value: generation},
		{Key: "lease.expires_at", Value: bson.D{{Key: "$gt", Value: now.UTC()}}},
	}
}

func validEvidenceQueueIdentity(jobID, workerID string) bool {
	return strings.TrimSpace(jobID) != "" && strings.TrimSpace(workerID) != ""
}

type evidenceJobDocument struct {
	ID                   string                           `bson:"_id"`
	OrganizationID       string                           `bson:"organization_id"`
	ProjectID            string                           `bson:"project_id"`
	ArtifactID           string                           `bson:"artifact_id"`
	SubjectDigest        string                           `bson:"subject_digest"`
	RegistryRepository   string                           `bson:"registry_repository"`
	RegistryCredentialID string                           `bson:"registry_credential_id"`
	Kind                 biz.EvidenceKind                 `bson:"kind"`
	FormatVersion        string                           `bson:"format_version"`
	Producer             string                           `bson:"producer"`
	Provenance           provenanceRecipeDocument         `bson:"provenance,omitempty"`
	Signature            signatureTrustSnapshotDocument   `bson:"signature,omitempty"`
	SignatureOperation   biz.SignatureJobOperation        `bson:"signature_operation,omitempty"`
	Signing              signatureSigningSnapshotDocument `bson:"signing,omitempty"`
	IdempotencyKey       string                           `bson:"idempotency_key"`
	Status               biz.EvidenceJobStatus            `bson:"status"`
	Active               bool                             `bson:"active"`
	Failure              biz.EvidenceJobFailure           `bson:"failure,omitempty"`
	Version              uint64                           `bson:"version"`
	Lease                evidenceLeaseDocument            `bson:"lease,omitempty"`
	CreatedAt            time.Time                        `bson:"created_at"`
	UpdatedAt            time.Time                        `bson:"updated_at"`
	StartedAt            time.Time                        `bson:"started_at,omitempty"`
	FinishedAt           time.Time                        `bson:"finished_at,omitempty"`
}

type evidenceLeaseDocument struct {
	Owner      string    `bson:"owner,omitempty"`
	ExpiresAt  time.Time `bson:"expires_at,omitempty"`
	Generation uint64    `bson:"generation,omitempty"`
}

type provenanceRecipeDocument struct {
	BuildID              string    `bson:"build_id,omitempty"`
	ApplicationID        string    `bson:"application_id,omitempty"`
	SourceURI            string    `bson:"source_uri,omitempty"`
	SourceRef            string    `bson:"source_ref,omitempty"`
	CommitSHA            string    `bson:"commit_sha,omitempty"`
	ConfigurationID      string    `bson:"configuration_id,omitempty"`
	ConfigurationVersion uint64    `bson:"configuration_version,omitempty"`
	DockerfilePath       string    `bson:"dockerfile_path,omitempty"`
	ContextPath          string    `bson:"context_path,omitempty"`
	TargetPlatform       string    `bson:"target_platform,omitempty"`
	CPUMilli             int64     `bson:"cpu_milli,omitempty"`
	MemoryBytes          int64     `bson:"memory_bytes,omitempty"`
	DiskBytes            int64     `bson:"disk_bytes,omitempty"`
	TimeoutSeconds       int64     `bson:"timeout_seconds,omitempty"`
	BuilderID            string    `bson:"builder_id,omitempty"`
	BuilderVersion       string    `bson:"builder_version,omitempty"`
	BuilderCommit        string    `bson:"builder_commit,omitempty"`
	BuildKitVersion      string    `bson:"buildkit_version,omitempty"`
	BuildKitImage        string    `bson:"buildkit_image,omitempty"`
	FrontendImage        string    `bson:"frontend_image,omitempty"`
	StartedAt            time.Time `bson:"started_at,omitempty"`
	FinishedAt           time.Time `bson:"finished_at,omitempty"`
}

type signatureTrustSnapshotDocument struct {
	PolicyID             string                 `bson:"policy_id,omitempty"`
	PolicyVersion        uint64                 `bson:"policy_version,omitempty"`
	Mode                 biz.SignatureTrustMode `bson:"mode,omitempty"`
	PublicKeyPEM         string                 `bson:"public_key_pem,omitempty"`
	PublicKeyFingerprint string                 `bson:"public_key_fingerprint,omitempty"`
	TrustedRootID        string                 `bson:"trusted_root_id,omitempty"`
	TrustedRootHash      string                 `bson:"trusted_root_hash,omitempty"`
	CertificateIdentity  string                 `bson:"certificate_identity,omitempty"`
	OIDCIssuer           string                 `bson:"oidc_issuer,omitempty"`
}

type signatureSigningSnapshotDocument struct {
	ProfileID               string                 `bson:"profile_id,omitempty"`
	ProfileVersion          uint64                 `bson:"profile_version,omitempty"`
	Provider                biz.SigningKeyProvider `bson:"provider,omitempty"`
	KeyReference            string                 `bson:"key_reference,omitempty"`
	KeyReferenceFingerprint string                 `bson:"key_reference_fingerprint,omitempty"`
	TrustPolicyID           string                 `bson:"trust_policy_id,omitempty"`
}

func signatureSigningSnapshotDocumentFromDomain(item biz.SignatureSigningSnapshot) signatureSigningSnapshotDocument {
	return signatureSigningSnapshotDocument{ProfileID: item.ProfileID, ProfileVersion: item.ProfileVersion,
		Provider: item.Provider, KeyReference: item.KeyReference,
		KeyReferenceFingerprint: item.KeyReferenceFingerprint, TrustPolicyID: item.TrustPolicyID}
}

func (d signatureSigningSnapshotDocument) domain() biz.SignatureSigningSnapshot {
	return biz.SignatureSigningSnapshot{ProfileID: d.ProfileID, ProfileVersion: d.ProfileVersion,
		Provider: d.Provider, KeyReference: d.KeyReference,
		KeyReferenceFingerprint: d.KeyReferenceFingerprint, TrustPolicyID: d.TrustPolicyID}
}

func signatureTrustSnapshotDocumentFromDomain(item biz.SignatureTrustSnapshot) signatureTrustSnapshotDocument {
	return signatureTrustSnapshotDocument{PolicyID: item.PolicyID, PolicyVersion: item.PolicyVersion,
		Mode: item.Mode, PublicKeyPEM: item.PublicKeyPEM, PublicKeyFingerprint: item.PublicKeyFingerprint,
		TrustedRootID: item.TrustedRootID, TrustedRootHash: item.TrustedRootHash,
		CertificateIdentity: item.CertificateIdentity, OIDCIssuer: item.OIDCIssuer}
}

func (d signatureTrustSnapshotDocument) domain() biz.SignatureTrustSnapshot {
	return biz.SignatureTrustSnapshot{PolicyID: d.PolicyID, PolicyVersion: d.PolicyVersion,
		Mode: d.Mode, PublicKeyPEM: d.PublicKeyPEM, PublicKeyFingerprint: d.PublicKeyFingerprint,
		TrustedRootID: d.TrustedRootID, TrustedRootHash: d.TrustedRootHash,
		CertificateIdentity: d.CertificateIdentity, OIDCIssuer: d.OIDCIssuer}
}

func provenanceRecipeDocumentFromDomain(item biz.ProvenanceRecipe) provenanceRecipeDocument {
	return provenanceRecipeDocument{
		BuildID: item.BuildID, ApplicationID: item.ApplicationID,
		SourceURI: item.SourceURI, SourceRef: item.SourceRef, CommitSHA: item.CommitSHA,
		ConfigurationID: item.ConfigurationID, ConfigurationVersion: item.ConfigurationVersion,
		DockerfilePath: item.DockerfilePath, ContextPath: item.ContextPath,
		TargetPlatform: item.TargetPlatform, CPUMilli: item.CPUMilli,
		MemoryBytes: item.MemoryBytes, DiskBytes: item.DiskBytes, TimeoutSeconds: item.TimeoutSeconds,
		BuilderID: item.BuilderID, BuilderVersion: item.BuilderVersion, BuilderCommit: item.BuilderCommit,
		BuildKitVersion: item.BuildKitVersion, BuildKitImage: item.BuildKitImage,
		FrontendImage: item.FrontendImage, StartedAt: item.StartedAt, FinishedAt: item.FinishedAt,
	}
}

func (d provenanceRecipeDocument) domain() biz.ProvenanceRecipe {
	return biz.ProvenanceRecipe{
		BuildID: d.BuildID, ApplicationID: d.ApplicationID,
		SourceURI: d.SourceURI, SourceRef: d.SourceRef, CommitSHA: d.CommitSHA,
		ConfigurationID: d.ConfigurationID, ConfigurationVersion: d.ConfigurationVersion,
		DockerfilePath: d.DockerfilePath, ContextPath: d.ContextPath,
		TargetPlatform: d.TargetPlatform, CPUMilli: d.CPUMilli,
		MemoryBytes: d.MemoryBytes, DiskBytes: d.DiskBytes, TimeoutSeconds: d.TimeoutSeconds,
		BuilderID: d.BuilderID, BuilderVersion: d.BuilderVersion, BuilderCommit: d.BuilderCommit,
		BuildKitVersion: d.BuildKitVersion, BuildKitImage: d.BuildKitImage,
		FrontendImage: d.FrontendImage, StartedAt: d.StartedAt, FinishedAt: d.FinishedAt,
	}
}

func evidenceJobDocumentFromDomain(item biz.EvidenceJob) evidenceJobDocument {
	return evidenceJobDocument{
		ID: item.ID, OrganizationID: item.OrganizationID, ProjectID: item.ProjectID,
		ArtifactID: item.ArtifactID, SubjectDigest: item.SubjectDigest,
		RegistryRepository: item.RegistryRepository, Kind: item.Kind,
		RegistryCredentialID: item.RegistryCredentialID,
		FormatVersion:        item.FormatVersion, Producer: item.Producer,
		Provenance:         provenanceRecipeDocumentFromDomain(item.Provenance),
		Signature:          signatureTrustSnapshotDocumentFromDomain(item.Signature),
		SignatureOperation: item.SignatureOperation,
		Signing:            signatureSigningSnapshotDocumentFromDomain(item.Signing),
		IdempotencyKey:     item.IdempotencyKey, Status: item.Status, Active: !item.Terminal(),
		Failure: item.Failure, Version: item.Version,
		Lease: evidenceLeaseDocument{
			Owner: item.Lease.Owner, ExpiresAt: item.Lease.ExpiresAt, Generation: item.Lease.Generation,
		},
		CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt,
		StartedAt: item.StartedAt, FinishedAt: item.FinishedAt,
	}
}

func (d evidenceJobDocument) domain() (biz.EvidenceJob, error) {
	item := biz.EvidenceJob{
		ID: d.ID, OrganizationID: d.OrganizationID, ProjectID: d.ProjectID,
		ArtifactID: d.ArtifactID, SubjectDigest: d.SubjectDigest,
		RegistryRepository: d.RegistryRepository, Kind: d.Kind,
		RegistryCredentialID: d.RegistryCredentialID,
		FormatVersion:        d.FormatVersion, Producer: d.Producer,
		Provenance:         d.Provenance.domain(),
		Signature:          d.Signature.domain(),
		SignatureOperation: d.SignatureOperation, Signing: d.Signing.domain(),
		IdempotencyKey: d.IdempotencyKey, Status: d.Status,
		Failure: d.Failure, Version: d.Version,
		Lease:     biz.EvidenceLease{Owner: d.Lease.Owner, ExpiresAt: d.Lease.ExpiresAt, Generation: d.Lease.Generation},
		CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt,
		StartedAt: d.StartedAt, FinishedAt: d.FinishedAt,
	}
	if err := item.Validate(); err != nil {
		return biz.EvidenceJob{}, fmt.Errorf("decode invalid evidence job: %w", err)
	}
	return item, nil
}
