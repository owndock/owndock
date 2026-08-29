package data

import (
	"context"
	"fmt"
	"time"

	"github.com/owndock/owndock/internal/modules/supplychain/biz"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func (r *MongoRepository) ListEvidenceVerifications(ctx context.Context, projectID,
	artifactID string) ([]biz.EvidenceVerification, error) {
	cursor, err := r.verifications.Find(ctx, bson.D{{Key: "project_id", Value: projectID},
		{Key: "artifact_id", Value: artifactID}}, options.Find().SetSort(
		bson.D{{Key: "created_at", Value: 1}, {Key: "_id", Value: 1}}))
	if err != nil {
		return nil, fmt.Errorf("find evidence verifications: %w", err)
	}
	defer cursor.Close(ctx)
	var documents []evidenceVerificationDocument
	if err := cursor.All(ctx, &documents); err != nil {
		return nil, fmt.Errorf("decode evidence verifications: %w", err)
	}
	items := make([]biz.EvidenceVerification, len(documents))
	for index := range documents {
		items[index], err = documents[index].domain()
		if err != nil {
			return nil, err
		}
	}
	return items, nil
}

func (r *MongoRepository) PublishClaimedSignatureVerification(ctx context.Context,
	item biz.EvidenceJob, verification biz.EvidenceVerification, expectedVersion uint64,
	workerID string, generation uint64, now time.Time,
) (biz.EvidenceJob, biz.EvidenceVerification, error) {
	if item.Kind != biz.EvidenceKindSignature || item.Status != biz.EvidenceJobSucceeded ||
		item.Signature.Validate() != nil || !validEvidenceQueueIdentity(item.ID, workerID) ||
		generation == 0 || now.IsZero() {
		return biz.EvidenceJob{}, biz.EvidenceVerification{}, biz.ErrInvalidEvidenceJob
	}
	verification, err := biz.NewEvidenceVerification(verification)
	if err != nil || verification.OrganizationID != item.OrganizationID ||
		verification.ProjectID != item.ProjectID || verification.ArtifactID != item.ArtifactID ||
		verification.SubjectDigest != item.SubjectDigest || verification.PolicyID != item.Signature.PolicyID ||
		verification.PolicyVersion != item.Signature.PolicyVersion || verification.TrustMode != item.Signature.Mode ||
		verification.TrustRootHash != signatureSnapshotTrustHash(item.Signature) ||
		verification.SignerIdentity != item.Signature.CertificateIdentity || verification.OIDCIssuer != item.Signature.OIDCIssuer {
		return biz.EvidenceJob{}, biz.EvidenceVerification{}, biz.ErrSignatureVerification
	}
	if item.SignatureOperation == biz.SignatureOperationSignAndVerify &&
		(verification.SigningProfileID != item.Signing.ProfileID ||
			verification.SigningProfileVersion != item.Signing.ProfileVersion ||
			verification.SigningKeyProvider != item.Signing.Provider ||
			verification.SigningKeyFingerprint != item.Signing.KeyReferenceFingerprint) ||
		item.SignatureOperation == biz.SignatureOperationVerify && verification.SigningProfileID != "" {
		return biz.EvidenceJob{}, biz.EvidenceVerification{}, biz.ErrSignatureVerification
	}
	item.Version = expectedVersion + 1
	session, err := r.client.StartSession()
	if err != nil {
		return biz.EvidenceJob{}, biz.EvidenceVerification{}, fmt.Errorf("start signature verification session: %w", err)
	}
	defer session.EndSession(ctx)
	_, err = session.WithTransaction(ctx, func(transactionContext context.Context) (any, error) {
		if _, insertErr := r.verifications.InsertOne(transactionContext,
			evidenceVerificationDocumentFromDomain(verification)); insertErr != nil {
			if mongo.IsDuplicateKeyError(insertErr) {
				return nil, biz.ErrDuplicate
			}
			return nil, fmt.Errorf("insert evidence verification: %w", insertErr)
		}
		result, replaceErr := r.jobs.ReplaceOne(transactionContext,
			activeEvidenceFence(item.ID, workerID, generation, expectedVersion, now), evidenceJobDocumentFromDomain(item))
		if replaceErr != nil {
			return nil, fmt.Errorf("complete signature verification job: %w", replaceErr)
		}
		if result.ModifiedCount != 1 {
			return nil, biz.ErrEvidenceLeaseExpired
		}
		return nil, nil
	})
	if err != nil {
		return biz.EvidenceJob{}, biz.EvidenceVerification{}, err
	}
	return item, verification, nil
}

func signatureSnapshotTrustHash(item biz.SignatureTrustSnapshot) string {
	if item.Mode == biz.SignatureTrustPublicKey {
		return item.PublicKeyFingerprint
	}
	return item.TrustedRootHash
}

type evidenceVerificationDocument struct {
	ID                    string                 `bson:"_id"`
	OrganizationID        string                 `bson:"organization_id"`
	ProjectID             string                 `bson:"project_id"`
	ArtifactID            string                 `bson:"artifact_id"`
	SubjectDigest         string                 `bson:"subject_digest"`
	PolicyID              string                 `bson:"policy_id"`
	PolicyVersion         uint64                 `bson:"policy_version"`
	SigningProfileID      string                 `bson:"signing_profile_id,omitempty"`
	SigningProfileVersion uint64                 `bson:"signing_profile_version,omitempty"`
	SigningKeyProvider    biz.SigningKeyProvider `bson:"signing_key_provider,omitempty"`
	SigningKeyFingerprint string                 `bson:"signing_key_fingerprint,omitempty"`
	TrustMode             biz.SignatureTrustMode `bson:"trust_mode"`
	TrustRootHash         string                 `bson:"trust_root_hash"`
	SignerIdentity        string                 `bson:"signer_identity,omitempty"`
	OIDCIssuer            string                 `bson:"oidc_issuer,omitempty"`
	BundleSetDigest       string                 `bson:"bundle_set_digest"`
	Verifier              string                 `bson:"verifier"`
	VerifierVersion       string                 `bson:"verifier_version"`
	VerificationStatus    biz.VerificationStatus `bson:"verification_status"`
	CreatedAt             time.Time              `bson:"created_at"`
}

func evidenceVerificationDocumentFromDomain(item biz.EvidenceVerification) evidenceVerificationDocument {
	return evidenceVerificationDocument{ID: item.ID, OrganizationID: item.OrganizationID,
		ProjectID: item.ProjectID, ArtifactID: item.ArtifactID, SubjectDigest: item.SubjectDigest,
		PolicyID: item.PolicyID, PolicyVersion: item.PolicyVersion, TrustMode: item.TrustMode,
		SigningProfileID: item.SigningProfileID, SigningProfileVersion: item.SigningProfileVersion,
		SigningKeyProvider: item.SigningKeyProvider, SigningKeyFingerprint: item.SigningKeyFingerprint,
		TrustRootHash: item.TrustRootHash, SignerIdentity: item.SignerIdentity, OIDCIssuer: item.OIDCIssuer,
		BundleSetDigest: item.BundleSetDigest, Verifier: item.Verifier, VerifierVersion: item.VerifierVersion,
		VerificationStatus: item.VerificationStatus, CreatedAt: item.CreatedAt}
}

func (d evidenceVerificationDocument) domain() (biz.EvidenceVerification, error) {
	item, err := biz.NewEvidenceVerification(biz.EvidenceVerification{ID: d.ID,
		OrganizationID: d.OrganizationID, ProjectID: d.ProjectID, ArtifactID: d.ArtifactID,
		SubjectDigest: d.SubjectDigest, PolicyID: d.PolicyID, PolicyVersion: d.PolicyVersion,
		SigningProfileID: d.SigningProfileID, SigningProfileVersion: d.SigningProfileVersion,
		SigningKeyProvider: d.SigningKeyProvider, SigningKeyFingerprint: d.SigningKeyFingerprint,
		TrustMode: d.TrustMode, TrustRootHash: d.TrustRootHash, SignerIdentity: d.SignerIdentity,
		OIDCIssuer: d.OIDCIssuer, BundleSetDigest: d.BundleSetDigest, Verifier: d.Verifier,
		VerifierVersion: d.VerifierVersion, VerificationStatus: d.VerificationStatus, CreatedAt: d.CreatedAt})
	if err != nil {
		return biz.EvidenceVerification{}, fmt.Errorf("decode invalid evidence verification: %w", err)
	}
	return item, nil
}

var _ biz.EvidenceVerificationRepository = (*MongoRepository)(nil)
