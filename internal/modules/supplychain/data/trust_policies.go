package data

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/owndock/owndock/internal/modules/supplychain/biz"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func (r *MongoRepository) CreateSignatureTrustPolicy(ctx context.Context,
	item biz.SignatureTrustPolicy) (biz.SignatureTrustPolicy, error) {
	normalized, err := biz.NewSignatureTrustPolicy(signatureTrustPolicyInput(item))
	if err != nil {
		return biz.SignatureTrustPolicy{}, err
	}
	if _, err := r.trustPolicies.InsertOne(ctx, signatureTrustPolicyDocumentFromDomain(normalized)); mongo.IsDuplicateKeyError(err) {
		return biz.SignatureTrustPolicy{}, biz.ErrDuplicate
	} else if err != nil {
		return biz.SignatureTrustPolicy{}, fmt.Errorf("insert signature trust policy: %w", err)
	}
	return normalized, nil
}

func (r *MongoRepository) ListSignatureTrustPolicies(ctx context.Context,
	projectID string) ([]biz.SignatureTrustPolicy, error) {
	cursor, err := r.trustPolicies.Find(ctx, bson.D{{Key: "project_id", Value: projectID}},
		options.Find().SetSort(bson.D{{Key: "created_at", Value: 1}, {Key: "_id", Value: 1}}))
	if err != nil {
		return nil, fmt.Errorf("find signature trust policies: %w", err)
	}
	defer cursor.Close(ctx)
	var documents []signatureTrustPolicyDocument
	if err := cursor.All(ctx, &documents); err != nil {
		return nil, fmt.Errorf("decode signature trust policies: %w", err)
	}
	items := make([]biz.SignatureTrustPolicy, len(documents))
	for index := range documents {
		items[index], err = documents[index].domain()
		if err != nil {
			return nil, err
		}
	}
	return items, nil
}

func (r *MongoRepository) GetSignatureTrustPolicy(ctx context.Context,
	projectID, policyID string) (biz.SignatureTrustPolicy, error) {
	var document signatureTrustPolicyDocument
	err := r.trustPolicies.FindOne(ctx, bson.D{
		{Key: "_id", Value: policyID}, {Key: "project_id", Value: projectID},
	}).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return biz.SignatureTrustPolicy{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.SignatureTrustPolicy{}, fmt.Errorf("find signature trust policy: %w", err)
	}
	return document.domain()
}

func (r *MongoRepository) SaveSignatureTrustPolicy(ctx context.Context,
	item biz.SignatureTrustPolicy, expectedVersion uint64) (biz.SignatureTrustPolicy, error) {
	normalized, err := biz.NewSignatureTrustPolicy(signatureTrustPolicyInput(item))
	if err != nil || expectedVersion == 0 || normalized.Version != expectedVersion+1 {
		return biz.SignatureTrustPolicy{}, biz.ErrInvalidSignatureTrustPolicy
	}
	result, err := r.trustPolicies.ReplaceOne(ctx, bson.D{
		{Key: "_id", Value: normalized.ID}, {Key: "project_id", Value: normalized.ProjectID},
		{Key: "version", Value: expectedVersion},
	}, signatureTrustPolicyDocumentFromDomain(normalized))
	if err != nil {
		return biz.SignatureTrustPolicy{}, fmt.Errorf("save signature trust policy: %w", err)
	}
	if result.MatchedCount != 1 {
		return biz.SignatureTrustPolicy{}, biz.ErrSignatureTrustPolicyConflict
	}
	return normalized, nil
}

type signatureTrustPolicyDocument struct {
	ID                   string                 `bson:"_id"`
	OrganizationID       string                 `bson:"organization_id"`
	ProjectID            string                 `bson:"project_id"`
	Name                 string                 `bson:"name"`
	Mode                 biz.SignatureTrustMode `bson:"mode"`
	PublicKeyPEM         string                 `bson:"public_key_pem,omitempty"`
	PublicKeyFingerprint string                 `bson:"public_key_fingerprint,omitempty"`
	TrustedRootID        string                 `bson:"trusted_root_id,omitempty"`
	TrustedRootHash      string                 `bson:"trusted_root_hash,omitempty"`
	CertificateIdentity  string                 `bson:"certificate_identity,omitempty"`
	OIDCIssuer           string                 `bson:"oidc_issuer,omitempty"`
	Enabled              bool                   `bson:"enabled"`
	Version              uint64                 `bson:"version"`
	CreatedAt            time.Time              `bson:"created_at"`
	UpdatedAt            time.Time              `bson:"updated_at"`
}

func signatureTrustPolicyDocumentFromDomain(item biz.SignatureTrustPolicy) signatureTrustPolicyDocument {
	return signatureTrustPolicyDocument{
		ID: item.ID, OrganizationID: item.OrganizationID, ProjectID: item.ProjectID,
		Name: item.Name, Mode: item.Mode, PublicKeyPEM: item.PublicKeyPEM,
		PublicKeyFingerprint: item.PublicKeyFingerprint, TrustedRootID: item.TrustedRootID,
		TrustedRootHash: item.TrustedRootHash, CertificateIdentity: item.CertificateIdentity,
		OIDCIssuer: item.OIDCIssuer, Enabled: item.Enabled, Version: item.Version,
		CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt,
	}
}

func signatureTrustPolicyInput(item biz.SignatureTrustPolicy) biz.SignatureTrustPolicyInput {
	return biz.SignatureTrustPolicyInput{
		ID: item.ID, OrganizationID: item.OrganizationID, ProjectID: item.ProjectID,
		Name: item.Name, Mode: item.Mode, PublicKeyPEM: item.PublicKeyPEM,
		TrustedRootID: item.TrustedRootID, TrustedRootHash: item.TrustedRootHash,
		CertificateIdentity: item.CertificateIdentity, OIDCIssuer: item.OIDCIssuer,
		Enabled: item.Enabled, Version: item.Version, CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt,
	}
}

func (d signatureTrustPolicyDocument) domain() (biz.SignatureTrustPolicy, error) {
	item, err := biz.NewSignatureTrustPolicy(biz.SignatureTrustPolicyInput{
		ID: d.ID, OrganizationID: d.OrganizationID, ProjectID: d.ProjectID,
		Name: d.Name, Mode: d.Mode, PublicKeyPEM: d.PublicKeyPEM,
		TrustedRootID: d.TrustedRootID, TrustedRootHash: d.TrustedRootHash,
		CertificateIdentity: d.CertificateIdentity, OIDCIssuer: d.OIDCIssuer,
		Enabled: d.Enabled, Version: d.Version, CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt,
	})
	if err != nil || item.PublicKeyFingerprint != d.PublicKeyFingerprint {
		return biz.SignatureTrustPolicy{}, fmt.Errorf("decode invalid signature trust policy: %w",
			biz.ErrInvalidSignatureTrustPolicy)
	}
	return item, nil
}

var _ biz.SignatureTrustPolicyRepository = (*MongoRepository)(nil)
