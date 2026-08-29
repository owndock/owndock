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

func (r *MongoRepository) CreateSignatureSigningProfile(ctx context.Context,
	item biz.SignatureSigningProfile) (biz.SignatureSigningProfile, error) {
	item, err := biz.NewSignatureSigningProfile(signingProfileInput(item))
	if err != nil {
		return biz.SignatureSigningProfile{}, err
	}
	if _, err = r.signingProfiles.InsertOne(ctx, signingProfileDocumentFromDomain(item)); mongo.IsDuplicateKeyError(err) {
		return biz.SignatureSigningProfile{}, biz.ErrDuplicate
	} else if err != nil {
		return biz.SignatureSigningProfile{}, fmt.Errorf("insert signature signing profile: %w", err)
	}
	return item, nil
}

func (r *MongoRepository) ListSignatureSigningProfiles(ctx context.Context,
	projectID string) ([]biz.SignatureSigningProfile, error) {
	cursor, err := r.signingProfiles.Find(ctx, bson.D{{Key: "project_id", Value: projectID}},
		options.Find().SetSort(bson.D{{Key: "created_at", Value: 1}, {Key: "_id", Value: 1}}))
	if err != nil {
		return nil, fmt.Errorf("find signature signing profiles: %w", err)
	}
	defer cursor.Close(ctx)
	var documents []signatureSigningProfileDocument
	if err := cursor.All(ctx, &documents); err != nil {
		return nil, fmt.Errorf("decode signature signing profiles: %w", err)
	}
	items := make([]biz.SignatureSigningProfile, len(documents))
	for index := range documents {
		items[index], err = documents[index].domain()
		if err != nil {
			return nil, err
		}
	}
	return items, nil
}

func (r *MongoRepository) GetSignatureSigningProfile(ctx context.Context, projectID,
	profileID string) (biz.SignatureSigningProfile, error) {
	var document signatureSigningProfileDocument
	err := r.signingProfiles.FindOne(ctx, bson.D{{Key: "_id", Value: profileID},
		{Key: "project_id", Value: projectID}}).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return biz.SignatureSigningProfile{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.SignatureSigningProfile{}, fmt.Errorf("find signature signing profile: %w", err)
	}
	return document.domain()
}

func (r *MongoRepository) SaveSignatureSigningProfile(ctx context.Context, item biz.SignatureSigningProfile,
	expectedVersion uint64) (biz.SignatureSigningProfile, error) {
	item, err := biz.NewSignatureSigningProfile(signingProfileInput(item))
	if err != nil || expectedVersion == 0 || item.Version != expectedVersion+1 {
		return biz.SignatureSigningProfile{}, biz.ErrInvalidSigningProfile
	}
	result, err := r.signingProfiles.ReplaceOne(ctx, bson.D{{Key: "_id", Value: item.ID},
		{Key: "project_id", Value: item.ProjectID}, {Key: "version", Value: expectedVersion}},
		signingProfileDocumentFromDomain(item))
	if err != nil {
		return biz.SignatureSigningProfile{}, fmt.Errorf("save signature signing profile: %w", err)
	}
	if result.ModifiedCount != 1 {
		return biz.SignatureSigningProfile{}, biz.ErrSigningProfileConflict
	}
	return item, nil
}

type signatureSigningProfileDocument struct {
	ID                      string                 `bson:"_id"`
	OrganizationID          string                 `bson:"organization_id"`
	ProjectID               string                 `bson:"project_id"`
	Name                    string                 `bson:"name"`
	Provider                biz.SigningKeyProvider `bson:"provider"`
	KeyReference            string                 `bson:"key_reference"`
	KeyReferenceFingerprint string                 `bson:"key_reference_fingerprint"`
	TrustPolicyID           string                 `bson:"trust_policy_id"`
	Enabled                 bool                   `bson:"enabled"`
	Version                 uint64                 `bson:"version"`
	CreatedAt               time.Time              `bson:"created_at"`
	UpdatedAt               time.Time              `bson:"updated_at"`
}

func signingProfileDocumentFromDomain(item biz.SignatureSigningProfile) signatureSigningProfileDocument {
	return signatureSigningProfileDocument{ID: item.ID, OrganizationID: item.OrganizationID,
		ProjectID: item.ProjectID, Name: item.Name, Provider: item.Provider, KeyReference: item.KeyReference,
		KeyReferenceFingerprint: item.KeyReferenceFingerprint, TrustPolicyID: item.TrustPolicyID,
		Enabled: item.Enabled, Version: item.Version, CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt}
}

func signingProfileInput(item biz.SignatureSigningProfile) biz.SignatureSigningProfileInput {
	return biz.SignatureSigningProfileInput{ID: item.ID, OrganizationID: item.OrganizationID,
		ProjectID: item.ProjectID, Name: item.Name, KeyReference: item.KeyReference,
		TrustPolicyID: item.TrustPolicyID, Enabled: item.Enabled, Version: item.Version,
		CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt}
}

func (d signatureSigningProfileDocument) domain() (biz.SignatureSigningProfile, error) {
	item, err := biz.NewSignatureSigningProfile(biz.SignatureSigningProfileInput{ID: d.ID,
		OrganizationID: d.OrganizationID, ProjectID: d.ProjectID, Name: d.Name,
		KeyReference: d.KeyReference, TrustPolicyID: d.TrustPolicyID, Enabled: d.Enabled,
		Version: d.Version, CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt})
	if err != nil || item.Provider != d.Provider || item.KeyReferenceFingerprint != d.KeyReferenceFingerprint {
		return biz.SignatureSigningProfile{}, fmt.Errorf("decode invalid signature signing profile: %w", biz.ErrInvalidSigningProfile)
	}
	return item, nil
}

var _ biz.SignatureSigningProfileRepository = (*MongoRepository)(nil)
