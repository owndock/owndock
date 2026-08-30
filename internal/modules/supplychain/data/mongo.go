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

type MongoRepository struct {
	evidence                  *mongo.Collection
	jobs                      *mongo.Collection
	trustPolicies             *mongo.Collection
	verifications             *mongo.Collection
	signingProfiles           *mongo.Collection
	vulnerabilityObservations *mongo.Collection
	vulnerabilityWaivers      *mongo.Collection
	deploymentPolicies        *mongo.Collection
	client                    *mongo.Client
}

func NewMongoRepository(database *mongo.Database) *MongoRepository {
	return &MongoRepository{
		evidence:      database.Collection("artifact_evidence"),
		jobs:          database.Collection("artifact_evidence_jobs"),
		trustPolicies: database.Collection("signature_trust_policies"), client: database.Client(),
		verifications:             database.Collection("evidence_verifications"),
		signingProfiles:           database.Collection("signature_signing_profiles"),
		vulnerabilityObservations: database.Collection("vulnerability_observations"),
		vulnerabilityWaivers:      database.Collection("vulnerability_waivers"),
		deploymentPolicies:        database.Collection("deployment_policies"),
	}
}

func (r *MongoRepository) ListEvidence(ctx context.Context, projectID, artifactID string) ([]biz.Evidence, error) {
	cursor, err := r.evidence.Find(ctx, bson.D{
		{Key: "project_id", Value: projectID}, {Key: "artifact_id", Value: artifactID},
	}, options.Find().SetSort(bson.D{{Key: "created_at", Value: 1}, {Key: "_id", Value: 1}}))
	if err != nil {
		return nil, fmt.Errorf("find artifact evidence: %w", err)
	}
	defer cursor.Close(ctx)
	var documents []evidenceDocument
	if err := cursor.All(ctx, &documents); err != nil {
		return nil, fmt.Errorf("decode artifact evidence: %w", err)
	}
	items := make([]biz.Evidence, len(documents))
	for index := range documents {
		items[index], err = documents[index].domain()
		if err != nil {
			return nil, err
		}
	}
	return items, nil
}

func (r *MongoRepository) GetEvidence(ctx context.Context, projectID, artifactID, evidenceID string) (biz.Evidence, error) {
	var document evidenceDocument
	err := r.evidence.FindOne(ctx, bson.D{
		{Key: "_id", Value: evidenceID}, {Key: "project_id", Value: projectID},
		{Key: "artifact_id", Value: artifactID},
	}).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return biz.Evidence{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.Evidence{}, fmt.Errorf("find artifact evidence: %w", err)
	}
	return document.domain()
}

func (r *MongoRepository) CreateEvidence(ctx context.Context, item biz.Evidence) (biz.Evidence, error) {
	normalized, err := biz.NewEvidence(inputFromDomain(item))
	if err != nil {
		return biz.Evidence{}, err
	}
	if _, err := r.evidence.InsertOne(ctx, documentFromDomain(normalized)); mongo.IsDuplicateKeyError(err) {
		return biz.Evidence{}, biz.ErrDuplicate
	} else if err != nil {
		return biz.Evidence{}, fmt.Errorf("insert artifact evidence: %w", err)
	}
	return normalized, nil
}

type evidenceDocument struct {
	ID                 string                 `bson:"_id"`
	OrganizationID     string                 `bson:"organization_id"`
	ProjectID          string                 `bson:"project_id"`
	ArtifactID         string                 `bson:"artifact_id"`
	SubjectDigest      string                 `bson:"subject_digest"`
	Kind               biz.EvidenceKind       `bson:"kind"`
	MediaType          string                 `bson:"media_type"`
	FormatVersion      string                 `bson:"format_version"`
	PredicateType      string                 `bson:"predicate_type,omitempty"`
	Producer           string                 `bson:"producer"`
	RegistryRepository string                 `bson:"registry_repository"`
	DescriptorDigest   string                 `bson:"descriptor_digest"`
	VerificationStatus biz.VerificationStatus `bson:"verification_status"`
	CreatedAt          time.Time              `bson:"created_at"`
}

func documentFromDomain(item biz.Evidence) evidenceDocument {
	return evidenceDocument{
		ID: item.ID, OrganizationID: item.OrganizationID, ProjectID: item.ProjectID,
		ArtifactID: item.ArtifactID, SubjectDigest: item.SubjectDigest, Kind: item.Kind,
		MediaType: item.MediaType, FormatVersion: item.FormatVersion,
		PredicateType: item.PredicateType, Producer: item.Producer,
		RegistryRepository: item.RegistryRepository, DescriptorDigest: item.DescriptorDigest,
		VerificationStatus: item.VerificationStatus, CreatedAt: item.CreatedAt,
	}
}

func inputFromDomain(item biz.Evidence) biz.EvidenceInput {
	return biz.EvidenceInput{
		ID: item.ID, OrganizationID: item.OrganizationID, ProjectID: item.ProjectID,
		ArtifactID: item.ArtifactID, SubjectDigest: item.SubjectDigest, Kind: item.Kind,
		MediaType: item.MediaType, FormatVersion: item.FormatVersion,
		PredicateType: item.PredicateType, Producer: item.Producer,
		RegistryRepository: item.RegistryRepository, DescriptorDigest: item.DescriptorDigest,
		VerificationStatus: item.VerificationStatus, CreatedAt: item.CreatedAt,
	}
}

func (d evidenceDocument) domain() (biz.Evidence, error) {
	item, err := biz.NewEvidence(biz.EvidenceInput{
		ID: d.ID, OrganizationID: d.OrganizationID, ProjectID: d.ProjectID,
		ArtifactID: d.ArtifactID, SubjectDigest: d.SubjectDigest, Kind: d.Kind,
		MediaType: d.MediaType, FormatVersion: d.FormatVersion,
		PredicateType: d.PredicateType, Producer: d.Producer,
		RegistryRepository: d.RegistryRepository, DescriptorDigest: d.DescriptorDigest,
		VerificationStatus: d.VerificationStatus, CreatedAt: d.CreatedAt,
	})
	if err != nil {
		return biz.Evidence{}, fmt.Errorf("decode invalid artifact evidence: %w", err)
	}
	return item, nil
}
