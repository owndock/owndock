package data

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/modules/build/biz"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type MongoRepository struct {
	credentials *mongo.Collection
	sources     *mongo.Collection
}

func NewMongoRepository(database *mongo.Database) *MongoRepository {
	return &MongoRepository{
		credentials: database.Collection("repository_credentials"),
		sources:     database.Collection("source_repositories"),
	}
}

func (r *MongoRepository) ListCredentials(
	ctx context.Context,
	projectID string,
) ([]biz.CredentialSummary, error) {
	cursor, err := r.credentials.Find(
		ctx,
		bson.D{{Key: "project_id", Value: projectID}},
		options.Find().
			SetProjection(bson.D{{Key: "secret_ref", Value: 0}}).
			SetSort(bson.D{{Key: "created_at", Value: 1}, {Key: "_id", Value: 1}}),
	)
	if err != nil {
		return nil, fmt.Errorf("find repository credentials: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()
	var documents []credentialSummaryDocument
	if err := cursor.All(ctx, &documents); err != nil {
		return nil, fmt.Errorf("decode repository credentials: %w", err)
	}
	items := make([]biz.CredentialSummary, len(documents))
	for index, document := range documents {
		items[index] = document.domain()
	}
	return items, nil
}

func (r *MongoRepository) CreateCredential(
	ctx context.Context,
	item biz.RepositoryCredential,
) (biz.CredentialSummary, error) {
	document := credentialDocumentFromDomain(item)
	if _, err := r.credentials.InsertOne(ctx, document); mongo.IsDuplicateKeyError(err) {
		return biz.CredentialSummary{}, biz.ErrDuplicateName
	} else if err != nil {
		return biz.CredentialSummary{}, fmt.Errorf("insert repository credential: %w", err)
	}
	return item.Summary(), nil
}

func (r *MongoRepository) GetCredential(
	ctx context.Context,
	projectID, credentialID string,
) (biz.RepositoryCredential, error) {
	var document credentialDocument
	err := r.credentials.FindOne(ctx, bson.D{
		{Key: "_id", Value: credentialID},
		{Key: "project_id", Value: projectID},
	}).Decode(&document)
	if err == mongo.ErrNoDocuments {
		return biz.RepositoryCredential{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.RepositoryCredential{}, fmt.Errorf("find repository credential: %w", err)
	}
	return document.domain(), nil
}

func (r *MongoRepository) ListSources(
	ctx context.Context,
	projectID string,
) ([]biz.SourceRepository, error) {
	cursor, err := r.sources.Find(
		ctx,
		bson.D{{Key: "project_id", Value: projectID}},
		options.Find().SetSort(bson.D{{Key: "created_at", Value: 1}, {Key: "_id", Value: 1}}),
	)
	if err != nil {
		return nil, fmt.Errorf("find source repositories: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()
	var documents []sourceDocument
	if err := cursor.All(ctx, &documents); err != nil {
		return nil, fmt.Errorf("decode source repositories: %w", err)
	}
	items := make([]biz.SourceRepository, len(documents))
	for index, document := range documents {
		items[index] = document.domain()
	}
	return items, nil
}

func (r *MongoRepository) CreateSource(
	ctx context.Context,
	item biz.SourceRepository,
) (biz.SourceRepository, error) {
	if _, err := r.sources.InsertOne(ctx, sourceDocumentFromDomain(item)); mongo.IsDuplicateKeyError(err) {
		return biz.SourceRepository{}, biz.ErrDuplicateName
	} else if err != nil {
		return biz.SourceRepository{}, fmt.Errorf("insert source repository: %w", err)
	}
	return item, nil
}

func (r *MongoRepository) GetSource(
	ctx context.Context,
	projectID, sourceID string,
) (biz.SourceRepository, error) {
	var document sourceDocument
	err := r.sources.FindOne(ctx, bson.D{
		{Key: "_id", Value: sourceID},
		{Key: "project_id", Value: projectID},
	}).Decode(&document)
	if err == mongo.ErrNoDocuments {
		return biz.SourceRepository{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.SourceRepository{}, fmt.Errorf("find source repository: %w", err)
	}
	return document.domain(), nil
}

func (r *MongoRepository) UpdateSourceProbe(
	ctx context.Context,
	projectID, sourceID string,
	status biz.SourceRepositoryStatus,
	probedAt time.Time,
) (biz.SourceRepository, error) {
	var document sourceDocument
	err := r.sources.FindOneAndUpdate(
		ctx,
		bson.D{
			{Key: "_id", Value: sourceID},
			{Key: "project_id", Value: projectID},
		},
		bson.D{{Key: "$set", Value: bson.D{
			{Key: "status", Value: status},
			{Key: "last_probed_at", Value: probedAt.UTC()},
			{Key: "updated_at", Value: probedAt.UTC()},
		}}},
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	).Decode(&document)
	if err == mongo.ErrNoDocuments {
		return biz.SourceRepository{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.SourceRepository{}, fmt.Errorf("update source repository probe: %w", err)
	}
	return document.domain(), nil
}

type credentialDocument struct {
	ID                   string             `bson:"_id"`
	ProjectID            string             `bson:"project_id"`
	Name                 string             `bson:"name"`
	NameNormalized       string             `bson:"name_normalized"`
	Type                 biz.CredentialType `bson:"type"`
	Username             string             `bson:"username,omitempty"`
	SecretRef            string             `bson:"secret_ref"`
	PublicKeyFingerprint string             `bson:"public_key_fingerprint,omitempty"`
	Version              uint64             `bson:"version"`
	CreatedBy            string             `bson:"created_by"`
	CreatedAt            time.Time          `bson:"created_at"`
}

type credentialSummaryDocument struct {
	ID                   string             `bson:"_id"`
	ProjectID            string             `bson:"project_id"`
	Name                 string             `bson:"name"`
	Type                 biz.CredentialType `bson:"type"`
	Username             string             `bson:"username,omitempty"`
	PublicKeyFingerprint string             `bson:"public_key_fingerprint,omitempty"`
	Version              uint64             `bson:"version"`
	CreatedBy            string             `bson:"created_by"`
	CreatedAt            time.Time          `bson:"created_at"`
}

func credentialDocumentFromDomain(item biz.RepositoryCredential) credentialDocument {
	return credentialDocument{
		ID: item.ID, ProjectID: item.ProjectID, Name: item.Name,
		NameNormalized: strings.ToLower(item.Name), Type: item.Type,
		Username: item.Username, SecretRef: item.SecretRef,
		PublicKeyFingerprint: item.PublicKeyFingerprint,
		Version:              item.Version, CreatedBy: item.CreatedBy, CreatedAt: item.CreatedAt,
	}
}

func (d credentialDocument) domain() biz.RepositoryCredential {
	return biz.RepositoryCredential{
		ID: d.ID, ProjectID: d.ProjectID, Name: d.Name, Type: d.Type,
		Username: d.Username, SecretRef: d.SecretRef,
		PublicKeyFingerprint: d.PublicKeyFingerprint,
		Version:              d.Version, CreatedBy: d.CreatedBy, CreatedAt: d.CreatedAt,
	}
}

func (d credentialSummaryDocument) domain() biz.CredentialSummary {
	return biz.CredentialSummary{
		ID: d.ID, ProjectID: d.ProjectID, Name: d.Name, Type: d.Type,
		Username: d.Username, SecretConfigured: true,
		PublicKeyFingerprint: d.PublicKeyFingerprint,
		Version:              d.Version, CreatedBy: d.CreatedBy, CreatedAt: d.CreatedAt,
	}
}

type sourceDocument struct {
	ID                    string                     `bson:"_id"`
	ProjectID             string                     `bson:"project_id"`
	Name                  string                     `bson:"name"`
	NameNormalized        string                     `bson:"name_normalized"`
	RepositoryURL         string                     `bson:"repository_url"`
	Protocol              biz.RepositoryProtocol     `bson:"protocol"`
	DefaultBranch         string                     `bson:"default_branch"`
	CredentialID          string                     `bson:"credential_id,omitempty"`
	SSHHostKeyFingerprint string                     `bson:"ssh_host_key_fingerprint,omitempty"`
	Status                biz.SourceRepositoryStatus `bson:"status"`
	LastProbedAt          time.Time                  `bson:"last_probed_at,omitempty"`
	CreatedBy             string                     `bson:"created_by"`
	CreatedAt             time.Time                  `bson:"created_at"`
	UpdatedAt             time.Time                  `bson:"updated_at"`
}

func sourceDocumentFromDomain(item biz.SourceRepository) sourceDocument {
	return sourceDocument{
		ID: item.ID, ProjectID: item.ProjectID, Name: item.Name,
		NameNormalized: strings.ToLower(item.Name), RepositoryURL: item.RepositoryURL,
		Protocol: item.Protocol, DefaultBranch: item.DefaultBranch,
		CredentialID:          item.CredentialID,
		SSHHostKeyFingerprint: item.SSHHostKeyFingerprint,
		Status:                item.Status, LastProbedAt: item.LastProbedAt,
		CreatedBy: item.CreatedBy, CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt,
	}
}

func (d sourceDocument) domain() biz.SourceRepository {
	return biz.SourceRepository{
		ID: d.ID, ProjectID: d.ProjectID, Name: d.Name,
		RepositoryURL: d.RepositoryURL, Protocol: d.Protocol,
		DefaultBranch: d.DefaultBranch, CredentialID: d.CredentialID,
		SSHHostKeyFingerprint: d.SSHHostKeyFingerprint,
		Status:                d.Status, LastProbedAt: d.LastProbedAt,
		CreatedBy: d.CreatedBy, CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt,
	}
}

var _ biz.Repository = (*MongoRepository)(nil)
