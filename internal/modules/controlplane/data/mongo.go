package data

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/modules/controlplane/biz"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type MongoStore struct {
	projects     *mongo.Collection
	applications *mongo.Collection
	releases     *mongo.Collection
	targets      *mongo.Collection
}

func NewMongoStore(database *mongo.Database) *MongoStore {
	return &MongoStore{
		projects:     database.Collection("projects"),
		applications: database.Collection("product_applications"),
		releases:     database.Collection("releases"),
		targets:      database.Collection("runtime_targets"),
	}
}

func (s *MongoStore) ListProjects(ctx context.Context, organizationID string) ([]biz.Project, error) {
	cursor, err := s.projects.Find(
		ctx,
		bson.D{{Key: "organization_id", Value: organizationID}},
		options.Find().SetSort(bson.D{{Key: "created_at", Value: 1}, {Key: "_id", Value: 1}}),
	)
	if err != nil {
		return nil, fmt.Errorf("find projects: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()
	var documents []projectDocument
	if err := cursor.All(ctx, &documents); err != nil {
		return nil, fmt.Errorf("decode projects: %w", err)
	}
	items := make([]biz.Project, len(documents))
	for i, document := range documents {
		items[i] = document.domain()
	}
	return items, nil
}

func (s *MongoStore) CreateProject(ctx context.Context, item biz.Project) (biz.Project, error) {
	_, err := s.projects.InsertOne(ctx, projectDocument{
		ID: item.ID, OrganizationID: item.OrganizationID,
		Name: item.Name, NameNormalized: normalizeName(item.Name),
		CreatedBy: item.CreatedBy, CreatedAt: item.CreatedAt,
	})
	if mongo.IsDuplicateKeyError(err) {
		return biz.Project{}, biz.ErrDuplicateName
	}
	if err != nil {
		return biz.Project{}, fmt.Errorf("insert project: %w", err)
	}
	return item, nil
}

func (s *MongoStore) ProjectExists(ctx context.Context, organizationID, projectID string) (bool, error) {
	count, err := s.projects.CountDocuments(ctx, bson.D{
		{Key: "_id", Value: projectID},
		{Key: "organization_id", Value: organizationID},
	})
	if err != nil {
		return false, fmt.Errorf("check project: %w", err)
	}
	return count == 1, nil
}

func (s *MongoStore) ListApplications(ctx context.Context, projectID string) ([]biz.Application, error) {
	cursor, err := s.applications.Find(
		ctx,
		bson.D{{Key: "project_id", Value: projectID}},
		options.Find().SetSort(bson.D{{Key: "created_at", Value: 1}, {Key: "_id", Value: 1}}),
	)
	if err != nil {
		return nil, fmt.Errorf("find applications: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()
	var documents []applicationDocument
	if err := cursor.All(ctx, &documents); err != nil {
		return nil, fmt.Errorf("decode applications: %w", err)
	}
	items := make([]biz.Application, len(documents))
	for i, document := range documents {
		items[i] = document.domain()
	}
	return items, nil
}

func (s *MongoStore) CreateApplication(ctx context.Context, item biz.Application) (biz.Application, error) {
	_, err := s.applications.InsertOne(ctx, applicationDocument{
		ID: item.ID, ProjectID: item.ProjectID,
		Name: item.Name, NameNormalized: normalizeName(item.Name),
		CreatedBy: item.CreatedBy, CreatedAt: item.CreatedAt,
	})
	if mongo.IsDuplicateKeyError(err) {
		return biz.Application{}, biz.ErrDuplicateName
	}
	if err != nil {
		return biz.Application{}, fmt.Errorf("insert application: %w", err)
	}
	return item, nil
}

func (s *MongoStore) ApplicationExists(ctx context.Context, projectID, applicationID string) (bool, error) {
	count, err := s.applications.CountDocuments(ctx, bson.D{
		{Key: "_id", Value: applicationID},
		{Key: "project_id", Value: projectID},
	})
	if err != nil {
		return false, fmt.Errorf("check application: %w", err)
	}
	return count == 1, nil
}

func (s *MongoStore) ListReleases(ctx context.Context, projectID, applicationID string) ([]biz.Release, error) {
	cursor, err := s.releases.Find(
		ctx,
		bson.D{{Key: "project_id", Value: projectID}, {Key: "application_id", Value: applicationID}},
		options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}, {Key: "_id", Value: -1}}),
	)
	if err != nil {
		return nil, fmt.Errorf("find releases: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()
	var documents []releaseDocument
	if err := cursor.All(ctx, &documents); err != nil {
		return nil, fmt.Errorf("decode releases: %w", err)
	}
	items := make([]biz.Release, len(documents))
	for i, document := range documents {
		items[i] = document.domain()
	}
	return items, nil
}

func (s *MongoStore) CreateRelease(ctx context.Context, item biz.Release) (biz.Release, error) {
	_, err := s.releases.InsertOne(ctx, releaseDocument{
		ID: item.ID, ProjectID: item.ProjectID, ApplicationID: item.ApplicationID,
		ImageDigest: item.ImageDigest, CreatedBy: item.CreatedBy, CreatedAt: item.CreatedAt,
	})
	if mongo.IsDuplicateKeyError(err) {
		return biz.Release{}, biz.ErrDuplicateRelease
	}
	if err != nil {
		return biz.Release{}, fmt.Errorf("insert release: %w", err)
	}
	return item, nil
}

func (s *MongoStore) ListRuntimeTargets(ctx context.Context, projectID string) ([]biz.RuntimeTarget, error) {
	cursor, err := s.targets.Find(
		ctx,
		bson.D{{Key: "project_id", Value: projectID}},
		options.Find().SetSort(bson.D{{Key: "created_at", Value: 1}, {Key: "_id", Value: 1}}),
	)
	if err != nil {
		return nil, fmt.Errorf("find runtime targets: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()
	var documents []runtimeTargetDocument
	if err := cursor.All(ctx, &documents); err != nil {
		return nil, fmt.Errorf("decode runtime targets: %w", err)
	}
	items := make([]biz.RuntimeTarget, len(documents))
	for i, document := range documents {
		items[i] = document.domain()
	}
	return items, nil
}

func (s *MongoStore) CreateRuntimeTarget(ctx context.Context, item biz.RuntimeTarget) (biz.RuntimeTarget, error) {
	_, err := s.targets.InsertOne(ctx, runtimeTargetDocument{
		ID: item.ID, ProjectID: item.ProjectID,
		Name: item.Name, NameNormalized: normalizeName(item.Name),
		Endpoint: item.Endpoint, TLSServerName: item.TLSServerName, CredentialRef: item.CredentialRef,
		Status: item.Status, CreatedBy: item.CreatedBy, CreatedAt: item.CreatedAt,
	})
	if mongo.IsDuplicateKeyError(err) {
		return biz.RuntimeTarget{}, biz.ErrDuplicateName
	}
	if err != nil {
		return biz.RuntimeTarget{}, fmt.Errorf("insert runtime target: %w", err)
	}
	return item, nil
}

func normalizeName(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

type projectDocument struct {
	ID             string    `bson:"_id"`
	OrganizationID string    `bson:"organization_id"`
	Name           string    `bson:"name"`
	NameNormalized string    `bson:"name_normalized"`
	CreatedBy      string    `bson:"created_by"`
	CreatedAt      time.Time `bson:"created_at"`
}

func (d projectDocument) domain() biz.Project {
	return biz.Project{
		ID: d.ID, OrganizationID: d.OrganizationID, Name: d.Name,
		CreatedBy: d.CreatedBy, CreatedAt: d.CreatedAt,
	}
}

type applicationDocument struct {
	ID             string    `bson:"_id"`
	ProjectID      string    `bson:"project_id"`
	Name           string    `bson:"name"`
	NameNormalized string    `bson:"name_normalized"`
	CreatedBy      string    `bson:"created_by"`
	CreatedAt      time.Time `bson:"created_at"`
}

func (d applicationDocument) domain() biz.Application {
	return biz.Application{
		ID: d.ID, ProjectID: d.ProjectID, Name: d.Name,
		CreatedBy: d.CreatedBy, CreatedAt: d.CreatedAt,
	}
}

type releaseDocument struct {
	ID            string    `bson:"_id"`
	ProjectID     string    `bson:"project_id"`
	ApplicationID string    `bson:"application_id"`
	ImageDigest   string    `bson:"image_digest"`
	CreatedBy     string    `bson:"created_by"`
	CreatedAt     time.Time `bson:"created_at"`
}

func (d releaseDocument) domain() biz.Release {
	return biz.Release{
		ID: d.ID, ProjectID: d.ProjectID, ApplicationID: d.ApplicationID,
		ImageDigest: d.ImageDigest, CreatedBy: d.CreatedBy, CreatedAt: d.CreatedAt,
	}
}

type runtimeTargetDocument struct {
	ID             string                  `bson:"_id"`
	ProjectID      string                  `bson:"project_id"`
	Name           string                  `bson:"name"`
	NameNormalized string                  `bson:"name_normalized"`
	Endpoint       string                  `bson:"endpoint"`
	TLSServerName  string                  `bson:"tls_server_name"`
	CredentialRef  string                  `bson:"credential_ref"`
	Status         biz.RuntimeTargetStatus `bson:"status"`
	CreatedBy      string                  `bson:"created_by"`
	CreatedAt      time.Time               `bson:"created_at"`
}

func (d runtimeTargetDocument) domain() biz.RuntimeTarget {
	return biz.RuntimeTarget{
		ID: d.ID, ProjectID: d.ProjectID, Name: d.Name, Endpoint: d.Endpoint,
		TLSServerName: d.TLSServerName, CredentialRef: d.CredentialRef,
		Status: d.Status, CreatedBy: d.CreatedBy, CreatedAt: d.CreatedAt,
	}
}
