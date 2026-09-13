package data

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/modules/controlplane/biz"
	"github.com/owndock/owndock/internal/shared/registryauth"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/runtimespec"
	"github.com/owndock/owndock/internal/shared/security"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type MongoStore struct {
	projects     *mongo.Collection
	members      *mongo.Collection
	users        *mongo.Collection
	applications *mongo.Collection
	releases     *mongo.Collection
	targets      *mongo.Collection
	registries   *mongo.Collection
	environments *mongo.Collection
}

func NewMongoStore(database *mongo.Database) *MongoStore {
	return &MongoStore{
		projects:     database.Collection("projects"),
		members:      database.Collection("project_members"),
		users:        database.Collection("users"),
		applications: database.Collection("product_applications"),
		releases:     database.Collection("releases"),
		targets:      database.Collection("runtime_targets"),
		registries:   database.Collection("registry_credentials"),
		environments: database.Collection("environments"),
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

func (s *MongoStore) ListProjectIDsForUser(
	ctx context.Context, organizationID, userID string,
) ([]string, error) {
	cursor, err := s.members.Find(ctx, bson.D{
		{Key: "organization_id", Value: organizationID}, {Key: "user_id", Value: userID},
	}, options.Find().SetProjection(bson.D{{Key: "project_id", Value: 1}, {Key: "_id", Value: 0}}))
	if err != nil {
		return nil, fmt.Errorf("find project memberships: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()
	var documents []struct {
		ProjectID string `bson:"project_id"`
	}
	if err := cursor.All(ctx, &documents); err != nil {
		return nil, fmt.Errorf("decode project memberships: %w", err)
	}
	result := make([]string, len(documents))
	for i, document := range documents {
		result[i] = document.ProjectID
	}
	return result, nil
}

func (s *MongoStore) ResolveProjectRole(
	ctx context.Context, organizationID, projectID, userID string,
) (security.Role, error) {
	if exists, err := s.ProjectExists(ctx, organizationID, projectID); err != nil {
		return "", err
	} else if !exists {
		return "", biz.ErrNotFound
	}
	var document struct {
		Role security.Role `bson:"role"`
	}
	err := s.members.FindOne(ctx, bson.D{
		{Key: "organization_id", Value: organizationID},
		{Key: "project_id", Value: projectID}, {Key: "user_id", Value: userID},
	}, options.FindOne().SetProjection(bson.D{{Key: "role", Value: 1}})).Decode(&document)
	if err == mongo.ErrNoDocuments {
		return "", biz.ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("resolve project role: %w", err)
	}
	if !document.Role.Valid() || document.Role == security.RoleOwner {
		return "", biz.ErrNotFound
	}
	return document.Role, nil
}

func (s *MongoStore) FindOrganizationUserByEmail(
	ctx context.Context, organizationID, email string,
) (biz.OrganizationUser, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	var document struct {
		ID             string        `bson:"_id"`
		OrganizationID string        `bson:"organization_id"`
		Email          string        `bson:"email"`
		Role           security.Role `bson:"role"`
	}
	err := s.users.FindOne(ctx, bson.D{
		{Key: "organization_id", Value: organizationID},
		{Key: "email_normalized", Value: email},
	}, options.FindOne().SetProjection(bson.D{
		{Key: "organization_id", Value: 1}, {Key: "email", Value: 1}, {Key: "role", Value: 1},
	})).Decode(&document)
	if err == mongo.ErrNoDocuments {
		return biz.OrganizationUser{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.OrganizationUser{}, fmt.Errorf("find organization user: %w", err)
	}
	return biz.OrganizationUser{
		ID: document.ID, OrganizationID: document.OrganizationID,
		Email: document.Email, Role: document.Role,
	}, nil
}

func (s *MongoStore) ListProjectMembers(ctx context.Context, projectID string) ([]biz.ProjectMember, error) {
	cursor, err := s.members.Find(ctx, bson.D{{Key: "project_id", Value: projectID}},
		options.Find().SetSort(bson.D{{Key: "created_at", Value: 1}, {Key: "user_id", Value: 1}}))
	if err != nil {
		return nil, fmt.Errorf("find project members: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()
	var documents []projectMemberDocument
	if err := cursor.All(ctx, &documents); err != nil {
		return nil, fmt.Errorf("decode project members: %w", err)
	}
	result := make([]biz.ProjectMember, len(documents))
	for i, document := range documents {
		result[i] = document.domain()
	}
	return result, nil
}

func (s *MongoStore) GetProjectMember(ctx context.Context, projectID, userID string) (biz.ProjectMember, error) {
	var document projectMemberDocument
	err := s.members.FindOne(ctx, bson.D{{Key: "project_id", Value: projectID}, {Key: "user_id", Value: userID}}).Decode(&document)
	if err == mongo.ErrNoDocuments {
		return biz.ProjectMember{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.ProjectMember{}, fmt.Errorf("find project member: %w", err)
	}
	return document.domain(), nil
}

func (s *MongoStore) CreateProjectMember(ctx context.Context, item biz.ProjectMember) (biz.ProjectMember, error) {
	_, err := s.members.InsertOne(ctx, projectMemberDocumentFromDomain(item))
	if mongo.IsDuplicateKeyError(err) {
		return biz.ProjectMember{}, biz.ErrProjectMemberConflict
	}
	if err != nil {
		return biz.ProjectMember{}, fmt.Errorf("insert project member: %w", err)
	}
	return item, nil
}

func (s *MongoStore) UpdateProjectMember(
	ctx context.Context, item biz.ProjectMember, expectedVersion uint64,
) (biz.ProjectMember, error) {
	var document projectMemberDocument
	err := s.members.FindOneAndUpdate(ctx, bson.D{
		{Key: "project_id", Value: item.ProjectID}, {Key: "user_id", Value: item.UserID},
		{Key: "version", Value: expectedVersion},
	}, bson.D{{Key: "$set", Value: bson.D{
		{Key: "role", Value: item.Role}, {Key: "version", Value: item.Version},
		{Key: "updated_by", Value: item.UpdatedBy}, {Key: "updated_at", Value: item.UpdatedAt},
	}}}, options.FindOneAndUpdate().SetReturnDocument(options.After)).Decode(&document)
	if err == mongo.ErrNoDocuments {
		return biz.ProjectMember{}, biz.ErrProjectMemberConflict
	}
	if err != nil {
		return biz.ProjectMember{}, fmt.Errorf("update project member: %w", err)
	}
	return document.domain(), nil
}

func (s *MongoStore) DeleteProjectMember(
	ctx context.Context, projectID, userID string, expectedVersion uint64,
) error {
	result, err := s.members.DeleteOne(ctx, bson.D{
		{Key: "project_id", Value: projectID}, {Key: "user_id", Value: userID},
		{Key: "version", Value: expectedVersion},
	})
	if err != nil {
		return fmt.Errorf("delete project member: %w", err)
	}
	if result.DeletedCount != 1 {
		return biz.ErrProjectMemberConflict
	}
	return nil
}

// ReleaseExists verifies ownership before a deployment may reference a release.
func (s *MongoStore) ReleaseExists(ctx context.Context, projectID, applicationID, releaseID string) (bool, error) {
	count, err := s.releases.CountDocuments(ctx, bson.D{
		{Key: "_id", Value: releaseID},
		{Key: "project_id", Value: projectID},
		{Key: "application_id", Value: applicationID},
	})
	if err != nil {
		return false, fmt.Errorf("check release: %w", err)
	}
	return count == 1, nil
}

func (s *MongoStore) ReleaseExecution(
	ctx context.Context,
	projectID, applicationID, releaseID string,
) (string, error) {
	var document releaseDocument
	err := s.releases.FindOne(ctx, bson.D{
		{Key: "_id", Value: releaseID},
		{Key: "project_id", Value: projectID},
		{Key: "application_id", Value: applicationID},
	}).Decode(&document)
	if err == mongo.ErrNoDocuments {
		return "", biz.ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("find release execution data: %w", err)
	}
	return document.ImageDigest, nil
}

func (s *MongoStore) ReleaseExecutionRegistry(
	ctx context.Context,
	projectID, applicationID, releaseID string,
) (imageDigest, server, username, passwordRef string, err error) {
	var release releaseDocument
	err = s.releases.FindOne(ctx, bson.D{
		{Key: "_id", Value: releaseID},
		{Key: "project_id", Value: projectID},
		{Key: "application_id", Value: applicationID},
	}).Decode(&release)
	if err == mongo.ErrNoDocuments {
		err = biz.ErrNotFound
		return
	}
	if err != nil {
		err = fmt.Errorf("find release execution registry: %w", err)
		return
	}
	imageDigest = release.ImageDigest
	if release.RegistryCredentialID == "" {
		return
	}
	var credential registryCredentialDocument
	err = s.registries.FindOne(ctx, bson.D{
		{Key: "_id", Value: release.RegistryCredentialID},
		{Key: "project_id", Value: projectID},
	}).Decode(&credential)
	if err == mongo.ErrNoDocuments {
		err = biz.ErrNotFound
		return
	}
	if err != nil {
		err = fmt.Errorf("find release registry credential: %w", err)
		return
	}
	var imageRegistry string
	imageRegistry, err = biz.ImageRegistry(imageDigest)
	if err != nil || imageRegistry != credential.Server {
		err = biz.ErrInvalidRegistry
		return
	}
	switch credential.AuthenticationMode {
	case registryauth.ModeAnonymous:
		if credential.Username != "" || credential.PasswordRef != "" {
			err = biz.ErrInvalidRegistry
			return
		}
	case registryauth.ModeBasic:
		if strings.TrimSpace(credential.Username) == "" || strings.TrimSpace(credential.PasswordRef) == "" {
			err = biz.ErrInvalidRegistry
			return
		}
	default:
		err = biz.ErrInvalidRegistry
		return
	}
	server, username, passwordRef = credential.Server, credential.Username, credential.PasswordRef
	return
}

func (s *MongoStore) ReleaseExecutionSpec(
	ctx context.Context,
	projectID, applicationID, releaseID string,
) (
	imageDigest, server, username, passwordRef string,
	spec runtimespec.Spec,
	err error,
) {
	imageDigest, server, username, passwordRef, err = s.ReleaseExecutionRegistry(
		ctx, projectID, applicationID, releaseID,
	)
	if err != nil {
		return
	}
	var release releaseDocument
	err = s.releases.FindOne(ctx, bson.D{
		{Key: "_id", Value: releaseID},
		{Key: "project_id", Value: projectID},
		{Key: "application_id", Value: applicationID},
	}).Decode(&release)
	if err != nil {
		err = fmt.Errorf("find release runtime specification: %w", err)
		return
	}
	spec, err = runtimespec.Normalize(release.RuntimeSpec.domain())
	if err != nil {
		err = biz.ErrInvalidRuntimeSpec
	}
	return
}

// ReleaseSourceArtifactID is the narrow admission boundary between the
// control plane and software-supply-chain evaluator. External-CI Releases may
// legitimately return an empty Artifact ID; an enabled policy then applies
// its advisory or fail-closed semantics explicitly.
func (s *MongoStore) ReleaseSourceArtifactID(ctx context.Context,
	projectID, applicationID, releaseID string) (string, error) {
	var release struct {
		SourceArtifactID string `bson:"source_artifact_id"`
	}
	err := s.releases.FindOne(ctx, bson.D{{Key: "_id", Value: releaseID},
		{Key: "project_id", Value: projectID}, {Key: "application_id", Value: applicationID}},
		options.FindOne().SetProjection(bson.D{{Key: "source_artifact_id", Value: 1}})).Decode(&release)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return "", biz.ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("find release source artifact: %w", err)
	}
	return release.SourceArtifactID, nil
}

// RuntimeTargetExists verifies that a deployment target belongs to the project.
func (s *MongoStore) RuntimeTargetExists(ctx context.Context, projectID, targetID string) (bool, error) {
	count, err := s.targets.CountDocuments(ctx, bson.D{{Key: "_id", Value: targetID}, {Key: "project_id", Value: projectID}})
	if err != nil {
		return false, fmt.Errorf("check runtime target: %w", err)
	}
	return count == 1, nil
}

func (s *MongoStore) RuntimeTargetReady(
	ctx context.Context,
	projectID, targetID string,
) (bool, error) {
	count, err := s.targets.CountDocuments(ctx, bson.D{
		{Key: "_id", Value: targetID},
		{Key: "project_id", Value: projectID},
		{Key: "status", Value: biz.RuntimeTargetStatusReady},
	})
	if err != nil {
		return false, fmt.Errorf("check runtime target readiness: %w", err)
	}
	return count == 1, nil
}

func (s *MongoStore) RuntimeTargetExecution(
	ctx context.Context,
	projectID, targetID string,
) (runtimeaccess.Connection, error) {
	var document runtimeTargetDocument
	err := s.targets.FindOne(ctx, bson.D{
		{Key: "_id", Value: targetID},
		{Key: "project_id", Value: projectID},
		{Key: "status", Value: biz.RuntimeTargetStatusReady},
	}).Decode(&document)
	if err == mongo.ErrNoDocuments {
		return runtimeaccess.Connection{}, biz.ErrNotFound
	}
	if err != nil {
		return runtimeaccess.Connection{}, fmt.Errorf("find runtime target execution data: %w", err)
	}
	return runtimeTargetConnection(document)
}

func runtimeTargetConnection(
	document runtimeTargetDocument,
) (runtimeaccess.Connection, error) {
	var connection runtimeaccess.Connection
	var err error
	switch document.ConnectionMode {
	case runtimeaccess.ModeDirectDocker:
		connection, err = runtimeaccess.NewDirectDocker(
			document.ManagedHostID,
			document.Endpoint,
			document.TLSServerName,
			document.CredentialRef,
		)
	case runtimeaccess.ModeAgent:
		connection, err = runtimeaccess.NewAgent(document.ManagedHostID)
	default:
		err = runtimeaccess.ErrUnsupportedMode
	}
	if err != nil {
		return runtimeaccess.Connection{}, fmt.Errorf("decode runtime target connection: %w", err)
	}
	return connection, nil
}

// RuntimeTargetCleanupExecution allows only ready or retiring targets. Normal
// prepare/deploy resolution remains ready-only, while a worker can finish a
// cancellation requested by the retirement state machine.
func (s *MongoStore) RuntimeTargetCleanupExecution(
	ctx context.Context,
	projectID, targetID string,
) (runtimeaccess.Connection, error) {
	var document runtimeTargetDocument
	err := s.targets.FindOne(ctx, bson.D{
		{Key: "_id", Value: targetID},
		{Key: "project_id", Value: projectID},
		{Key: "status", Value: bson.D{{Key: "$in", Value: bson.A{
			biz.RuntimeTargetStatusReady,
			biz.RuntimeTargetStatusRetiring,
		}}}},
	}).Decode(&document)
	if err == mongo.ErrNoDocuments {
		return runtimeaccess.Connection{}, biz.ErrNotFound
	}
	if err != nil {
		return runtimeaccess.Connection{}, fmt.Errorf("find runtime target cleanup data: %w", err)
	}
	return runtimeTargetConnection(document)
}

func (s *MongoStore) EnvironmentExists(ctx context.Context, projectID, environmentID string) (bool, error) {
	count, err := s.environments.CountDocuments(ctx, bson.D{
		{Key: "_id", Value: environmentID},
		{Key: "project_id", Value: projectID},
	})
	if err != nil {
		return false, fmt.Errorf("check environment: %w", err)
	}
	return count == 1, nil
}

func (s *MongoStore) EnvironmentExecution(
	ctx context.Context,
	projectID, environmentID string,
) (map[string]string, error) {
	var document environmentDocument
	err := s.environments.FindOne(ctx, bson.D{
		{Key: "_id", Value: environmentID},
		{Key: "project_id", Value: projectID},
	}).Decode(&document)
	if err == mongo.ErrNoDocuments {
		return nil, biz.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find environment execution data: %w", err)
	}
	return document.Variables, nil
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
		item, domainErr := document.domain()
		if domainErr != nil {
			return nil, fmt.Errorf("decode application: %w", domainErr)
		}
		items[i] = item
	}
	return items, nil
}

func (s *MongoStore) CreateApplication(ctx context.Context, item biz.Application) (biz.Application, error) {
	snapshot, err := biz.NormalizeApplicationTemplateSnapshot(
		item.TemplateSnapshot,
	)
	if err != nil {
		return biz.Application{}, err
	}
	item.TemplateSnapshot = snapshot
	_, err = s.applications.InsertOne(ctx, applicationDocument{
		ID: item.ID, ProjectID: item.ProjectID,
		Name: item.Name, NameNormalized: normalizeName(item.Name),
		TemplateSnapshot: applicationTemplateSnapshotDocumentFromDomain(
			item.TemplateSnapshot,
		),
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
		ImageDigest: item.ImageDigest, RegistryCredentialID: item.RegistryCredentialID,
		SourceArtifactID: item.SourceArtifactID,
		RuntimeSpec:      runtimeSpecDocumentFromDomain(item.RuntimeSpec),
		CreatedBy:        item.CreatedBy, CreatedAt: item.CreatedAt,
	})
	if mongo.IsDuplicateKeyError(err) {
		return biz.Release{}, biz.ErrDuplicateRelease
	}
	if err != nil {
		return biz.Release{}, fmt.Errorf("insert release: %w", err)
	}
	return item, nil
}

func (s *MongoStore) GetReleaseByArtifact(ctx context.Context, projectID, artifactID string) (biz.Release, error) {
	var document releaseDocument
	err := s.releases.FindOne(ctx, bson.D{
		{Key: "project_id", Value: projectID}, {Key: "source_artifact_id", Value: artifactID},
	}).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return biz.Release{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.Release{}, fmt.Errorf("find artifact release: %w", err)
	}
	return document.domain(), nil
}

func (s *MongoStore) ListRegistryCredentials(
	ctx context.Context,
	projectID string,
) ([]biz.RegistryCredential, error) {
	cursor, err := s.registries.Find(
		ctx,
		bson.D{{Key: "project_id", Value: projectID}},
		options.Find().SetSort(bson.D{{Key: "created_at", Value: 1}, {Key: "_id", Value: 1}}),
	)
	if err != nil {
		return nil, fmt.Errorf("find registry credentials: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()
	var documents []registryCredentialDocument
	if err := cursor.All(ctx, &documents); err != nil {
		return nil, fmt.Errorf("decode registry credentials: %w", err)
	}
	items := make([]biz.RegistryCredential, len(documents))
	for i, document := range documents {
		items[i] = document.domain()
	}
	return items, nil
}

func (s *MongoStore) CreateRegistryCredential(
	ctx context.Context,
	item biz.RegistryCredential,
) (biz.RegistryCredential, error) {
	_, err := s.registries.InsertOne(ctx, registryCredentialDocument{
		ID: item.ID, ProjectID: item.ProjectID,
		Name: item.Name, NameNormalized: normalizeName(item.Name),
		Server: item.Server, AuthenticationMode: item.AuthenticationMode,
		Username: item.Username, PasswordRef: item.PasswordRef,
		CreatedBy: item.CreatedBy, CreatedAt: item.CreatedAt,
	})
	if mongo.IsDuplicateKeyError(err) {
		return biz.RegistryCredential{}, biz.ErrDuplicateName
	}
	if err != nil {
		return biz.RegistryCredential{}, fmt.Errorf("insert registry credential: %w", err)
	}
	return item, nil
}

func (s *MongoStore) GetRegistryCredential(
	ctx context.Context,
	projectID, credentialID string,
) (biz.RegistryCredential, error) {
	var document registryCredentialDocument
	err := s.registries.FindOne(ctx, bson.D{
		{Key: "_id", Value: credentialID},
		{Key: "project_id", Value: projectID},
	}).Decode(&document)
	if err == mongo.ErrNoDocuments {
		return biz.RegistryCredential{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.RegistryCredential{}, fmt.Errorf("find registry credential: %w", err)
	}
	return document.domain(), nil
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
		ManagedHostID: item.ManagedHostID, ConnectionMode: item.ConnectionMode,
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

func (s *MongoStore) GetRuntimeTarget(
	ctx context.Context,
	projectID, targetID string,
) (biz.RuntimeTarget, error) {
	var document runtimeTargetDocument
	err := s.targets.FindOne(ctx, bson.D{
		{Key: "_id", Value: targetID},
		{Key: "project_id", Value: projectID},
	}).Decode(&document)
	if err == mongo.ErrNoDocuments {
		return biz.RuntimeTarget{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.RuntimeTarget{}, fmt.Errorf("find runtime target: %w", err)
	}
	return document.domain(), nil
}

func (s *MongoStore) UpdateRuntimeTargetProbe(
	ctx context.Context,
	projectID, targetID string,
	status biz.RuntimeTargetStatus,
	probedAt time.Time,
) (biz.RuntimeTarget, error) {
	var document runtimeTargetDocument
	err := s.targets.FindOneAndUpdate(
		ctx,
		bson.D{
			{Key: "_id", Value: targetID},
			{Key: "project_id", Value: projectID},
			{Key: "status", Value: bson.D{{Key: "$ne", Value: biz.RuntimeTargetStatusRetiring}}},
		},
		bson.D{{Key: "$set", Value: bson.D{
			{Key: "status", Value: status},
			{Key: "last_probed_at", Value: probedAt.UTC()},
		}}},
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	).Decode(&document)
	if err == mongo.ErrNoDocuments {
		return biz.RuntimeTarget{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.RuntimeTarget{}, fmt.Errorf("update runtime target probe: %w", err)
	}
	return document.domain(), nil
}

func (s *MongoStore) BeginRuntimeTargetRetirement(
	ctx context.Context,
	projectID, targetID string,
	now time.Time,
) (biz.RuntimeTarget, bool, error) {
	var document runtimeTargetDocument
	err := s.targets.FindOneAndUpdate(
		ctx,
		bson.D{
			{Key: "_id", Value: targetID},
			{Key: "project_id", Value: projectID},
			{Key: "status", Value: bson.D{{Key: "$ne", Value: biz.RuntimeTargetStatusRetiring}}},
		},
		bson.D{{Key: "$set", Value: bson.D{
			{Key: "status", Value: biz.RuntimeTargetStatusRetiring},
			{Key: "retirement_started_at", Value: now.UTC()},
		}}},
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	).Decode(&document)
	if err == nil {
		return document.domain(), true, nil
	}
	if err != mongo.ErrNoDocuments {
		return biz.RuntimeTarget{}, false, fmt.Errorf("begin runtime target retirement: %w", err)
	}
	target, findErr := s.GetRuntimeTarget(ctx, projectID, targetID)
	if findErr != nil {
		return biz.RuntimeTarget{}, false, findErr
	}
	if target.Status != biz.RuntimeTargetStatusRetiring {
		return biz.RuntimeTarget{}, false, biz.ErrNotFound
	}
	return target, false, nil
}

func (s *MongoStore) DeleteRetiringRuntimeTarget(
	ctx context.Context,
	projectID, targetID string,
) error {
	result, err := s.targets.DeleteOne(ctx, bson.D{
		{Key: "_id", Value: targetID},
		{Key: "project_id", Value: projectID},
		{Key: "status", Value: biz.RuntimeTargetStatusRetiring},
	})
	if err != nil {
		return fmt.Errorf("delete retiring runtime target: %w", err)
	}
	if result.DeletedCount != 1 {
		return biz.ErrNotFound
	}
	return nil
}

func (s *MongoStore) ListEnvironments(ctx context.Context, projectID string) ([]biz.Environment, error) {
	cursor, err := s.environments.Find(ctx, bson.D{{Key: "project_id", Value: projectID}}, options.Find().SetSort(bson.D{{Key: "created_at", Value: 1}, {Key: "_id", Value: 1}}))
	if err != nil {
		return nil, fmt.Errorf("find environments: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()
	var documents []environmentDocument
	if err := cursor.All(ctx, &documents); err != nil {
		return nil, fmt.Errorf("decode environments: %w", err)
	}
	items := make([]biz.Environment, len(documents))
	for i, document := range documents {
		items[i] = document.domain()
	}
	return items, nil
}

func (s *MongoStore) EnvironmentStage(ctx context.Context, projectID, environmentID string) (string, error) {
	var document struct {
		Stage string `bson:"stage"`
	}
	err := s.environments.FindOne(ctx, bson.D{
		{Key: "_id", Value: environmentID}, {Key: "project_id", Value: projectID},
	}, options.FindOne().SetProjection(bson.D{{Key: "stage", Value: 1}})).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return "", biz.ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("find environment stage: %w", err)
	}
	return document.Stage, nil
}

func (s *MongoStore) CreateEnvironment(ctx context.Context, item biz.Environment) (biz.Environment, error) {
	_, err := s.environments.InsertOne(ctx, environmentDocument{
		ID: item.ID, ProjectID: item.ProjectID, Name: item.Name, NameNormalized: normalizeName(item.Name),
		Stage: item.Stage, Variables: item.Variables,
		CreatedBy: item.CreatedBy, CreatedAt: item.CreatedAt,
	})
	if mongo.IsDuplicateKeyError(err) {
		return biz.Environment{}, biz.ErrDuplicateName
	}
	if err != nil {
		return biz.Environment{}, fmt.Errorf("insert environment: %w", err)
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

type projectMemberDocument struct {
	OrganizationID string        `bson:"organization_id"`
	ProjectID      string        `bson:"project_id"`
	UserID         string        `bson:"user_id"`
	Email          string        `bson:"email"`
	Role           security.Role `bson:"role"`
	Version        uint64        `bson:"version"`
	CreatedBy      string        `bson:"created_by"`
	CreatedAt      time.Time     `bson:"created_at"`
	UpdatedBy      string        `bson:"updated_by"`
	UpdatedAt      time.Time     `bson:"updated_at"`
}

func projectMemberDocumentFromDomain(item biz.ProjectMember) projectMemberDocument {
	return projectMemberDocument{
		OrganizationID: item.OrganizationID, ProjectID: item.ProjectID,
		UserID: item.UserID, Email: item.Email, Role: item.Role, Version: item.Version,
		CreatedBy: item.CreatedBy, CreatedAt: item.CreatedAt,
		UpdatedBy: item.UpdatedBy, UpdatedAt: item.UpdatedAt,
	}
}

func (d projectMemberDocument) domain() biz.ProjectMember {
	return biz.ProjectMember{
		OrganizationID: d.OrganizationID, ProjectID: d.ProjectID,
		UserID: d.UserID, Email: d.Email, Role: d.Role, Version: d.Version,
		CreatedBy: d.CreatedBy, CreatedAt: d.CreatedAt,
		UpdatedBy: d.UpdatedBy, UpdatedAt: d.UpdatedAt,
	}
}

func (d projectDocument) domain() biz.Project {
	return biz.Project{
		ID: d.ID, OrganizationID: d.OrganizationID, Name: d.Name,
		CreatedBy: d.CreatedBy, CreatedAt: d.CreatedAt,
	}
}

type applicationDocument struct {
	ID               string                               `bson:"_id"`
	ProjectID        string                               `bson:"project_id"`
	Name             string                               `bson:"name"`
	NameNormalized   string                               `bson:"name_normalized"`
	TemplateSnapshot *applicationTemplateSnapshotDocument `bson:"template_snapshot,omitempty"`
	CreatedBy        string                               `bson:"created_by"`
	CreatedAt        time.Time                            `bson:"created_at"`
}

func (d applicationDocument) domain() (biz.Application, error) {
	snapshot, err := biz.NormalizeApplicationTemplateSnapshot(
		d.TemplateSnapshot.domain(),
	)
	if err != nil {
		return biz.Application{}, err
	}
	return biz.Application{
		ID: d.ID, ProjectID: d.ProjectID, Name: d.Name,
		TemplateSnapshot: snapshot,
		CreatedBy:        d.CreatedBy, CreatedAt: d.CreatedAt,
	}, nil
}

type applicationTemplateSnapshotDocument struct {
	TemplateID      string              `bson:"template_id"`
	TemplateVersion uint64              `bson:"template_version"`
	DockerfilePath  string              `bson:"dockerfile_path"`
	ContextPath     string              `bson:"context_path"`
	RuntimeSpec     runtimeSpecDocument `bson:"runtime_spec"`
}

func applicationTemplateSnapshotDocumentFromDomain(
	item *biz.ApplicationTemplateSnapshot,
) *applicationTemplateSnapshotDocument {
	if item == nil {
		return nil
	}
	return &applicationTemplateSnapshotDocument{
		TemplateID: item.TemplateID, TemplateVersion: item.TemplateVersion,
		DockerfilePath: item.DockerfilePath, ContextPath: item.ContextPath,
		RuntimeSpec: runtimeSpecDocumentFromDomain(item.RuntimeSpec),
	}
}

func (d *applicationTemplateSnapshotDocument) domain() *biz.ApplicationTemplateSnapshot {
	if d == nil {
		return nil
	}
	return &biz.ApplicationTemplateSnapshot{
		TemplateID: d.TemplateID, TemplateVersion: d.TemplateVersion,
		DockerfilePath: d.DockerfilePath, ContextPath: d.ContextPath,
		RuntimeSpec: normalizedRuntimeSpec(d.RuntimeSpec.domain()),
	}
}

type releaseDocument struct {
	ID                   string              `bson:"_id"`
	ProjectID            string              `bson:"project_id"`
	ApplicationID        string              `bson:"application_id"`
	ImageDigest          string              `bson:"image_digest"`
	RegistryCredentialID string              `bson:"registry_credential_id,omitempty"`
	SourceArtifactID     string              `bson:"source_artifact_id,omitempty"`
	RuntimeSpec          runtimeSpecDocument `bson:"runtime_spec"`
	CreatedBy            string              `bson:"created_by"`
	CreatedAt            time.Time           `bson:"created_at"`
}

func (d releaseDocument) domain() biz.Release {
	return biz.Release{
		ID: d.ID, ProjectID: d.ProjectID, ApplicationID: d.ApplicationID,
		ImageDigest: d.ImageDigest, RegistryCredentialID: d.RegistryCredentialID,
		SourceArtifactID: d.SourceArtifactID,
		RuntimeSpec:      normalizedRuntimeSpec(d.RuntimeSpec.domain()),
		CreatedBy:        d.CreatedBy, CreatedAt: d.CreatedAt,
	}
}

type registryCredentialDocument struct {
	ID                 string            `bson:"_id"`
	ProjectID          string            `bson:"project_id"`
	Name               string            `bson:"name"`
	NameNormalized     string            `bson:"name_normalized"`
	Server             string            `bson:"server"`
	AuthenticationMode registryauth.Mode `bson:"authentication_mode"`
	Username           string            `bson:"username,omitempty"`
	PasswordRef        string            `bson:"password_ref,omitempty"`
	CreatedBy          string            `bson:"created_by"`
	CreatedAt          time.Time         `bson:"created_at"`
}

func (d registryCredentialDocument) domain() biz.RegistryCredential {
	return biz.RegistryCredential{
		ID: d.ID, ProjectID: d.ProjectID, Name: d.Name,
		Server: d.Server, AuthenticationMode: d.AuthenticationMode,
		Username: d.Username, PasswordRef: d.PasswordRef,
		CreatedBy: d.CreatedBy, CreatedAt: d.CreatedAt,
	}
}

type runtimeTargetDocument struct {
	ID             string                  `bson:"_id"`
	ProjectID      string                  `bson:"project_id"`
	Name           string                  `bson:"name"`
	NameNormalized string                  `bson:"name_normalized"`
	ManagedHostID  string                  `bson:"managed_host_id"`
	ConnectionMode runtimeaccess.Mode      `bson:"connection_mode"`
	Endpoint       string                  `bson:"endpoint,omitempty"`
	TLSServerName  string                  `bson:"tls_server_name,omitempty"`
	CredentialRef  string                  `bson:"credential_ref,omitempty"`
	Status         biz.RuntimeTargetStatus `bson:"status"`
	LastProbedAt   time.Time               `bson:"last_probed_at,omitempty"`
	CreatedBy      string                  `bson:"created_by"`
	CreatedAt      time.Time               `bson:"created_at"`
}

type environmentDocument struct {
	ID             string            `bson:"_id"`
	ProjectID      string            `bson:"project_id"`
	Name           string            `bson:"name"`
	NameNormalized string            `bson:"name_normalized"`
	Stage          string            `bson:"stage"`
	Variables      map[string]string `bson:"variables,omitempty"`
	CreatedBy      string            `bson:"created_by"`
	CreatedAt      time.Time         `bson:"created_at"`
}

func (d environmentDocument) domain() biz.Environment {
	return biz.Environment{
		ID: d.ID, ProjectID: d.ProjectID, Name: d.Name, Stage: d.Stage,
		Variables: d.Variables, CreatedBy: d.CreatedBy, CreatedAt: d.CreatedAt,
	}
}

func (d runtimeTargetDocument) domain() biz.RuntimeTarget {
	return biz.RuntimeTarget{
		ID: d.ID, ProjectID: d.ProjectID, Name: d.Name,
		ManagedHostID: d.ManagedHostID, ConnectionMode: d.ConnectionMode,
		Endpoint:      d.Endpoint,
		TLSServerName: d.TLSServerName, CredentialRef: d.CredentialRef,
		Status: d.Status, LastProbedAt: d.LastProbedAt,
		CreatedBy: d.CreatedBy, CreatedAt: d.CreatedAt,
	}
}

type runtimeSpecDocument struct {
	Ports           []runtimePortDocument `bson:"ports,omitempty"`
	EnvironmentKeys []string              `bson:"environment_keys,omitempty"`
	Resources       resourceDocument      `bson:"resources"`
	HealthCheck     *healthCheckDocument  `bson:"health_check,omitempty"`
}

type runtimePortDocument struct {
	Name          string `bson:"name"`
	ContainerPort uint16 `bson:"container_port"`
	Protocol      string `bson:"protocol"`
}

type resourceDocument struct {
	CPUMilli    int64 `bson:"cpu_milli"`
	MemoryBytes int64 `bson:"memory_bytes"`
}

type healthCheckDocument struct {
	Command            []string `bson:"command"`
	IntervalSeconds    int      `bson:"interval_seconds"`
	TimeoutSeconds     int      `bson:"timeout_seconds"`
	Retries            int      `bson:"retries"`
	StartPeriodSeconds int      `bson:"start_period_seconds"`
}

func runtimeSpecDocumentFromDomain(spec runtimespec.Spec) runtimeSpecDocument {
	ports := make([]runtimePortDocument, len(spec.Ports))
	for i, port := range spec.Ports {
		ports[i] = runtimePortDocument{
			Name: port.Name, ContainerPort: port.ContainerPort, Protocol: port.Protocol,
		}
	}
	document := runtimeSpecDocument{
		Ports: ports, EnvironmentKeys: spec.EnvironmentKeys,
		Resources: resourceDocument{
			CPUMilli: spec.Resources.CPUMilli, MemoryBytes: spec.Resources.MemoryBytes,
		},
	}
	if spec.HealthCheck != nil {
		document.HealthCheck = &healthCheckDocument{
			Command:            spec.HealthCheck.Command,
			IntervalSeconds:    spec.HealthCheck.IntervalSeconds,
			TimeoutSeconds:     spec.HealthCheck.TimeoutSeconds,
			Retries:            spec.HealthCheck.Retries,
			StartPeriodSeconds: spec.HealthCheck.StartPeriodSeconds,
		}
	}
	return document
}

func (d runtimeSpecDocument) domain() runtimespec.Spec {
	ports := make([]runtimespec.Port, len(d.Ports))
	for i, port := range d.Ports {
		ports[i] = runtimespec.Port{
			Name: port.Name, ContainerPort: port.ContainerPort, Protocol: port.Protocol,
		}
	}
	spec := runtimespec.Spec{
		Ports: ports, EnvironmentKeys: d.EnvironmentKeys,
		Resources: runtimespec.Resources{
			CPUMilli: d.Resources.CPUMilli, MemoryBytes: d.Resources.MemoryBytes,
		},
	}
	if d.HealthCheck != nil {
		spec.HealthCheck = &runtimespec.HealthCheck{
			Command:            d.HealthCheck.Command,
			IntervalSeconds:    d.HealthCheck.IntervalSeconds,
			TimeoutSeconds:     d.HealthCheck.TimeoutSeconds,
			Retries:            d.HealthCheck.Retries,
			StartPeriodSeconds: d.HealthCheck.StartPeriodSeconds,
		}
	}
	return spec
}

func normalizedRuntimeSpec(spec runtimespec.Spec) runtimespec.Spec {
	normalized, err := runtimespec.Normalize(spec)
	if err != nil {
		return spec
	}
	return normalized
}
