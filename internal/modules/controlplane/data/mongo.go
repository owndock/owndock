package data

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/modules/controlplane/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/runtimespec"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type MongoStore struct {
	projects     *mongo.Collection
	applications *mongo.Collection
	releases     *mongo.Collection
	targets      *mongo.Collection
	registries   *mongo.Collection
	environments *mongo.Collection
}

func NewMongoStore(database *mongo.Database) *MongoStore {
	return &MongoStore{
		projects:     database.Collection("projects"),
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
	var connection runtimeaccess.Connection
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
		ImageDigest: item.ImageDigest, RegistryCredentialID: item.RegistryCredentialID,
		RuntimeSpec: runtimeSpecDocumentFromDomain(item.RuntimeSpec),
		CreatedBy:   item.CreatedBy, CreatedAt: item.CreatedAt,
	})
	if mongo.IsDuplicateKeyError(err) {
		return biz.Release{}, biz.ErrDuplicateRelease
	}
	if err != nil {
		return biz.Release{}, fmt.Errorf("insert release: %w", err)
	}
	return item, nil
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
		Server: item.Server, Username: item.Username, PasswordRef: item.PasswordRef,
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
		bson.D{{Key: "_id", Value: targetID}, {Key: "project_id", Value: projectID}},
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
	ID                   string              `bson:"_id"`
	ProjectID            string              `bson:"project_id"`
	ApplicationID        string              `bson:"application_id"`
	ImageDigest          string              `bson:"image_digest"`
	RegistryCredentialID string              `bson:"registry_credential_id,omitempty"`
	RuntimeSpec          runtimeSpecDocument `bson:"runtime_spec"`
	CreatedBy            string              `bson:"created_by"`
	CreatedAt            time.Time           `bson:"created_at"`
}

func (d releaseDocument) domain() biz.Release {
	return biz.Release{
		ID: d.ID, ProjectID: d.ProjectID, ApplicationID: d.ApplicationID,
		ImageDigest: d.ImageDigest, RegistryCredentialID: d.RegistryCredentialID,
		RuntimeSpec: normalizedRuntimeSpec(d.RuntimeSpec.domain()),
		CreatedBy:   d.CreatedBy, CreatedAt: d.CreatedAt,
	}
}

type registryCredentialDocument struct {
	ID             string    `bson:"_id"`
	ProjectID      string    `bson:"project_id"`
	Name           string    `bson:"name"`
	NameNormalized string    `bson:"name_normalized"`
	Server         string    `bson:"server"`
	Username       string    `bson:"username"`
	PasswordRef    string    `bson:"password_ref"`
	CreatedBy      string    `bson:"created_by"`
	CreatedAt      time.Time `bson:"created_at"`
}

func (d registryCredentialDocument) domain() biz.RegistryCredential {
	return biz.RegistryCredential{
		ID: d.ID, ProjectID: d.ProjectID, Name: d.Name,
		Server: d.Server, Username: d.Username, PasswordRef: d.PasswordRef,
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
