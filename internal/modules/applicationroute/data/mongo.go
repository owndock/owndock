package data

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/owndock/owndock/internal/modules/applicationroute/biz"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const listLimit = biz.MaxRoutesPerProject + 1

type MongoRepository struct {
	routes *mongo.Collection
}

func NewMongoRepository(database *mongo.Database) *MongoRepository {
	return &MongoRepository{routes: database.Collection("application_routes")}
}

type routeDocument struct {
	ID              string               `bson:"_id"`
	Slot            uint16               `bson:"slot"`
	OrganizationID  string               `bson:"organization_id"`
	ProjectID       string               `bson:"project_id"`
	ApplicationID   string               `bson:"application_id"`
	EnvironmentID   string               `bson:"environment_id"`
	RuntimeTargetID string               `bson:"runtime_target_id"`
	Hostname        string               `bson:"hostname"`
	PortName        string               `bson:"port_name"`
	TLSMode         biz.TLSMode          `bson:"tls_mode"`
	Status          biz.Status           `bson:"status"`
	Revision        uint64               `bson:"revision"`
	Version         uint64               `bson:"version"`
	Observation     *observationDocument `bson:"observation,omitempty"`
	CreatedBy       string               `bson:"created_by"`
	UpdatedBy       string               `bson:"updated_by"`
	CreatedAt       time.Time            `bson:"created_at"`
	UpdatedAt       time.Time            `bson:"updated_at"`
}

type observationDocument struct {
	Revision          uint64                `bson:"revision"`
	DeploymentID      string                `bson:"deployment_id"`
	CutoverSequence   uint64                `bson:"cutover_sequence"`
	ConfigDigest      string                `bson:"config_digest"`
	CertificateStatus biz.CertificateStatus `bson:"certificate_status"`
	ObservedAt        time.Time             `bson:"observed_at"`
}

func observationDocumentFromDomain(value *biz.Observation) *observationDocument {
	if value == nil {
		return nil
	}
	return &observationDocument{Revision: value.Revision, DeploymentID: value.DeploymentID,
		CutoverSequence: value.CutoverSequence, ConfigDigest: value.ConfigDigest,
		CertificateStatus: value.CertificateStatus, ObservedAt: value.ObservedAt}
}

func (d *observationDocument) domain() *biz.Observation {
	if d == nil {
		return nil
	}
	return &biz.Observation{Revision: d.Revision, DeploymentID: d.DeploymentID,
		CutoverSequence: d.CutoverSequence, ConfigDigest: d.ConfigDigest,
		CertificateStatus: d.CertificateStatus, ObservedAt: d.ObservedAt}
}

func documentFromDomain(item biz.ApplicationRoute) routeDocument {
	return routeDocument{ID: item.ID, OrganizationID: item.OrganizationID, ProjectID: item.ProjectID,
		ApplicationID: item.ApplicationID, EnvironmentID: item.EnvironmentID,
		RuntimeTargetID: item.RuntimeTargetID, Hostname: item.Hostname, PortName: item.PortName,
		TLSMode: item.TLSMode, Status: item.Status, Revision: item.Revision, Version: item.Version,
		Observation: observationDocumentFromDomain(item.Observation),
		CreatedBy:   item.CreatedBy, UpdatedBy: item.UpdatedBy,
		CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt}
}

func inputFromDomain(item biz.ApplicationRoute) biz.Input {
	return biz.Input{ID: item.ID, OrganizationID: item.OrganizationID, ProjectID: item.ProjectID,
		ApplicationID: item.ApplicationID, EnvironmentID: item.EnvironmentID,
		RuntimeTargetID: item.RuntimeTargetID, Hostname: item.Hostname, PortName: item.PortName,
		TLSMode: item.TLSMode, Status: item.Status, Revision: item.Revision, Version: item.Version,
		Observation: item.Observation,
		CreatedBy:   item.CreatedBy, UpdatedBy: item.UpdatedBy,
		CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt}
}

func (d routeDocument) domain() (biz.ApplicationRoute, error) {
	item, err := biz.NewApplicationRoute(biz.Input{ID: d.ID, OrganizationID: d.OrganizationID, ProjectID: d.ProjectID,
		ApplicationID: d.ApplicationID, EnvironmentID: d.EnvironmentID, RuntimeTargetID: d.RuntimeTargetID,
		Hostname: d.Hostname, PortName: d.PortName, TLSMode: d.TLSMode, Status: d.Status,
		Revision: d.Revision, Version: d.Version, Observation: d.Observation.domain(),
		CreatedBy: d.CreatedBy, UpdatedBy: d.UpdatedBy, CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt})
	if err != nil {
		return biz.ApplicationRoute{}, fmt.Errorf("decode invalid application route: %w", err)
	}
	return item, nil
}

func (r *MongoRepository) Create(ctx context.Context, item biz.ApplicationRoute) (biz.ApplicationRoute, error) {
	normalized, err := biz.NewApplicationRoute(inputFromDomain(item))
	if err != nil {
		return biz.ApplicationRoute{}, err
	}
	document := documentFromDomain(normalized)
	for slot := 1; slot <= biz.MaxRoutesPerProject; slot++ {
		document.Slot = uint16(slot)
		if _, err := r.routes.InsertOne(ctx, document); err == nil {
			return normalized, nil
		} else if !mongo.IsDuplicateKeyError(err) {
			return biz.ApplicationRoute{}, fmt.Errorf("insert application route: %w", err)
		}
		var existing struct {
			ID string `bson:"_id"`
		}
		err := r.routes.FindOne(ctx, bson.D{{Key: "organization_id", Value: normalized.OrganizationID},
			{Key: "hostname", Value: normalized.Hostname}, {Key: "status", Value: activeStatusExpression()}}).Decode(&existing)
		if err == nil {
			return biz.ApplicationRoute{}, biz.ErrRouteConflict
		}
		if !errors.Is(err, mongo.ErrNoDocuments) {
			return biz.ApplicationRoute{}, fmt.Errorf("resolve application route conflict: %w", err)
		}
	}
	return biz.ApplicationRoute{}, biz.ErrRouteLimitExceeded
}

func activeStatusExpression() bson.D {
	return bson.D{{Key: "$in", Value: bson.A{biz.StatusPending, biz.StatusProvisioning,
		biz.StatusReady, biz.StatusDegraded, biz.StatusRetiring}}}
}

func (r *MongoRepository) List(ctx context.Context, organizationID, projectID string) ([]biz.ApplicationRoute, error) {
	cursor, err := r.routes.Find(ctx, bson.D{{Key: "organization_id", Value: organizationID},
		{Key: "project_id", Value: projectID}, {Key: "status", Value: bson.D{{Key: "$ne", Value: biz.StatusRetired}}}},
		options.Find().SetSort(bson.D{{Key: "created_at", Value: 1}, {Key: "_id", Value: 1}}).SetLimit(listLimit))
	if err != nil {
		return nil, fmt.Errorf("find application routes: %w", err)
	}
	defer cursor.Close(ctx)
	var documents []routeDocument
	if err := cursor.All(ctx, &documents); err != nil {
		return nil, fmt.Errorf("decode application routes: %w", err)
	}
	if len(documents) > biz.MaxRoutesPerProject {
		return nil, biz.ErrRouteLimitExceeded
	}
	items := make([]biz.ApplicationRoute, len(documents))
	for index := range documents {
		items[index], err = documents[index].domain()
		if err != nil {
			return nil, err
		}
	}
	return items, nil
}

func (r *MongoRepository) Get(ctx context.Context, organizationID, projectID, routeID string) (biz.ApplicationRoute, error) {
	var document routeDocument
	err := r.routes.FindOne(ctx, bson.D{{Key: "_id", Value: routeID},
		{Key: "organization_id", Value: organizationID}, {Key: "project_id", Value: projectID},
		{Key: "status", Value: bson.D{{Key: "$ne", Value: biz.StatusRetired}}}}).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return biz.ApplicationRoute{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.ApplicationRoute{}, fmt.Errorf("find application route: %w", err)
	}
	return document.domain()
}

func (r *MongoRepository) Save(ctx context.Context, item biz.ApplicationRoute, expectedVersion uint64) (biz.ApplicationRoute, error) {
	normalized, err := biz.NewApplicationRoute(inputFromDomain(item))
	if err != nil || expectedVersion == 0 || normalized.Version != expectedVersion+1 {
		return biz.ApplicationRoute{}, biz.ErrInvalidRoute
	}
	result, err := r.routes.UpdateOne(ctx, bson.D{{Key: "_id", Value: normalized.ID},
		{Key: "organization_id", Value: normalized.OrganizationID}, {Key: "project_id", Value: normalized.ProjectID},
		{Key: "application_id", Value: normalized.ApplicationID}, {Key: "environment_id", Value: normalized.EnvironmentID},
		{Key: "runtime_target_id", Value: normalized.RuntimeTargetID}, {Key: "version", Value: expectedVersion}},
		routeUpdate(normalized))
	if mongo.IsDuplicateKeyError(err) {
		return biz.ApplicationRoute{}, biz.ErrRouteConflict
	}
	if err != nil {
		return biz.ApplicationRoute{}, fmt.Errorf("save application route: %w", err)
	}
	if result.MatchedCount != 1 {
		return biz.ApplicationRoute{}, biz.ErrRouteConflict
	}
	return normalized, nil
}

func routeUpdate(item biz.ApplicationRoute) bson.D {
	set := bson.D{{Key: "hostname", Value: item.Hostname}, {Key: "port_name", Value: item.PortName},
		{Key: "tls_mode", Value: item.TLSMode}, {Key: "status", Value: item.Status},
		{Key: "revision", Value: item.Revision}, {Key: "version", Value: item.Version},
		{Key: "updated_by", Value: item.UpdatedBy}, {Key: "updated_at", Value: item.UpdatedAt}}
	update := bson.D{{Key: "$set", Value: set}}
	if item.Observation == nil {
		return append(update, bson.E{Key: "$unset", Value: bson.D{{Key: "observation", Value: ""}}})
	}
	set = append(set, bson.E{Key: "observation", Value: observationDocumentFromDomain(item.Observation)})
	update[0].Value = set
	return update
}

var _ biz.Repository = (*MongoRepository)(nil)
