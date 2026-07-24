package data

import (
	"context"
	"fmt"
	"time"

	"github.com/owndock/owndock/internal/modules/deployment/biz"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// MongoRepository is the persistence boundary for formal deployments. Worker
// lease updates always include the expected version to prevent stale workers.
type MongoRepository struct{ deployments *mongo.Collection }

func NewMongoRepository(database *mongo.Database) *MongoRepository {
	return &MongoRepository{deployments: database.Collection("deployments")}
}

func (r *MongoRepository) List(ctx context.Context, applicationID, environmentID string) ([]biz.Deployment, error) {
	filter := bson.D{}
	if applicationID != "" {
		filter = append(filter, bson.E{Key: "application_id", Value: applicationID})
	}
	if environmentID != "" {
		filter = append(filter, bson.E{Key: "environment_id", Value: environmentID})
	}
	cursor, err := r.deployments.Find(ctx, filter, options.Find().SetSort(bson.D{{Key: "created_at", Value: 1}}))
	if err != nil {
		return nil, fmt.Errorf("find deployments: %w", err)
	}
	defer cursor.Close(ctx)
	var docs []deploymentDocument
	if err := cursor.All(ctx, &docs); err != nil {
		return nil, fmt.Errorf("decode deployments: %w", err)
	}
	items := make([]biz.Deployment, len(docs))
	for i := range docs {
		items[i] = docs[i].domain()
	}
	return items, nil
}

func (r *MongoRepository) GetByIdempotency(ctx context.Context, key string) (biz.Deployment, error) {
	var doc deploymentDocument
	err := r.deployments.FindOne(ctx, bson.D{{Key: "idempotency_key", Value: key}}).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return biz.Deployment{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.Deployment{}, fmt.Errorf("find deployment idempotency: %w", err)
	}
	return doc.domain(), nil
}

func (r *MongoRepository) Create(ctx context.Context, item biz.Deployment) (biz.Deployment, error) {
	_, err := r.deployments.InsertOne(ctx, deploymentDocumentFromDomain(item))
	if mongo.IsDuplicateKeyError(err) {
		return biz.Deployment{}, biz.ErrDuplicateIdempotency
	}
	if err != nil {
		return biz.Deployment{}, fmt.Errorf("insert deployment: %w", err)
	}
	return item, nil
}

func (r *MongoRepository) ClaimNext(ctx context.Context, claim biz.Claim) (biz.Deployment, bool, error) {
	if err := claim.Validate(); err != nil {
		return biz.Deployment{}, false, err
	}
	lease := bson.D{{Key: "owner", Value: claim.WorkerID}, {Key: "expires_at", Value: claim.ExpiresAt.UTC()}}
	base := bson.D{{Key: "$or", Value: bson.A{bson.D{{Key: "lease.expires_at", Value: bson.D{{Key: "$lte", Value: claim.Now}}}}, bson.D{{Key: "lease.expires_at", Value: bson.D{{Key: "$exists", Value: false}}}}}}}
	var doc deploymentDocument
	queuedUpdate := bson.D{{Key: "$set", Value: bson.D{{Key: "status", Value: string(biz.StatusBuilding)}, {Key: "lease", Value: lease}, {Key: "updated_at", Value: claim.Now.UTC()}}}, {Key: "$inc", Value: bson.D{{Key: "version", Value: 1}}}}
	result := r.deployments.FindOneAndUpdate(ctx, append(base, bson.E{Key: "status", Value: string(biz.StatusQueued)}), queuedUpdate, options.FindOneAndUpdate().SetSort(bson.D{{Key: "created_at", Value: 1}}).SetReturnDocument(options.After))
	err := result.Decode(&doc)
	if err == nil {
		return doc.domain(), true, nil
	}
	if err != mongo.ErrNoDocuments {
		return biz.Deployment{}, false, err
	}
	reclaimUpdate := bson.D{{Key: "$set", Value: bson.D{{Key: "lease", Value: lease}, {Key: "updated_at", Value: claim.Now.UTC()}}}, {Key: "$inc", Value: bson.D{{Key: "version", Value: 1}}}}
	result = r.deployments.FindOneAndUpdate(ctx, append(base, bson.E{Key: "status", Value: bson.D{{Key: "$in", Value: []string{string(biz.StatusBuilding), string(biz.StatusDeploying)}}}}), reclaimUpdate, options.FindOneAndUpdate().SetSort(bson.D{{Key: "created_at", Value: 1}}).SetReturnDocument(options.After))
	if err := result.Decode(&doc); err == mongo.ErrNoDocuments {
		return biz.Deployment{}, false, nil
	} else if err != nil {
		return biz.Deployment{}, false, err
	}
	return doc.domain(), true, nil
}

func (r *MongoRepository) SaveClaimed(ctx context.Context, item biz.Deployment, expectedVersion uint64, workerID string, now time.Time) (biz.Deployment, error) {
	if item.Lease.Owner != workerID || !item.Lease.Active(now) {
		return biz.Deployment{}, biz.ErrLeaseExpired
	}
	item.Version = expectedVersion + 1
	result, err := r.deployments.ReplaceOne(ctx, bson.D{{Key: "_id", Value: item.ID}, {Key: "version", Value: expectedVersion}, {Key: "lease.owner", Value: workerID}}, deploymentDocumentFromDomain(item))
	if err != nil {
		return biz.Deployment{}, err
	}
	if result.ModifiedCount != 1 {
		return biz.Deployment{}, biz.ErrConflict
	}
	return item, nil
}

// RenewLease extends a live worker lease only when owner and version still
// match. A stale worker therefore cannot keep a reclaimed deployment alive.
func (r *MongoRepository) RenewLease(ctx context.Context, deploymentID, workerID string, expectedVersion uint64, now, expiresAt time.Time) error {
	if workerID == "" || !expiresAt.After(now) {
		return biz.ErrInvalidLease
	}
	result, err := r.deployments.UpdateOne(ctx, bson.D{{Key: "_id", Value: deploymentID}, {Key: "version", Value: expectedVersion}, {Key: "lease.owner", Value: workerID}, {Key: "lease.expires_at", Value: bson.D{{Key: "$gt", Value: now}}}}, bson.D{{Key: "$set", Value: bson.D{{Key: "lease.expires_at", Value: expiresAt.UTC()}, {Key: "updated_at", Value: now.UTC()}}}, {Key: "$inc", Value: bson.D{{Key: "version", Value: 1}}}})
	if err != nil {
		return err
	}
	if result.ModifiedCount != 1 {
		return biz.ErrConflict
	}
	return nil
}

type deploymentDocument struct {
	ID              string                  `bson:"_id"`
	ReleaseID       string                  `bson:"release_id"`
	ApplicationID   string                  `bson:"application_id"`
	EnvironmentID   string                  `bson:"environment_id"`
	RuntimeTargetID string                  `bson:"runtime_target_id"`
	IdempotencyKey  string                  `bson:"idempotency_key"`
	Revision        string                  `bson:"revision"`
	Status          string                  `bson:"status"`
	CreatedAt       time.Time               `bson:"created_at"`
	UpdatedAt       time.Time               `bson:"updated_at"`
	Version         uint64                  `bson:"version"`
	Lease           deploymentLeaseDocument `bson:"lease"`
}
type deploymentLeaseDocument struct {
	Owner     string    `bson:"owner,omitempty"`
	ExpiresAt time.Time `bson:"expires_at,omitempty"`
}

func deploymentDocumentFromDomain(d biz.Deployment) deploymentDocument {
	return deploymentDocument{d.ID, d.ReleaseID, d.ApplicationID, d.EnvironmentID, d.RuntimeTargetID, d.IdempotencyKey, d.Revision, string(d.Status), d.CreatedAt, d.UpdatedAt, d.Version, deploymentLeaseDocument{d.Lease.Owner, d.Lease.ExpiresAt}}
}
func (d deploymentDocument) domain() biz.Deployment {
	return biz.Deployment{ID: d.ID, ReleaseID: d.ReleaseID, ApplicationID: d.ApplicationID, EnvironmentID: d.EnvironmentID, RuntimeTargetID: d.RuntimeTargetID, IdempotencyKey: d.IdempotencyKey, Revision: d.Revision, Status: biz.Status(d.Status), CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt, Version: d.Version, Lease: biz.Lease{Owner: d.Lease.Owner, ExpiresAt: d.Lease.ExpiresAt}}
}
