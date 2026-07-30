package data

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/owndock/owndock/internal/modules/deployment/biz"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// MongoRepository is the persistence boundary for formal deployments. Worker
// lease updates always include the expected version to prevent stale workers.
type MongoRepository struct {
	deployments      *mongo.Collection
	cutoverSequences *mongo.Collection
}

func NewMongoRepository(database *mongo.Database) *MongoRepository {
	return &MongoRepository{
		deployments:      database.Collection("deployments"),
		cutoverSequences: database.Collection("deployment_cutover_sequences"),
	}
}

func (r *MongoRepository) List(ctx context.Context, projectID, applicationID, environmentID string) ([]biz.Deployment, error) {
	filter := bson.D{{Key: "project_id", Value: projectID}}
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

func (r *MongoRepository) GetByIdempotency(ctx context.Context, projectID, key string) (biz.Deployment, error) {
	var doc deploymentDocument
	err := r.deployments.FindOne(ctx, bson.D{{Key: "project_id", Value: projectID}, {Key: "idempotency_key", Value: key}}).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return biz.Deployment{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.Deployment{}, fmt.Errorf("find deployment idempotency: %w", err)
	}
	return doc.domain(), nil
}

func (r *MongoRepository) Get(ctx context.Context, projectID, deploymentID string) (biz.Deployment, error) {
	var doc deploymentDocument
	err := r.deployments.FindOne(ctx, bson.D{
		{Key: "_id", Value: deploymentID},
		{Key: "project_id", Value: projectID},
	}).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return biz.Deployment{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.Deployment{}, fmt.Errorf("find deployment: %w", err)
	}
	return doc.domain(), nil
}

func (r *MongoRepository) HasSucceeded(
	ctx context.Context,
	projectID, releaseID, applicationID, environmentID, runtimeTargetID string,
) (bool, error) {
	err := r.deployments.FindOne(
		ctx,
		bson.D{
			{Key: "project_id", Value: projectID},
			{Key: "application_id", Value: applicationID},
			{Key: "environment_id", Value: environmentID},
			{Key: "runtime_target_id", Value: runtimeTargetID},
			{Key: "release_id", Value: releaseID},
			{Key: "status", Value: string(biz.StatusSucceeded)},
		},
		options.FindOne().SetProjection(bson.D{{Key: "_id", Value: 1}}),
	).Err()
	if err == mongo.ErrNoDocuments {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("find successful deployment: %w", err)
	}
	return true, nil
}

func (r *MongoRepository) Create(ctx context.Context, item biz.Deployment) (biz.Deployment, error) {
	if mongo.SessionFromContext(ctx) != nil {
		return r.createWithinTransaction(ctx, item)
	}
	session, err := r.deployments.Database().Client().StartSession()
	if err != nil {
		return biz.Deployment{}, fmt.Errorf(
			"start deployment creation transaction: %w",
			err,
		)
	}
	defer session.EndSession(ctx)
	var created biz.Deployment
	_, err = session.WithTransaction(
		ctx,
		func(transactionContext context.Context) (any, error) {
			var createErr error
			created, createErr = r.createWithinTransaction(
				transactionContext,
				item,
			)
			return nil, createErr
		},
	)
	if err != nil {
		return biz.Deployment{}, err
	}
	return created, nil
}

func (r *MongoRepository) createWithinTransaction(
	ctx context.Context,
	item biz.Deployment,
) (biz.Deployment, error) {
	sequence, err := r.nextCutoverSequence(ctx, item)
	if err != nil {
		return biz.Deployment{}, err
	}
	item.CutoverSequence = sequence
	_, err = r.deployments.InsertOne(ctx, deploymentDocumentFromDomain(item))
	if mongo.IsDuplicateKeyError(err) {
		var serverError mongo.ServerError
		if errors.As(err, &serverError) && serverError.HasErrorMessage("uniq_deployment_idempotency") {
			return biz.Deployment{}, biz.ErrDuplicateIdempotency
		}
		return biz.Deployment{}, biz.ErrConflict
	}
	if err != nil {
		return biz.Deployment{}, fmt.Errorf("insert deployment: %w", err)
	}
	return item, nil
}

func (r *MongoRepository) nextCutoverSequence(
	ctx context.Context,
	item biz.Deployment,
) (uint64, error) {
	scopeHash := sha256.Sum256([]byte(item.CutoverScope()))
	var counter struct {
		Sequence uint64 `bson:"sequence"`
	}
	result := r.cutoverSequences.FindOneAndUpdate(
		ctx,
		bson.D{{Key: "_id", Value: fmt.Sprintf("%x", scopeHash[:])}},
		bson.D{
			{Key: "$inc", Value: bson.D{{Key: "sequence", Value: 1}}},
			{Key: "$setOnInsert", Value: bson.D{
				{Key: "project_id", Value: item.ProjectID},
				{Key: "application_id", Value: item.ApplicationID},
				{Key: "environment_id", Value: item.EnvironmentID},
				{Key: "runtime_target_id", Value: item.RuntimeTargetID},
			}},
		},
		options.FindOneAndUpdate().
			SetUpsert(true).
			SetReturnDocument(options.After),
	)
	if err := result.Decode(&counter); err != nil {
		return 0, fmt.Errorf("allocate deployment cutover sequence: %w", err)
	}
	if counter.Sequence == 0 {
		return 0, fmt.Errorf("allocate deployment cutover sequence: zero sequence")
	}
	return counter.Sequence, nil
}

func (r *MongoRepository) Save(ctx context.Context, item biz.Deployment, expectedVersion uint64) (biz.Deployment, error) {
	item.Version = expectedVersion + 1
	result, err := r.deployments.ReplaceOne(ctx, bson.D{
		{Key: "_id", Value: item.ID},
		{Key: "project_id", Value: item.ProjectID},
		{Key: "version", Value: expectedVersion},
	}, deploymentDocumentFromDomain(item))
	if err != nil {
		return biz.Deployment{}, fmt.Errorf("save deployment: %w", err)
	}
	if result.ModifiedCount != 1 {
		if _, findErr := r.Get(ctx, item.ProjectID, item.ID); errors.Is(findErr, biz.ErrNotFound) {
			return biz.Deployment{}, biz.ErrNotFound
		}
		return biz.Deployment{}, biz.ErrConflict
	}
	return item, nil
}

func (r *MongoRepository) ClaimNext(ctx context.Context, claim biz.Claim) (biz.Deployment, bool, error) {
	if err := claim.Validate(); err != nil {
		return biz.Deployment{}, false, err
	}
	base := bson.D{{Key: "$or", Value: bson.A{bson.D{{Key: "lease.expires_at", Value: bson.D{{Key: "$lte", Value: claim.Now}}}}, bson.D{{Key: "lease.expires_at", Value: bson.D{{Key: "$exists", Value: false}}}}}}}
	var doc deploymentDocument
	claimUpdate := bson.D{
		{Key: "$set", Value: bson.D{
			{Key: "lease.owner", Value: claim.WorkerID},
			{Key: "lease.expires_at", Value: claim.ExpiresAt.UTC()},
			{Key: "updated_at", Value: claim.Now.UTC()},
		}},
		{Key: "$inc", Value: bson.D{
			{Key: "lease.generation", Value: 1},
			{Key: "version", Value: 1},
		}},
	}
	result := r.deployments.FindOneAndUpdate(ctx, append(base, bson.E{Key: "status", Value: string(biz.StatusQueued)}), claimUpdate, options.FindOneAndUpdate().SetSort(bson.D{{Key: "created_at", Value: 1}}).SetReturnDocument(options.After))
	err := result.Decode(&doc)
	if err == nil {
		return doc.domain(), true, nil
	}
	if err != mongo.ErrNoDocuments {
		return biz.Deployment{}, false, err
	}
	result = r.deployments.FindOneAndUpdate(ctx, append(base, bson.E{Key: "status", Value: bson.D{{Key: "$in", Value: []string{string(biz.StatusPreparing), string(biz.StatusDeploying)}}}}), claimUpdate, options.FindOneAndUpdate().SetSort(bson.D{{Key: "created_at", Value: 1}}).SetReturnDocument(options.After))
	if err := result.Decode(&doc); err == mongo.ErrNoDocuments {
		result = r.deployments.FindOneAndUpdate(
			ctx,
			append(base, bson.E{Key: "status", Value: string(biz.StatusCanceling)}),
			claimUpdate,
			options.FindOneAndUpdate().SetSort(bson.D{{Key: "created_at", Value: 1}}).SetReturnDocument(options.After),
		)
		if cancelErr := result.Decode(&doc); cancelErr == mongo.ErrNoDocuments {
			return biz.Deployment{}, false, nil
		} else if cancelErr != nil {
			return biz.Deployment{}, false, cancelErr
		}
		return doc.domain(), true, nil
	} else if err != nil {
		return biz.Deployment{}, false, err
	}
	return doc.domain(), true, nil
}

func (r *MongoRepository) SaveClaimed(ctx context.Context, item biz.Deployment, expectedVersion uint64, workerID string, now time.Time) (biz.Deployment, error) {
	if !item.Terminal() && (item.Lease.Owner != workerID || !item.Lease.Active(now)) {
		return biz.Deployment{}, biz.ErrLeaseExpired
	}
	item.Version = expectedVersion + 1
	result, err := r.deployments.ReplaceOne(ctx, bson.D{
		{Key: "_id", Value: item.ID},
		{Key: "version", Value: expectedVersion},
		{Key: "lease.owner", Value: workerID},
		{Key: "lease.expires_at", Value: bson.D{{Key: "$gt", Value: now}}},
	}, deploymentDocumentFromDomain(item))
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
func (r *MongoRepository) RenewLease(ctx context.Context, deploymentID, workerID string, expectedVersion uint64, now, expiresAt time.Time) (biz.Deployment, error) {
	if workerID == "" || !expiresAt.After(now) {
		return biz.Deployment{}, biz.ErrInvalidLease
	}
	var document deploymentDocument
	result := r.deployments.FindOneAndUpdate(
		ctx,
		bson.D{{Key: "_id", Value: deploymentID}, {Key: "version", Value: expectedVersion}, {Key: "lease.owner", Value: workerID}, {Key: "lease.expires_at", Value: bson.D{{Key: "$gt", Value: now}}}},
		bson.D{{Key: "$set", Value: bson.D{{Key: "lease.expires_at", Value: expiresAt.UTC()}, {Key: "updated_at", Value: now.UTC()}}}, {Key: "$inc", Value: bson.D{{Key: "version", Value: 1}}}},
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	)
	if err := result.Decode(&document); err == mongo.ErrNoDocuments {
		return biz.Deployment{}, biz.ErrConflict
	} else if err != nil {
		return biz.Deployment{}, err
	}
	return document.domain(), nil
}

func (r *MongoRepository) ValidateFence(
	ctx context.Context,
	projectID, deploymentID, workerID string,
	generation uint64,
	now time.Time,
) error {
	if projectID == "" || deploymentID == "" || workerID == "" || generation == 0 || now.IsZero() {
		return biz.ErrStaleExecution
	}
	var deployment struct {
		ProjectID       string `bson:"project_id"`
		ApplicationID   string `bson:"application_id"`
		EnvironmentID   string `bson:"environment_id"`
		RuntimeTargetID string `bson:"runtime_target_id"`
		CutoverSequence uint64 `bson:"cutover_sequence"`
	}
	err := r.deployments.FindOne(ctx, bson.D{
		{Key: "_id", Value: deploymentID},
		{Key: "project_id", Value: projectID},
		{Key: "lease.owner", Value: workerID},
		{Key: "lease.generation", Value: generation},
		{Key: "lease.expires_at", Value: bson.D{{Key: "$gt", Value: now.UTC()}}},
		{Key: "status", Value: bson.D{{Key: "$in", Value: bson.A{
			string(biz.StatusPreparing), string(biz.StatusDeploying), string(biz.StatusCanceling),
		}}}},
	}, options.FindOne().SetProjection(bson.D{
		{Key: "project_id", Value: 1},
		{Key: "application_id", Value: 1},
		{Key: "environment_id", Value: 1},
		{Key: "runtime_target_id", Value: 1},
		{Key: "cutover_sequence", Value: 1},
	})).Decode(&deployment)
	if err == mongo.ErrNoDocuments {
		return biz.ErrStaleExecution
	}
	if err != nil {
		return fmt.Errorf("validate deployment fence: %w", err)
	}
	scope := deployment.ProjectID + "\x00" + deployment.ApplicationID + "\x00" +
		deployment.EnvironmentID + "\x00" + deployment.RuntimeTargetID
	scopeHash := sha256.Sum256([]byte(scope))
	var counter struct {
		Sequence uint64 `bson:"sequence"`
	}
	err = r.cutoverSequences.FindOne(
		ctx,
		bson.D{{Key: "_id", Value: fmt.Sprintf("%x", scopeHash[:])}},
		options.FindOne().SetProjection(bson.D{{Key: "sequence", Value: 1}}),
	).Decode(&counter)
	if err == mongo.ErrNoDocuments {
		return biz.ErrStaleExecution
	}
	if err != nil {
		return fmt.Errorf("validate deployment cutover sequence: %w", err)
	}
	if counter.Sequence != deployment.CutoverSequence {
		return biz.ErrStaleExecution
	}
	return nil
}

type deploymentDocument struct {
	ID                 string                  `bson:"_id"`
	OrganizationID     string                  `bson:"organization_id,omitempty"`
	ProjectID          string                  `bson:"project_id"`
	ReleaseID          string                  `bson:"release_id"`
	ApplicationID      string                  `bson:"application_id"`
	EnvironmentID      string                  `bson:"environment_id"`
	RuntimeTargetID    string                  `bson:"runtime_target_id"`
	IdempotencyKey     string                  `bson:"idempotency_key"`
	Operation          string                  `bson:"operation"`
	SourceDeploymentID string                  `bson:"source_deployment_id,omitempty"`
	Revision           string                  `bson:"revision"`
	Status             string                  `bson:"status"`
	FailureCategory    string                  `bson:"failure_category,omitempty"`
	CutoverSequence    uint64                  `bson:"cutover_sequence,omitempty"`
	CreatedAt          time.Time               `bson:"created_at"`
	UpdatedAt          time.Time               `bson:"updated_at"`
	Version            uint64                  `bson:"version"`
	Lease              deploymentLeaseDocument `bson:"lease"`
}
type deploymentLeaseDocument struct {
	Owner      string    `bson:"owner,omitempty"`
	ExpiresAt  time.Time `bson:"expires_at,omitempty"`
	Generation uint64    `bson:"generation,omitempty"`
}

func deploymentDocumentFromDomain(d biz.Deployment) deploymentDocument {
	return deploymentDocument{
		ID: d.ID, OrganizationID: d.OrganizationID, ProjectID: d.ProjectID, ReleaseID: d.ReleaseID,
		ApplicationID: d.ApplicationID, EnvironmentID: d.EnvironmentID,
		RuntimeTargetID: d.RuntimeTargetID, IdempotencyKey: d.IdempotencyKey,
		Operation: string(d.Operation), SourceDeploymentID: d.SourceDeploymentID,
		Revision: d.Revision, Status: string(d.Status), FailureCategory: string(d.FailureCategory),
		CutoverSequence: d.CutoverSequence, CreatedAt: d.CreatedAt,
		UpdatedAt: d.UpdatedAt, Version: d.Version,
		Lease: deploymentLeaseDocument{
			Owner: d.Lease.Owner, ExpiresAt: d.Lease.ExpiresAt,
			Generation: d.Lease.Generation,
		},
	}
}
func (d deploymentDocument) domain() biz.Deployment {
	operation := biz.Operation(d.Operation)
	if operation == "" {
		operation = biz.OperationDeploy
	}
	return biz.Deployment{
		ID: d.ID, OrganizationID: d.OrganizationID, ProjectID: d.ProjectID, ReleaseID: d.ReleaseID,
		ApplicationID: d.ApplicationID, EnvironmentID: d.EnvironmentID,
		RuntimeTargetID: d.RuntimeTargetID, IdempotencyKey: d.IdempotencyKey,
		Operation: operation, SourceDeploymentID: d.SourceDeploymentID,
		Revision: d.Revision, Status: biz.Status(d.Status), FailureCategory: biz.FailureCategory(d.FailureCategory),
		CutoverSequence: d.CutoverSequence, CreatedAt: d.CreatedAt,
		UpdatedAt: d.UpdatedAt, Version: d.Version,
		Lease: biz.Lease{
			Owner: d.Lease.Owner, ExpiresAt: d.Lease.ExpiresAt,
			Generation: d.Lease.Generation,
		},
	}
}
