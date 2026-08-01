package data

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/owndock/owndock/internal/modules/build/biz"
	"github.com/owndock/owndock/internal/shared/runtimespec"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type MongoRepository struct {
	credentials    *mongo.Collection
	sources        *mongo.Collection
	configurations *mongo.Collection
	builds         *mongo.Collection
	artifacts      *mongo.Collection
	triggers       *mongo.Collection
	triggerRates   *mongo.Collection
	hooks          *mongo.Collection
	deliveries     *mongo.Collection
	logStreams     *mongo.Collection
	logChunks      *mongo.Collection
	logRetention   time.Duration
	logMaxBytes    int64
	logChunkBytes  int
}

func NewMongoRepository(database *mongo.Database) *MongoRepository {
	return &MongoRepository{
		credentials:    database.Collection("repository_credentials"),
		sources:        database.Collection("source_repositories"),
		configurations: database.Collection("build_configurations"),
		builds:         database.Collection("builds"),
		artifacts:      database.Collection("artifacts"),
		triggers:       database.Collection("build_triggers"),
		triggerRates:   database.Collection("build_trigger_rate_limits"),
		hooks:          database.Collection("build_hooks"),
		deliveries:     database.Collection("webhook_deliveries"),
		logStreams:     database.Collection("build_log_streams"),
		logChunks:      database.Collection("build_log_chunks"),
		logRetention:   biz.DefaultBuildLogRetention,
		logMaxBytes:    biz.DefaultBuildLogMaxBytes,
		logChunkBytes:  biz.DefaultBuildLogChunkBytes,
	}
}

func (r *MongoRepository) WithBuildLogLimits(retention time.Duration, maximumBytes int64, chunkBytes int) *MongoRepository {
	if retention > 0 {
		r.logRetention = retention
	}
	if maximumBytes > 0 {
		r.logMaxBytes = maximumBytes
	}
	if chunkBytes > 0 {
		r.logChunkBytes = chunkBytes
	}
	return r
}

func (r *MongoRepository) AppendBuildLog(ctx context.Context, item biz.BuildLogAppend) error {
	if err := item.Validate(); err != nil {
		return err
	}
	message := normalizeBuildLogMessage(item.Message)
	if message == "" {
		return biz.ErrInvalidBuildLog
	}
	var stream buildLogStreamDocument
	err := r.logStreams.FindOneAndUpdate(ctx,
		bson.D{{Key: "_id", Value: item.BuildID}, {Key: "project_id", Value: item.ProjectID}},
		bson.D{{Key: "$setOnInsert", Value: bson.D{
			{Key: "project_id", Value: item.ProjectID}, {Key: "next_sequence", Value: int64(0)},
			{Key: "total_bytes", Value: int64(0)}, {Key: "truncated", Value: false},
			{Key: "created_at", Value: item.CreatedAt.UTC()},
			{Key: "expires_at", Value: item.CreatedAt.UTC().Add(r.logRetention)},
		}}}, options.FindOneAndUpdate().SetUpsert(true).SetReturnDocument(options.After),
	).Decode(&stream)
	if mongo.IsDuplicateKeyError(err) {
		return biz.ErrInvalidBuildLog
	}
	if err != nil {
		return fmt.Errorf("initialize build log stream: %w", err)
	}
	for _, chunk := range splitBuildLogMessage(message, r.logChunkBytes) {
		appended, appendErr := r.appendBuildLogChunk(ctx, item, chunk, stream.ExpiresAt)
		if appendErr != nil {
			return appendErr
		}
		if !appended {
			return nil
		}
	}
	return nil
}

func (r *MongoRepository) appendBuildLogChunk(ctx context.Context, item biz.BuildLogAppend,
	message string, expiresAt time.Time) (bool, error) {
	if mongo.SessionFromContext(ctx) != nil {
		return r.appendBuildLogChunkTransaction(ctx, item, message, expiresAt)
	}
	session, err := r.logStreams.Database().Client().StartSession()
	if err != nil {
		return false, fmt.Errorf("start build log append transaction: %w", err)
	}
	defer session.EndSession(ctx)
	var appended bool
	_, err = session.WithTransaction(ctx, func(transactionContext context.Context) (any, error) {
		var transactionErr error
		appended, transactionErr = r.appendBuildLogChunkTransaction(transactionContext, item, message, expiresAt)
		return nil, transactionErr
	})
	return appended, err
}

func (r *MongoRepository) appendBuildLogChunkTransaction(ctx context.Context, item biz.BuildLogAppend,
	message string, expiresAt time.Time) (bool, error) {
	messageBytes := int64(len([]byte(message)))
	var stream buildLogStreamDocument
	err := r.logStreams.FindOneAndUpdate(ctx, bson.D{
		{Key: "_id", Value: item.BuildID}, {Key: "project_id", Value: item.ProjectID},
		{Key: "truncated", Value: false},
		{Key: "total_bytes", Value: bson.D{{Key: "$lte", Value: r.logMaxBytes - messageBytes}}},
	}, bson.D{
		{Key: "$inc", Value: bson.D{{Key: "next_sequence", Value: 1}, {Key: "total_bytes", Value: messageBytes}}},
		{Key: "$max", Value: bson.D{{Key: "expires_at", Value: expiresAt}}},
		{Key: "$set", Value: bson.D{{Key: "updated_at", Value: item.CreatedAt.UTC()}}},
	}, options.FindOneAndUpdate().SetReturnDocument(options.After)).Decode(&stream)
	if errors.Is(err, mongo.ErrNoDocuments) {
		_, updateErr := r.logStreams.UpdateOne(ctx,
			bson.D{{Key: "_id", Value: item.BuildID}, {Key: "project_id", Value: item.ProjectID}},
			bson.D{{Key: "$set", Value: bson.D{{Key: "truncated", Value: true},
				{Key: "updated_at", Value: item.CreatedAt.UTC()}}},
				{Key: "$max", Value: bson.D{{Key: "expires_at", Value: expiresAt}}}},
		)
		if updateErr != nil {
			return false, fmt.Errorf("truncate build log stream: %w", updateErr)
		}
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reserve build log sequence: %w", err)
	}
	document := buildLogChunkDocument{
		ID:      fmt.Sprintf("%s:%020d", item.BuildID, stream.NextSequence),
		BuildID: item.BuildID, ProjectID: item.ProjectID, Sequence: stream.NextSequence,
		Stage: item.Stage, Message: message, CreatedAt: item.CreatedAt.UTC(), ExpiresAt: expiresAt,
	}
	if _, err := r.logChunks.InsertOne(ctx, document); err != nil {
		return false, fmt.Errorf("insert build log chunk: %w", err)
	}
	return true, nil
}

func (r *MongoRepository) ReadBuildLogs(ctx context.Context, projectID, buildID string,
	query biz.BuildLogQuery) (biz.BuildLogPage, error) {
	query, err := query.Normalize()
	if err != nil {
		return biz.BuildLogPage{}, err
	}
	var stream buildLogStreamDocument
	err = r.logStreams.FindOne(ctx, bson.D{{Key: "_id", Value: buildID}, {Key: "project_id", Value: projectID}}).Decode(&stream)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return biz.BuildLogPage{Entries: []biz.BuildLogEntry{}, NextSequence: query.AfterSequence}, nil
	}
	if err != nil {
		return biz.BuildLogPage{}, fmt.Errorf("find build log stream: %w", err)
	}
	cursor, err := r.logChunks.Find(ctx, bson.D{
		{Key: "build_id", Value: buildID}, {Key: "project_id", Value: projectID},
		{Key: "sequence", Value: bson.D{{Key: "$gt", Value: query.AfterSequence}}},
	}, options.Find().SetSort(bson.D{{Key: "sequence", Value: 1}}).SetLimit(int64(query.Limit)))
	if err != nil {
		return biz.BuildLogPage{}, fmt.Errorf("find build log chunks: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()
	var documents []buildLogChunkDocument
	if err := cursor.All(ctx, &documents); err != nil {
		return biz.BuildLogPage{}, fmt.Errorf("decode build log chunks: %w", err)
	}
	entries := make([]biz.BuildLogEntry, len(documents))
	nextSequence := query.AfterSequence
	for index, document := range documents {
		entries[index] = document.domain()
		nextSequence = document.Sequence
	}
	return biz.BuildLogPage{
		Entries: entries, NextSequence: nextSequence,
		Truncated: stream.Truncated, ExpiresAt: stream.ExpiresAt,
	}, nil
}

func (r *MongoRepository) ListBuildHooks(ctx context.Context, projectID, applicationID, configurationID string) ([]biz.BuildHookSummary, error) {
	cursor, err := r.hooks.Find(ctx, bson.D{
		{Key: "project_id", Value: projectID}, {Key: "application_id", Value: applicationID},
		{Key: "build_configuration_id", Value: configurationID},
	}, options.Find().SetProjection(bson.D{{Key: "secret_ref", Value: 0}}).
		SetSort(bson.D{{Key: "created_at", Value: 1}, {Key: "_id", Value: 1}}))
	if err != nil {
		return nil, fmt.Errorf("find build hooks: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()
	var documents []buildHookSummaryDocument
	if err := cursor.All(ctx, &documents); err != nil {
		return nil, fmt.Errorf("decode build hooks: %w", err)
	}
	items := make([]biz.BuildHookSummary, len(documents))
	for index, document := range documents {
		items[index] = document.domain()
	}
	return items, nil
}

func (r *MongoRepository) CreateBuildHook(ctx context.Context, item biz.BuildHook) (biz.BuildHookSummary, error) {
	_, err := r.hooks.InsertOne(ctx, buildHookDocumentFromDomain(item))
	if mongo.IsDuplicateKeyError(err) {
		var serverError mongo.ServerError
		if errors.As(err, &serverError) && serverError.HasErrorMessage("uniq_build_hook_project_name") {
			return biz.BuildHookSummary{}, biz.ErrDuplicateName
		}
		return biz.BuildHookSummary{}, fmt.Errorf("insert build hook duplicate key: %w", err)
	}
	if err != nil {
		return biz.BuildHookSummary{}, fmt.Errorf("insert build hook: %w", err)
	}
	return item.Summary(), nil
}

func (r *MongoRepository) GetBuildHook(ctx context.Context, hookID string) (biz.BuildHook, error) {
	var document buildHookDocument
	err := r.hooks.FindOne(ctx, bson.D{{Key: "_id", Value: hookID}}).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return biz.BuildHook{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.BuildHook{}, fmt.Errorf("find build hook: %w", err)
	}
	return document.domain(), nil
}

func (r *MongoRepository) RevokeBuildHook(ctx context.Context, item biz.BuildHook, expectedVersion uint64) (biz.BuildHookSummary, error) {
	var document buildHookDocument
	err := r.hooks.FindOneAndReplace(ctx, bson.D{
		{Key: "_id", Value: item.ID}, {Key: "version", Value: expectedVersion},
		{Key: "status", Value: biz.BuildHookStatusActive},
	}, buildHookDocumentFromDomain(item), options.FindOneAndReplace().SetReturnDocument(options.After)).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return biz.BuildHookSummary{}, biz.ErrVersionConflict
	}
	if err != nil {
		return biz.BuildHookSummary{}, fmt.Errorf("revoke build hook: %w", err)
	}
	return document.domain().Summary(), nil
}

func (r *MongoRepository) CreateWebhookDelivery(ctx context.Context, item biz.WebhookDelivery) error {
	_, err := r.deliveries.InsertOne(ctx, webhookDeliveryDocumentFromDomain(item))
	if mongo.IsDuplicateKeyError(err) {
		return biz.ErrDuplicateWebhookDelivery
	}
	if err != nil {
		return fmt.Errorf("insert webhook delivery: %w", err)
	}
	return nil
}

func (r *MongoRepository) GetWebhookDelivery(ctx context.Context, hookID string, provider biz.WebhookProvider, deliveryID string) (biz.WebhookDelivery, error) {
	var document webhookDeliveryDocument
	err := r.deliveries.FindOne(ctx, bson.D{
		{Key: "hook_id", Value: hookID}, {Key: "provider", Value: provider},
		{Key: "delivery_id", Value: deliveryID},
	}).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return biz.WebhookDelivery{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.WebhookDelivery{}, fmt.Errorf("find webhook delivery: %w", err)
	}
	return document.domain(), nil
}

func (r *MongoRepository) ListBuildTriggers(
	ctx context.Context,
	projectID, applicationID, configurationID string,
) ([]biz.BuildTrigger, error) {
	cursor, err := r.triggers.Find(ctx, bson.D{
		{Key: "project_id", Value: projectID},
		{Key: "application_id", Value: applicationID},
		{Key: "build_configuration_id", Value: configurationID},
	}, options.Find().SetProjection(bson.D{{Key: "token_hash", Value: 0}}).
		SetSort(bson.D{{Key: "created_at", Value: 1}, {Key: "_id", Value: 1}}))
	if err != nil {
		return nil, fmt.Errorf("find build triggers: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()
	var documents []buildTriggerDocument
	if err := cursor.All(ctx, &documents); err != nil {
		return nil, fmt.Errorf("decode build triggers: %w", err)
	}
	items := make([]biz.BuildTrigger, len(documents))
	for index, document := range documents {
		items[index] = document.domain()
	}
	return items, nil
}

func (r *MongoRepository) CreateBuildTrigger(ctx context.Context, item biz.BuildTrigger) (biz.BuildTrigger, error) {
	_, err := r.triggers.InsertOne(ctx, buildTriggerDocumentFromDomain(item))
	if mongo.IsDuplicateKeyError(err) {
		var serverError mongo.ServerError
		if errors.As(err, &serverError) && serverError.HasErrorMessage("uniq_build_trigger_project_name") {
			return biz.BuildTrigger{}, biz.ErrDuplicateName
		}
		return biz.BuildTrigger{}, fmt.Errorf("insert build trigger duplicate key: %w", err)
	}
	if err != nil {
		return biz.BuildTrigger{}, fmt.Errorf("insert build trigger: %w", err)
	}
	return item, nil
}

func (r *MongoRepository) GetBuildTrigger(ctx context.Context, triggerID string) (biz.BuildTrigger, error) {
	var document buildTriggerDocument
	err := r.triggers.FindOne(ctx, bson.D{{Key: "_id", Value: triggerID}}).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return biz.BuildTrigger{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.BuildTrigger{}, fmt.Errorf("find build trigger: %w", err)
	}
	return document.domain(), nil
}

func (r *MongoRepository) RevokeBuildTrigger(
	ctx context.Context, item biz.BuildTrigger, expectedVersion uint64,
) (biz.BuildTrigger, error) {
	var document buildTriggerDocument
	err := r.triggers.FindOneAndReplace(ctx, bson.D{
		{Key: "_id", Value: item.ID}, {Key: "version", Value: expectedVersion},
		{Key: "status", Value: biz.BuildTriggerStatusActive},
	}, buildTriggerDocumentFromDomain(item), options.FindOneAndReplace().SetReturnDocument(options.After)).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return biz.BuildTrigger{}, biz.ErrVersionConflict
	}
	if err != nil {
		return biz.BuildTrigger{}, fmt.Errorf("revoke build trigger: %w", err)
	}
	return document.domain(), nil
}

func (r *MongoRepository) ListBuilds(
	ctx context.Context,
	projectID string,
) ([]biz.Build, error) {
	cursor, err := r.builds.Find(
		ctx,
		bson.D{{Key: "project_id", Value: projectID}},
		options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}, {Key: "_id", Value: -1}}),
	)
	if err != nil {
		return nil, fmt.Errorf("find builds: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()
	var documents []buildDocument
	if err := cursor.All(ctx, &documents); err != nil {
		return nil, fmt.Errorf("decode builds: %w", err)
	}
	items := make([]biz.Build, len(documents))
	for index, document := range documents {
		items[index] = document.domain()
	}
	return items, nil
}

func (r *MongoRepository) CreateBuild(
	ctx context.Context,
	item biz.Build,
) (biz.Build, error) {
	_, err := r.builds.InsertOne(ctx, buildDocumentFromDomain(item))
	if mongo.IsDuplicateKeyError(err) {
		var serverError mongo.ServerError
		if errors.As(err, &serverError) && serverError.HasErrorMessage("uniq_build_idempotency") {
			return biz.Build{}, biz.ErrDuplicateIdempotency
		}
		return biz.Build{}, fmt.Errorf("insert build duplicate key: %w", err)
	}
	if err != nil {
		return biz.Build{}, fmt.Errorf("insert build: %w", err)
	}
	return item, nil
}

func (r *MongoRepository) SaveBuild(ctx context.Context, item biz.Build, expectedVersion uint64) (biz.Build, error) {
	item.Version = expectedVersion + 1
	result, err := r.builds.ReplaceOne(ctx, bson.D{
		{Key: "_id", Value: item.ID}, {Key: "project_id", Value: item.ProjectID},
		{Key: "version", Value: expectedVersion},
	}, buildDocumentFromDomain(item))
	if err != nil {
		return biz.Build{}, fmt.Errorf("save build: %w", err)
	}
	if result.ModifiedCount != 1 {
		if _, findErr := r.GetBuild(ctx, item.ProjectID, item.ID); errors.Is(findErr, biz.ErrNotFound) {
			return biz.Build{}, biz.ErrNotFound
		}
		return biz.Build{}, biz.ErrVersionConflict
	}
	return item, nil
}

func (r *MongoRepository) ListArtifacts(ctx context.Context, projectID string) ([]biz.Artifact, error) {
	cursor, err := r.artifacts.Find(ctx, bson.D{{Key: "project_id", Value: projectID}},
		options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}, {Key: "_id", Value: -1}}))
	if err != nil {
		return nil, fmt.Errorf("find artifacts: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()
	var documents []artifactDocument
	if err := cursor.All(ctx, &documents); err != nil {
		return nil, fmt.Errorf("decode artifacts: %w", err)
	}
	items := make([]biz.Artifact, len(documents))
	for index, document := range documents {
		items[index] = document.domain()
	}
	return items, nil
}

func (r *MongoRepository) GetArtifact(ctx context.Context, projectID, artifactID string) (biz.Artifact, error) {
	var document artifactDocument
	err := r.artifacts.FindOne(ctx, bson.D{{Key: "_id", Value: artifactID}, {Key: "project_id", Value: projectID}}).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return biz.Artifact{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.Artifact{}, fmt.Errorf("find artifact: %w", err)
	}
	return document.domain(), nil
}

func (r *MongoRepository) GetArtifactByBuild(ctx context.Context, buildID string) (biz.Artifact, error) {
	var document artifactDocument
	err := r.artifacts.FindOne(ctx, bson.D{{Key: "build_id", Value: buildID}}).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return biz.Artifact{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.Artifact{}, fmt.Errorf("find build artifact: %w", err)
	}
	return document.domain(), nil
}

func (r *MongoRepository) CreateArtifact(ctx context.Context, item biz.Artifact) (biz.Artifact, error) {
	_, err := r.artifacts.InsertOne(ctx, artifactDocumentFromDomain(item))
	if mongo.IsDuplicateKeyError(err) {
		return biz.Artifact{}, biz.ErrDuplicateArtifact
	}
	if err != nil {
		return biz.Artifact{}, fmt.Errorf("insert artifact: %w", err)
	}
	return item, nil
}

func (r *MongoRepository) NextPendingArtifact(ctx context.Context) (biz.Artifact, bool, error) {
	var document artifactDocument
	err := r.artifacts.FindOne(ctx, bson.D{{Key: "release_status", Value: biz.ArtifactReleasePending}},
		options.FindOne().SetSort(bson.D{{Key: "created_at", Value: 1}, {Key: "_id", Value: 1}})).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return biz.Artifact{}, false, nil
	}
	if err != nil {
		return biz.Artifact{}, false, fmt.Errorf("find pending artifact release: %w", err)
	}
	return document.domain(), true, nil
}

func (r *MongoRepository) SaveArtifactRelease(ctx context.Context, item biz.Artifact, expectedVersion uint64) (biz.Artifact, error) {
	item.Version = expectedVersion + 1
	result, err := r.artifacts.ReplaceOne(ctx, bson.D{
		{Key: "_id", Value: item.ID}, {Key: "project_id", Value: item.ProjectID},
		{Key: "version", Value: expectedVersion},
	}, artifactDocumentFromDomain(item))
	if err != nil {
		return biz.Artifact{}, fmt.Errorf("save artifact release: %w", err)
	}
	if result.ModifiedCount != 1 {
		return biz.Artifact{}, biz.ErrVersionConflict
	}
	return item, nil
}

func (r *MongoRepository) ClaimNextBuild(ctx context.Context, claim biz.BuildClaim) (biz.Build, bool, error) {
	if err := claim.Validate(); err != nil {
		return biz.Build{}, false, err
	}
	leaseAvailable := bson.D{{Key: "$or", Value: bson.A{
		bson.D{{Key: "lease.expires_at", Value: bson.D{{Key: "$lte", Value: claim.Now.UTC()}}}},
		bson.D{{Key: "lease.expires_at", Value: bson.D{{Key: "$exists", Value: false}}}},
		bson.D{{Key: "lease.owner", Value: ""}},
	}}}
	update := bson.D{
		{Key: "$set", Value: bson.D{{Key: "lease.owner", Value: claim.WorkerID}, {Key: "lease.expires_at", Value: claim.ExpiresAt.UTC()}, {Key: "updated_at", Value: claim.Now.UTC()}}},
		{Key: "$inc", Value: bson.D{{Key: "lease.generation", Value: 1}, {Key: "version", Value: 1}}},
	}
	for _, status := range claim.ClaimableStatuses() {
		var document buildDocument
		filter := append(append(bson.D{}, leaseAvailable...), bson.E{Key: "status", Value: status})
		err := r.builds.FindOneAndUpdate(ctx, filter, update, options.FindOneAndUpdate().
			SetSort(bson.D{{Key: "created_at", Value: 1}, {Key: "_id", Value: 1}}).
			SetReturnDocument(options.After)).Decode(&document)
		if err == nil {
			return document.domain(), true, nil
		}
		if !errors.Is(err, mongo.ErrNoDocuments) {
			return biz.Build{}, false, fmt.Errorf("claim build: %w", err)
		}
	}
	return biz.Build{}, false, nil
}

func (r *MongoRepository) SaveClaimedBuild(ctx context.Context, item biz.Build, expectedVersion uint64,
	workerID string, generation uint64, now time.Time) (biz.Build, error) {
	if !item.Terminal() && (item.Lease.Owner != workerID || item.Lease.Generation != generation || !item.Lease.Active(now)) {
		return biz.Build{}, biz.ErrBuildLeaseExpired
	}
	item.Version = expectedVersion + 1
	result, err := r.builds.ReplaceOne(ctx, bson.D{
		{Key: "_id", Value: item.ID}, {Key: "version", Value: expectedVersion},
		{Key: "lease.owner", Value: workerID}, {Key: "lease.generation", Value: generation},
		{Key: "lease.expires_at", Value: bson.D{{Key: "$gt", Value: now.UTC()}}},
	}, buildDocumentFromDomain(item))
	if err != nil {
		return biz.Build{}, fmt.Errorf("save claimed build: %w", err)
	}
	if result.ModifiedCount != 1 {
		return biz.Build{}, biz.ErrBuildLeaseExpired
	}
	return item, nil
}

func (r *MongoRepository) RenewBuildLease(ctx context.Context, buildID, workerID string,
	generation, expectedVersion uint64, now, expiresAt time.Time) (biz.Build, error) {
	if !validQueueIdentity(buildID, workerID) || generation == 0 || !expiresAt.After(now) {
		return biz.Build{}, biz.ErrInvalidBuildLease
	}
	var document buildDocument
	err := r.builds.FindOneAndUpdate(ctx, bson.D{
		{Key: "_id", Value: buildID}, {Key: "version", Value: expectedVersion},
		{Key: "lease.owner", Value: workerID}, {Key: "lease.generation", Value: generation},
		{Key: "lease.expires_at", Value: bson.D{{Key: "$gt", Value: now.UTC()}}},
	}, bson.D{
		{Key: "$set", Value: bson.D{{Key: "lease.expires_at", Value: expiresAt.UTC()}, {Key: "updated_at", Value: now.UTC()}}},
		{Key: "$inc", Value: bson.D{{Key: "version", Value: 1}}},
	}, options.FindOneAndUpdate().SetReturnDocument(options.After)).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return biz.Build{}, biz.ErrBuildLeaseExpired
	}
	if err != nil {
		return biz.Build{}, fmt.Errorf("renew build lease: %w", err)
	}
	return document.domain(), nil
}

func (r *MongoRepository) ValidateBuildFence(ctx context.Context, buildID, workerID string, generation uint64, now time.Time) error {
	if !validQueueIdentity(buildID, workerID) || generation == 0 || now.IsZero() {
		return biz.ErrInvalidBuildLease
	}
	err := r.builds.FindOne(ctx, bson.D{
		{Key: "_id", Value: buildID}, {Key: "lease.owner", Value: workerID},
		{Key: "lease.generation", Value: generation}, {Key: "lease.expires_at", Value: bson.D{{Key: "$gt", Value: now.UTC()}}},
	}, options.FindOne().SetProjection(bson.D{{Key: "_id", Value: 1}})).Err()
	if errors.Is(err, mongo.ErrNoDocuments) {
		return biz.ErrBuildLeaseExpired
	}
	if err != nil {
		return fmt.Errorf("validate build fence: %w", err)
	}
	return nil
}

func validQueueIdentity(buildID, workerID string) bool {
	return strings.TrimSpace(buildID) != "" && strings.TrimSpace(workerID) != ""
}

func (r *MongoRepository) GetBuild(
	ctx context.Context,
	projectID, buildID string,
) (biz.Build, error) {
	var document buildDocument
	err := r.builds.FindOne(ctx, bson.D{
		{Key: "_id", Value: buildID},
		{Key: "project_id", Value: projectID},
	}).Decode(&document)
	if err == mongo.ErrNoDocuments {
		return biz.Build{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.Build{}, fmt.Errorf("find build: %w", err)
	}
	return document.domain(), nil
}

func (r *MongoRepository) GetBuildByIdempotency(
	ctx context.Context,
	projectID, idempotencyKey string,
) (biz.Build, error) {
	var document buildDocument
	err := r.builds.FindOne(ctx, bson.D{
		{Key: "project_id", Value: projectID},
		{Key: "idempotency_key", Value: idempotencyKey},
	}).Decode(&document)
	if err == mongo.ErrNoDocuments {
		return biz.Build{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.Build{}, fmt.Errorf("find build idempotency: %w", err)
	}
	return document.domain(), nil
}

func (r *MongoRepository) ListBuildConfigurations(
	ctx context.Context,
	projectID, applicationID string,
) ([]biz.BuildConfiguration, error) {
	cursor, err := r.configurations.Find(
		ctx,
		bson.D{
			{Key: "project_id", Value: projectID},
			{Key: "application_id", Value: applicationID},
		},
		options.Find().SetSort(bson.D{{Key: "created_at", Value: 1}, {Key: "_id", Value: 1}}),
	)
	if err != nil {
		return nil, fmt.Errorf("find build configurations: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()
	var documents []buildConfigurationDocument
	if err := cursor.All(ctx, &documents); err != nil {
		return nil, fmt.Errorf("decode build configurations: %w", err)
	}
	items := make([]biz.BuildConfiguration, len(documents))
	for index, document := range documents {
		items[index] = document.domain()
	}
	return items, nil
}

func (r *MongoRepository) CreateBuildConfiguration(
	ctx context.Context,
	item biz.BuildConfiguration,
) (biz.BuildConfiguration, error) {
	if _, err := r.configurations.InsertOne(ctx, buildConfigurationDocumentFromDomain(item)); mongo.IsDuplicateKeyError(err) {
		return biz.BuildConfiguration{}, biz.ErrDuplicateName
	} else if err != nil {
		return biz.BuildConfiguration{}, fmt.Errorf("insert build configuration: %w", err)
	}
	return item, nil
}

func (r *MongoRepository) GetBuildConfiguration(
	ctx context.Context,
	projectID, applicationID, configurationID string,
) (biz.BuildConfiguration, error) {
	var document buildConfigurationDocument
	err := r.configurations.FindOne(ctx, bson.D{
		{Key: "_id", Value: configurationID},
		{Key: "project_id", Value: projectID},
		{Key: "application_id", Value: applicationID},
	}).Decode(&document)
	if err == mongo.ErrNoDocuments {
		return biz.BuildConfiguration{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.BuildConfiguration{}, fmt.Errorf("find build configuration: %w", err)
	}
	return document.domain(), nil
}

func (r *MongoRepository) UpdateBuildConfiguration(
	ctx context.Context,
	item biz.BuildConfiguration,
	expectedVersion uint64,
) (biz.BuildConfiguration, error) {
	var document buildConfigurationDocument
	err := r.configurations.FindOneAndReplace(
		ctx,
		bson.D{
			{Key: "_id", Value: item.ID},
			{Key: "project_id", Value: item.ProjectID},
			{Key: "application_id", Value: item.ApplicationID},
			{Key: "version", Value: expectedVersion},
		},
		buildConfigurationDocumentFromDomain(item),
		options.FindOneAndReplace().SetReturnDocument(options.After),
	).Decode(&document)
	if mongo.IsDuplicateKeyError(err) {
		return biz.BuildConfiguration{}, biz.ErrDuplicateName
	}
	if err == mongo.ErrNoDocuments {
		return biz.BuildConfiguration{}, biz.ErrVersionConflict
	}
	if err != nil {
		return biz.BuildConfiguration{}, fmt.Errorf("update build configuration: %w", err)
	}
	return document.domain(), nil
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

type buildResourcesDocument struct {
	CPUMilli    int64 `bson:"cpu_milli"`
	MemoryBytes int64 `bson:"memory_bytes"`
	DiskBytes   int64 `bson:"disk_bytes"`
}

type releaseRuntimeSpecDocument struct {
	Ports           []releaseRuntimePortDocument `bson:"ports"`
	EnvironmentKeys []string                     `bson:"environment_keys"`
	Resources       releaseRuntimeResources      `bson:"resources"`
	HealthCheck     *releaseHealthCheckDocument  `bson:"health_check,omitempty"`
}

type releaseRuntimePortDocument struct {
	Name          string `bson:"name"`
	ContainerPort uint16 `bson:"container_port"`
	Protocol      string `bson:"protocol"`
}

type releaseRuntimeResources struct {
	CPUMilli    int64 `bson:"cpu_milli"`
	MemoryBytes int64 `bson:"memory_bytes"`
}

type releaseHealthCheckDocument struct {
	Command            []string `bson:"command"`
	IntervalSeconds    int      `bson:"interval_seconds"`
	TimeoutSeconds     int      `bson:"timeout_seconds"`
	Retries            int      `bson:"retries"`
	StartPeriodSeconds int      `bson:"start_period_seconds"`
}

func releaseRuntimeSpecDocumentFromDomain(value runtimespec.Spec) releaseRuntimeSpecDocument {
	ports := make([]releaseRuntimePortDocument, len(value.Ports))
	for index, port := range value.Ports {
		ports[index] = releaseRuntimePortDocument{Name: port.Name, ContainerPort: port.ContainerPort, Protocol: port.Protocol}
	}
	result := releaseRuntimeSpecDocument{
		Ports: ports, EnvironmentKeys: append([]string(nil), value.EnvironmentKeys...),
		Resources: releaseRuntimeResources{CPUMilli: value.Resources.CPUMilli, MemoryBytes: value.Resources.MemoryBytes},
	}
	if value.HealthCheck != nil {
		result.HealthCheck = &releaseHealthCheckDocument{
			Command:            append([]string(nil), value.HealthCheck.Command...),
			IntervalSeconds:    value.HealthCheck.IntervalSeconds,
			TimeoutSeconds:     value.HealthCheck.TimeoutSeconds,
			Retries:            value.HealthCheck.Retries,
			StartPeriodSeconds: value.HealthCheck.StartPeriodSeconds,
		}
	}
	return result
}

func (d releaseRuntimeSpecDocument) domain() runtimespec.Spec {
	ports := make([]runtimespec.Port, len(d.Ports))
	for index, port := range d.Ports {
		ports[index] = runtimespec.Port{Name: port.Name, ContainerPort: port.ContainerPort, Protocol: port.Protocol}
	}
	result := runtimespec.Spec{
		Ports: ports, EnvironmentKeys: append([]string(nil), d.EnvironmentKeys...),
		Resources: runtimespec.Resources{CPUMilli: d.Resources.CPUMilli, MemoryBytes: d.Resources.MemoryBytes},
	}
	if d.HealthCheck != nil {
		result.HealthCheck = &runtimespec.HealthCheck{
			Command:            append([]string(nil), d.HealthCheck.Command...),
			IntervalSeconds:    d.HealthCheck.IntervalSeconds,
			TimeoutSeconds:     d.HealthCheck.TimeoutSeconds,
			Retries:            d.HealthCheck.Retries,
			StartPeriodSeconds: d.HealthCheck.StartPeriodSeconds,
		}
	}
	return result
}

type buildConfigurationDocument struct {
	ID                   string                        `bson:"_id"`
	ProjectID            string                        `bson:"project_id"`
	ApplicationID        string                        `bson:"application_id"`
	Name                 string                        `bson:"name"`
	NameNormalized       string                        `bson:"name_normalized"`
	SourceRepositoryID   string                        `bson:"source_repository_id"`
	DockerfilePath       string                        `bson:"dockerfile_path"`
	ContextPath          string                        `bson:"context_path"`
	AllowedRefs          []string                      `bson:"allowed_refs"`
	RegistryCredentialID string                        `bson:"registry_credential_id"`
	ImageRepository      string                        `bson:"image_repository"`
	TargetPlatform       biz.BuildPlatform             `bson:"target_platform"`
	Resources            buildResourcesDocument        `bson:"resources"`
	TimeoutSeconds       int64                         `bson:"timeout_seconds"`
	MaxConcurrency       int                           `bson:"max_concurrency"`
	AutoCreateRelease    bool                          `bson:"auto_create_release"`
	ReleaseRuntimeSpec   releaseRuntimeSpecDocument    `bson:"release_runtime_spec"`
	AutomaticDeployments []automaticDeploymentDocument `bson:"automatic_deployments"`
	Version              uint64                        `bson:"version"`
	CreatedBy            string                        `bson:"created_by"`
	UpdatedBy            string                        `bson:"updated_by"`
	CreatedAt            time.Time                     `bson:"created_at"`
	UpdatedAt            time.Time                     `bson:"updated_at"`
}

type sourceRevisionDocument struct {
	SourceRepositoryID string `bson:"source_repository_id"`
	Ref                string `bson:"ref"`
	CommitSHA          string `bson:"commit_sha"`
}

type buildConfigurationSnapshotDocument struct {
	ConfigurationID      string                        `bson:"configuration_id"`
	ConfigurationVersion uint64                        `bson:"configuration_version"`
	SourceRepositoryID   string                        `bson:"source_repository_id"`
	DockerfilePath       string                        `bson:"dockerfile_path"`
	ContextPath          string                        `bson:"context_path"`
	AllowedRefs          []string                      `bson:"allowed_refs"`
	RegistryCredentialID string                        `bson:"registry_credential_id"`
	ImageRepository      string                        `bson:"image_repository"`
	TargetPlatform       biz.BuildPlatform             `bson:"target_platform"`
	Resources            buildResourcesDocument        `bson:"resources"`
	TimeoutSeconds       int64                         `bson:"timeout_seconds"`
	MaxConcurrency       int                           `bson:"max_concurrency"`
	AutoCreateRelease    bool                          `bson:"auto_create_release"`
	ReleaseRuntimeSpec   releaseRuntimeSpecDocument    `bson:"release_runtime_spec"`
	AutomaticDeployments []automaticDeploymentDocument `bson:"automatic_deployments"`
}

type automaticDeploymentDocument struct {
	EnvironmentID   string `bson:"environment_id"`
	RuntimeTargetID string `bson:"runtime_target_id"`
}

func automaticDeploymentDocumentsFromDomain(values []biz.AutomaticDeploymentRule) []automaticDeploymentDocument {
	result := make([]automaticDeploymentDocument, len(values))
	for index, value := range values {
		result[index] = automaticDeploymentDocument{
			EnvironmentID: value.EnvironmentID, RuntimeTargetID: value.RuntimeTargetID,
		}
	}
	return result
}

func automaticDeploymentDocumentsDomain(values []automaticDeploymentDocument) []biz.AutomaticDeploymentRule {
	result := make([]biz.AutomaticDeploymentRule, len(values))
	for index, value := range values {
		result[index] = biz.AutomaticDeploymentRule{
			EnvironmentID: value.EnvironmentID, RuntimeTargetID: value.RuntimeTargetID,
		}
	}
	return result
}

type buildDocument struct {
	ID                   string                             `bson:"_id"`
	OrganizationID       string                             `bson:"organization_id"`
	ProjectID            string                             `bson:"project_id"`
	ApplicationID        string                             `bson:"application_id"`
	BuildConfigurationID string                             `bson:"build_configuration_id"`
	Revision             sourceRevisionDocument             `bson:"revision"`
	Configuration        buildConfigurationSnapshotDocument `bson:"configuration_snapshot"`
	TriggerSource        biz.BuildTriggerSource             `bson:"trigger_source"`
	TriggerID            string                             `bson:"trigger_id,omitempty"`
	IdempotencyKey       string                             `bson:"idempotency_key"`
	Status               biz.BuildStatus                    `bson:"status"`
	FailureCategory      biz.BuildFailureCategory           `bson:"failure_category,omitempty"`
	Version              uint64                             `bson:"version"`
	TriggeredBy          string                             `bson:"triggered_by"`
	SourceBuildID        string                             `bson:"source_build_id,omitempty"`
	ImageDigest          string                             `bson:"image_digest,omitempty"`
	ArtifactID           string                             `bson:"artifact_id,omitempty"`
	Lease                buildLeaseDocument                 `bson:"lease,omitempty"`
	CreatedAt            time.Time                          `bson:"created_at"`
	UpdatedAt            time.Time                          `bson:"updated_at"`
	StartedAt            time.Time                          `bson:"started_at,omitempty"`
	FinishedAt           time.Time                          `bson:"finished_at,omitempty"`
}

type buildLeaseDocument struct {
	Owner      string    `bson:"owner,omitempty"`
	ExpiresAt  time.Time `bson:"expires_at,omitempty"`
	Generation uint64    `bson:"generation,omitempty"`
}

func buildDocumentFromDomain(item biz.Build) buildDocument {
	return buildDocument{
		ID: item.ID, OrganizationID: item.OrganizationID,
		ProjectID: item.ProjectID, ApplicationID: item.ApplicationID,
		BuildConfigurationID: item.BuildConfigurationID,
		Revision: sourceRevisionDocument{
			SourceRepositoryID: item.Revision.SourceRepositoryID,
			Ref:                item.Revision.Ref, CommitSHA: item.Revision.CommitSHA,
		},
		Configuration: buildConfigurationSnapshotDocument{
			ConfigurationID:      item.Configuration.ConfigurationID,
			ConfigurationVersion: item.Configuration.ConfigurationVersion,
			SourceRepositoryID:   item.Configuration.SourceRepositoryID,
			DockerfilePath:       item.Configuration.DockerfilePath,
			ContextPath:          item.Configuration.ContextPath,
			AllowedRefs:          append([]string(nil), item.Configuration.AllowedRefs...),
			RegistryCredentialID: item.Configuration.RegistryCredentialID,
			ImageRepository:      item.Configuration.ImageRepository,
			TargetPlatform:       item.Configuration.TargetPlatform,
			Resources: buildResourcesDocument{
				CPUMilli:    item.Configuration.Resources.CPUMilli,
				MemoryBytes: item.Configuration.Resources.MemoryBytes,
				DiskBytes:   item.Configuration.Resources.DiskBytes,
			},
			TimeoutSeconds:       item.Configuration.TimeoutSeconds,
			MaxConcurrency:       item.Configuration.MaxConcurrency,
			AutoCreateRelease:    item.Configuration.AutoCreateRelease,
			ReleaseRuntimeSpec:   releaseRuntimeSpecDocumentFromDomain(item.Configuration.ReleaseRuntimeSpec),
			AutomaticDeployments: automaticDeploymentDocumentsFromDomain(item.Configuration.AutomaticDeployments),
		},
		TriggerSource: item.TriggerSource, TriggerID: item.TriggerID, IdempotencyKey: item.IdempotencyKey,
		Status: item.Status, FailureCategory: item.FailureCategory, Version: item.Version,
		TriggeredBy: item.TriggeredBy, SourceBuildID: item.SourceBuildID, ImageDigest: item.ImageDigest,
		ArtifactID: item.ArtifactID,
		Lease:      buildLeaseDocument{Owner: item.Lease.Owner, ExpiresAt: item.Lease.ExpiresAt, Generation: item.Lease.Generation},
		CreatedAt:  item.CreatedAt, UpdatedAt: item.UpdatedAt, StartedAt: item.StartedAt, FinishedAt: item.FinishedAt,
	}
}

func (d buildDocument) domain() biz.Build {
	return biz.Build{
		ID: d.ID, OrganizationID: d.OrganizationID,
		ProjectID: d.ProjectID, ApplicationID: d.ApplicationID,
		BuildConfigurationID: d.BuildConfigurationID,
		Revision: biz.SourceRevision{
			SourceRepositoryID: d.Revision.SourceRepositoryID,
			Ref:                d.Revision.Ref, CommitSHA: d.Revision.CommitSHA,
		},
		Configuration: biz.BuildConfigurationSnapshot{
			ConfigurationID:      d.Configuration.ConfigurationID,
			ConfigurationVersion: d.Configuration.ConfigurationVersion,
			SourceRepositoryID:   d.Configuration.SourceRepositoryID,
			DockerfilePath:       d.Configuration.DockerfilePath,
			ContextPath:          d.Configuration.ContextPath,
			AllowedRefs:          append([]string(nil), d.Configuration.AllowedRefs...),
			RegistryCredentialID: d.Configuration.RegistryCredentialID,
			ImageRepository:      d.Configuration.ImageRepository,
			TargetPlatform:       d.Configuration.TargetPlatform,
			Resources: biz.BuildResources{
				CPUMilli:    d.Configuration.Resources.CPUMilli,
				MemoryBytes: d.Configuration.Resources.MemoryBytes,
				DiskBytes:   d.Configuration.Resources.DiskBytes,
			},
			TimeoutSeconds:       d.Configuration.TimeoutSeconds,
			MaxConcurrency:       d.Configuration.MaxConcurrency,
			AutoCreateRelease:    d.Configuration.AutoCreateRelease,
			ReleaseRuntimeSpec:   d.Configuration.ReleaseRuntimeSpec.domain(),
			AutomaticDeployments: automaticDeploymentDocumentsDomain(d.Configuration.AutomaticDeployments),
		},
		TriggerSource: d.TriggerSource, TriggerID: d.TriggerID, IdempotencyKey: d.IdempotencyKey,
		Status: d.Status, FailureCategory: d.FailureCategory, Version: d.Version,
		TriggeredBy: d.TriggeredBy, SourceBuildID: d.SourceBuildID, ImageDigest: d.ImageDigest,
		ArtifactID: d.ArtifactID,
		Lease:      biz.BuildLease{Owner: d.Lease.Owner, ExpiresAt: d.Lease.ExpiresAt, Generation: d.Lease.Generation},
		CreatedAt:  d.CreatedAt, UpdatedAt: d.UpdatedAt, StartedAt: d.StartedAt, FinishedAt: d.FinishedAt,
	}
}

type artifactDocument struct {
	ID                   string                        `bson:"_id"`
	OrganizationID       string                        `bson:"organization_id"`
	ProjectID            string                        `bson:"project_id"`
	ApplicationID        string                        `bson:"application_id"`
	BuildID              string                        `bson:"build_id"`
	BuildConfigurationID string                        `bson:"build_configuration_id"`
	RegistryCredentialID string                        `bson:"registry_credential_id"`
	ImageRepository      string                        `bson:"image_repository"`
	ImageDigest          string                        `bson:"image_digest"`
	TargetPlatform       biz.BuildPlatform             `bson:"target_platform"`
	ReleaseRuntimeSpec   releaseRuntimeSpecDocument    `bson:"release_runtime_spec"`
	AutomaticDeployments []automaticDeploymentDocument `bson:"automatic_deployments"`
	ReleaseStatus        biz.ArtifactReleaseStatus     `bson:"release_status"`
	ReleaseID            string                        `bson:"release_id,omitempty"`
	Version              uint64                        `bson:"version"`
	CreatedAt            time.Time                     `bson:"created_at"`
	ReleasedAt           time.Time                     `bson:"released_at,omitempty"`
}

type buildLogStreamDocument struct {
	ID           string    `bson:"_id"`
	ProjectID    string    `bson:"project_id"`
	NextSequence uint64    `bson:"next_sequence"`
	TotalBytes   int64     `bson:"total_bytes"`
	Truncated    bool      `bson:"truncated"`
	CreatedAt    time.Time `bson:"created_at"`
	UpdatedAt    time.Time `bson:"updated_at,omitempty"`
	ExpiresAt    time.Time `bson:"expires_at"`
}

type buildLogChunkDocument struct {
	ID        string            `bson:"_id"`
	BuildID   string            `bson:"build_id"`
	ProjectID string            `bson:"project_id"`
	Sequence  uint64            `bson:"sequence"`
	Stage     biz.BuildLogStage `bson:"stage"`
	Message   string            `bson:"message"`
	CreatedAt time.Time         `bson:"created_at"`
	ExpiresAt time.Time         `bson:"expires_at"`
}

func (d buildLogChunkDocument) domain() biz.BuildLogEntry {
	return biz.BuildLogEntry{
		Sequence: d.Sequence, Stage: d.Stage, Message: d.Message, CreatedAt: d.CreatedAt,
	}
}

func normalizeBuildLogMessage(value string) string {
	value = strings.ToValidUTF8(value, "�")
	var builder strings.Builder
	builder.Grow(len(value))
	for _, character := range value {
		if character == '\n' || character == '\t' || character >= 0x20 {
			builder.WriteRune(character)
		}
	}
	return strings.TrimSpace(builder.String())
}

func splitBuildLogMessage(value string, maximumBytes int) []string {
	if maximumBytes <= 0 || len(value) <= maximumBytes {
		return []string{value}
	}
	chunks := make([]string, 0, len(value)/maximumBytes+1)
	for len(value) > maximumBytes {
		end := maximumBytes
		for end > 0 && !utf8.ValidString(value[:end]) {
			end--
		}
		if end == 0 {
			end = maximumBytes
		}
		chunks = append(chunks, value[:end])
		value = value[end:]
	}
	if value != "" {
		chunks = append(chunks, value)
	}
	return chunks
}

func artifactDocumentFromDomain(item biz.Artifact) artifactDocument {
	return artifactDocument{
		ID: item.ID, OrganizationID: item.OrganizationID, ProjectID: item.ProjectID,
		ApplicationID: item.ApplicationID, BuildID: item.BuildID,
		BuildConfigurationID: item.BuildConfigurationID,
		RegistryCredentialID: item.RegistryCredentialID,
		ImageRepository:      item.ImageRepository, ImageDigest: item.ImageDigest,
		TargetPlatform: item.TargetPlatform, ReleaseStatus: item.ReleaseStatus,
		ReleaseRuntimeSpec:   releaseRuntimeSpecDocumentFromDomain(item.ReleaseRuntimeSpec),
		AutomaticDeployments: automaticDeploymentDocumentsFromDomain(item.AutomaticDeployments),
		ReleaseID:            item.ReleaseID, Version: item.Version,
		CreatedAt: item.CreatedAt, ReleasedAt: item.ReleasedAt,
	}
}

func (d artifactDocument) domain() biz.Artifact {
	return biz.Artifact{
		ID: d.ID, OrganizationID: d.OrganizationID, ProjectID: d.ProjectID,
		ApplicationID: d.ApplicationID, BuildID: d.BuildID,
		BuildConfigurationID: d.BuildConfigurationID,
		RegistryCredentialID: d.RegistryCredentialID,
		ImageRepository:      d.ImageRepository, ImageDigest: d.ImageDigest,
		TargetPlatform: d.TargetPlatform, ReleaseStatus: d.ReleaseStatus,
		ReleaseRuntimeSpec:   d.ReleaseRuntimeSpec.domain(),
		AutomaticDeployments: automaticDeploymentDocumentsDomain(d.AutomaticDeployments),
		ReleaseID:            d.ReleaseID, Version: d.Version,
		CreatedAt: d.CreatedAt, ReleasedAt: d.ReleasedAt,
	}
}

type buildTriggerDocument struct {
	ID                   string                 `bson:"_id"`
	OrganizationID       string                 `bson:"organization_id"`
	ProjectID            string                 `bson:"project_id"`
	ApplicationID        string                 `bson:"application_id"`
	BuildConfigurationID string                 `bson:"build_configuration_id"`
	Name                 string                 `bson:"name"`
	NameNormalized       string                 `bson:"name_normalized"`
	AllowedRefs          []string               `bson:"allowed_refs"`
	TokenHash            string                 `bson:"token_hash,omitempty"`
	Status               biz.BuildTriggerStatus `bson:"status"`
	Version              uint64                 `bson:"version"`
	CreatedBy            string                 `bson:"created_by"`
	CreatedAt            time.Time              `bson:"created_at"`
	RevokedBy            string                 `bson:"revoked_by,omitempty"`
	RevokedAt            time.Time              `bson:"revoked_at,omitempty"`
}

type buildHookDocument struct {
	ID                   string              `bson:"_id"`
	OrganizationID       string              `bson:"organization_id"`
	ProjectID            string              `bson:"project_id"`
	ApplicationID        string              `bson:"application_id"`
	BuildConfigurationID string              `bson:"build_configuration_id"`
	Name                 string              `bson:"name"`
	NameNormalized       string              `bson:"name_normalized"`
	Provider             biz.WebhookProvider `bson:"provider"`
	AllowedRefs          []string            `bson:"allowed_refs"`
	SecretRef            string              `bson:"secret_ref"`
	Status               biz.BuildHookStatus `bson:"status"`
	Version              uint64              `bson:"version"`
	CreatedBy            string              `bson:"created_by"`
	CreatedAt            time.Time           `bson:"created_at"`
	RevokedBy            string              `bson:"revoked_by,omitempty"`
	RevokedAt            time.Time           `bson:"revoked_at,omitempty"`
}

type buildHookSummaryDocument struct {
	ID                   string              `bson:"_id"`
	ProjectID            string              `bson:"project_id"`
	ApplicationID        string              `bson:"application_id"`
	BuildConfigurationID string              `bson:"build_configuration_id"`
	Name                 string              `bson:"name"`
	Provider             biz.WebhookProvider `bson:"provider"`
	AllowedRefs          []string            `bson:"allowed_refs"`
	Status               biz.BuildHookStatus `bson:"status"`
	Version              uint64              `bson:"version"`
	CreatedBy            string              `bson:"created_by"`
	CreatedAt            time.Time           `bson:"created_at"`
	RevokedBy            string              `bson:"revoked_by,omitempty"`
	RevokedAt            time.Time           `bson:"revoked_at,omitempty"`
}

func (d buildHookSummaryDocument) domain() biz.BuildHookSummary {
	return biz.BuildHookSummary{
		ID: d.ID, ProjectID: d.ProjectID, ApplicationID: d.ApplicationID,
		BuildConfigurationID: d.BuildConfigurationID, Name: d.Name, Provider: d.Provider,
		AllowedRefs: append([]string(nil), d.AllowedRefs...), SecretConfigured: true,
		Status: d.Status, Version: d.Version, CreatedBy: d.CreatedBy, CreatedAt: d.CreatedAt,
		RevokedBy: d.RevokedBy, RevokedAt: d.RevokedAt,
	}
}

func buildHookDocumentFromDomain(item biz.BuildHook) buildHookDocument {
	return buildHookDocument{
		ID: item.ID, OrganizationID: item.OrganizationID, ProjectID: item.ProjectID,
		ApplicationID: item.ApplicationID, BuildConfigurationID: item.BuildConfigurationID,
		Name: item.Name, NameNormalized: strings.ToLower(item.Name), Provider: item.Provider,
		AllowedRefs: append([]string(nil), item.AllowedRefs...), SecretRef: item.SecretRef,
		Status: item.Status, Version: item.Version, CreatedBy: item.CreatedBy, CreatedAt: item.CreatedAt,
		RevokedBy: item.RevokedBy, RevokedAt: item.RevokedAt,
	}
}

func (d buildHookDocument) domain() biz.BuildHook {
	return biz.BuildHook{
		ID: d.ID, OrganizationID: d.OrganizationID, ProjectID: d.ProjectID,
		ApplicationID: d.ApplicationID, BuildConfigurationID: d.BuildConfigurationID,
		Name: d.Name, Provider: d.Provider, AllowedRefs: append([]string(nil), d.AllowedRefs...),
		SecretRef: d.SecretRef, Status: d.Status, Version: d.Version,
		CreatedBy: d.CreatedBy, CreatedAt: d.CreatedAt, RevokedBy: d.RevokedBy, RevokedAt: d.RevokedAt,
	}
}

type webhookDeliveryDocument struct {
	ID             string                    `bson:"_id"`
	OrganizationID string                    `bson:"organization_id"`
	ProjectID      string                    `bson:"project_id"`
	HookID         string                    `bson:"hook_id"`
	Provider       biz.WebhookProvider       `bson:"provider"`
	DeliveryID     string                    `bson:"delivery_id"`
	Event          string                    `bson:"event"`
	Ref            string                    `bson:"ref"`
	CommitSHA      string                    `bson:"commit_sha"`
	Status         biz.WebhookDeliveryStatus `bson:"status"`
	BuildID        string                    `bson:"build_id,omitempty"`
	CreatedAt      time.Time                 `bson:"created_at"`
}

func webhookDeliveryDocumentFromDomain(item biz.WebhookDelivery) webhookDeliveryDocument {
	return webhookDeliveryDocument{ID: item.ID, OrganizationID: item.OrganizationID, ProjectID: item.ProjectID,
		HookID: item.HookID, Provider: item.Provider, DeliveryID: item.DeliveryID, Event: item.Event,
		Ref: item.Ref, CommitSHA: item.CommitSHA, Status: item.Status, BuildID: item.BuildID, CreatedAt: item.CreatedAt}
}

func (d webhookDeliveryDocument) domain() biz.WebhookDelivery {
	return biz.WebhookDelivery{ID: d.ID, OrganizationID: d.OrganizationID, ProjectID: d.ProjectID,
		HookID: d.HookID, Provider: d.Provider, DeliveryID: d.DeliveryID, Event: d.Event,
		Ref: d.Ref, CommitSHA: d.CommitSHA, Status: d.Status, BuildID: d.BuildID, CreatedAt: d.CreatedAt}
}

func buildTriggerDocumentFromDomain(item biz.BuildTrigger) buildTriggerDocument {
	return buildTriggerDocument{
		ID: item.ID, OrganizationID: item.OrganizationID, ProjectID: item.ProjectID,
		ApplicationID: item.ApplicationID, BuildConfigurationID: item.BuildConfigurationID,
		Name: item.Name, NameNormalized: strings.ToLower(item.Name),
		AllowedRefs: append([]string(nil), item.AllowedRefs...), TokenHash: item.TokenHash,
		Status: item.Status, Version: item.Version, CreatedBy: item.CreatedBy,
		CreatedAt: item.CreatedAt, RevokedBy: item.RevokedBy, RevokedAt: item.RevokedAt,
	}
}

func (d buildTriggerDocument) domain() biz.BuildTrigger {
	return biz.BuildTrigger{
		ID: d.ID, OrganizationID: d.OrganizationID, ProjectID: d.ProjectID,
		ApplicationID: d.ApplicationID, BuildConfigurationID: d.BuildConfigurationID,
		Name: d.Name, AllowedRefs: append([]string(nil), d.AllowedRefs...),
		TokenHash: d.TokenHash, Status: d.Status, Version: d.Version,
		CreatedBy: d.CreatedBy, CreatedAt: d.CreatedAt,
		RevokedBy: d.RevokedBy, RevokedAt: d.RevokedAt,
	}
}

func buildConfigurationDocumentFromDomain(item biz.BuildConfiguration) buildConfigurationDocument {
	return buildConfigurationDocument{
		ID: item.ID, ProjectID: item.ProjectID, ApplicationID: item.ApplicationID,
		Name: item.Name, NameNormalized: strings.ToLower(item.Name),
		SourceRepositoryID: item.SourceRepositoryID,
		DockerfilePath:     item.DockerfilePath, ContextPath: item.ContextPath,
		AllowedRefs:          append([]string(nil), item.AllowedRefs...),
		RegistryCredentialID: item.RegistryCredentialID,
		ImageRepository:      item.ImageRepository, TargetPlatform: item.TargetPlatform,
		Resources: buildResourcesDocument{
			CPUMilli:    item.Resources.CPUMilli,
			MemoryBytes: item.Resources.MemoryBytes,
			DiskBytes:   item.Resources.DiskBytes,
		},
		TimeoutSeconds: item.TimeoutSeconds, MaxConcurrency: item.MaxConcurrency,
		AutoCreateRelease:    item.AutoCreateRelease,
		ReleaseRuntimeSpec:   releaseRuntimeSpecDocumentFromDomain(item.ReleaseRuntimeSpec),
		AutomaticDeployments: automaticDeploymentDocumentsFromDomain(item.AutomaticDeployments),
		Version:              item.Version,
		CreatedBy:            item.CreatedBy, UpdatedBy: item.UpdatedBy,
		CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt,
	}
}

func (d buildConfigurationDocument) domain() biz.BuildConfiguration {
	return biz.BuildConfiguration{
		ID: d.ID, ProjectID: d.ProjectID, ApplicationID: d.ApplicationID,
		Name: d.Name, SourceRepositoryID: d.SourceRepositoryID,
		DockerfilePath: d.DockerfilePath, ContextPath: d.ContextPath,
		AllowedRefs:          append([]string(nil), d.AllowedRefs...),
		RegistryCredentialID: d.RegistryCredentialID,
		ImageRepository:      d.ImageRepository, TargetPlatform: d.TargetPlatform,
		Resources: biz.BuildResources{
			CPUMilli:    d.Resources.CPUMilli,
			MemoryBytes: d.Resources.MemoryBytes,
			DiskBytes:   d.Resources.DiskBytes,
		},
		TimeoutSeconds: d.TimeoutSeconds, MaxConcurrency: d.MaxConcurrency,
		AutoCreateRelease:  d.AutoCreateRelease,
		ReleaseRuntimeSpec: d.ReleaseRuntimeSpec.domain(), Version: d.Version,
		AutomaticDeployments: automaticDeploymentDocumentsDomain(d.AutomaticDeployments),
		CreatedBy:            d.CreatedBy, UpdatedBy: d.UpdatedBy,
		CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt,
	}
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
