package data

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/owndock/owndock/internal/modules/runtimeinventory/biz"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const (
	openObservationRetention     = 2 * time.Hour
	replacedObservationRetention = 7 * 24 * time.Hour
	currentProjectionBatchSize   = 500
)

type MongoRepository struct {
	observations *mongo.Collection
	chunks       *mongo.Collection
	resources    *mongo.Collection
	current      *mongo.Collection
	heads        *mongo.Collection
	counters     *mongo.Collection
}

func NewMongoRepository(database *mongo.Database) *MongoRepository {
	return &MongoRepository{
		observations: database.Collection("runtime_inventory_observations"),
		chunks:       database.Collection("runtime_inventory_chunks"),
		resources:    database.Collection("runtime_inventory_resources"),
		current:      database.Collection("runtime_inventory_current"),
		heads:        database.Collection("runtime_inventory_heads"),
		counters:     database.Collection("runtime_inventory_counters"),
	}
}

func (r *MongoRepository) Begin(
	ctx context.Context,
	observation biz.Observation,
) error {
	if err := validateNewObservation(observation); err != nil {
		return err
	}
	var existing observationDocument
	err := r.observations.FindOne(
		ctx,
		bson.D{{Key: "_id", Value: observation.ID}},
	).Decode(&existing)
	if err == nil {
		if existing.sameDeclaration(observationDocumentFromDomain(observation)) {
			return nil
		}
		return biz.ErrConflict
	}
	if err != mongo.ErrNoDocuments {
		return fmt.Errorf("find runtime inventory observation: %w", err)
	}
	session, err := r.observations.Database().Client().StartSession()
	if err != nil {
		return fmt.Errorf("start runtime inventory begin transaction: %w", err)
	}
	defer session.EndSession(ctx)
	_, err = session.WithTransaction(
		ctx,
		func(transactionContext context.Context) (any, error) {
			return nil, r.begin(transactionContext, observation)
		},
	)
	if err != nil {
		return fmt.Errorf("begin runtime inventory observation: %w", err)
	}
	return nil
}

func (r *MongoRepository) begin(
	ctx context.Context,
	observation biz.Observation,
) error {
	var counter counterDocument
	err := r.counters.FindOneAndUpdate(
		ctx,
		bson.D{{Key: "_id", Value: observation.RuntimeTargetID}},
		bson.D{
			{Key: "$inc", Value: bson.D{{Key: "generation", Value: 1}}},
			{Key: "$setOnInsert", Value: bson.D{
				{Key: "organization_id", Value: observation.OrganizationID},
				{Key: "managed_host_id", Value: observation.ManagedHostID},
				{Key: "runtime_target_id", Value: observation.RuntimeTargetID},
			}},
		},
		options.FindOneAndUpdate().
			SetUpsert(true).
			SetReturnDocument(options.After),
	).Decode(&counter)
	if err != nil {
		return fmt.Errorf("allocate runtime inventory generation: %w", err)
	}
	if counter.OrganizationID != observation.OrganizationID ||
		counter.ManagedHostID != observation.ManagedHostID ||
		counter.RuntimeTargetID != observation.RuntimeTargetID {
		return biz.ErrConflict
	}
	document := observationDocumentFromDomain(observation)
	document.Generation = counter.Generation
	// Retention is operational cleanup, not event ordering. Base it on the
	// repository clock so a skewed collector timestamp cannot immediately
	// expire an observation or keep it forever.
	expiresAt := time.Now().UTC().Add(openObservationRetention)
	document.ExpiresAt = &expiresAt
	result, err := r.observations.UpdateOne(
		ctx,
		bson.D{{Key: "_id", Value: observation.ID}},
		bson.D{{Key: "$setOnInsert", Value: document}},
		options.UpdateOne().SetUpsert(true),
	)
	if err != nil {
		return fmt.Errorf("upsert runtime inventory observation: %w", err)
	}
	if result.UpsertedCount == 1 {
		return nil
	}
	if result.MatchedCount != 1 {
		return biz.ErrConflict
	}
	var existing observationDocument
	if err := r.observations.FindOne(
		ctx,
		bson.D{{Key: "_id", Value: observation.ID}},
	).Decode(&existing); err != nil {
		return fmt.Errorf("find concurrent runtime inventory observation: %w", err)
	}
	if !existing.sameDeclaration(document) {
		return biz.ErrConflict
	}
	return nil
}

func (r *MongoRepository) Append(ctx context.Context, chunk biz.Chunk) error {
	if err := chunk.Validate(); err != nil {
		return err
	}
	session, err := r.observations.Database().Client().StartSession()
	if err != nil {
		return fmt.Errorf("start runtime inventory append transaction: %w", err)
	}
	defer session.EndSession(ctx)
	_, err = session.WithTransaction(
		ctx,
		func(transactionContext context.Context) (any, error) {
			return nil, r.append(transactionContext, chunk)
		},
	)
	if err != nil {
		return fmt.Errorf("append runtime inventory chunk: %w", err)
	}
	return nil
}

func (r *MongoRepository) append(
	ctx context.Context,
	chunk biz.Chunk,
) error {
	var observation observationDocument
	err := r.observations.FindOne(ctx, bson.D{
		{Key: "_id", Value: chunk.ObservationID},
		{Key: "status", Value: biz.ObservationOpen},
	}).Decode(&observation)
	if err == mongo.ErrNoDocuments {
		return biz.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("find open runtime inventory observation: %w", err)
	}
	if chunk.Index >= observation.ExpectedChunks {
		return biz.ErrInvalidChunk
	}
	for _, resource := range chunk.Resources {
		if resource.OrganizationID != observation.OrganizationID ||
			resource.ManagedHostID != observation.ManagedHostID ||
			resource.RuntimeTargetID != observation.RuntimeTargetID {
			return biz.ErrInvalidChunk
		}
	}

	receipt := chunkDocument{
		ID:            chunkDocumentID(chunk.ObservationID, chunk.Index),
		ObservationID: chunk.ObservationID,
		Index:         chunk.Index,
		Digest:        chunk.Digest,
		ResourceCount: len(chunk.Resources),
		CreatedAt:     time.Now().UTC(),
		ExpiresAt:     observation.ExpiresAt,
	}
	receiptResult, err := r.chunks.UpdateOne(
		ctx,
		bson.D{{Key: "_id", Value: receipt.ID}},
		bson.D{{Key: "$setOnInsert", Value: receipt}},
		options.UpdateOne().SetUpsert(true),
	)
	if err != nil {
		return fmt.Errorf("upsert runtime inventory chunk receipt: %w", err)
	}
	if receiptResult.MatchedCount == 1 {
		var existing chunkDocument
		if findErr := r.chunks.FindOne(
			ctx,
			bson.D{{Key: "_id", Value: receipt.ID}},
		).Decode(&existing); findErr != nil {
			return fmt.Errorf(
				"find duplicate runtime inventory chunk receipt: %w",
				findErr,
			)
		}
		if existing.Digest != receipt.Digest ||
			existing.ResourceCount != receipt.ResourceCount {
			return biz.ErrConflict
		}
		return nil
	}
	if receiptResult.UpsertedCount != 1 {
		return biz.ErrConflict
	}

	documents := make([]any, len(chunk.Resources))
	for index, resource := range chunk.Resources {
		document := resourceDocumentFromDomain(resource)
		document.ExpiresAt = observation.ExpiresAt
		documents[index] = document
	}
	if _, err := r.resources.InsertMany(ctx, documents); err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return biz.ErrConflict
		}
		return fmt.Errorf("insert runtime inventory resources: %w", err)
	}

	result, err := r.observations.UpdateOne(
		ctx,
		bson.D{
			{Key: "_id", Value: observation.ID},
			{Key: "status", Value: biz.ObservationOpen},
			{Key: "received_chunks", Value: bson.D{
				{Key: "$lte", Value: observation.ExpectedChunks - 1},
			}},
			{Key: "received_resources", Value: bson.D{
				{Key: "$lte", Value: observation.ExpectedResources - len(chunk.Resources)},
			}},
		},
		bson.D{{Key: "$inc", Value: bson.D{
			{Key: "received_chunks", Value: 1},
			{Key: "received_resources", Value: len(chunk.Resources)},
		}}},
	)
	if err != nil {
		return fmt.Errorf("advance runtime inventory observation: %w", err)
	}
	if result.ModifiedCount != 1 {
		return biz.ErrConflict
	}
	return nil
}

func (r *MongoRepository) Complete(
	ctx context.Context,
	observationID, runtimeTargetID string,
	completedAt time.Time,
) error {
	if observationID == "" || runtimeTargetID == "" || completedAt.IsZero() {
		return biz.ErrInvalidObservation
	}
	session, err := r.observations.Database().Client().StartSession()
	if err != nil {
		return fmt.Errorf("start runtime inventory completion transaction: %w", err)
	}
	defer session.EndSession(ctx)
	_, err = session.WithTransaction(
		ctx,
		func(transactionContext context.Context) (any, error) {
			return nil, r.complete(
				transactionContext,
				observationID,
				runtimeTargetID,
				completedAt.UTC(),
			)
		},
	)
	if err != nil {
		return fmt.Errorf("complete runtime inventory observation: %w", err)
	}
	return nil
}

func (r *MongoRepository) complete(
	ctx context.Context,
	observationID, runtimeTargetID string,
	completedAt time.Time,
) error {
	var observation observationDocument
	err := r.observations.FindOne(
		ctx,
		bson.D{{Key: "_id", Value: observationID}},
	).Decode(&observation)
	if err == mongo.ErrNoDocuments {
		return biz.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("find runtime inventory observation: %w", err)
	}
	if observation.RuntimeTargetID != runtimeTargetID {
		return biz.ErrConflict
	}
	if observation.Status == biz.ObservationComplete {
		var existing headDocument
		err := r.heads.FindOne(ctx, bson.D{
			{Key: "_id", Value: runtimeTargetID},
			{Key: "organization_id", Value: observation.OrganizationID},
			{Key: "observation_id", Value: observation.ID},
		}).Decode(&existing)
		if err == nil {
			return nil
		}
		if err == mongo.ErrNoDocuments {
			return biz.ErrConflict
		}
		return fmt.Errorf("find completed runtime inventory head: %w", err)
	}
	if observation.Status != biz.ObservationOpen ||
		observation.ReceivedChunks != observation.ExpectedChunks ||
		observation.ReceivedResources != observation.ExpectedResources ||
		completedAt.Before(observation.StartedAt) {
		return biz.ErrConflict
	}

	var previous headDocument
	err = r.heads.FindOne(
		ctx,
		bson.D{{Key: "_id", Value: runtimeTargetID}},
	).Decode(&previous)
	switch {
	case err == nil:
		if previous.ObservationID == observation.ID {
			return biz.ErrConflict
		}
		if observation.Generation <= previous.Generation {
			return biz.ErrConflict
		}
	case err == mongo.ErrNoDocuments:
		previous = headDocument{}
	default:
		return fmt.Errorf("find current runtime inventory head: %w", err)
	}

	result, err := r.observations.UpdateOne(
		ctx,
		bson.D{
			{Key: "_id", Value: observation.ID},
			{Key: "status", Value: biz.ObservationOpen},
			{Key: "received_chunks", Value: observation.ExpectedChunks},
			{Key: "received_resources", Value: observation.ExpectedResources},
		},
		bson.D{
			{Key: "$set", Value: bson.D{
				{Key: "status", Value: biz.ObservationComplete},
				{Key: "completed_at", Value: completedAt},
			}},
			{Key: "$unset", Value: bson.D{{Key: "expires_at", Value: ""}}},
		},
	)
	if err != nil {
		return fmt.Errorf("mark runtime inventory observation complete: %w", err)
	}
	if result.ModifiedCount != 1 {
		return biz.ErrConflict
	}
	for name, collection := range map[string]*mongo.Collection{
		"chunks":    r.chunks,
		"resources": r.resources,
	} {
		if _, err := collection.UpdateMany(
			ctx,
			bson.D{{Key: "observation_id", Value: observation.ID}},
			bson.D{{Key: "$unset", Value: bson.D{{Key: "expires_at", Value: ""}}}},
		); err != nil {
			return fmt.Errorf("retain current runtime inventory %s: %w", name, err)
		}
	}
	if err := r.reconcileCurrent(ctx, observation, completedAt); err != nil {
		return err
	}

	head := headDocument{
		ID:              runtimeTargetID,
		OrganizationID:  observation.OrganizationID,
		ManagedHostID:   observation.ManagedHostID,
		RuntimeTargetID: runtimeTargetID,
		ObservationID:   observation.ID,
		Generation:      observation.Generation,
		StartedAt:       observation.StartedAt,
		CompletedAt:     completedAt,
	}
	if _, err := r.heads.ReplaceOne(
		ctx,
		bson.D{{Key: "_id", Value: runtimeTargetID}},
		head,
		options.Replace().SetUpsert(true),
	); err != nil {
		return fmt.Errorf("replace runtime inventory head: %w", err)
	}
	if previous.ObservationID != "" {
		expireAt := completedAt.Add(replacedObservationRetention)
		if err := r.expireObservation(
			ctx,
			previous.ObservationID,
			expireAt,
		); err != nil {
			return err
		}
	}
	return nil
}

// reconcileCurrent is called only after every declared chunk and resource has
// been validated. The surrounding completion transaction makes the absent
// pass, present upserts and head switch visible atomically.
func (r *MongoRepository) reconcileCurrent(
	ctx context.Context,
	observation observationDocument,
	completedAt time.Time,
) error {
	absentExpiresAt := completedAt.Add(replacedObservationRetention)
	_, err := r.current.UpdateMany(
		ctx,
		bson.D{
			{Key: "organization_id", Value: observation.OrganizationID},
			{Key: "runtime_target_id", Value: observation.RuntimeTargetID},
			{Key: "presence", Value: biz.PresencePresent},
			{Key: "generation", Value: bson.D{{Key: "$lt", Value: observation.Generation}}},
		},
		bson.D{{Key: "$set", Value: bson.D{
			{Key: "presence", Value: biz.PresenceAbsent},
			{Key: "absent_at", Value: completedAt},
			{Key: "reconciled_at", Value: completedAt},
			{Key: "expires_at", Value: absentExpiresAt},
		}}},
	)
	if err != nil {
		return fmt.Errorf("mark missing runtime inventory resources absent: %w", err)
	}

	cursor, err := r.resources.Find(ctx, bson.D{
		{Key: "observation_id", Value: observation.ID},
		{Key: "organization_id", Value: observation.OrganizationID},
		{Key: "runtime_target_id", Value: observation.RuntimeTargetID},
	}, options.Find().SetSort(bson.D{
		{Key: "kind", Value: 1},
		{Key: "runtime_id", Value: 1},
	}))
	if err != nil {
		return fmt.Errorf("find completed runtime inventory projection: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()

	models := make([]mongo.WriteModel, 0, currentProjectionBatchSize)
	for cursor.Next(ctx) {
		var document resourceDocument
		if err := cursor.Decode(&document); err != nil {
			return fmt.Errorf("decode completed runtime inventory projection: %w", err)
		}
		set, err := currentResourceSet(document, observation.Generation, completedAt)
		if err != nil {
			return err
		}
		models = append(models, mongo.NewUpdateOneModel().
			SetFilter(bson.D{{Key: "_id", Value: currentResourceDocumentID(document)}}).
			SetUpdate(bson.D{
				{Key: "$set", Value: set},
				{Key: "$setOnInsert", Value: bson.D{{Key: "first_seen_at", Value: completedAt}}},
				{Key: "$unset", Value: bson.D{
					{Key: "absent_at", Value: ""},
					{Key: "expires_at", Value: ""},
				}},
			}).SetUpsert(true))
		if len(models) == currentProjectionBatchSize {
			if err := r.writeCurrentBatch(ctx, models); err != nil {
				return err
			}
			models = models[:0]
		}
	}
	if err := cursor.Err(); err != nil {
		return fmt.Errorf("iterate completed runtime inventory projection: %w", err)
	}
	return r.writeCurrentBatch(ctx, models)
}

func (r *MongoRepository) writeCurrentBatch(
	ctx context.Context,
	models []mongo.WriteModel,
) error {
	if len(models) == 0 {
		return nil
	}
	if _, err := r.current.BulkWrite(
		ctx,
		models,
		options.BulkWrite().SetOrdered(true),
	); err != nil {
		return fmt.Errorf("upsert current runtime inventory projection: %w", err)
	}
	return nil
}

func currentResourceSet(
	document resourceDocument,
	generation uint64,
	reconciledAt time.Time,
) (bson.M, error) {
	document.ID = ""
	document.ExpiresAt = nil
	document.Presence = biz.PresencePresent
	document.LastSeenAt = reconciledAt
	document.ReconciledAt = reconciledAt
	document.Generation = generation
	encoded, err := bson.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("encode current runtime inventory projection: %w", err)
	}
	var set bson.M
	if err := bson.Unmarshal(encoded, &set); err != nil {
		return nil, fmt.Errorf("decode current runtime inventory projection: %w", err)
	}
	delete(set, "_id")
	delete(set, "first_seen_at")
	delete(set, "absent_at")
	delete(set, "expires_at")
	return set, nil
}

func (r *MongoRepository) expireObservation(
	ctx context.Context,
	observationID string,
	expireAt time.Time,
) error {
	for name, collection := range map[string]*mongo.Collection{
		"observation": r.observations,
		"chunks":      r.chunks,
		"resources":   r.resources,
	} {
		filter := bson.D{{Key: "observation_id", Value: observationID}}
		if name == "observation" {
			filter = bson.D{{Key: "_id", Value: observationID}}
		}
		if _, err := collection.UpdateMany(
			ctx,
			filter,
			bson.D{{Key: "$set", Value: bson.D{{Key: "expires_at", Value: expireAt}}}},
		); err != nil {
			return fmt.Errorf("expire previous runtime inventory %s: %w", name, err)
		}
	}
	return nil
}

func (r *MongoRepository) Current(
	ctx context.Context,
	query biz.Query,
) ([]biz.Resource, error) {
	states, err := r.CurrentState(ctx, biz.StateQuery{
		OrganizationID: query.OrganizationID, RuntimeTargetID: query.RuntimeTargetID,
		Kind: query.Kind,
	})
	if err != nil {
		return nil, err
	}
	resources := make([]biz.Resource, len(states))
	for index, state := range states {
		resources[index] = state.Resource
	}
	return resources, nil
}

func (r *MongoRepository) CurrentState(
	ctx context.Context,
	query biz.StateQuery,
) ([]biz.State, error) {
	if query.OrganizationID == "" || query.RuntimeTargetID == "" ||
		(query.Kind != "" && !query.Kind.Valid()) {
		return nil, biz.ErrInvalidResource
	}
	var head headDocument
	err := r.heads.FindOne(ctx, bson.D{
		{Key: "_id", Value: query.RuntimeTargetID},
		{Key: "organization_id", Value: query.OrganizationID},
	}).Decode(&head)
	if err == mongo.ErrNoDocuments {
		return nil, biz.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find runtime inventory head: %w", err)
	}
	filter := bson.D{
		{Key: "organization_id", Value: query.OrganizationID},
		{Key: "runtime_target_id", Value: query.RuntimeTargetID},
	}
	if !query.IncludeAbsent {
		filter = append(filter, bson.E{Key: "presence", Value: biz.PresencePresent})
	}
	if query.Kind != "" {
		filter = append(filter, bson.E{Key: "kind", Value: query.Kind})
	}
	cursor, err := r.current.Find(
		ctx,
		filter,
		options.Find().SetSort(bson.D{
			{Key: "kind", Value: 1},
			{Key: "name", Value: 1},
			{Key: "runtime_id", Value: 1},
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("find current runtime inventory state: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()
	var documents []resourceDocument
	if err := cursor.All(ctx, &documents); err != nil {
		return nil, fmt.Errorf("decode current runtime inventory state: %w", err)
	}
	states := make([]biz.State, len(documents))
	for index, document := range documents {
		states[index] = document.state()
	}
	return states, nil
}

func validateNewObservation(observation biz.Observation) error {
	expected, err := biz.NewObservation(
		observation.ID,
		observation.OrganizationID,
		observation.ManagedHostID,
		observation.RuntimeTargetID,
		observation.ExpectedChunks,
		observation.ExpectedResources,
		observation.StartedAt,
	)
	if err != nil || observation.Status != biz.ObservationOpen ||
		observation.ReceivedChunks != 0 ||
		observation.ReceivedResources != 0 ||
		!observation.CompletedAt.IsZero() ||
		expected != observation {
		return biz.ErrInvalidObservation
	}
	return nil
}

func resourceDocumentID(resource biz.Resource) string {
	return digestID(
		resource.ObservationID,
		string(resource.Kind),
		resource.RuntimeID,
	)
}

func currentResourceDocumentID(resource resourceDocument) string {
	return digestID(resource.RuntimeTargetID, string(resource.Kind), resource.RuntimeID)
}

func chunkDocumentID(observationID string, index int) string {
	return digestID(observationID, fmt.Sprintf("%d", index))
}

func digestID(values ...string) string {
	hash := sha256.New()
	for _, value := range values {
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0})
	}
	return fmt.Sprintf("%x", hash.Sum(nil))
}

type observationDocument struct {
	ID                string                `bson:"_id"`
	OrganizationID    string                `bson:"organization_id"`
	ManagedHostID     string                `bson:"managed_host_id"`
	RuntimeTargetID   string                `bson:"runtime_target_id"`
	ExpectedChunks    int                   `bson:"expected_chunks"`
	ExpectedResources int                   `bson:"expected_resources"`
	ReceivedChunks    int                   `bson:"received_chunks"`
	ReceivedResources int                   `bson:"received_resources"`
	Generation        uint64                `bson:"generation"`
	Status            biz.ObservationStatus `bson:"status"`
	StartedAt         time.Time             `bson:"started_at"`
	CompletedAt       time.Time             `bson:"completed_at,omitempty"`
	ExpiresAt         *time.Time            `bson:"expires_at,omitempty"`
}

func observationDocumentFromDomain(item biz.Observation) observationDocument {
	return observationDocument{
		ID: item.ID, OrganizationID: item.OrganizationID,
		ManagedHostID: item.ManagedHostID, RuntimeTargetID: item.RuntimeTargetID,
		ExpectedChunks: item.ExpectedChunks, ExpectedResources: item.ExpectedResources,
		ReceivedChunks: item.ReceivedChunks, ReceivedResources: item.ReceivedResources,
		Status: item.Status, StartedAt: item.StartedAt,
		CompletedAt: item.CompletedAt,
	}
}

func (d observationDocument) sameDeclaration(other observationDocument) bool {
	return d.ID == other.ID &&
		d.OrganizationID == other.OrganizationID &&
		d.ManagedHostID == other.ManagedHostID &&
		d.RuntimeTargetID == other.RuntimeTargetID &&
		d.ExpectedChunks == other.ExpectedChunks &&
		d.ExpectedResources == other.ExpectedResources &&
		d.Status == other.Status &&
		d.StartedAt.Equal(other.StartedAt)
}

type chunkDocument struct {
	ID            string     `bson:"_id"`
	ObservationID string     `bson:"observation_id"`
	Index         int        `bson:"index"`
	Digest        string     `bson:"digest"`
	ResourceCount int        `bson:"resource_count"`
	CreatedAt     time.Time  `bson:"created_at"`
	ExpiresAt     *time.Time `bson:"expires_at,omitempty"`
}

type headDocument struct {
	ID              string    `bson:"_id"`
	OrganizationID  string    `bson:"organization_id"`
	ManagedHostID   string    `bson:"managed_host_id"`
	RuntimeTargetID string    `bson:"runtime_target_id"`
	ObservationID   string    `bson:"observation_id"`
	Generation      uint64    `bson:"generation"`
	StartedAt       time.Time `bson:"started_at"`
	CompletedAt     time.Time `bson:"completed_at"`
}

type counterDocument struct {
	ID              string `bson:"_id"`
	OrganizationID  string `bson:"organization_id"`
	ManagedHostID   string `bson:"managed_host_id"`
	RuntimeTargetID string `bson:"runtime_target_id"`
	Generation      uint64 `bson:"generation"`
}

type resourceDocument struct {
	ID              string                  `bson:"_id"`
	ObservationID   string                  `bson:"observation_id"`
	OrganizationID  string                  `bson:"organization_id"`
	ManagedHostID   string                  `bson:"managed_host_id"`
	RuntimeTargetID string                  `bson:"runtime_target_id"`
	Kind            biz.Kind                `bson:"kind"`
	RuntimeID       string                  `bson:"runtime_id"`
	Name            string                  `bson:"name"`
	Managed         bool                    `bson:"managed"`
	ProjectID       string                  `bson:"project_id,omitempty"`
	DeploymentID    string                  `bson:"deployment_id,omitempty"`
	Container       *biz.ContainerSummary   `bson:"container,omitempty"`
	Image           *biz.ImageSummary       `bson:"image,omitempty"`
	Network         *biz.NetworkSummary     `bson:"network,omitempty"`
	Volume          *biz.VolumeSummary      `bson:"volume,omitempty"`
	Labels          map[string]string       `bson:"labels"`
	Attributes      map[string]string       `bson:"attributes"`
	Ports           []biz.Port              `bson:"ports"`
	Mounts          []biz.Mount             `bson:"mounts"`
	Networks        []biz.NetworkAttachment `bson:"networks"`
	ObservedAt      time.Time               `bson:"observed_at"`
	SchemaVersion   int                     `bson:"schema_version"`
	Presence        biz.Presence            `bson:"presence,omitempty"`
	FirstSeenAt     time.Time               `bson:"first_seen_at,omitempty"`
	LastSeenAt      time.Time               `bson:"last_seen_at,omitempty"`
	AbsentAt        time.Time               `bson:"absent_at,omitempty"`
	ReconciledAt    time.Time               `bson:"reconciled_at,omitempty"`
	Generation      uint64                  `bson:"generation,omitempty"`
	ExpiresAt       *time.Time              `bson:"expires_at,omitempty"`
}

func resourceDocumentFromDomain(item biz.Resource) resourceDocument {
	return resourceDocument{
		ID:              resourceDocumentID(item),
		ObservationID:   item.ObservationID,
		OrganizationID:  item.OrganizationID,
		ManagedHostID:   item.ManagedHostID,
		RuntimeTargetID: item.RuntimeTargetID,
		Kind:            item.Kind,
		RuntimeID:       item.RuntimeID,
		Name:            item.Name,
		Managed:         item.Managed,
		ProjectID:       item.ProjectID,
		DeploymentID:    item.DeploymentID,
		Container:       item.Container,
		Image:           item.Image,
		Network:         item.Network,
		Volume:          item.Volume,
		Labels:          cloneMap(item.Labels),
		Attributes:      cloneMap(item.Attributes),
		Ports:           append([]biz.Port{}, item.Ports...),
		Mounts:          append([]biz.Mount{}, item.Mounts...),
		Networks:        append([]biz.NetworkAttachment{}, item.Networks...),
		ObservedAt:      item.ObservedAt,
		SchemaVersion:   item.SchemaVersion,
	}
}

func (d resourceDocument) domain() biz.Resource {
	return biz.Resource{
		ObservationID:   d.ObservationID,
		OrganizationID:  d.OrganizationID,
		ManagedHostID:   d.ManagedHostID,
		RuntimeTargetID: d.RuntimeTargetID,
		Kind:            d.Kind,
		RuntimeID:       d.RuntimeID,
		Name:            d.Name,
		Managed:         d.Managed,
		ProjectID:       d.ProjectID,
		DeploymentID:    d.DeploymentID,
		Container:       d.Container,
		Image:           d.Image,
		Network:         d.Network,
		Volume:          d.Volume,
		Labels:          cloneMap(d.Labels),
		Attributes:      cloneMap(d.Attributes),
		Ports:           append([]biz.Port{}, d.Ports...),
		Mounts:          append([]biz.Mount{}, d.Mounts...),
		Networks:        append([]biz.NetworkAttachment{}, d.Networks...),
		ObservedAt:      d.ObservedAt,
		SchemaVersion:   d.SchemaVersion,
	}
}

func (d resourceDocument) state() biz.State {
	return biz.State{
		Resource: d.domain(), Presence: d.Presence,
		FirstSeenAt: d.FirstSeenAt, LastSeenAt: d.LastSeenAt,
		AbsentAt: d.AbsentAt, ReconciledAt: d.ReconciledAt,
		Generation: d.Generation,
	}
}

func cloneMap(source map[string]string) map[string]string {
	cloned := make(map[string]string, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
}

var _ biz.Repository = (*MongoRepository)(nil)
var _ biz.StateRepository = (*MongoRepository)(nil)
