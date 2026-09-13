package data

import (
	"context"
	"fmt"
	"strings"

	"github.com/owndock/owndock/internal/modules/runtimeinventory/biz"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const runtimeTargetObservationCleanupBatchSize int64 = 256

// RuntimeTargetConvergence removes the entirely rebuildable inventory state
// owned by one Runtime Target. Observation receipts are deleted in bounded
// batches; the durable control-plane retirement record drives later passes.
type RuntimeTargetConvergence struct {
	client       *mongo.Client
	observations *mongo.Collection
	chunks       *mongo.Collection
	resources    *mongo.Collection
	current      *mongo.Collection
	heads        *mongo.Collection
	counters     *mongo.Collection
	schedule     *mongo.Collection
	hints        *mongo.Collection
}

func NewRuntimeTargetConvergence(database *mongo.Database) *RuntimeTargetConvergence {
	if database == nil {
		return &RuntimeTargetConvergence{}
	}
	return &RuntimeTargetConvergence{
		client:       database.Client(),
		observations: database.Collection("runtime_inventory_observations"),
		chunks:       database.Collection("runtime_inventory_chunks"),
		resources:    database.Collection("runtime_inventory_resources"),
		current:      database.Collection("runtime_inventory_current"),
		heads:        database.Collection("runtime_inventory_heads"),
		counters:     database.Collection("runtime_inventory_counters"),
		schedule:     database.Collection("runtime_inventory_schedule"),
		hints:        database.Collection("runtime_inventory_event_hints"),
	}
}

func (c *RuntimeTargetConvergence) ConvergeRuntimeTarget(
	ctx context.Context,
	organizationID, projectID, runtimeTargetID, actorID, _ string,
) (bool, error) {
	organizationID = strings.TrimSpace(organizationID)
	projectID = strings.TrimSpace(projectID)
	runtimeTargetID = strings.TrimSpace(runtimeTargetID)
	actorID = strings.TrimSpace(actorID)
	if c == nil || c.client == nil || organizationID == "" || projectID == "" ||
		runtimeTargetID == "" || actorID == "" {
		return false, biz.ErrInvalidTarget
	}
	session, err := c.client.StartSession()
	if err != nil {
		return false, fmt.Errorf("start runtime inventory convergence transaction: %w", err)
	}
	defer session.EndSession(ctx)
	pending := false
	_, err = session.WithTransaction(
		ctx,
		func(transactionContext context.Context) (any, error) {
			var convergeErr error
			pending, convergeErr = c.converge(
				transactionContext, organizationID, runtimeTargetID,
			)
			return nil, convergeErr
		},
	)
	if err != nil {
		return false, fmt.Errorf("converge runtime inventory target: %w", err)
	}
	return pending, nil
}

func (c *RuntimeTargetConvergence) converge(
	ctx context.Context,
	organizationID, runtimeTargetID string,
) (bool, error) {
	scope := bson.D{
		{Key: "organization_id", Value: organizationID},
		{Key: "runtime_target_id", Value: runtimeTargetID},
	}
	if _, err := c.schedule.DeleteOne(
		ctx, bson.D{{Key: "_id", Value: runtimeTargetID}},
	); err != nil {
		return false, fmt.Errorf("delete runtime inventory schedule: %w", err)
	}
	if _, err := c.hints.DeleteMany(ctx, scope); err != nil {
		return false, fmt.Errorf("delete runtime inventory event hints: %w", err)
	}

	cursor, err := c.observations.Find(
		ctx, scope,
		options.Find().SetProjection(bson.D{{Key: "_id", Value: 1}}).
			SetSort(bson.D{{Key: "started_at", Value: 1}, {Key: "_id", Value: 1}}).
			SetLimit(runtimeTargetObservationCleanupBatchSize),
	)
	if err != nil {
		return false, fmt.Errorf("find runtime inventory observations for convergence: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()
	var observations []struct {
		ID string `bson:"_id"`
	}
	if err := cursor.All(ctx, &observations); err != nil {
		return false, fmt.Errorf("decode runtime inventory observations for convergence: %w", err)
	}
	if len(observations) > 0 {
		ids := make(bson.A, len(observations))
		for index, observation := range observations {
			ids[index] = observation.ID
		}
		observationFilter := bson.D{{Key: "observation_id", Value: bson.D{{Key: "$in", Value: ids}}}}
		if _, err := c.chunks.DeleteMany(ctx, observationFilter); err != nil {
			return false, fmt.Errorf("delete runtime inventory chunks: %w", err)
		}
		if _, err := c.observations.DeleteMany(ctx, bson.D{
			{Key: "_id", Value: bson.D{{Key: "$in", Value: ids}}},
			{Key: "organization_id", Value: organizationID},
			{Key: "runtime_target_id", Value: runtimeTargetID},
		}); err != nil {
			return false, fmt.Errorf("delete runtime inventory observations: %w", err)
		}
	}
	for name, collection := range map[string]*mongo.Collection{
		"resources":          c.resources,
		"current projection": c.current,
	} {
		if _, err := collection.DeleteMany(ctx, scope); err != nil {
			return false, fmt.Errorf("delete runtime inventory %s: %w", name, err)
		}
	}
	if int64(len(observations)) == runtimeTargetObservationCleanupBatchSize {
		return true, nil
	}
	for name, collection := range map[string]*mongo.Collection{
		"head":    c.heads,
		"counter": c.counters,
	} {
		if _, err := collection.DeleteOne(ctx, bson.D{
			{Key: "_id", Value: runtimeTargetID},
			{Key: "organization_id", Value: organizationID},
		}); err != nil {
			return false, fmt.Errorf("delete runtime inventory %s: %w", name, err)
		}
	}
	return false, nil
}
