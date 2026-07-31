package data

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/modules/runtimeinventory/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const (
	maximumScheduleCandidates = 1000
	eventHintRetention        = 24 * time.Hour
)

// MongoScheduleRepository reads a deliberately narrow projection from the
// control-plane collections and owns distributed collection leases in its own
// runtime-inventory collection.
type MongoScheduleRepository struct {
	targets  *mongo.Collection
	projects *mongo.Collection
	hosts    *mongo.Collection
	leases   *mongo.Collection
	hints    *mongo.Collection
}

func NewMongoScheduleRepository(database *mongo.Database) *MongoScheduleRepository {
	return &MongoScheduleRepository{
		targets:  database.Collection("runtime_targets"),
		projects: database.Collection("projects"),
		hosts:    database.Collection("managed_hosts"),
		leases:   database.Collection("runtime_inventory_schedule"),
		hints:    database.Collection("runtime_inventory_event_hints"),
	}
}

func (r *MongoScheduleRepository) ListReadyTargets(
	ctx context.Context,
	limit int,
	now time.Time,
) ([]biz.Target, error) {
	if limit < 1 || limit > maximumScheduleCandidates || now.IsZero() {
		return nil, fmt.Errorf("runtime inventory candidate limit is invalid")
	}
	dueFilter := bson.D{{Key: "$and", Value: bson.A{
		bson.D{{Key: "$or", Value: bson.A{
			bson.D{{Key: "schedule.next_due_at", Value: bson.D{{Key: "$exists", Value: false}}}},
			bson.D{{Key: "schedule.next_due_at", Value: bson.D{{Key: "$lte", Value: now.UTC()}}}},
		}}},
		bson.D{{Key: "$or", Value: bson.A{
			bson.D{{Key: "schedule.lease_expires_at", Value: bson.D{{Key: "$exists", Value: false}}}},
			bson.D{{Key: "schedule.lease_expires_at", Value: bson.D{{Key: "$lte", Value: now.UTC()}}}},
		}}},
	}}}
	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.D{
			{Key: "status", Value: "ready"},
		}}},
		{{Key: "$lookup", Value: bson.D{
			{Key: "from", Value: r.leases.Name()},
			{Key: "localField", Value: "_id"},
			{Key: "foreignField", Value: "_id"},
			{Key: "as", Value: "schedule"},
		}}},
		{{Key: "$unwind", Value: bson.D{
			{Key: "path", Value: "$schedule"},
			{Key: "preserveNullAndEmptyArrays", Value: true},
		}}},
		{{Key: "$match", Value: dueFilter}},
		{{Key: "$lookup", Value: bson.D{
			{Key: "from", Value: r.projects.Name()},
			{Key: "localField", Value: "project_id"},
			{Key: "foreignField", Value: "_id"},
			{Key: "as", Value: "project"},
		}}},
		{{Key: "$unwind", Value: "$project"}},
		{{Key: "$lookup", Value: bson.D{
			{Key: "from", Value: r.hosts.Name()},
			{Key: "localField", Value: "managed_host_id"},
			{Key: "foreignField", Value: "_id"},
			{Key: "as", Value: "host"},
		}}},
		{{Key: "$unwind", Value: "$host"}},
		{{Key: "$match", Value: bson.D{
			{Key: "host.status", Value: bson.D{{Key: "$ne", Value: "disabled"}}},
			{Key: "$expr", Value: bson.D{{Key: "$eq", Value: bson.A{
				"$project.organization_id",
				"$host.organization_id",
			}}}},
		}}},
		{{Key: "$sort", Value: bson.D{
			{Key: "schedule.next_due_at", Value: 1},
			{Key: "created_at", Value: 1},
			{Key: "_id", Value: 1},
		}}},
		{{Key: "$limit", Value: limit}},
		{{Key: "$project", Value: bson.D{
			{Key: "_id", Value: 1},
			{Key: "project_id", Value: 1},
			{Key: "managed_host_id", Value: 1},
			{Key: "connection_mode", Value: 1},
			{Key: "endpoint", Value: 1},
			{Key: "tls_server_name", Value: 1},
			{Key: "credential_ref", Value: 1},
			{Key: "organization_id", Value: "$project.organization_id"},
		}}},
	}
	cursor, err := r.targets.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, fmt.Errorf("find runtime inventory targets: %w", err)
	}
	defer cursor.Close(ctx)
	var documents []scheduleTargetDocument
	if err := cursor.All(ctx, &documents); err != nil {
		return nil, fmt.Errorf("decode runtime inventory targets: %w", err)
	}
	targets := make([]biz.Target, 0, len(documents))
	for _, document := range documents {
		target, decodeErr := document.target()
		if decodeErr != nil {
			return nil, decodeErr
		}
		targets = append(targets, target)
	}
	return targets, nil
}

func (r *MongoScheduleRepository) TryAcquire(
	ctx context.Context,
	target biz.Target,
	ownerID string,
	now, expiresAt time.Time,
) (biz.ScheduleLease, bool, error) {
	ownerID = strings.TrimSpace(ownerID)
	if err := target.Validate(); err != nil || ownerID == "" ||
		now.IsZero() || !expiresAt.After(now) {
		return biz.ScheduleLease{}, false, biz.ErrInvalidTarget
	}
	filter := bson.D{
		{Key: "_id", Value: target.RuntimeTargetID},
		{Key: "$and", Value: bson.A{
			bson.D{{Key: "$or", Value: bson.A{
				bson.D{{Key: "next_due_at", Value: bson.D{{Key: "$exists", Value: false}}}},
				bson.D{{Key: "next_due_at", Value: bson.D{{Key: "$lte", Value: now.UTC()}}}},
			}}},
			bson.D{{Key: "$or", Value: bson.A{
				bson.D{{Key: "lease_expires_at", Value: bson.D{{Key: "$exists", Value: false}}}},
				bson.D{{Key: "lease_expires_at", Value: bson.D{{Key: "$lte", Value: now.UTC()}}}},
			}}},
		}},
	}
	var document scheduleLeaseDocument
	err := r.leases.FindOneAndUpdate(
		ctx,
		filter,
		bson.D{
			{Key: "$set", Value: bson.D{
				{Key: "organization_id", Value: target.OrganizationID},
				{Key: "project_id", Value: target.ProjectID},
				{Key: "managed_host_id", Value: target.ManagedHostID},
				{Key: "owner_id", Value: ownerID},
				{Key: "lease_expires_at", Value: expiresAt.UTC()},
				{Key: "updated_at", Value: now.UTC()},
			}},
			{Key: "$unset", Value: bson.D{{Key: "next_due_at", Value: ""}}},
			{Key: "$inc", Value: bson.D{{Key: "token", Value: 1}}},
			{Key: "$setOnInsert", Value: bson.D{{Key: "created_at", Value: now.UTC()}}},
		},
		options.FindOneAndUpdate().
			SetUpsert(true).
			SetReturnDocument(options.After),
	).Decode(&document)
	if mongo.IsDuplicateKeyError(err) || err == mongo.ErrNoDocuments {
		return biz.ScheduleLease{}, false, nil
	}
	if err != nil {
		return biz.ScheduleLease{}, false,
			fmt.Errorf("claim runtime inventory target: %w", err)
	}
	return biz.ScheduleLease{
		RuntimeTargetID: document.ID,
		OwnerID:         document.OwnerID,
		Token:           document.Token,
	}, true, nil
}

func (r *MongoScheduleRepository) Finish(
	ctx context.Context,
	lease biz.ScheduleLease,
	finishedAt, nextDueAt time.Time,
	succeeded bool,
) error {
	if strings.TrimSpace(lease.RuntimeTargetID) == "" ||
		strings.TrimSpace(lease.OwnerID) == "" || lease.Token == 0 ||
		finishedAt.IsZero() || nextDueAt.Before(finishedAt) {
		return biz.ErrLeaseLost
	}
	resultField := "last_failure_at"
	if succeeded {
		resultField = "last_success_at"
	}
	result, err := r.leases.UpdateOne(
		ctx,
		bson.D{
			{Key: "_id", Value: lease.RuntimeTargetID},
			{Key: "owner_id", Value: lease.OwnerID},
			{Key: "token", Value: lease.Token},
		},
		bson.D{
			{Key: "$set", Value: bson.D{
				{Key: resultField, Value: finishedAt.UTC()},
				{Key: "updated_at", Value: finishedAt.UTC()},
			}},
			{Key: "$min", Value: bson.D{{Key: "next_due_at", Value: nextDueAt.UTC()}}},
			{Key: "$unset", Value: bson.D{
				{Key: "owner_id", Value: ""},
				{Key: "lease_expires_at", Value: ""},
			}},
		},
	)
	if err != nil {
		return fmt.Errorf("finish runtime inventory schedule: %w", err)
	}
	if result.MatchedCount != 1 {
		return biz.ErrLeaseLost
	}
	return nil
}

// RecordEventHint retains only a bounded safe summary and advances the
// periodic reconciliation schedule. $min makes duplicate and out-of-order
// delivery harmless; it can never postpone an already due reconciliation.
func (r *MongoScheduleRepository) RecordEventHint(
	ctx context.Context,
	hint biz.EventHint,
) error {
	if err := hint.Validate(); err != nil {
		return err
	}
	document := eventHintDocument{
		ID: hint.ID, OrganizationID: hint.OrganizationID,
		RuntimeTargetID: hint.RuntimeTargetID,
		Kind:            hint.Kind, RuntimeID: hint.RuntimeID, Action: hint.Action,
		OccurredAt: hint.OccurredAt, ReceivedAt: hint.ReceivedAt,
		ExpiresAt: hint.ReceivedAt.Add(eventHintRetention),
	}
	if _, err := r.hints.UpdateOne(
		ctx,
		bson.D{{Key: "_id", Value: hint.ID}},
		bson.D{{Key: "$setOnInsert", Value: document}},
		options.UpdateOne().SetUpsert(true),
	); err != nil {
		return fmt.Errorf("retain runtime inventory event hint: %w", err)
	}
	if _, err := r.leases.UpdateOne(
		ctx,
		bson.D{{Key: "_id", Value: hint.RuntimeTargetID}},
		bson.D{
			{Key: "$min", Value: bson.D{
				{Key: "next_due_at", Value: hint.ReceivedAt},
			}},
			{Key: "$max", Value: bson.D{
				{Key: "last_event_hint_at", Value: hint.ReceivedAt},
				{Key: "updated_at", Value: hint.ReceivedAt},
			}},
			{Key: "$setOnInsert", Value: bson.D{
				{Key: "created_at", Value: hint.ReceivedAt},
			}},
		},
		options.UpdateOne().SetUpsert(true),
	); err != nil {
		return fmt.Errorf("schedule runtime inventory event reconciliation: %w", err)
	}
	return nil
}

type scheduleTargetDocument struct {
	ID             string             `bson:"_id"`
	OrganizationID string             `bson:"organization_id"`
	ProjectID      string             `bson:"project_id"`
	ManagedHostID  string             `bson:"managed_host_id"`
	ConnectionMode runtimeaccess.Mode `bson:"connection_mode"`
	Endpoint       string             `bson:"endpoint,omitempty"`
	TLSServerName  string             `bson:"tls_server_name,omitempty"`
	CredentialRef  string             `bson:"credential_ref,omitempty"`
}

func (d scheduleTargetDocument) target() (biz.Target, error) {
	var connection runtimeaccess.Connection
	var err error
	switch d.ConnectionMode {
	case runtimeaccess.ModeDirectDocker:
		connection, err = runtimeaccess.NewDirectDocker(
			d.ManagedHostID,
			d.Endpoint,
			d.TLSServerName,
			d.CredentialRef,
		)
	case runtimeaccess.ModeAgent:
		connection, err = runtimeaccess.NewAgent(d.ManagedHostID)
	default:
		err = runtimeaccess.ErrUnsupportedMode
	}
	if err != nil {
		return biz.Target{}, fmt.Errorf("decode runtime inventory target: %w", err)
	}
	target := biz.Target{
		OrganizationID:  d.OrganizationID,
		ProjectID:       d.ProjectID,
		ManagedHostID:   d.ManagedHostID,
		RuntimeTargetID: d.ID,
		Connection:      connection,
	}
	if err := target.Validate(); err != nil {
		return biz.Target{}, err
	}
	return target, nil
}

type scheduleLeaseDocument struct {
	ID      string `bson:"_id"`
	OwnerID string `bson:"owner_id"`
	Token   uint64 `bson:"token"`
}

type eventHintDocument struct {
	ID              string          `bson:"_id"`
	OrganizationID  string          `bson:"organization_id"`
	RuntimeTargetID string          `bson:"runtime_target_id"`
	Kind            biz.Kind        `bson:"kind"`
	RuntimeID       string          `bson:"runtime_id"`
	Action          biz.EventAction `bson:"action"`
	OccurredAt      time.Time       `bson:"occurred_at"`
	ReceivedAt      time.Time       `bson:"received_at"`
	ExpiresAt       time.Time       `bson:"expires_at"`
}

var _ biz.ScheduleRepository = (*MongoScheduleRepository)(nil)
var _ biz.EventHintRepository = (*MongoScheduleRepository)(nil)
