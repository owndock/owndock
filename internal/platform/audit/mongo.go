package audit

import (
	"context"
	"fmt"
	"strings"
	"time"

	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const collectionName = "audit_events"

type MongoStore struct {
	collection *mongo.Collection
}

func NewMongoStore(database *mongo.Database) *MongoStore {
	return &MongoStore{collection: database.Collection(collectionName)}
}

func (s *MongoStore) Record(ctx context.Context, event sharedaudit.Event) error {
	if strings.TrimSpace(event.ID) == "" ||
		strings.TrimSpace(event.OrganizationID) == "" ||
		strings.TrimSpace(event.ActorID) == "" ||
		strings.TrimSpace(event.Action) == "" ||
		strings.TrimSpace(event.ResourceType) == "" ||
		strings.TrimSpace(event.ResourceID) == "" ||
		event.CreatedAt.IsZero() {
		return fmt.Errorf("invalid audit event")
	}
	_, err := s.collection.InsertOne(ctx, eventDocument{
		ID:             event.ID,
		OrganizationID: event.OrganizationID,
		ProjectID:      event.ProjectID,
		ActorID:        event.ActorID,
		Action:         event.Action,
		ResourceType:   event.ResourceType,
		ResourceID:     event.ResourceID,
		RequestID:      event.RequestID,
		CreatedAt:      event.CreatedAt.UTC(),
	})
	if err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}
	return nil
}

func (s *MongoStore) List(ctx context.Context, organizationID, projectID string, limit int64) ([]sharedaudit.Event, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	filter := bson.D{{Key: "organization_id", Value: organizationID}}
	if projectID != "" {
		filter = append(filter, bson.E{Key: "project_id", Value: projectID})
	}
	cursor, err := s.collection.Find(
		ctx,
		filter,
		options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}, {Key: "_id", Value: -1}}).SetLimit(limit),
	)
	if err != nil {
		return nil, fmt.Errorf("find audit events: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()
	var documents []eventDocument
	if err := cursor.All(ctx, &documents); err != nil {
		return nil, fmt.Errorf("decode audit events: %w", err)
	}
	events := make([]sharedaudit.Event, len(documents))
	for i, item := range documents {
		events[i] = item.event()
	}
	return events, nil
}

type eventDocument struct {
	ID             string    `bson:"_id"`
	OrganizationID string    `bson:"organization_id"`
	ProjectID      string    `bson:"project_id,omitempty"`
	ActorID        string    `bson:"actor_id"`
	Action         string    `bson:"action"`
	ResourceType   string    `bson:"resource_type"`
	ResourceID     string    `bson:"resource_id"`
	RequestID      string    `bson:"request_id,omitempty"`
	CreatedAt      time.Time `bson:"created_at"`
}

func (d eventDocument) event() sharedaudit.Event {
	return sharedaudit.Event{
		ID:             d.ID,
		OrganizationID: d.OrganizationID,
		ProjectID:      d.ProjectID,
		ActorID:        d.ActorID,
		Action:         d.Action,
		ResourceType:   d.ResourceType,
		ResourceID:     d.ResourceID,
		RequestID:      d.RequestID,
		CreatedAt:      d.CreatedAt,
	}
}
