package data

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/owndock/owndock/internal/modules/runtimeinventory/biz"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type MongoViewRepository struct {
	current  *mongo.Collection
	projects *mongo.Collection
	hosts    *mongo.Collection
}

func NewMongoViewRepository(database *mongo.Database) *MongoViewRepository {
	return &MongoViewRepository{
		current:  database.Collection("runtime_inventory_current"),
		projects: database.Collection("projects"),
		hosts:    database.Collection("managed_hosts"),
	}
}

func (r *MongoViewRepository) ListProject(
	ctx context.Context,
	organizationID, projectID string,
	query biz.ViewQuery,
) (biz.StatePage, error) {
	if err := query.Validate(); err != nil {
		return biz.StatePage{}, err
	}
	if query.Cursor != "" {
		if _, err := decodeViewCursor(query.Cursor); err != nil {
			return biz.StatePage{}, err
		}
	}
	if err := scopeExists(ctx, r.projects, organizationID, projectID); err != nil {
		return biz.StatePage{}, err
	}
	if query.Kind != "" && query.Kind != biz.KindContainer {
		return biz.StatePage{Items: []biz.State{}}, nil
	}
	filter := bson.D{
		{Key: "organization_id", Value: organizationID},
		{Key: "project_id", Value: projectID},
		{Key: "managed", Value: true},
		// Project ownership is currently verified for containers only. Image,
		// network and volume details remain available as safe container summaries.
		{Key: "kind", Value: biz.KindContainer},
	}
	return r.list(ctx, filter, query)
}

func (r *MongoViewRepository) ListHost(
	ctx context.Context,
	organizationID, hostID string,
	query biz.ViewQuery,
) (biz.StatePage, error) {
	if err := query.Validate(); err != nil {
		return biz.StatePage{}, err
	}
	if query.Cursor != "" {
		if _, err := decodeViewCursor(query.Cursor); err != nil {
			return biz.StatePage{}, err
		}
	}
	if err := scopeExists(ctx, r.hosts, organizationID, hostID); err != nil {
		return biz.StatePage{}, err
	}
	return r.list(ctx, bson.D{
		{Key: "organization_id", Value: organizationID},
		{Key: "managed_host_id", Value: hostID},
	}, query)
}

func scopeExists(
	ctx context.Context,
	collection *mongo.Collection,
	organizationID, id string,
) error {
	err := collection.FindOne(ctx, bson.D{
		{Key: "_id", Value: id},
		{Key: "organization_id", Value: organizationID},
	}, options.FindOne().SetProjection(bson.D{{Key: "_id", Value: 1}})).Err()
	if err == mongo.ErrNoDocuments {
		return biz.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("find runtime inventory scope: %w", err)
	}
	return nil
}

type viewCursor struct {
	Version         int      `json:"v"`
	RuntimeTargetID string   `json:"runtime_target_id"`
	Kind            biz.Kind `json:"kind"`
	Name            string   `json:"name"`
	RuntimeID       string   `json:"runtime_id"`
}

func (r *MongoViewRepository) list(
	ctx context.Context,
	filter bson.D,
	query biz.ViewQuery,
) (biz.StatePage, error) {
	if err := query.Validate(); err != nil {
		return biz.StatePage{}, err
	}
	if !query.IncludeAbsent {
		filter = append(filter, bson.E{Key: "presence", Value: biz.PresencePresent})
	}
	if query.RuntimeTargetID != "" {
		filter = append(filter, bson.E{Key: "runtime_target_id", Value: query.RuntimeTargetID})
	}
	if query.Kind != "" {
		filter = append(filter, bson.E{Key: "kind", Value: query.Kind})
	}
	if query.Cursor != "" {
		cursor, err := decodeViewCursor(query.Cursor)
		if err != nil {
			return biz.StatePage{}, err
		}
		filter = append(filter, bson.E{Key: "$or", Value: cursorAfter(cursor)})
	}
	findCursor, err := r.current.Find(ctx, filter, options.Find().
		SetProjection(bson.D{
			{Key: "labels", Value: 0},
			{Key: "attributes", Value: 0},
			{Key: "expires_at", Value: 0},
		}).
		SetSort(viewSort()).SetLimit(int64(query.Limit+1)))
	if err != nil {
		return biz.StatePage{}, fmt.Errorf("find runtime inventory view: %w", err)
	}
	defer func() { _ = findCursor.Close(ctx) }()
	var documents []resourceDocument
	if err := findCursor.All(ctx, &documents); err != nil {
		return biz.StatePage{}, fmt.Errorf("decode runtime inventory view: %w", err)
	}
	page := biz.StatePage{Items: make([]biz.State, 0, min(len(documents), query.Limit))}
	for index, document := range documents {
		if index == query.Limit {
			last := documents[index-1]
			page.NextCursor, err = encodeViewCursor(viewCursor{
				Version: 1, RuntimeTargetID: last.RuntimeTargetID,
				Kind: last.Kind, Name: last.Name, RuntimeID: last.RuntimeID,
			})
			if err != nil {
				return biz.StatePage{}, err
			}
			break
		}
		state := document.state()
		if err := state.Validate(); err != nil {
			return biz.StatePage{}, fmt.Errorf("validate runtime inventory view: %w", err)
		}
		page.Items = append(page.Items, state)
	}
	return page, nil
}

func viewSort() bson.D {
	return bson.D{
		{Key: "runtime_target_id", Value: 1},
		{Key: "kind", Value: 1},
		{Key: "name", Value: 1},
		{Key: "runtime_id", Value: 1},
	}
}

func cursorAfter(cursor viewCursor) bson.A {
	return bson.A{
		bson.D{{Key: "runtime_target_id", Value: bson.D{{Key: "$gt", Value: cursor.RuntimeTargetID}}}},
		bson.D{{Key: "runtime_target_id", Value: cursor.RuntimeTargetID}, {Key: "kind", Value: bson.D{{Key: "$gt", Value: cursor.Kind}}}},
		bson.D{{Key: "runtime_target_id", Value: cursor.RuntimeTargetID}, {Key: "kind", Value: cursor.Kind}, {Key: "name", Value: bson.D{{Key: "$gt", Value: cursor.Name}}}},
		bson.D{{Key: "runtime_target_id", Value: cursor.RuntimeTargetID}, {Key: "kind", Value: cursor.Kind}, {Key: "name", Value: cursor.Name}, {Key: "runtime_id", Value: bson.D{{Key: "$gt", Value: cursor.RuntimeID}}}},
	}
}

func encodeViewCursor(cursor viewCursor) (string, error) {
	payload, err := json.Marshal(cursor)
	if err != nil {
		return "", fmt.Errorf("encode runtime inventory cursor: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func decodeViewCursor(value string) (viewCursor, error) {
	payload, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return viewCursor{}, biz.ErrInvalidViewQuery
	}
	var cursor viewCursor
	if err := json.Unmarshal(payload, &cursor); err != nil || cursor.Version != 1 ||
		cursor.RuntimeTargetID == "" || !cursor.Kind.Valid() ||
		cursor.Name == "" || cursor.RuntimeID == "" {
		return viewCursor{}, biz.ErrInvalidViewQuery
	}
	return cursor, nil
}

var _ biz.ViewRepository = (*MongoViewRepository)(nil)
