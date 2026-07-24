package migration

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func Default() []Migration {
	return []Migration{{
		Version: 1,
		Name:    "initial_product_indexes",
		Up:      createInitialProductIndexes,
	}}
}

func createInitialProductIndexes(ctx context.Context, database *mongo.Database) error {
	indexes := map[string][]mongo.IndexModel{
		"organizations": {
			uniqueIndex("uniq_organization_singleton", bson.D{{Key: "singleton_key", Value: 1}}),
		},
		"users": {
			uniqueIndex("uniq_user_email", bson.D{{Key: "organization_id", Value: 1}, {Key: "email_normalized", Value: 1}}),
		},
		"sessions": {
			uniqueIndex("uniq_session_token_hash", bson.D{{Key: "token_hash", Value: 1}}),
			{
				Keys:    bson.D{{Key: "expires_at", Value: 1}},
				Options: options.Index().SetName("ttl_session_expiry").SetExpireAfterSeconds(0),
			},
			{
				Keys:    bson.D{{Key: "user_id", Value: 1}},
				Options: options.Index().SetName("idx_session_user"),
			},
		},
		"projects": {
			uniqueIndex("uniq_project_name", bson.D{{Key: "organization_id", Value: 1}, {Key: "name_normalized", Value: 1}}),
		},
		"product_applications": {
			uniqueIndex("uniq_application_name", bson.D{{Key: "project_id", Value: 1}, {Key: "name_normalized", Value: 1}}),
		},
		"releases": {
			uniqueIndex("uniq_release_image", bson.D{{Key: "application_id", Value: 1}, {Key: "image_digest", Value: 1}}),
			{
				Keys:    bson.D{{Key: "project_id", Value: 1}, {Key: "application_id", Value: 1}, {Key: "created_at", Value: -1}},
				Options: options.Index().SetName("idx_release_application_created"),
			},
		},
		"runtime_targets": {
			uniqueIndex("uniq_runtime_target_name", bson.D{{Key: "project_id", Value: 1}, {Key: "name_normalized", Value: 1}}),
		},
		"environments": {
			uniqueIndex("uniq_environment_name", bson.D{{Key: "project_id", Value: 1}, {Key: "name_normalized", Value: 1}}),
		},
		"deployments": {
			uniqueIndex("uniq_deployment_idempotency", bson.D{{Key: "idempotency_key", Value: 1}}),
			{Keys: bson.D{{Key: "status", Value: 1}, {Key: "created_at", Value: 1}}, Options: options.Index().SetName("idx_deployment_claim")},
		},
		"audit_events": {
			{
				Keys:    bson.D{{Key: "organization_id", Value: 1}, {Key: "project_id", Value: 1}, {Key: "created_at", Value: -1}},
				Options: options.Index().SetName("idx_audit_scope_created"),
			},
		},
	}
	for collection, models := range indexes {
		if _, err := database.Collection(collection).Indexes().CreateMany(ctx, models); err != nil {
			return fmt.Errorf("create %s indexes: %w", collection, err)
		}
	}
	return nil
}

func uniqueIndex(name string, keys bson.D) mongo.IndexModel {
	return mongo.IndexModel{
		Keys:    keys,
		Options: options.Index().SetName(name).SetUnique(true),
	}
}
