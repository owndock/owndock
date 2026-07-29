package migration

import (
	"context"
	"errors"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func Default() []Migration {
	return []Migration{
		{Version: 1, Name: "initial_product_indexes", Up: createInitialProductIndexes},
		{Version: 2, Name: "scope_deployment_idempotency", Up: scopeDeploymentIdempotency},
		{Version: 3, Name: "index_deployment_rollback_lookup", Up: indexDeploymentRollbackLookup},
		{Version: 4, Name: "prepare_deployment_execution_metadata", Up: prepareDeploymentExecutionMetadata},
		{Version: 5, Name: "index_registry_credentials", Up: indexRegistryCredentials},
		{Version: 6, Name: "backfill_release_runtime_spec", Up: backfillReleaseRuntimeSpec},
		{Version: 7, Name: "allow_release_spec_variants", Up: allowReleaseSpecVariants},
		{Version: 8, Name: "index_managed_hosts_and_target_connections", Up: indexManagedHostsAndTargetConnections},
		{Version: 9, Name: "index_agent_enrollment_and_identity", Up: indexAgentEnrollmentAndIdentity},
	}
}

func indexAgentEnrollmentAndIdentity(
	ctx context.Context,
	database *mongo.Database,
) error {
	if _, err := database.Collection("agent_enrollments").Indexes().CreateMany(
		ctx,
		[]mongo.IndexModel{
			uniqueIndex(
				"uniq_agent_enrollment_token",
				bson.D{{Key: "token_hash", Value: 1}},
			),
			{
				Keys: bson.D{{Key: "expires_at", Value: 1}},
				Options: options.Index().
					SetName("ttl_agent_enrollment_expiry").
					SetExpireAfterSeconds(0),
			},
			{
				Keys: bson.D{
					{Key: "managed_host_id", Value: 1},
					{Key: "created_at", Value: -1},
				},
				Options: options.Index().SetName("idx_agent_enrollment_host"),
			},
		},
	); err != nil {
		return fmt.Errorf("create agent enrollment indexes: %w", err)
	}
	if _, err := database.Collection("agent_identities").Indexes().CreateMany(
		ctx,
		[]mongo.IndexModel{
			uniqueIndex(
				"uniq_agent_certificate_serial",
				bson.D{{Key: "certificate_serial", Value: 1}},
			),
			uniqueIndex(
				"uniq_agent_certificate_fingerprint",
				bson.D{{Key: "certificate_sha256", Value: 1}},
			),
			{
				Keys: bson.D{
					{Key: "managed_host_id", Value: 1},
					{Key: "issued_at", Value: -1},
				},
				Options: options.Index().SetName("idx_agent_identity_host"),
			},
		},
	); err != nil {
		return fmt.Errorf("create agent identity indexes: %w", err)
	}
	return nil
}

func indexManagedHostsAndTargetConnections(
	ctx context.Context,
	database *mongo.Database,
) error {
	if _, err := database.Collection("managed_hosts").Indexes().CreateMany(
		ctx,
		[]mongo.IndexModel{
			uniqueIndex(
				"uniq_managed_host_name",
				bson.D{
					{Key: "organization_id", Value: 1},
					{Key: "name_normalized", Value: 1},
				},
			),
			{
				Keys: bson.D{
					{Key: "organization_id", Value: 1},
					{Key: "status", Value: 1},
					{Key: "updated_at", Value: -1},
				},
				Options: options.Index().SetName("idx_managed_host_status"),
			},
		},
	); err != nil {
		return fmt.Errorf("create managed host indexes: %w", err)
	}
	if _, err := database.Collection("runtime_targets").Indexes().CreateOne(
		ctx,
		mongo.IndexModel{
			Keys: bson.D{
				{Key: "managed_host_id", Value: 1},
				{Key: "project_id", Value: 1},
				{Key: "created_at", Value: 1},
			},
			Options: options.Index().SetName("idx_runtime_target_host"),
		},
	); err != nil {
		return fmt.Errorf("create runtime target host index: %w", err)
	}
	return nil
}

func allowReleaseSpecVariants(ctx context.Context, database *mongo.Database) error {
	indexes := database.Collection("releases").Indexes()
	if err := indexes.DropOne(ctx, "uniq_release_image"); err != nil {
		var commandError mongo.CommandError
		if !errors.As(err, &commandError) || commandError.Code != 27 {
			return fmt.Errorf("drop release image uniqueness index: %w", err)
		}
	}
	_, err := indexes.CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{
			{Key: "application_id", Value: 1},
			{Key: "image_digest", Value: 1},
		},
		Options: options.Index().SetName("idx_release_image"),
	})
	if err != nil {
		return fmt.Errorf("create release image lookup index: %w", err)
	}
	return nil
}

func backfillReleaseRuntimeSpec(ctx context.Context, database *mongo.Database) error {
	_, err := database.Collection("releases").UpdateMany(
		ctx,
		bson.D{{Key: "runtime_spec", Value: bson.D{{Key: "$exists", Value: false}}}},
		bson.D{{Key: "$set", Value: bson.D{{Key: "runtime_spec", Value: bson.D{
			{Key: "ports", Value: bson.A{}},
			{Key: "environment_keys", Value: bson.A{}},
			{Key: "resources", Value: bson.D{
				{Key: "cpu_milli", Value: 500},
				{Key: "memory_bytes", Value: 256 * 1024 * 1024},
			}},
		}}}}},
	)
	if err != nil {
		return fmt.Errorf("backfill release runtime specifications: %w", err)
	}
	return nil
}

func indexRegistryCredentials(ctx context.Context, database *mongo.Database) error {
	_, err := database.Collection("registry_credentials").Indexes().CreateMany(ctx, []mongo.IndexModel{
		uniqueIndex(
			"uniq_registry_credential_name",
			bson.D{{Key: "project_id", Value: 1}, {Key: "name_normalized", Value: 1}},
		),
		{
			Keys: bson.D{
				{Key: "project_id", Value: 1},
				{Key: "server", Value: 1},
				{Key: "created_at", Value: 1},
			},
			Options: options.Index().SetName("idx_registry_credential_server"),
		},
	})
	if err != nil {
		return fmt.Errorf("create registry credential indexes: %w", err)
	}
	return nil
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
			{
				Keys:    bson.D{{Key: "application_id", Value: 1}, {Key: "image_digest", Value: 1}},
				Options: options.Index().SetName("idx_release_image"),
			},
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

func scopeDeploymentIdempotency(ctx context.Context, database *mongo.Database) error {
	indexes := database.Collection("deployments").Indexes()
	if err := indexes.DropOne(ctx, "uniq_deployment_idempotency"); err != nil {
		var commandError mongo.CommandError
		if !errors.As(err, &commandError) || commandError.Code != 27 {
			return fmt.Errorf("drop global deployment idempotency index: %w", err)
		}
	}
	if _, err := indexes.CreateOne(ctx, uniqueIndex(
		"uniq_deployment_idempotency",
		bson.D{{Key: "project_id", Value: 1}, {Key: "idempotency_key", Value: 1}},
	)); err != nil {
		return fmt.Errorf("create scoped deployment idempotency index: %w", err)
	}
	return nil
}

func indexDeploymentRollbackLookup(ctx context.Context, database *mongo.Database) error {
	_, err := database.Collection("deployments").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{
			{Key: "project_id", Value: 1},
			{Key: "application_id", Value: 1},
			{Key: "environment_id", Value: 1},
			{Key: "runtime_target_id", Value: 1},
			{Key: "release_id", Value: 1},
			{Key: "status", Value: 1},
			{Key: "created_at", Value: -1},
		},
		Options: options.Index().SetName("idx_deployment_rollback_lookup"),
	})
	if err != nil {
		return fmt.Errorf("create deployment rollback lookup index: %w", err)
	}
	return nil
}

func prepareDeploymentExecutionMetadata(ctx context.Context, database *mongo.Database) error {
	deployments := database.Collection("deployments")
	if _, err := deployments.UpdateMany(
		ctx,
		bson.D{{Key: "status", Value: "building"}},
		bson.D{{Key: "$set", Value: bson.D{{Key: "status", Value: "preparing"}}}},
	); err != nil {
		return fmt.Errorf("rename deployment building status: %w", err)
	}
	if _, err := deployments.UpdateMany(
		ctx,
		bson.D{
			{Key: "status", Value: "failed"},
			{Key: "failure_category", Value: bson.D{{Key: "$exists", Value: false}}},
		},
		bson.D{{Key: "$set", Value: bson.D{{Key: "failure_category", Value: "unknown"}}}},
	); err != nil {
		return fmt.Errorf("backfill deployment failure category: %w", err)
	}
	cursor, err := deployments.Find(ctx, bson.D{
		{Key: "project_id", Value: bson.D{{Key: "$ne", Value: ""}}},
		{Key: "organization_id", Value: bson.D{{Key: "$exists", Value: false}}},
	})
	if err != nil {
		return fmt.Errorf("find deployments missing organization: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()
	for cursor.Next(ctx) {
		var deployment struct {
			ID        string `bson:"_id"`
			ProjectID string `bson:"project_id"`
		}
		if err := cursor.Decode(&deployment); err != nil {
			return fmt.Errorf("decode deployment organization backfill: %w", err)
		}
		var project struct {
			OrganizationID string `bson:"organization_id"`
		}
		if err := database.Collection("projects").FindOne(
			ctx, bson.D{{Key: "_id", Value: deployment.ProjectID}},
		).Decode(&project); err != nil {
			return fmt.Errorf("resolve deployment project organization: %w", err)
		}
		if _, err := deployments.UpdateOne(
			ctx,
			bson.D{
				{Key: "_id", Value: deployment.ID},
				{Key: "organization_id", Value: bson.D{{Key: "$exists", Value: false}}},
			},
			bson.D{{Key: "$set", Value: bson.D{{Key: "organization_id", Value: project.OrganizationID}}}},
		); err != nil {
			return fmt.Errorf("backfill deployment organization: %w", err)
		}
	}
	if err := cursor.Err(); err != nil {
		return fmt.Errorf("scan deployments missing organization: %w", err)
	}
	return nil
}

func uniqueIndex(name string, keys bson.D) mongo.IndexModel {
	return mongo.IndexModel{
		Keys:    keys,
		Options: options.Index().SetName(name).SetUnique(true),
	}
}
