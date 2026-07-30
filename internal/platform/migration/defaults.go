package migration

import (
	"context"
	"crypto/sha256"
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
		{Version: 10, Name: "add_deployment_cutover_sequences", Up: addDeploymentCutoverSequences},
		{Version: 11, Name: "index_login_attempt_expiry", Up: indexLoginAttemptExpiry},
		{Version: 12, Name: "index_runtime_inventory", Up: indexRuntimeInventory},
	}
}

func indexRuntimeInventory(
	ctx context.Context,
	database *mongo.Database,
) error {
	if _, err := database.Collection("runtime_inventory_observations").
		Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys: bson.D{
				{Key: "runtime_target_id", Value: 1},
				{Key: "status", Value: 1},
				{Key: "started_at", Value: -1},
			},
			Options: options.Index().SetName("idx_runtime_inventory_observation_target"),
		},
		{
			Keys: bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().
				SetName("ttl_runtime_inventory_observations").
				SetExpireAfterSeconds(0),
		},
	}); err != nil {
		return fmt.Errorf("create runtime inventory observation indexes: %w", err)
	}
	if _, err := database.Collection("runtime_inventory_chunks").
		Indexes().CreateMany(ctx, []mongo.IndexModel{
		uniqueIndex(
			"uniq_runtime_inventory_chunk",
			bson.D{
				{Key: "observation_id", Value: 1},
				{Key: "index", Value: 1},
			},
		),
		{
			Keys: bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().
				SetName("ttl_runtime_inventory_chunks").
				SetExpireAfterSeconds(0),
		},
	}); err != nil {
		return fmt.Errorf("create runtime inventory chunk indexes: %w", err)
	}
	if _, err := database.Collection("runtime_inventory_resources").
		Indexes().CreateMany(ctx, []mongo.IndexModel{
		uniqueIndex(
			"uniq_runtime_inventory_resource",
			bson.D{
				{Key: "runtime_target_id", Value: 1},
				{Key: "observation_id", Value: 1},
				{Key: "kind", Value: 1},
				{Key: "runtime_id", Value: 1},
			},
		),
		{
			Keys: bson.D{
				{Key: "observation_id", Value: 1},
				{Key: "organization_id", Value: 1},
				{Key: "runtime_target_id", Value: 1},
				{Key: "kind", Value: 1},
				{Key: "name", Value: 1},
				{Key: "runtime_id", Value: 1},
			},
			Options: options.Index().SetName("idx_runtime_inventory_current"),
		},
		{
			Keys: bson.D{
				{Key: "organization_id", Value: 1},
				{Key: "project_id", Value: 1},
				{Key: "managed", Value: 1},
				{Key: "kind", Value: 1},
			},
			Options: options.Index().SetName("idx_runtime_inventory_project"),
		},
		{
			Keys: bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().
				SetName("ttl_runtime_inventory_resources").
				SetExpireAfterSeconds(0),
		},
	}); err != nil {
		return fmt.Errorf("create runtime inventory resource indexes: %w", err)
	}
	if _, err := database.Collection("runtime_inventory_heads").
		Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{
			{Key: "organization_id", Value: 1},
			{Key: "runtime_target_id", Value: 1},
		},
		Options: options.Index().
			SetName("uniq_runtime_inventory_head").
			SetUnique(true),
	}); err != nil {
		return fmt.Errorf("create runtime inventory head index: %w", err)
	}
	if _, err := database.Collection("runtime_inventory_counters").
		Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{
			{Key: "organization_id", Value: 1},
			{Key: "runtime_target_id", Value: 1},
		},
		Options: options.Index().
			SetName("uniq_runtime_inventory_counter").
			SetUnique(true),
	}); err != nil {
		return fmt.Errorf("create runtime inventory counter index: %w", err)
	}
	return nil
}

func indexLoginAttemptExpiry(
	ctx context.Context,
	database *mongo.Database,
) error {
	_, err := database.Collection("login_attempts").Indexes().CreateOne(
		ctx,
		mongo.IndexModel{
			Keys: bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().
				SetName("ttl_login_attempt_expiry").
				SetExpireAfterSeconds(0),
		},
	)
	if err != nil {
		return fmt.Errorf("create login attempt expiry index: %w", err)
	}
	return nil
}

func addDeploymentCutoverSequences(
	ctx context.Context,
	database *mongo.Database,
) error {
	deployments := database.Collection("deployments")
	cursor, err := deployments.Find(
		ctx,
		bson.D{},
		options.Find().SetSort(bson.D{
			{Key: "project_id", Value: 1},
			{Key: "application_id", Value: 1},
			{Key: "environment_id", Value: 1},
			{Key: "runtime_target_id", Value: 1},
			{Key: "created_at", Value: 1},
			{Key: "_id", Value: 1},
		}),
	)
	if err != nil {
		return fmt.Errorf("find deployments for cutover sequence migration: %w", err)
	}
	defer cursor.Close(ctx)

	type deploymentScope struct {
		ID              string `bson:"_id"`
		ProjectID       string `bson:"project_id"`
		ApplicationID   string `bson:"application_id"`
		EnvironmentID   string `bson:"environment_id"`
		RuntimeTargetID string `bson:"runtime_target_id"`
		CutoverSequence uint64 `bson:"cutover_sequence,omitempty"`
	}
	sequences := make(map[string]uint64)
	counters := database.Collection("deployment_cutover_sequences")
	for cursor.Next(ctx) {
		var item deploymentScope
		if err := cursor.Decode(&item); err != nil {
			return fmt.Errorf("decode deployment cutover scope: %w", err)
		}
		scope := item.ProjectID + "\x00" + item.ApplicationID + "\x00" +
			item.EnvironmentID + "\x00" + item.RuntimeTargetID
		sequence := sequences[scope] + 1
		if item.CutoverSequence > sequence {
			sequence = item.CutoverSequence
		}
		sequences[scope] = sequence
		if item.CutoverSequence == 0 {
			if _, err := deployments.UpdateByID(
				ctx,
				item.ID,
				bson.D{{Key: "$set", Value: bson.D{
					{Key: "cutover_sequence", Value: sequence},
				}}},
			); err != nil {
				return fmt.Errorf("backfill deployment cutover sequence: %w", err)
			}
		}
		scopeHash := sha256.Sum256([]byte(scope))
		if _, err := counters.UpdateOne(
			ctx,
			bson.D{{Key: "_id", Value: fmt.Sprintf("%x", scopeHash[:])}},
			bson.D{
				{Key: "$max", Value: bson.D{{Key: "sequence", Value: sequence}}},
				{Key: "$setOnInsert", Value: bson.D{
					{Key: "project_id", Value: item.ProjectID},
					{Key: "application_id", Value: item.ApplicationID},
					{Key: "environment_id", Value: item.EnvironmentID},
					{Key: "runtime_target_id", Value: item.RuntimeTargetID},
				}},
			},
			options.UpdateOne().SetUpsert(true),
		); err != nil {
			return fmt.Errorf("seed deployment cutover counter: %w", err)
		}
	}
	if err := cursor.Err(); err != nil {
		return fmt.Errorf("iterate deployment cutover scopes: %w", err)
	}
	return nil
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
