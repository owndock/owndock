package migration

import (
	"context"
	"fmt"
	"sort"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// createInitialOwnDockSchema is the first public release's empty-database
// baseline. Development migrations are not an upgrade path for installations.
func createInitialOwnDockSchema(ctx context.Context, database *mongo.Database) error {
	collections, err := database.ListCollectionNames(ctx, bson.D{})
	if err != nil {
		return fmt.Errorf("inspect initial OwnDock database: %w", err)
	}
	for _, name := range collections {
		if name != migrationsCollection && name != lockCollection {
			return fmt.Errorf("initial OwnDock schema requires an empty database")
		}
	}
	steps := []struct {
		name string
		up   func(context.Context, *mongo.Database) error
	}{
		{"product", createBaselineProductIndexes},
		{"deployment rollback", indexDeploymentRollbackLookup},
		{"registry credentials", indexRegistryCredentials},
		{"managed hosts", indexManagedHostsAndTargetConnections},
		{"agent identity", indexAgentEnrollmentAndIdentity},
		{"login attempts", indexLoginAttemptExpiry},
		{"inventory", indexRuntimeInventory},
		{"inventory schedule", scheduleRuntimeInventory},
		{"inventory current", createBaselineInventoryCurrentIndexes},
		{"inventory events", scheduleRuntimeInventoryEvents},
		{"inventory views", createRuntimeInventoryViewIndexes},
		{"source repositories", indexSourceRepositories},
		{"build configurations", indexBuildConfigurations},
		{"builds", indexBuilds},
		{"build triggers", indexBuildTriggers},
		{"build hooks", indexBuildHooks},
		{"build execution", createBaselineBuildExecutionIndexes},
		{"build push results", indexBuildPushResults},
		{"artifacts", createBaselineArtifactIndexes},
		{"build logs", indexBoundedBuildLogs},
		{"automatic deployments", createBaselineAutomaticDeploymentIndex},
		{"invitations", addUserInvitations},
		{"project members", addProjectMembers},
		{"ingress limits", addIngressRateLimits},
		{"terminal", addTerminalAccessAndSessions},
		{"terminal lifecycle", createBaselineTerminalLifecycleIndexes},
		{"evidence", createBaselineEvidenceIndexes},
		{"trust policies", indexSignatureTrustPolicies},
		{"evidence verifications", indexEvidenceVerifications},
		{"signing profiles", indexSignatureSigningProfiles},
		{"vulnerability observations", indexVulnerabilityObservations},
		{"vulnerability waivers", indexVulnerabilityWaivers},
		{"deployment policies", indexDeploymentPolicies},
		{"runtime target retirements", scheduleRuntimeTargetRetirements},
		{"runtime target sessions", indexRuntimeTargetTerminalConvergence},
		{"resource retirements", createBaselineResourceRetirementIndexes},
		{"resource sessions", createBaselineResourceSessionIndexes},
		{"application builds", indexApplicationBuildRetirement},
		{"application artifacts", indexApplicationArtifactReleaseRetirement},
		{"vulnerability rescans", createBaselineVulnerabilityRescanIndexes},
	}
	for _, step := range steps {
		if err := step.up(ctx, database); err != nil {
			return fmt.Errorf("create initial OwnDock %s indexes: %w", step.name, err)
		}
	}
	return nil
}

func createBaselineProductIndexes(ctx context.Context, database *mongo.Database) error {
	indexes := map[string][]mongo.IndexModel{
		"organizations": {uniqueIndex("uniq_organization_singleton", bson.D{{Key: "singleton_key", Value: 1}})},
		"users":         {uniqueIndex("uniq_user_email", bson.D{{Key: "organization_id", Value: 1}, {Key: "email_normalized", Value: 1}})},
		"sessions": {
			uniqueIndex("uniq_session_token_hash", bson.D{{Key: "token_hash", Value: 1}}),
			{Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: options.Index().SetName("ttl_session_expiry").SetExpireAfterSeconds(0)},
			{Keys: bson.D{{Key: "user_id", Value: 1}}, Options: options.Index().SetName("idx_session_user")},
		},
		"projects": {uniqueIndex("uniq_project_name", bson.D{{Key: "organization_id", Value: 1}, {Key: "name_normalized", Value: 1}})},
		"product_applications": {
			{Keys: bson.D{{Key: "project_id", Value: 1}, {Key: "name_normalized", Value: 1}},
				Options: options.Index().SetName("uniq_application_name").SetUnique(true).
					SetPartialFilterExpression(bson.D{{Key: "status", Value: "active"}})},
		},
		"environments": {
			{Keys: bson.D{{Key: "project_id", Value: 1}, {Key: "name_normalized", Value: 1}},
				Options: options.Index().SetName("uniq_environment_name").SetUnique(true).
					SetPartialFilterExpression(bson.D{{Key: "status", Value: "active"}})},
		},
		"releases": {
			{Keys: bson.D{{Key: "application_id", Value: 1}, {Key: "image_digest", Value: 1}}, Options: options.Index().SetName("idx_release_image")},
			{Keys: bson.D{{Key: "project_id", Value: 1}, {Key: "application_id", Value: 1}, {Key: "created_at", Value: -1}}, Options: options.Index().SetName("idx_release_application_created")},
		},
		"runtime_targets": {uniqueIndex("uniq_runtime_target_name", bson.D{{Key: "project_id", Value: 1}, {Key: "name_normalized", Value: 1}})},
		"application_routes": {
			{Keys: bson.D{{Key: "organization_id", Value: 1}, {Key: "hostname", Value: 1}},
				Options: options.Index().SetName("uniq_application_route_hostname").SetUnique(true).
					SetPartialFilterExpression(bson.D{{Key: "status", Value: bson.D{{Key: "$in", Value: bson.A{"pending", "provisioning", "ready", "degraded", "retiring"}}}}})},
			{Keys: bson.D{{Key: "organization_id", Value: 1}, {Key: "project_id", Value: 1}, {Key: "slot", Value: 1}},
				Options: options.Index().SetName("uniq_application_route_project_slot").SetUnique(true).
					SetPartialFilterExpression(bson.D{{Key: "status", Value: bson.D{{Key: "$in", Value: bson.A{"pending", "provisioning", "ready", "degraded", "retiring"}}}}})},
			{Keys: bson.D{{Key: "organization_id", Value: 1}, {Key: "project_id", Value: 1}, {Key: "created_at", Value: 1}, {Key: "_id", Value: 1}}, Options: options.Index().SetName("idx_application_route_project_created")},
			{Keys: bson.D{{Key: "status", Value: 1}, {Key: "updated_at", Value: 1}, {Key: "_id", Value: 1}}, Options: options.Index().SetName("idx_application_route_status_updated")},
			{Keys: bson.D{{Key: "runtime_target_id", Value: 1}, {Key: "status", Value: 1}, {Key: "updated_at", Value: 1}}, Options: options.Index().SetName("idx_application_route_target_status")},
		},
		"application_route_host_configs": {
			{Keys: bson.D{{Key: "pending.request.deployment_id", Value: 1}},
				Options: options.Index().SetName("uniq_application_route_pending_deployment").SetUnique(true).
					SetPartialFilterExpression(bson.D{{Key: "pending.request.deployment_id", Value: bson.D{{Key: "$type", Value: "string"}}}})},
			{Keys: bson.D{{Key: "retirement.route_id", Value: 1}},
				Options: options.Index().SetName("uniq_application_route_retirement").SetUnique(true).
					SetPartialFilterExpression(bson.D{{Key: "retirement.route_id", Value: bson.D{{Key: "$type", Value: "string"}}}})},
			{Keys: bson.D{{Key: "reconciliation.route_id", Value: 1}},
				Options: options.Index().SetName("uniq_application_route_reconciliation").SetUnique(true).
					SetPartialFilterExpression(bson.D{{Key: "reconciliation.route_id", Value: bson.D{{Key: "$type", Value: "string"}}}})},
		},
		"deployments": {
			uniqueIndex("uniq_deployment_idempotency", bson.D{{Key: "project_id", Value: 1}, {Key: "idempotency_key", Value: 1}}),
			{Keys: bson.D{{Key: "status", Value: 1}, {Key: "created_at", Value: 1}}, Options: options.Index().SetName("idx_deployment_claim")},
		},
		"audit_events": {
			{Keys: bson.D{{Key: "organization_id", Value: 1}, {Key: "project_id", Value: 1}, {Key: "created_at", Value: -1}}, Options: options.Index().SetName("idx_audit_scope_created")},
		},
	}
	collections := make([]string, 0, len(indexes))
	for name := range indexes {
		collections = append(collections, name)
	}
	sort.Strings(collections)
	for _, name := range collections {
		if _, err := database.Collection(name).Indexes().CreateMany(ctx, indexes[name]); err != nil {
			return fmt.Errorf("create %s indexes: %w", name, err)
		}
	}
	return nil
}

func createBaselineInventoryCurrentIndexes(ctx context.Context, database *mongo.Database) error {
	if _, err := database.Collection("runtime_inventory_current").Indexes().CreateMany(ctx, []mongo.IndexModel{
		uniqueIndex("uniq_runtime_inventory_current_resource", bson.D{{Key: "runtime_target_id", Value: 1}, {Key: "kind", Value: 1}, {Key: "runtime_id", Value: 1}}),
		{Keys: bson.D{{Key: "organization_id", Value: 1}, {Key: "runtime_target_id", Value: 1}, {Key: "presence", Value: 1}, {Key: "kind", Value: 1}, {Key: "name", Value: 1}, {Key: "runtime_id", Value: 1}}, Options: options.Index().SetName("idx_runtime_inventory_current_state")},
		{Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: options.Index().SetName("ttl_runtime_inventory_current_absent").SetExpireAfterSeconds(0)},
	}); err != nil {
		return err
	}
	_, err := database.Collection("runtime_inventory_event_hints").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "runtime_target_id", Value: 1}, {Key: "received_at", Value: -1}}, Options: options.Index().SetName("idx_runtime_inventory_event_target")},
		{Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: options.Index().SetName("ttl_runtime_inventory_event_hints").SetExpireAfterSeconds(0)},
	})
	return err
}

func createBaselineBuildExecutionIndexes(ctx context.Context, database *mongo.Database) error {
	_, err := database.Collection("builds").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "status", Value: 1}, {Key: "lease.expires_at", Value: 1}, {Key: "created_at", Value: 1}, {Key: "_id", Value: 1}}, Options: options.Index().SetName("idx_build_execution_queue")},
		{Keys: bson.D{{Key: "build_configuration_id", Value: 1}, {Key: "status", Value: 1}}, Options: options.Index().SetName("idx_build_configuration_status")},
		{Keys: bson.D{{Key: "project_id", Value: 1}, {Key: "source_build_id", Value: 1}}, Options: options.Index().SetName("idx_build_retry_source")},
	})
	return err
}

func createBaselineArtifactIndexes(ctx context.Context, database *mongo.Database) error {
	if _, err := database.Collection("artifacts").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "build_id", Value: 1}}, Options: options.Index().SetName("uniq_artifact_build").SetUnique(true).SetPartialFilterExpression(bson.D{{Key: "build_id", Value: bson.D{{Key: "$type", Value: "string"}}}})},
		{Keys: bson.D{{Key: "project_id", Value: 1}, {Key: "created_at", Value: -1}, {Key: "_id", Value: -1}}, Options: options.Index().SetName("idx_artifact_project_created")},
		{Keys: bson.D{{Key: "release_status", Value: 1}, {Key: "created_at", Value: 1}, {Key: "_id", Value: 1}}, Options: options.Index().SetName("idx_artifact_release_queue")},
		{Keys: bson.D{{Key: "image_repository", Value: 1}, {Key: "image_digest", Value: 1}, {Key: "target_platform", Value: 1}}, Options: options.Index().SetName("idx_artifact_image")},
		{Keys: bson.D{{Key: "project_id", Value: 1}, {Key: "registration_key", Value: 1}}, Options: options.Index().SetName("uniq_external_artifact_registration").SetUnique(true).SetPartialFilterExpression(bson.D{{Key: "registration_key", Value: bson.D{{Key: "$type", Value: "string"}}}})},
		{Keys: bson.D{{Key: "project_id", Value: 1}, {Key: "origin", Value: 1}, {Key: "created_at", Value: -1}, {Key: "_id", Value: -1}}, Options: options.Index().SetName("idx_artifact_project_origin")},
	}); err != nil {
		return err
	}
	if _, err := database.Collection("releases").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "source_artifact_id", Value: 1}},
		Options: options.Index().SetName("uniq_release_source_artifact").SetUnique(true).
			SetPartialFilterExpression(bson.D{{Key: "source_artifact_id", Value: bson.D{{Key: "$type", Value: "string"}}}}),
	}); err != nil {
		return err
	}
	_, err := database.Collection("builds").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "project_id", Value: 1}, {Key: "artifact_id", Value: 1}}, Options: options.Index().SetName("idx_build_artifact"),
	})
	return err
}

func createBaselineAutomaticDeploymentIndex(ctx context.Context, database *mongo.Database) error {
	_, err := database.Collection("deployments").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "project_id", Value: 1}, {Key: "source_artifact_id", Value: 1}, {Key: "environment_id", Value: 1}, {Key: "runtime_target_id", Value: 1}},
		Options: options.Index().SetName("idx_automatic_deployment_artifact").SetPartialFilterExpression(bson.D{{Key: "trigger_source", Value: "automatic"}}),
	})
	return err
}

func createBaselineTerminalLifecycleIndexes(ctx context.Context, database *mongo.Database) error {
	_, err := database.Collection("terminal_sessions").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "authentication_session_id", Value: 1}, {Key: "active", Value: 1}},
		Options: options.Index().SetName("idx_terminal_authentication_session_active"),
	})
	return err
}

func createBaselineEvidenceIndexes(ctx context.Context, database *mongo.Database) error {
	if _, err := database.Collection("artifact_evidence").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "project_id", Value: 1}, {Key: "artifact_id", Value: 1}, {Key: "created_at", Value: 1}, {Key: "_id", Value: 1}}, Options: options.Index().SetName("idx_artifact_evidence_list")},
		{Keys: bson.D{{Key: "subject_digest", Value: 1}, {Key: "descriptor_digest", Value: 1}}, Options: options.Index().SetName("idx_artifact_evidence_digest")},
		uniqueIndex("uniq_artifact_evidence_descriptor", bson.D{{Key: "project_id", Value: 1}, {Key: "artifact_id", Value: 1}, {Key: "kind", Value: 1}, {Key: "producer", Value: 1}, {Key: "format_version", Value: 1}, {Key: "descriptor_digest", Value: 1}}),
	}); err != nil {
		return err
	}
	_, err := database.Collection("artifact_evidence_jobs").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "status", Value: 1}, {Key: "lease.expires_at", Value: 1}, {Key: "created_at", Value: 1}, {Key: "_id", Value: 1}}, Options: options.Index().SetName("idx_artifact_evidence_job_queue")},
		uniqueIndex("uniq_artifact_evidence_job_idempotency", bson.D{{Key: "organization_id", Value: 1}, {Key: "project_id", Value: 1}, {Key: "idempotency_key", Value: 1}}),
	})
	return err
}

func createBaselineResourceRetirementIndexes(ctx context.Context, database *mongo.Database) error {
	for _, item := range []struct{ collection, queue string }{
		{"product_applications", "idx_application_retirement_queue"},
		{"environments", "idx_environment_retirement_queue"},
	} {
		_, err := database.Collection(item.collection).Indexes().CreateOne(ctx, mongo.IndexModel{
			Keys:    bson.D{{Key: "status", Value: 1}, {Key: "retirement.started_at", Value: 1}, {Key: "_id", Value: 1}},
			Options: options.Index().SetName(item.queue).SetPartialFilterExpression(bson.D{{Key: "status", Value: "retiring"}}),
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func createBaselineResourceSessionIndexes(ctx context.Context, database *mongo.Database) error {
	_, err := database.Collection("terminal_sessions").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys: bson.D{{Key: "organization_id", Value: 1}, {Key: "project_id", Value: 1},
				{Key: "application_id", Value: 1}, {Key: "active", Value: 1},
				{Key: "created_at", Value: 1}, {Key: "_id", Value: 1}},
			Options: options.Index().SetName("idx_terminal_application_active").
				SetPartialFilterExpression(bson.D{{Key: "active", Value: true}}),
		},
		{
			Keys: bson.D{{Key: "organization_id", Value: 1}, {Key: "project_id", Value: 1},
				{Key: "environment_id", Value: 1}, {Key: "active", Value: 1},
				{Key: "created_at", Value: 1}, {Key: "_id", Value: 1}},
			Options: options.Index().SetName("idx_terminal_environment_active").
				SetPartialFilterExpression(bson.D{{Key: "active", Value: true}}),
		},
	})
	return err
}

func createBaselineVulnerabilityRescanIndexes(ctx context.Context, database *mongo.Database) error {
	if _, err := database.Collection("artifact_evidence_jobs").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "artifact_id", Value: 1}, {Key: "kind", Value: 1}},
		Options: options.Index().SetName("uniq_active_vulnerability_scan").SetUnique(true).
			SetPartialFilterExpression(bson.D{{Key: "kind", Value: "vulnerability_report"}, {Key: "active", Value: true}}),
	}); err != nil {
		return err
	}
	_, err := database.Collection("vulnerability_observations").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "scanner", Value: 1}, {Key: "fresh_until", Value: 1}, {Key: "_id", Value: 1}},
		Options: options.Index().SetName("idx_vulnerability_observation_rescan"),
	})
	return err
}
