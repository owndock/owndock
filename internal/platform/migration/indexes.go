package migration

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func indexApplicationArtifactReleaseRetirement(ctx context.Context, database *mongo.Database) error {
	_, err := database.Collection("artifacts").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{
			{Key: "organization_id", Value: 1},
			{Key: "project_id", Value: 1},
			{Key: "application_id", Value: 1},
			{Key: "release_status", Value: 1},
			{Key: "created_at", Value: 1},
			{Key: "_id", Value: 1},
		},
		Options: options.Index().SetName("idx_artifact_application_release_retirement"),
	})
	if err != nil {
		return fmt.Errorf("create Application Artifact release retirement index: %w", err)
	}
	return nil
}

func indexApplicationBuildRetirement(ctx context.Context, database *mongo.Database) error {
	_, err := database.Collection("builds").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{
			{Key: "organization_id", Value: 1},
			{Key: "project_id", Value: 1},
			{Key: "application_id", Value: 1},
			{Key: "status", Value: 1},
			{Key: "created_at", Value: 1},
			{Key: "_id", Value: 1},
		},
		Options: options.Index().SetName("idx_build_application_retirement"),
	})
	if err != nil {
		return fmt.Errorf("create application build retirement index: %w", err)
	}
	return nil
}

func indexRuntimeTargetTerminalConvergence(ctx context.Context, database *mongo.Database) error {
	_, err := database.Collection("terminal_sessions").Indexes().CreateOne(
		ctx,
		mongo.IndexModel{
			Keys: bson.D{
				{Key: "organization_id", Value: 1},
				{Key: "project_id", Value: 1},
				{Key: "runtime_target_id", Value: 1},
				{Key: "active", Value: 1},
				{Key: "created_at", Value: 1},
				{Key: "_id", Value: 1},
			},
			Options: options.Index().SetName("idx_terminal_runtime_target_active").
				SetPartialFilterExpression(bson.D{{Key: "active", Value: true}}),
		},
	)
	if err != nil {
		return fmt.Errorf("create Runtime Target terminal convergence index: %w", err)
	}
	return nil
}

func scheduleRuntimeTargetRetirements(ctx context.Context, database *mongo.Database) error {
	_, err := database.Collection("runtime_targets").Indexes().CreateOne(
		ctx,
		mongo.IndexModel{
			Keys: bson.D{
				{Key: "status", Value: 1},
				{Key: "retirement.started_at", Value: 1},
				{Key: "_id", Value: 1},
			},
			Options: options.Index().SetName("idx_runtime_target_retirement_queue"),
		},
	)
	if err != nil {
		return fmt.Errorf("create Runtime Target retirement queue index: %w", err)
	}
	return nil
}

func indexDeploymentPolicies(ctx context.Context, database *mongo.Database) error {
	_, err := database.Collection("deployment_policies").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "organization_id", Value: 1}, {Key: "project_id", Value: 1},
			{Key: "scope", Value: 1}, {Key: "environment_id", Value: 1}},
			Options: options.Index().SetName("uniq_deployment_policy_scope").SetUnique(true)},
		{Keys: bson.D{{Key: "organization_id", Value: 1}, {Key: "project_id", Value: 1},
			{Key: "enabled", Value: 1}, {Key: "scope", Value: 1}, {Key: "environment_id", Value: 1}},
			Options: options.Index().SetName("idx_deployment_policy_evaluation")},
	})
	if err != nil {
		return fmt.Errorf("create deployment policy indexes: %w", err)
	}
	return nil
}

func indexVulnerabilityWaivers(ctx context.Context, database *mongo.Database) error {
	_, err := database.Collection("vulnerability_waivers").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "organization_id", Value: 1}, {Key: "project_id", Value: 1},
			{Key: "created_at", Value: -1}, {Key: "_id", Value: -1}},
			Options: options.Index().SetName("idx_vulnerability_waiver_list")},
		{Keys: bson.D{{Key: "organization_id", Value: 1}, {Key: "project_id", Value: 1},
			{Key: "vulnerability_id", Value: 1}, {Key: "scope", Value: 1},
			{Key: "artifact_id", Value: 1}, {Key: "expires_at", Value: 1}, {Key: "revoked_at", Value: 1}},
			Options: options.Index().SetName("idx_vulnerability_waiver_applicability")},
	})
	if err != nil {
		return fmt.Errorf("create vulnerability waiver indexes: %w", err)
	}
	return nil
}

func indexVulnerabilityObservations(ctx context.Context, database *mongo.Database) error {
	_, err := database.Collection("vulnerability_observations").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "project_id", Value: 1}, {Key: "artifact_id", Value: 1},
			{Key: "scanner", Value: 1}}, Options: options.Index().SetName("uniq_vulnerability_observation_latest").SetUnique(true)},
		{Keys: bson.D{{Key: "project_id", Value: 1}, {Key: "fresh_until", Value: 1},
			{Key: "highest_severity", Value: 1}}, Options: options.Index().SetName("idx_vulnerability_observation_policy")},
		{Keys: bson.D{{Key: "subject_digest", Value: 1}, {Key: "descriptor_digest", Value: 1}},
			Options: options.Index().SetName("idx_vulnerability_observation_evidence")},
	})
	if err != nil {
		return fmt.Errorf("create vulnerability observation indexes: %w", err)
	}
	return nil
}

func indexSignatureSigningProfiles(ctx context.Context, database *mongo.Database) error {
	_, err := database.Collection("signature_signing_profiles").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "organization_id", Value: 1}, {Key: "project_id", Value: 1},
			{Key: "name", Value: 1}}, Options: options.Index().SetName("uniq_signature_signing_profile_name").SetUnique(true)},
		{Keys: bson.D{{Key: "project_id", Value: 1}, {Key: "trust_policy_id", Value: 1}},
			Options: options.Index().SetName("uniq_signature_signing_profile_policy").SetUnique(true)},
		{Keys: bson.D{{Key: "project_id", Value: 1}, {Key: "enabled", Value: 1},
			{Key: "created_at", Value: 1}, {Key: "_id", Value: 1}},
			Options: options.Index().SetName("idx_signature_signing_profile_list")},
	})
	if err != nil {
		return fmt.Errorf("create signature signing profile indexes: %w", err)
	}
	return nil
}

func indexEvidenceVerifications(ctx context.Context, database *mongo.Database) error {
	_, err := database.Collection("evidence_verifications").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "project_id", Value: 1}, {Key: "artifact_id", Value: 1},
			{Key: "created_at", Value: 1}, {Key: "_id", Value: 1}},
			Options: options.Index().SetName("idx_evidence_verification_list")},
		{Keys: bson.D{{Key: "artifact_id", Value: 1}, {Key: "subject_digest", Value: 1},
			{Key: "policy_id", Value: 1}, {Key: "policy_version", Value: 1},
			{Key: "bundle_set_digest", Value: 1}},
			Options: options.Index().SetName("uniq_evidence_verification_snapshot").SetUnique(true)},
	})
	if err != nil {
		return fmt.Errorf("create evidence verification indexes: %w", err)
	}
	return nil
}

func indexSignatureTrustPolicies(ctx context.Context, database *mongo.Database) error {
	_, err := database.Collection("signature_trust_policies").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys: bson.D{{Key: "organization_id", Value: 1}, {Key: "project_id", Value: 1},
				{Key: "name", Value: 1}},
			Options: options.Index().SetName("uniq_signature_trust_policy_name").SetUnique(true),
		},
		{
			Keys: bson.D{{Key: "project_id", Value: 1}, {Key: "enabled", Value: 1},
				{Key: "created_at", Value: 1}, {Key: "_id", Value: 1}},
			Options: options.Index().SetName("idx_signature_trust_policy_list"),
		},
	})
	if err != nil {
		return fmt.Errorf("create signature trust policy indexes: %w", err)
	}
	return nil
}

func addTerminalAccessAndSessions(ctx context.Context, database *mongo.Database) error {
	policies := database.Collection("terminal_access_policies")
	if _, err := policies.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "organization_id", Value: 1}, {Key: "project_id", Value: 1}}, Options: options.Index().
			SetName("uniq_terminal_project_policy").SetUnique(true).
			SetPartialFilterExpression(bson.D{{Key: "scope", Value: "project"}})},
		{Keys: bson.D{{Key: "organization_id", Value: 1}}, Options: options.Index().
			SetName("uniq_terminal_organization_policy").SetUnique(true).
			SetPartialFilterExpression(bson.D{{Key: "scope", Value: "organization"}})},
	}); err != nil {
		return fmt.Errorf("create terminal access policy indexes: %w", err)
	}
	sessions := database.Collection("terminal_sessions")
	if _, err := sessions.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "ticket_hash", Value: 1}}, Options: options.Index().
			SetName("uniq_terminal_ticket_hash").SetUnique(true).
			SetPartialFilterExpression(bson.D{{Key: "ticket_hash", Value: bson.D{{Key: "$type", Value: "string"}}}})},
		{Keys: bson.D{{Key: "organization_id", Value: 1}, {Key: "actor_id", Value: 1}, {Key: "user_concurrency_slot", Value: 1}}, Options: options.Index().
			SetName("uniq_active_terminal_user_slot").SetUnique(true).
			SetPartialFilterExpression(bson.D{{Key: "active", Value: true}})},
		{Keys: bson.D{{Key: "organization_id", Value: 1}, {Key: "target_scope", Value: 1}, {Key: "target_concurrency_slot", Value: 1}}, Options: options.Index().
			SetName("uniq_active_terminal_target_slot").SetUnique(true).
			SetPartialFilterExpression(bson.D{{Key: "active", Value: true}})},
		{Keys: bson.D{{Key: "organization_id", Value: 1}, {Key: "project_id", Value: 1}, {Key: "created_at", Value: -1}, {Key: "_id", Value: -1}}, Options: options.Index().
			SetName("idx_terminal_project_created")},
		{Keys: bson.D{{Key: "organization_id", Value: 1}, {Key: "actor_id", Value: 1}, {Key: "created_at", Value: -1}}, Options: options.Index().
			SetName("idx_terminal_actor_created")},
		{Keys: bson.D{{Key: "active", Value: 1}, {Key: "maximum_deadline", Value: 1}, {Key: "idle_deadline", Value: 1}}, Options: options.Index().
			SetName("idx_terminal_expiry_reconciliation")},
	}); err != nil {
		return fmt.Errorf("create terminal session indexes: %w", err)
	}
	return nil
}

func addIngressRateLimits(ctx context.Context, database *mongo.Database) error {
	_, err := database.Collection("ingress_rate_limits").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "expires_at", Value: 1}},
		Options: options.Index().SetName("ttl_ingress_rate_limit").SetExpireAfterSeconds(0),
	})
	if err != nil {
		return fmt.Errorf("create ingress rate limit index: %w", err)
	}
	return nil
}

func addProjectMembers(ctx context.Context, database *mongo.Database) error {
	_, err := database.Collection("project_members").Indexes().CreateMany(ctx, []mongo.IndexModel{
		uniqueIndex("uniq_project_member_user", bson.D{{Key: "project_id", Value: 1}, {Key: "user_id", Value: 1}}),
		uniqueIndex("uniq_project_member_email", bson.D{{Key: "project_id", Value: 1}, {Key: "email", Value: 1}}),
		{Keys: bson.D{{Key: "organization_id", Value: 1}, {Key: "user_id", Value: 1}, {Key: "project_id", Value: 1}},
			Options: options.Index().SetName("idx_project_member_user_projects")},
	})
	if err != nil {
		return fmt.Errorf("create project member indexes: %w", err)
	}
	return nil
}

func addUserInvitations(ctx context.Context, database *mongo.Database) error {
	_, err := database.Collection("user_invitations").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "token_hash", Value: 1}}, Options: options.Index().
			SetName("uniq_user_invitation_token_hash").SetUnique(true).
			SetPartialFilterExpression(bson.D{{Key: "token_hash", Value: bson.D{{Key: "$type", Value: "string"}}}})},
		{Keys: bson.D{{Key: "organization_id", Value: 1}, {Key: "created_at", Value: -1}, {Key: "_id", Value: -1}},
			Options: options.Index().SetName("idx_user_invitation_organization_created")},
		{Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: options.Index().
			SetName("ttl_active_user_invitation").SetExpireAfterSeconds(0).
			SetPartialFilterExpression(bson.D{{Key: "status", Value: "active"}})},
	})
	if err != nil {
		return fmt.Errorf("create user invitation indexes: %w", err)
	}
	return nil
}

func indexBoundedBuildLogs(ctx context.Context, database *mongo.Database) error {
	_, err := database.Collection("build_log_streams").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "project_id", Value: 1}, {Key: "_id", Value: 1}},
			Options: options.Index().SetName("idx_build_log_stream_project")},
		{Keys: bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().SetName("ttl_build_log_stream").SetExpireAfterSeconds(0)},
	})
	if err != nil {
		return fmt.Errorf("create build log stream indexes: %w", err)
	}
	_, err = database.Collection("build_log_chunks").Indexes().CreateMany(ctx, []mongo.IndexModel{
		uniqueIndex("uniq_build_log_sequence", bson.D{{Key: "build_id", Value: 1}, {Key: "sequence", Value: 1}}),
		{Keys: bson.D{{Key: "project_id", Value: 1}, {Key: "build_id", Value: 1}, {Key: "sequence", Value: 1}},
			Options: options.Index().SetName("idx_build_log_read")},
		{Keys: bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().SetName("ttl_build_log_chunk").SetExpireAfterSeconds(0)},
	})
	if err != nil {
		return fmt.Errorf("create build log chunk indexes: %w", err)
	}
	return nil
}

func indexBuildPushResults(ctx context.Context, database *mongo.Database) error {
	_, err := database.Collection("builds").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{
			{Key: "status", Value: 1}, {Key: "image_digest", Value: 1},
			{Key: "lease.expires_at", Value: 1}, {Key: "created_at", Value: 1}, {Key: "_id", Value: 1},
		},
		Options: options.Index().SetName("idx_build_push_result_queue"),
	})
	if err != nil {
		return fmt.Errorf("create build push result index: %w", err)
	}
	return nil
}

func indexBuildHooks(ctx context.Context, database *mongo.Database) error {
	_, err := database.Collection("build_hooks").Indexes().CreateMany(ctx, []mongo.IndexModel{
		uniqueIndex("uniq_build_hook_project_name", bson.D{{Key: "project_id", Value: 1}, {Key: "name_normalized", Value: 1}}),
		{Keys: bson.D{
			{Key: "project_id", Value: 1}, {Key: "application_id", Value: 1},
			{Key: "build_configuration_id", Value: 1}, {Key: "created_at", Value: 1}, {Key: "_id", Value: 1},
		}, Options: options.Index().SetName("idx_build_hook_configuration_created")},
	})
	if err != nil {
		return fmt.Errorf("create build hook indexes: %w", err)
	}
	_, err = database.Collection("webhook_deliveries").Indexes().CreateMany(ctx, []mongo.IndexModel{
		uniqueIndex("uniq_webhook_delivery", bson.D{{Key: "hook_id", Value: 1}, {Key: "provider", Value: 1}, {Key: "delivery_id", Value: 1}}),
		{Keys: bson.D{{Key: "project_id", Value: 1}, {Key: "created_at", Value: -1}, {Key: "_id", Value: -1}},
			Options: options.Index().SetName("idx_webhook_delivery_project_created")},
		{Keys: bson.D{{Key: "build_id", Value: 1}}, Options: options.Index().SetName("idx_webhook_delivery_build")},
	})
	if err != nil {
		return fmt.Errorf("create webhook delivery indexes: %w", err)
	}
	return nil
}

func indexBuildTriggers(ctx context.Context, database *mongo.Database) error {
	_, err := database.Collection("build_triggers").Indexes().CreateMany(ctx, []mongo.IndexModel{
		uniqueIndex("uniq_build_trigger_project_name", bson.D{
			{Key: "project_id", Value: 1}, {Key: "name_normalized", Value: 1},
		}),
		uniqueIndex("uniq_build_trigger_token_hash", bson.D{{Key: "token_hash", Value: 1}}),
		{
			Keys: bson.D{
				{Key: "project_id", Value: 1}, {Key: "application_id", Value: 1},
				{Key: "build_configuration_id", Value: 1}, {Key: "created_at", Value: 1},
			},
			Options: options.Index().SetName("idx_build_trigger_configuration_created"),
		},
	})
	if err != nil {
		return fmt.Errorf("create build trigger indexes: %w", err)
	}
	_, err = database.Collection("build_trigger_rate_limits").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "expires_at", Value: 1}},
		Options: options.Index().SetName("ttl_build_trigger_rate_limit").SetExpireAfterSeconds(0),
	})
	if err != nil {
		return fmt.Errorf("create build trigger rate limit index: %w", err)
	}
	return nil
}

func indexBuilds(
	ctx context.Context,
	database *mongo.Database,
) error {
	_, err := database.Collection("builds").Indexes().CreateMany(
		ctx,
		[]mongo.IndexModel{
			uniqueIndex("uniq_build_idempotency", bson.D{
				{Key: "project_id", Value: 1},
				{Key: "idempotency_key", Value: 1},
			}),
			{
				Keys: bson.D{
					{Key: "project_id", Value: 1},
					{Key: "created_at", Value: -1},
					{Key: "_id", Value: -1},
				},
				Options: options.Index().SetName("idx_build_project_created"),
			},
			{
				Keys: bson.D{
					{Key: "project_id", Value: 1},
					{Key: "application_id", Value: 1},
					{Key: "created_at", Value: -1},
					{Key: "_id", Value: -1},
				},
				Options: options.Index().SetName("idx_build_application_created"),
			},
			{
				Keys: bson.D{
					{Key: "project_id", Value: 1},
					{Key: "build_configuration_id", Value: 1},
					{Key: "created_at", Value: -1},
				},
				Options: options.Index().SetName("idx_build_configuration_created"),
			},
		},
	)
	if err != nil {
		return fmt.Errorf("create build indexes: %w", err)
	}
	return nil
}

func indexBuildConfigurations(
	ctx context.Context,
	database *mongo.Database,
) error {
	_, err := database.Collection("build_configurations").Indexes().CreateMany(
		ctx,
		[]mongo.IndexModel{
			uniqueIndex("uniq_build_configuration_application_name", bson.D{
				{Key: "project_id", Value: 1},
				{Key: "application_id", Value: 1},
				{Key: "name_normalized", Value: 1},
			}),
			{
				Keys: bson.D{
					{Key: "project_id", Value: 1},
					{Key: "application_id", Value: 1},
					{Key: "created_at", Value: 1},
					{Key: "_id", Value: 1},
				},
				Options: options.Index().SetName("idx_build_configuration_application_created"),
			},
			{
				Keys: bson.D{
					{Key: "project_id", Value: 1},
					{Key: "source_repository_id", Value: 1},
				},
				Options: options.Index().SetName("idx_build_configuration_source"),
			},
			{
				Keys: bson.D{
					{Key: "project_id", Value: 1},
					{Key: "registry_credential_id", Value: 1},
				},
				Options: options.Index().SetName("idx_build_configuration_registry"),
			},
		},
	)
	if err != nil {
		return fmt.Errorf("create build configuration indexes: %w", err)
	}
	return nil
}

func indexSourceRepositories(
	ctx context.Context,
	database *mongo.Database,
) error {
	_, err := database.Collection("repository_credentials").Indexes().CreateMany(
		ctx,
		[]mongo.IndexModel{
			uniqueIndex("uniq_repository_credential_project_name", bson.D{
				{Key: "project_id", Value: 1},
				{Key: "name_normalized", Value: 1},
			}),
			{
				Keys: bson.D{
					{Key: "project_id", Value: 1},
					{Key: "created_at", Value: 1},
					{Key: "_id", Value: 1},
				},
				Options: options.Index().SetName("idx_repository_credential_project_created"),
			},
		},
	)
	if err != nil {
		return fmt.Errorf("create repository credential indexes: %w", err)
	}
	_, err = database.Collection("source_repositories").Indexes().CreateMany(
		ctx,
		[]mongo.IndexModel{
			uniqueIndex("uniq_source_repository_project_name", bson.D{
				{Key: "project_id", Value: 1},
				{Key: "name_normalized", Value: 1},
			}),
			{
				Keys: bson.D{
					{Key: "project_id", Value: 1},
					{Key: "created_at", Value: 1},
					{Key: "_id", Value: 1},
				},
				Options: options.Index().SetName("idx_source_repository_project_created"),
			},
			{
				Keys: bson.D{
					{Key: "project_id", Value: 1},
					{Key: "credential_id", Value: 1},
				},
				Options: options.Index().SetName("idx_source_repository_credential"),
			},
		},
	)
	if err != nil {
		return fmt.Errorf("create source repository indexes: %w", err)
	}
	return nil
}

func createRuntimeInventoryViewIndexes(
	ctx context.Context,
	database *mongo.Database,
) error {
	projectKeys := bson.D{
		{Key: "organization_id", Value: 1},
		{Key: "project_id", Value: 1},
		{Key: "managed", Value: 1},
		{Key: "runtime_target_id", Value: 1},
		{Key: "kind", Value: 1},
		{Key: "name", Value: 1},
		{Key: "runtime_id", Value: 1},
		{Key: "presence", Value: 1},
	}
	hostKeys := bson.D{
		{Key: "organization_id", Value: 1},
		{Key: "managed_host_id", Value: 1},
		{Key: "runtime_target_id", Value: 1},
		{Key: "kind", Value: 1},
		{Key: "name", Value: 1},
		{Key: "runtime_id", Value: 1},
		{Key: "presence", Value: 1},
	}
	_, err := database.Collection("runtime_inventory_current").
		Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys:    projectKeys,
			Options: options.Index().SetName("idx_runtime_inventory_project_view"),
		},
		{
			Keys:    hostKeys,
			Options: options.Index().SetName("idx_runtime_inventory_host_view"),
		},
	})
	if err != nil {
		return fmt.Errorf("create runtime inventory view indexes: %w", err)
	}
	return nil
}

func scheduleRuntimeInventoryEvents(
	ctx context.Context,
	database *mongo.Database,
) error {
	_, err := database.Collection("runtime_inventory_schedule").
		Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{
			{Key: "event_next_poll_at", Value: 1},
			{Key: "event_lease_expires_at", Value: 1},
			{Key: "_id", Value: 1},
		},
		Options: options.Index().SetName("idx_runtime_inventory_event_schedule_due"),
	})
	if err != nil {
		return fmt.Errorf("create runtime inventory event schedule index: %w", err)
	}
	return nil
}

func scheduleRuntimeInventory(
	ctx context.Context,
	database *mongo.Database,
) error {
	_, err := database.Collection("runtime_inventory_schedule").
		Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys: bson.D{
				{Key: "next_due_at", Value: 1},
				{Key: "lease_expires_at", Value: 1},
				{Key: "_id", Value: 1},
			},
			Options: options.Index().SetName("idx_runtime_inventory_schedule_due"),
		},
		{
			Keys: bson.D{
				{Key: "organization_id", Value: 1},
				{Key: "managed_host_id", Value: 1},
			},
			Options: options.Index().SetName("idx_runtime_inventory_schedule_host"),
		},
	})
	if err != nil {
		return fmt.Errorf("create runtime inventory schedule indexes: %w", err)
	}
	return nil
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

func uniqueIndex(name string, keys bson.D) mongo.IndexModel {
	return mongo.IndexModel{
		Keys:    keys,
		Options: options.Index().SetName(name).SetUnique(true),
	}
}
