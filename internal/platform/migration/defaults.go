package migration

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

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
		{Version: 13, Name: "schedule_runtime_inventory", Up: scheduleRuntimeInventory},
		{Version: 14, Name: "reconcile_runtime_inventory_state", Up: reconcileRuntimeInventoryState},
		{Version: 15, Name: "schedule_runtime_inventory_events", Up: scheduleRuntimeInventoryEvents},
		{Version: 16, Name: "index_runtime_inventory_views", Up: indexRuntimeInventoryViews},
		{Version: 17, Name: "optimize_runtime_inventory_view_indexes", Up: optimizeRuntimeInventoryViewIndexes},
		{Version: 18, Name: "index_source_repositories", Up: indexSourceRepositories},
		{Version: 19, Name: "index_build_configurations", Up: indexBuildConfigurations},
		{Version: 20, Name: "index_builds", Up: indexBuilds},
		{Version: 21, Name: "index_build_triggers", Up: indexBuildTriggers},
		{Version: 22, Name: "index_build_hooks", Up: indexBuildHooks},
		{Version: 23, Name: "build_execution_queue", Up: buildExecutionQueue},
		{Version: 24, Name: "index_build_push_results", Up: indexBuildPushResults},
		{Version: 25, Name: "index_build_artifacts", Up: indexBuildArtifacts},
		{Version: 26, Name: "backfill_build_release_runtime_spec", Up: backfillBuildReleaseRuntimeSpec},
		{Version: 27, Name: "index_bounded_build_logs", Up: indexBoundedBuildLogs},
		{Version: 28, Name: "add_automatic_deployment_rules", Up: addAutomaticDeploymentRules},
		{Version: 29, Name: "add_user_invitations", Up: addUserInvitations},
		{Version: 30, Name: "add_project_members", Up: addProjectMembers},
		{Version: 31, Name: "add_ingress_rate_limits", Up: addIngressRateLimits},
		{Version: 32, Name: "add_terminal_access_and_sessions", Up: addTerminalAccessAndSessions},
		{Version: 33, Name: "bind_terminal_authentication_sessions", Up: bindTerminalAuthenticationSessions},
		{Version: 34, Name: "index_artifact_evidence", Up: indexArtifactEvidence},
		{Version: 35, Name: "index_artifact_evidence_jobs", Up: indexArtifactEvidenceJobs},
		{Version: 36, Name: "revise_artifact_evidence_idempotency", Up: reviseArtifactEvidenceIdempotency},
		{Version: 37, Name: "index_signature_trust_policies", Up: indexSignatureTrustPolicies},
		{Version: 38, Name: "index_evidence_verifications", Up: indexEvidenceVerifications},
		{Version: 39, Name: "index_signature_signing_profiles", Up: indexSignatureSigningProfiles},
		{Version: 40, Name: "backfill_signature_job_operation", Up: backfillSignatureJobOperation},
		{Version: 41, Name: "index_vulnerability_observations", Up: indexVulnerabilityObservations},
		{Version: 42, Name: "index_vulnerability_waivers", Up: indexVulnerabilityWaivers},
		{Version: 43, Name: "index_deployment_policies", Up: indexDeploymentPolicies},
		{Version: 44, Name: "support_external_artifacts", Up: supportExternalArtifacts},
		{Version: 45, Name: "support_registry_authentication_modes", Up: supportRegistryAuthenticationModes},
		{Version: 46, Name: "schedule_runtime_target_retirements", Up: scheduleRuntimeTargetRetirements},
		{Version: 47, Name: "index_runtime_target_terminal_convergence", Up: indexRuntimeTargetTerminalConvergence},
	}
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

func supportRegistryAuthenticationModes(ctx context.Context, database *mongo.Database) error {
	_, err := database.Collection("registry_credentials").UpdateMany(ctx,
		bson.D{{Key: "authentication_mode", Value: bson.D{{Key: "$exists", Value: false}}}},
		bson.D{{Key: "$set", Value: bson.D{{Key: "authentication_mode", Value: "basic"}}}})
	if err != nil {
		return fmt.Errorf("backfill Registry authentication modes: %w", err)
	}
	return nil
}

func supportExternalArtifacts(ctx context.Context, database *mongo.Database) error {
	artifacts := database.Collection("artifacts")
	_, err := artifacts.UpdateMany(ctx,
		bson.D{{Key: "origin", Value: bson.D{{Key: "$exists", Value: false}}}},
		bson.D{{Key: "$set", Value: bson.D{{Key: "origin", Value: "owndock_build"},
			{Key: "producer", Value: "owndock-build-worker"},
			{Key: "producer_verification", Value: "verified"}}}})
	if err != nil {
		return fmt.Errorf("backfill Artifact producer identity: %w", err)
	}
	if err := artifacts.Indexes().DropOne(ctx, "uniq_artifact_build"); err != nil {
		var commandError mongo.CommandError
		if !errors.As(err, &commandError) || commandError.Code != 27 {
			return fmt.Errorf("replace Artifact Build uniqueness index: %w", err)
		}
	}
	_, err = artifacts.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "build_id", Value: 1}}, Options: options.Index().
			SetName("uniq_artifact_build").SetUnique(true).
			SetPartialFilterExpression(bson.D{{Key: "build_id", Value: bson.D{{Key: "$type", Value: "string"}}}})},
		{Keys: bson.D{{Key: "project_id", Value: 1}, {Key: "registration_key", Value: 1}},
			Options: options.Index().SetName("uniq_external_artifact_registration").SetUnique(true).
				SetPartialFilterExpression(bson.D{{Key: "registration_key", Value: bson.D{{Key: "$type", Value: "string"}}}})},
		{Keys: bson.D{{Key: "project_id", Value: 1}, {Key: "origin", Value: 1},
			{Key: "created_at", Value: -1}, {Key: "_id", Value: -1}},
			Options: options.Index().SetName("idx_artifact_project_origin")},
	})
	if err != nil {
		return fmt.Errorf("create external Artifact indexes: %w", err)
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

func backfillSignatureJobOperation(ctx context.Context, database *mongo.Database) error {
	_, err := database.Collection("artifact_evidence_jobs").UpdateMany(ctx,
		bson.D{{Key: "kind", Value: "signature"},
			{Key: "signature_operation", Value: bson.D{{Key: "$exists", Value: false}}}},
		bson.D{{Key: "$set", Value: bson.D{{Key: "signature_operation", Value: "verify"}}}})
	if err != nil {
		return fmt.Errorf("backfill signature job operation: %w", err)
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

func reviseArtifactEvidenceIdempotency(ctx context.Context, database *mongo.Database) error {
	evidence := database.Collection("artifact_evidence")
	jobs := database.Collection("artifact_evidence_jobs")
	if _, err := jobs.UpdateMany(ctx,
		bson.D{{Key: "idempotency_key", Value: bson.D{{Key: "$exists", Value: false}}}},
		mongo.Pipeline{bson.D{{Key: "$set", Value: bson.D{{Key: "idempotency_key", Value: "$_id"}}}}},
	); err != nil {
		return fmt.Errorf("backfill artifact evidence job idempotency: %w", err)
	}
	if err := evidence.Indexes().DropOne(ctx, "uniq_artifact_evidence_identity"); err != nil {
		return fmt.Errorf("drop artifact evidence identity index: %w", err)
	}
	if err := jobs.Indexes().DropOne(ctx, "uniq_artifact_evidence_job_identity"); err != nil {
		return fmt.Errorf("drop artifact evidence job identity index: %w", err)
	}
	if _, err := evidence.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{
			{Key: "project_id", Value: 1}, {Key: "artifact_id", Value: 1},
			{Key: "kind", Value: 1}, {Key: "producer", Value: 1},
			{Key: "format_version", Value: 1}, {Key: "descriptor_digest", Value: 1},
		},
		Options: options.Index().SetName("uniq_artifact_evidence_descriptor").SetUnique(true),
	}); err != nil {
		return fmt.Errorf("create artifact evidence descriptor index: %w", err)
	}
	if _, err := jobs.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{
			{Key: "organization_id", Value: 1}, {Key: "project_id", Value: 1},
			{Key: "idempotency_key", Value: 1},
		},
		Options: options.Index().SetName("uniq_artifact_evidence_job_idempotency").SetUnique(true),
	}); err != nil {
		return fmt.Errorf("create artifact evidence job idempotency index: %w", err)
	}
	return nil
}

func indexArtifactEvidenceJobs(ctx context.Context, database *mongo.Database) error {
	_, err := database.Collection("artifact_evidence_jobs").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys: bson.D{
				{Key: "status", Value: 1}, {Key: "lease.expires_at", Value: 1},
				{Key: "created_at", Value: 1}, {Key: "_id", Value: 1},
			},
			Options: options.Index().SetName("idx_artifact_evidence_job_queue"),
		},
		{
			Keys: bson.D{
				{Key: "project_id", Value: 1}, {Key: "artifact_id", Value: 1},
				{Key: "kind", Value: 1}, {Key: "producer", Value: 1},
				{Key: "format_version", Value: 1},
			},
			Options: options.Index().SetName("uniq_artifact_evidence_job_identity").SetUnique(true),
		},
	})
	if err != nil {
		return fmt.Errorf("create artifact evidence job indexes: %w", err)
	}
	return nil
}

func indexArtifactEvidence(ctx context.Context, database *mongo.Database) error {
	collection := database.Collection("artifact_evidence")
	_, err := collection.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys: bson.D{
				{Key: "project_id", Value: 1}, {Key: "artifact_id", Value: 1},
				{Key: "created_at", Value: 1}, {Key: "_id", Value: 1},
			},
			Options: options.Index().SetName("idx_artifact_evidence_list"),
		},
		{
			Keys: bson.D{
				{Key: "project_id", Value: 1}, {Key: "artifact_id", Value: 1},
				{Key: "kind", Value: 1}, {Key: "producer", Value: 1},
				{Key: "format_version", Value: 1},
			},
			Options: options.Index().SetName("uniq_artifact_evidence_identity").SetUnique(true),
		},
		{
			Keys: bson.D{
				{Key: "subject_digest", Value: 1}, {Key: "descriptor_digest", Value: 1},
			},
			Options: options.Index().SetName("idx_artifact_evidence_digest"),
		},
	})
	if err != nil {
		return fmt.Errorf("create artifact evidence indexes: %w", err)
	}
	return nil
}

func bindTerminalAuthenticationSessions(ctx context.Context, database *mongo.Database) error {
	sessions := database.Collection("terminal_sessions")
	missingBinding := bson.D{{Key: "authentication_session_id", Value: bson.D{{Key: "$exists", Value: false}}}}
	now := time.Now().UTC()
	if _, err := sessions.UpdateMany(ctx, bson.D{
		{Key: "authentication_session_id", Value: bson.D{{Key: "$exists", Value: false}}},
		{Key: "active", Value: true},
	}, bson.D{
		{Key: "$set", Value: bson.D{
			{Key: "authentication_session_id", Value: "legacy-invalidated"},
			{Key: "status", Value: "failed"},
			{Key: "active", Value: false},
			{Key: "ended_at", Value: now},
			{Key: "close_reason", Value: "permission_revoked"},
			{Key: "safe_error_code", Value: "terminal_authentication_session_missing"},
		}},
		{Key: "$unset", Value: bson.D{{Key: "ticket_hash", Value: ""}}},
	}); err != nil {
		return fmt.Errorf("invalidate unbound active terminal sessions: %w", err)
	}
	if _, err := sessions.UpdateMany(ctx, missingBinding, bson.D{{Key: "$set", Value: bson.D{
		{Key: "authentication_session_id", Value: "legacy-invalidated"},
	}}}); err != nil {
		return fmt.Errorf("mark unbound historical terminal sessions: %w", err)
	}
	if _, err := sessions.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{
			{Key: "authentication_session_id", Value: 1},
			{Key: "active", Value: 1},
		},
		Options: options.Index().SetName("idx_terminal_authentication_session_active"),
	}); err != nil {
		return fmt.Errorf("index bound terminal authentication sessions: %w", err)
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

func addAutomaticDeploymentRules(ctx context.Context, database *mongo.Database) error {
	for _, update := range []struct {
		collection string
		field      string
	}{
		{collection: "build_configurations", field: "automatic_deployments"},
		{collection: "builds", field: "configuration_snapshot.automatic_deployments"},
		{collection: "artifacts", field: "automatic_deployments"},
	} {
		if _, err := database.Collection(update.collection).UpdateMany(ctx,
			bson.D{{Key: update.field, Value: bson.D{{Key: "$exists", Value: false}}}},
			bson.D{{Key: "$set", Value: bson.D{{Key: update.field, Value: bson.A{}}}}},
		); err != nil {
			return fmt.Errorf("backfill %s automatic deployments: %w", update.collection, err)
		}
	}
	if _, err := database.Collection("deployments").UpdateMany(ctx,
		bson.D{{Key: "trigger_source", Value: bson.D{{Key: "$exists", Value: false}}}},
		bson.D{{Key: "$set", Value: bson.D{{Key: "trigger_source", Value: "manual"}}}},
	); err != nil {
		return fmt.Errorf("backfill deployment trigger source: %w", err)
	}
	_, err := database.Collection("deployments").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{
			{Key: "project_id", Value: 1}, {Key: "source_artifact_id", Value: 1},
			{Key: "environment_id", Value: 1}, {Key: "runtime_target_id", Value: 1},
		},
		Options: options.Index().SetName("idx_automatic_deployment_artifact").
			SetPartialFilterExpression(bson.D{{Key: "trigger_source", Value: "automatic"}}),
	})
	if err != nil {
		return fmt.Errorf("create automatic deployment index: %w", err)
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

func backfillBuildReleaseRuntimeSpec(ctx context.Context, database *mongo.Database) error {
	defaultSpec := bson.D{
		{Key: "ports", Value: bson.A{}},
		{Key: "environment_keys", Value: bson.A{}},
		{Key: "resources", Value: bson.D{
			{Key: "cpu_milli", Value: int64(500)},
			{Key: "memory_bytes", Value: int64(256 * 1024 * 1024)},
		}},
	}
	updates := []struct {
		collection string
		field      string
	}{
		{collection: "build_configurations", field: "release_runtime_spec"},
		{collection: "builds", field: "configuration.release_runtime_spec"},
		{collection: "artifacts", field: "release_runtime_spec"},
	}
	for _, update := range updates {
		if _, err := database.Collection(update.collection).UpdateMany(
			ctx,
			bson.D{{Key: update.field, Value: bson.D{{Key: "$exists", Value: false}}}},
			bson.D{{Key: "$set", Value: bson.D{{Key: update.field, Value: defaultSpec}}}},
		); err != nil {
			return fmt.Errorf("backfill %s release runtime spec: %w", update.collection, err)
		}
	}
	return nil
}

func indexBuildArtifacts(ctx context.Context, database *mongo.Database) error {
	_, err := database.Collection("artifacts").Indexes().CreateMany(ctx, []mongo.IndexModel{
		uniqueIndex("uniq_artifact_build", bson.D{{Key: "build_id", Value: 1}}),
		{Keys: bson.D{{Key: "project_id", Value: 1}, {Key: "created_at", Value: -1}, {Key: "_id", Value: -1}},
			Options: options.Index().SetName("idx_artifact_project_created")},
		{Keys: bson.D{{Key: "release_status", Value: 1}, {Key: "created_at", Value: 1}, {Key: "_id", Value: 1}},
			Options: options.Index().SetName("idx_artifact_release_queue")},
		{Keys: bson.D{{Key: "image_repository", Value: 1}, {Key: "image_digest", Value: 1}, {Key: "target_platform", Value: 1}},
			Options: options.Index().SetName("idx_artifact_image")},
	})
	if err != nil {
		return fmt.Errorf("create artifact indexes: %w", err)
	}
	_, err = database.Collection("releases").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "source_artifact_id", Value: 1}},
		Options: options.Index().SetName("uniq_release_source_artifact").SetUnique(true).
			SetPartialFilterExpression(bson.D{{Key: "source_artifact_id", Value: bson.D{{Key: "$type", Value: "string"}}}}),
	})
	if err != nil {
		return fmt.Errorf("create artifact release index: %w", err)
	}
	_, err = database.Collection("builds").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "project_id", Value: 1}, {Key: "artifact_id", Value: 1}},
		Options: options.Index().SetName("idx_build_artifact")})
	if err != nil {
		return fmt.Errorf("create build artifact index: %w", err)
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

func buildExecutionQueue(ctx context.Context, database *mongo.Database) error {
	if _, err := database.Collection("builds").UpdateMany(ctx,
		bson.D{{Key: "updated_at", Value: bson.D{{Key: "$exists", Value: false}}}},
		bson.A{bson.D{{Key: "$set", Value: bson.D{{Key: "updated_at", Value: "$created_at"}}}}},
	); err != nil {
		return fmt.Errorf("backfill build execution metadata: %w", err)
	}
	_, err := database.Collection("builds").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "status", Value: 1}, {Key: "lease.expires_at", Value: 1}, {Key: "created_at", Value: 1}, {Key: "_id", Value: 1}}, Options: options.Index().SetName("idx_build_execution_queue")},
		{Keys: bson.D{{Key: "build_configuration_id", Value: 1}, {Key: "status", Value: 1}}, Options: options.Index().SetName("idx_build_configuration_status")},
		{Keys: bson.D{{Key: "project_id", Value: 1}, {Key: "source_build_id", Value: 1}}, Options: options.Index().SetName("idx_build_retry_source")},
	})
	if err != nil {
		return fmt.Errorf("create build execution indexes: %w", err)
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

func indexRuntimeInventoryViews(
	ctx context.Context,
	database *mongo.Database,
) error {
	return createRuntimeInventoryViewIndexes(ctx, database, false)
}

func optimizeRuntimeInventoryViewIndexes(
	ctx context.Context,
	database *mongo.Database,
) error {
	indexes := database.Collection("runtime_inventory_current").Indexes()
	for _, name := range []string{
		"idx_runtime_inventory_project_view",
		"idx_runtime_inventory_host_view",
	} {
		if err := indexes.DropOne(ctx, name); err != nil {
			var commandError mongo.CommandError
			if errors.As(err, &commandError) && commandError.Code == 27 {
				continue
			}
			return fmt.Errorf("drop runtime inventory view index %s: %w", name, err)
		}
	}
	return createRuntimeInventoryViewIndexes(ctx, database, true)
}

func createRuntimeInventoryViewIndexes(
	ctx context.Context,
	database *mongo.Database,
	optimized bool,
) error {
	projectKeys := bson.D{
		{Key: "organization_id", Value: 1},
		{Key: "project_id", Value: 1},
		{Key: "managed", Value: 1},
		{Key: "presence", Value: 1},
		{Key: "runtime_target_id", Value: 1},
		{Key: "kind", Value: 1},
		{Key: "name", Value: 1},
		{Key: "runtime_id", Value: 1},
	}
	hostKeys := bson.D{
		{Key: "organization_id", Value: 1},
		{Key: "managed_host_id", Value: 1},
		{Key: "presence", Value: 1},
		{Key: "runtime_target_id", Value: 1},
		{Key: "kind", Value: 1},
		{Key: "name", Value: 1},
		{Key: "runtime_id", Value: 1},
	}
	if optimized {
		projectKeys = bson.D{
			{Key: "organization_id", Value: 1},
			{Key: "project_id", Value: 1},
			{Key: "managed", Value: 1},
			{Key: "runtime_target_id", Value: 1},
			{Key: "kind", Value: 1},
			{Key: "name", Value: 1},
			{Key: "runtime_id", Value: 1},
			{Key: "presence", Value: 1},
		}
		hostKeys = bson.D{
			{Key: "organization_id", Value: 1},
			{Key: "managed_host_id", Value: 1},
			{Key: "runtime_target_id", Value: 1},
			{Key: "kind", Value: 1},
			{Key: "name", Value: 1},
			{Key: "runtime_id", Value: 1},
			{Key: "presence", Value: 1},
		}
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

func reconcileRuntimeInventoryState(
	ctx context.Context,
	database *mongo.Database,
) error {
	if err := backfillRuntimeInventoryCurrent(ctx, database); err != nil {
		return err
	}
	_, err := database.Collection("runtime_inventory_current").
		Indexes().CreateMany(ctx, []mongo.IndexModel{
		uniqueIndex(
			"uniq_runtime_inventory_current_resource",
			bson.D{
				{Key: "runtime_target_id", Value: 1},
				{Key: "kind", Value: 1},
				{Key: "runtime_id", Value: 1},
			},
		),
		{
			Keys: bson.D{
				{Key: "organization_id", Value: 1},
				{Key: "runtime_target_id", Value: 1},
				{Key: "presence", Value: 1},
				{Key: "kind", Value: 1},
				{Key: "name", Value: 1},
				{Key: "runtime_id", Value: 1},
			},
			Options: options.Index().SetName("idx_runtime_inventory_current_state"),
		},
		{
			Keys: bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().
				SetName("ttl_runtime_inventory_current_absent").
				SetExpireAfterSeconds(0),
		},
	})
	if err != nil {
		return fmt.Errorf("create runtime inventory current indexes: %w", err)
	}
	_, err = database.Collection("runtime_inventory_event_hints").
		Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys: bson.D{
				{Key: "runtime_target_id", Value: 1},
				{Key: "received_at", Value: -1},
			},
			Options: options.Index().SetName("idx_runtime_inventory_event_target"),
		},
		{
			Keys: bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().
				SetName("ttl_runtime_inventory_event_hints").
				SetExpireAfterSeconds(0),
		},
	})
	if err != nil {
		return fmt.Errorf("create runtime inventory event hint indexes: %w", err)
	}
	return nil
}

func backfillRuntimeInventoryCurrent(
	ctx context.Context,
	database *mongo.Database,
) error {
	type inventoryHead struct {
		ObservationID   string    `bson:"observation_id"`
		RuntimeTargetID string    `bson:"runtime_target_id"`
		Generation      uint64    `bson:"generation"`
		CompletedAt     time.Time `bson:"completed_at"`
	}
	heads, err := database.Collection("runtime_inventory_heads").Find(ctx, bson.D{})
	if err != nil {
		return fmt.Errorf("find runtime inventory heads for current backfill: %w", err)
	}
	defer heads.Close(ctx)
	current := database.Collection("runtime_inventory_current")
	resources := database.Collection("runtime_inventory_resources")
	for heads.Next(ctx) {
		var head inventoryHead
		if err := heads.Decode(&head); err != nil {
			return fmt.Errorf("decode runtime inventory head for current backfill: %w", err)
		}
		cursor, err := resources.Find(ctx, bson.D{
			{Key: "observation_id", Value: head.ObservationID},
			{Key: "runtime_target_id", Value: head.RuntimeTargetID},
		})
		if err != nil {
			return fmt.Errorf("find runtime inventory resources for current backfill: %w", err)
		}
		models := make([]mongo.WriteModel, 0, 500)
		for cursor.Next(ctx) {
			var document bson.M
			if err := cursor.Decode(&document); err != nil {
				_ = cursor.Close(ctx)
				return fmt.Errorf("decode runtime inventory resource for current backfill: %w", err)
			}
			kind, kindOK := document["kind"].(string)
			runtimeID, runtimeIDOK := document["runtime_id"].(string)
			if !kindOK || !runtimeIDOK || kind == "" || runtimeID == "" ||
				head.Generation == 0 || head.CompletedAt.IsZero() {
				_ = cursor.Close(ctx)
				return fmt.Errorf("runtime inventory resource current backfill identity is invalid")
			}
			delete(document, "_id")
			delete(document, "expires_at")
			delete(document, "first_seen_at")
			delete(document, "absent_at")
			document["presence"] = "present"
			document["last_seen_at"] = head.CompletedAt
			document["reconciled_at"] = head.CompletedAt
			document["generation"] = head.Generation
			models = append(models, mongo.NewUpdateOneModel().
				SetFilter(bson.D{{
					Key:   "_id",
					Value: runtimeInventoryCurrentID(head.RuntimeTargetID, kind, runtimeID),
				}}).
				SetUpdate(bson.D{
					{Key: "$set", Value: document},
					{Key: "$setOnInsert", Value: bson.D{{
						Key: "first_seen_at", Value: head.CompletedAt,
					}}},
					{Key: "$unset", Value: bson.D{
						{Key: "absent_at", Value: ""},
						{Key: "expires_at", Value: ""},
					}},
				}).SetUpsert(true))
			if len(models) == 500 {
				if _, err := current.BulkWrite(ctx, models); err != nil {
					_ = cursor.Close(ctx)
					return fmt.Errorf("backfill runtime inventory current batch: %w", err)
				}
				models = models[:0]
			}
		}
		if err := cursor.Err(); err != nil {
			_ = cursor.Close(ctx)
			return fmt.Errorf("iterate runtime inventory resources for current backfill: %w", err)
		}
		if err := cursor.Close(ctx); err != nil {
			return fmt.Errorf("close runtime inventory resource backfill cursor: %w", err)
		}
		if len(models) > 0 {
			if _, err := current.BulkWrite(ctx, models); err != nil {
				return fmt.Errorf("backfill runtime inventory current batch: %w", err)
			}
		}
	}
	if err := heads.Err(); err != nil {
		return fmt.Errorf("iterate runtime inventory heads for current backfill: %w", err)
	}
	return nil
}

func runtimeInventoryCurrentID(values ...string) string {
	hash := sha256.New()
	for _, value := range values {
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0})
	}
	return fmt.Sprintf("%x", hash.Sum(nil))
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
