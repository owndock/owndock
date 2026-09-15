package migration

import (
	"context"
	"errors"
	"testing"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func TestValidateMigrations(t *testing.T) {
	valid := []Migration{
		{Version: 2, Name: "two", Up: func(context.Context, *mongo.Database) error { return nil }},
		{Version: 1, Name: "one", Up: func(context.Context, *mongo.Database) error { return nil }},
	}
	if err := validate(sorted(valid)); err != nil {
		t.Fatalf("validate() error = %v", err)
	}
	invalid := []Migration{
		{Version: 1, Name: "one", Up: func(context.Context, *mongo.Database) error { return nil }},
		{Version: 1, Name: "duplicate", Up: func(context.Context, *mongo.Database) error { return nil }},
	}
	if err := validate(invalid); !errors.Is(err, ErrInvalidMigration) {
		t.Fatalf("validate() error = %v, want ErrInvalidMigration", err)
	}
}

func TestDefaultMigrationIsSingleInitialSchema(t *testing.T) {
	items := Default()
	if len(items) != 1 {
		t.Fatalf("Default() migration count = %d, want 1", len(items))
	}
	item := items[0]
	if item.Version != 1 || item.Name != "initial_owndock_schema" || item.Up == nil {
		t.Fatalf("initial migration = %+v", item)
	}
}

func TestInitialIndexStepsPropagateCanceledDatabaseOperations(t *testing.T) {
	client, err := mongo.Connect(options.Client().ApplyURI("mongodb://127.0.0.1:1"))
	if err != nil {
		t.Fatalf("create disconnected MongoDB client: %v", err)
	}
	t.Cleanup(func() { _ = client.Disconnect(context.Background()) })
	database := client.Database("owndock_cancelled_schema")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	steps := []struct {
		name string
		up   func(context.Context, *mongo.Database) error
	}{
		{"product", createBaselineProductIndexes},
		{"inventory current", createBaselineInventoryCurrentIndexes},
		{"build execution", createBaselineBuildExecutionIndexes},
		{"artifacts", createBaselineArtifactIndexes},
		{"automatic deployments", createBaselineAutomaticDeploymentIndex},
		{"terminal lifecycle", createBaselineTerminalLifecycleIndexes},
		{"evidence", createBaselineEvidenceIndexes},
		{"resource retirements", createBaselineResourceRetirementIndexes},
		{"resource sessions", createBaselineResourceSessionIndexes},
		{"vulnerability rescans", createBaselineVulnerabilityRescanIndexes},
		{"deployment rollback", indexDeploymentRollbackLookup},
		{"registry credentials", indexRegistryCredentials},
		{"managed hosts", indexManagedHostsAndTargetConnections},
		{"agent identity", indexAgentEnrollmentAndIdentity},
		{"login attempts", indexLoginAttemptExpiry},
		{"inventory", indexRuntimeInventory},
		{"inventory schedule", scheduleRuntimeInventory},
		{"inventory events", scheduleRuntimeInventoryEvents},
		{"inventory views", createRuntimeInventoryViewIndexes},
		{"source repositories", indexSourceRepositories},
		{"build configurations", indexBuildConfigurations},
		{"builds", indexBuilds},
		{"build triggers", indexBuildTriggers},
		{"build hooks", indexBuildHooks},
		{"build push results", indexBuildPushResults},
		{"build logs", indexBoundedBuildLogs},
		{"invitations", addUserInvitations},
		{"project members", addProjectMembers},
		{"ingress limits", addIngressRateLimits},
		{"terminal", addTerminalAccessAndSessions},
		{"trust policies", indexSignatureTrustPolicies},
		{"evidence verifications", indexEvidenceVerifications},
		{"signing profiles", indexSignatureSigningProfiles},
		{"vulnerability observations", indexVulnerabilityObservations},
		{"vulnerability waivers", indexVulnerabilityWaivers},
		{"deployment policies", indexDeploymentPolicies},
		{"runtime target retirements", scheduleRuntimeTargetRetirements},
		{"runtime target sessions", indexRuntimeTargetTerminalConvergence},
		{"application builds", indexApplicationBuildRetirement},
		{"application artifacts", indexApplicationArtifactReleaseRetirement},
	}
	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			if err := step.up(ctx, database); !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled index operation error = %v, want context.Canceled", err)
			}
		})
	}
}

func sorted(items []Migration) []Migration {
	result := append([]Migration(nil), items...)
	if result[0].Version > result[1].Version {
		result[0], result[1] = result[1], result[0]
	}
	return result
}
