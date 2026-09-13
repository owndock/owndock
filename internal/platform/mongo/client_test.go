package mongo

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	buildbiz "github.com/owndock/owndock/internal/modules/build/biz"
	builddata "github.com/owndock/owndock/internal/modules/build/data"
	buildservice "github.com/owndock/owndock/internal/modules/build/service"
	buildworker "github.com/owndock/owndock/internal/modules/build/worker"
	controlplanebiz "github.com/owndock/owndock/internal/modules/controlplane/biz"
	controlplanedata "github.com/owndock/owndock/internal/modules/controlplane/data"
	controlplaneservice "github.com/owndock/owndock/internal/modules/controlplane/service"
	deploymentbiz "github.com/owndock/owndock/internal/modules/deployment/biz"
	deploymentdata "github.com/owndock/owndock/internal/modules/deployment/data"
	deploymentworker "github.com/owndock/owndock/internal/modules/deployment/worker"
	identitybiz "github.com/owndock/owndock/internal/modules/identity/biz"
	identitydata "github.com/owndock/owndock/internal/modules/identity/data"
	identityservice "github.com/owndock/owndock/internal/modules/identity/service"
	managedhostbiz "github.com/owndock/owndock/internal/modules/managedhost/biz"
	managedhostdata "github.com/owndock/owndock/internal/modules/managedhost/data"
	runtimeinventorybiz "github.com/owndock/owndock/internal/modules/runtimeinventory/biz"
	runtimeinventorydata "github.com/owndock/owndock/internal/modules/runtimeinventory/data"
	runtimeinventoryworker "github.com/owndock/owndock/internal/modules/runtimeinventory/worker"
	supplychainbiz "github.com/owndock/owndock/internal/modules/supplychain/biz"
	supplychaindata "github.com/owndock/owndock/internal/modules/supplychain/data"
	terminalbiz "github.com/owndock/owndock/internal/modules/terminal/biz"
	terminaldata "github.com/owndock/owndock/internal/modules/terminal/data"
	platformaudit "github.com/owndock/owndock/internal/platform/audit"
	"github.com/owndock/owndock/internal/platform/config"
	"github.com/owndock/owndock/internal/platform/id"
	platformingress "github.com/owndock/owndock/internal/platform/ingress"
	"github.com/owndock/owndock/internal/platform/migration"
	"github.com/owndock/owndock/internal/server"
	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/registryauth"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/runtimespec"
	"github.com/owndock/owndock/internal/shared/security"
	"github.com/testcontainers/testcontainers-go"
	testmongo "github.com/testcontainers/testcontainers-go/modules/mongodb"
	"go.mongodb.org/mongo-driver/v2/bson"
	drivermongo "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

const integrationImage = "mongo:8.3.7-noble@sha256:8444a416f2fc991f15064df9f6ea31ee02877607a70fd352ea998e6dbb5714b3"

type readyRuntimeTargetProber struct{}

type completedRuntimeTargetRetirer struct{}

func (completedRuntimeTargetRetirer) RetireRuntimeTarget(
	context.Context,
	controlplanebiz.RuntimeTarget,
	security.Principal,
	string,
) error {
	return nil
}

type staticAdmissionEvaluator struct{ stage string }

func (e staticAdmissionEvaluator) EvaluateAdmission(_ context.Context,
	_ deploymentbiz.AdmissionRequest) (deploymentbiz.AdmissionSnapshot, error) {
	return (deploymentbiz.AdmissionSnapshot{EvaluatedAt: time.Now().UTC(), EnvironmentStage: e.stage,
		Policies: []deploymentbiz.AdmissionPolicySnapshot{}, Evidence: []deploymentbiz.AdmissionEvidenceSnapshot{},
		Verifications: []deploymentbiz.AdmissionVerificationSnapshot{}, Waivers: []deploymentbiz.AdmissionWaiverSnapshot{},
		Violations: []deploymentbiz.AdmissionViolation{}, Decision: deploymentbiz.AdmissionNotConfigured}).Seal()
}

func (readyRuntimeTargetProber) ProbeRuntimeTarget(
	context.Context,
	controlplanebiz.RuntimeTarget,
) (controlplanebiz.RuntimeTargetStatus, error) {
	return controlplanebiz.RuntimeTargetStatusReady, nil
}

type readySourceRepositoryProber struct{}

type readyWebhookVerifier struct{ event buildbiz.WebhookEvent }

type integrationWebhookSecrets struct{ secret []byte }

func (s integrationWebhookSecrets) ResolveWebhookSecret(context.Context, buildbiz.BuildHook) ([]byte, error) {
	return append([]byte(nil), s.secret...), nil
}

func (v *readyWebhookVerifier) VerifyAndParse(context.Context, buildbiz.BuildHook, buildbiz.WebhookEnvelope) (buildbiz.WebhookEvent, error) {
	return v.event, nil
}

func (readySourceRepositoryProber) ProbeSource(
	context.Context,
	buildbiz.SourceRepository,
	*buildbiz.RepositoryCredential,
) (buildbiz.SourceRepositoryStatus, error) {
	return buildbiz.SourceRepositoryStatusReady, nil
}

func (readySourceRepositoryProber) ResolveSourceRevision(
	_ context.Context,
	source buildbiz.SourceRepository,
	_ *buildbiz.RepositoryCredential,
	ref, expectedCommitSHA string,
) (buildbiz.SourceRevision, error) {
	commitSHA := "a975c10d68a2d7461634f13b15c52a2efba72d16"
	if expectedCommitSHA != "" && expectedCommitSHA != commitSHA {
		return buildbiz.SourceRevision{}, buildbiz.ErrRevisionMismatch
	}
	return buildbiz.NewSourceRevision(source.ID, ref, commitSHA)
}

func TestOpenRejectsDisabledConfig(t *testing.T) {
	if _, err := Open(context.Background(), config.Mongo{}); err == nil {
		t.Fatal("Open() error = nil, want an error")
	}
}

func TestProductTransactionsUseDurableReplicaSetSemantics(t *testing.T) {
	configured := &options.TransactionOptions{}
	for _, apply := range productTransactionOptions().List() {
		if err := apply(configured); err != nil {
			t.Fatalf("apply transaction option: %v", err)
		}
	}
	if configured.ReadConcern == nil || configured.ReadConcern.Level != "snapshot" {
		t.Fatalf("read concern = %+v, want snapshot", configured.ReadConcern)
	}
	if configured.ReadPreference == nil || configured.ReadPreference.Mode() != readpref.PrimaryMode {
		t.Fatalf("read preference = %+v, want primary", configured.ReadPreference)
	}
	if configured.WriteConcern == nil || configured.WriteConcern.W != "majority" {
		t.Fatalf("write concern = %+v, want majority", configured.WriteConcern)
	}
}

func TestMongoReplicaSetIntegration(t *testing.T) {
	if os.Getenv("OWNDOCK_RUN_MONGO_INTEGRATION") != "1" {
		t.Skip("set OWNDOCK_RUN_MONGO_INTEGRATION=1 to run the MongoDB integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	container, err := testmongo.Run(ctx, integrationImage, testmongo.WithReplicaSet("rs0"))
	if err != nil {
		t.Fatalf("start MongoDB container: %v", err)
	}
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if err := testcontainers.TerminateContainer(container, testcontainers.StopContext(cleanupContext)); err != nil {
			t.Errorf("terminate MongoDB container: %v", err)
		}
	})

	uri, err := container.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("MongoDB connection string: %v", err)
	}
	uri = directConnectionURI(t, uri)
	t.Setenv("OWNDOCK_TEST_MONGODB_URI", uri)
	client, err := Open(ctx, config.Mongo{
		Enabled:          true,
		URIEnv:           "OWNDOCK_TEST_MONGODB_URI",
		Database:         "owndock_integration",
		ConnectTimeout:   "30s",
		OperationTimeout: "5s",
		MaxIdleTime:      "1m",
		MaxPoolSize:      10,
	})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() {
		closeContext, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer closeCancel()
		if err := client.Close(closeContext); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})

	if err := client.Ping(ctx); err != nil {
		t.Fatalf("Ping() error = %v", err)
	}
	var hello bson.M
	if err := client.Database().Client().Database("admin").
		RunCommand(ctx, bson.D{{Key: "hello", Value: 1}}).
		Decode(&hello); err != nil {
		t.Fatalf("hello command: %v", err)
	}
	if hello["setName"] != "rs0" {
		t.Fatalf("replica set name = %v, want rs0", hello["setName"])
	}

	session, err := client.Database().Client().StartSession()
	if err != nil {
		t.Fatalf("start session: %v", err)
	}
	defer session.EndSession(ctx)
	if _, err := session.WithTransaction(ctx, func(transactionContext context.Context) (any, error) {
		return client.Database().Collection("platform_probe").InsertOne(
			transactionContext,
			bson.D{{Key: "probe", Value: "transaction"}},
		)
	}); err != nil {
		t.Fatalf("transaction: %v", err)
	}
	count, err := client.Database().Collection("platform_probe").CountDocuments(ctx, bson.D{})
	if err != nil {
		t.Fatalf("count transaction result: %v", err)
	}
	if count != 1 {
		t.Fatalf("transaction result count = %d, want 1", count)
	}

	if _, err := client.Database().Collection("projects").InsertOne(ctx, bson.D{
		{Key: "_id", Value: "legacy-project"},
		{Key: "organization_id", Value: "legacy-organization"},
	}); err != nil {
		t.Fatalf("seed legacy project: %v", err)
	}
	if _, err := client.Database().Collection("product_applications").InsertOne(ctx, bson.D{
		{Key: "_id", Value: "legacy-application"},
		{Key: "project_id", Value: "legacy-project"},
		{Key: "name", Value: "Legacy Application"},
		{Key: "name_normalized", Value: "legacy application"},
		{Key: "created_by", Value: "legacy-user"},
		{Key: "created_at", Value: time.Now().UTC()},
	}); err != nil {
		t.Fatalf("seed legacy Application: %v", err)
	}
	if _, err := client.Database().Collection("environments").InsertOne(ctx, bson.D{
		{Key: "_id", Value: "legacy-environment"},
		{Key: "project_id", Value: "legacy-project"},
		{Key: "name", Value: "Legacy Environment"},
		{Key: "name_normalized", Value: "legacy environment"},
		{Key: "stage", Value: "development"},
		{Key: "created_by", Value: "legacy-user"},
		{Key: "created_at", Value: time.Now().UTC()},
	}); err != nil {
		t.Fatalf("seed legacy Environment: %v", err)
	}
	if _, err := client.Database().Collection("releases").InsertOne(ctx, bson.D{
		{Key: "_id", Value: "legacy-release"},
		{Key: "project_id", Value: "legacy-project"},
		{Key: "application_id", Value: "legacy-application"},
		{Key: "image_digest", Value: "registry.example.com/api@sha256:" + strings.Repeat("f", 64)},
	}); err != nil {
		t.Fatalf("seed legacy release: %v", err)
	}
	if _, err := client.Database().Collection("artifacts").InsertOne(ctx, bson.D{
		{Key: "_id", Value: "legacy-artifact"},
		{Key: "organization_id", Value: "legacy-organization"},
		{Key: "project_id", Value: "legacy-project"},
		{Key: "application_id", Value: "legacy-application"},
		{Key: "build_id", Value: "legacy-build"},
		{Key: "build_configuration_id", Value: "legacy-build-configuration"},
		{Key: "registry_credential_id", Value: "legacy-registry"},
		{Key: "image_repository", Value: "registry.example.com/team/legacy"},
		{Key: "image_digest", Value: "registry.example.com/team/legacy@sha256:" + strings.Repeat("e", 64)},
		{Key: "target_platform", Value: "linux/amd64"},
		{Key: "automatic_deployments", Value: bson.A{}},
		{Key: "release_status", Value: "available"},
		{Key: "version", Value: uint64(1)},
		{Key: "created_at", Value: time.Now().UTC()},
	}); err != nil {
		t.Fatalf("seed legacy Artifact: %v", err)
	}
	if _, err := client.Database().Collection("registry_credentials").InsertOne(ctx, bson.D{
		{Key: "_id", Value: "legacy-registry"},
		{Key: "project_id", Value: "legacy-project"},
		{Key: "name", Value: "Legacy Registry"},
		{Key: "name_normalized", Value: "legacy registry"},
		{Key: "server", Value: "registry.example.com"},
		{Key: "username", Value: "legacy-robot"},
		{Key: "password_ref", Value: "secret://legacy-registry"},
		{Key: "created_by", Value: "legacy-user"},
		{Key: "created_at", Value: time.Now().UTC()},
	}); err != nil {
		t.Fatalf("seed legacy Registry Credential: %v", err)
	}
	if _, err := client.Database().Collection("deployments").InsertOne(ctx, bson.D{
		{Key: "_id", Value: "legacy-deployment"},
		{Key: "project_id", Value: "legacy-project"},
		{Key: "application_id", Value: "legacy-application"},
		{Key: "environment_id", Value: "legacy-environment"},
		{Key: "idempotency_key", Value: "legacy-key"},
		{Key: "status", Value: "building"},
		{Key: "created_at", Value: time.Now().UTC()},
	}); err != nil {
		t.Fatalf("seed legacy deployment: %v", err)
	}
	if _, err := client.Database().Collection("terminal_sessions").InsertOne(ctx, bson.D{
		{Key: "_id", Value: "legacy-terminal-session"},
		{Key: "organization_id", Value: "legacy-organization"},
		{Key: "project_id", Value: "legacy-project"},
		{Key: "kind", Value: "container"},
		{Key: "authentication_session_id", Value: "legacy-authentication-session"},
		{Key: "deployment_id", Value: "legacy-deployment"},
		{Key: "active", Value: true},
		{Key: "created_at", Value: time.Now().UTC()},
	}); err != nil {
		t.Fatalf("seed legacy TerminalSession: %v", err)
	}
	if _, err := client.Database().Collection("deployments").InsertOne(ctx, bson.D{
		{Key: "_id", Value: "legacy-failed-deployment"},
		{Key: "project_id", Value: "legacy-project"},
		{Key: "idempotency_key", Value: "legacy-failed-key"},
		{Key: "status", Value: "failed"},
		{Key: "created_at", Value: time.Now().UTC()},
	}); err != nil {
		t.Fatalf("seed legacy failed deployment: %v", err)
	}
	legacyInventoryCompletedAt := time.Now().UTC().Add(-time.Minute)
	if _, err := client.Database().Collection("runtime_inventory_heads").InsertOne(ctx, bson.D{
		{Key: "_id", Value: "legacy-inventory-target"},
		{Key: "organization_id", Value: "legacy-organization"},
		{Key: "managed_host_id", Value: "legacy-inventory-host"},
		{Key: "runtime_target_id", Value: "legacy-inventory-target"},
		{Key: "observation_id", Value: "legacy-inventory-observation"},
		{Key: "generation", Value: uint64(9)},
		{Key: "started_at", Value: legacyInventoryCompletedAt.Add(-time.Second)},
		{Key: "completed_at", Value: legacyInventoryCompletedAt},
	}); err != nil {
		t.Fatalf("seed legacy runtime inventory head: %v", err)
	}
	if _, err := client.Database().Collection("runtime_inventory_resources").InsertOne(ctx, bson.D{
		{Key: "_id", Value: "legacy-inventory-resource-document"},
		{Key: "observation_id", Value: "legacy-inventory-observation"},
		{Key: "organization_id", Value: "legacy-organization"},
		{Key: "managed_host_id", Value: "legacy-inventory-host"},
		{Key: "runtime_target_id", Value: "legacy-inventory-target"},
		{Key: "kind", Value: "container"},
		{Key: "runtime_id", Value: "legacy-inventory-container"},
		{Key: "name", Value: "legacy-api"},
		{Key: "managed", Value: false},
		{Key: "container", Value: bson.D{{Key: "state", Value: "running"}}},
		{Key: "labels", Value: bson.D{}},
		{Key: "attributes", Value: bson.D{}},
		{Key: "ports", Value: bson.A{}},
		{Key: "mounts", Value: bson.A{}},
		{Key: "networks", Value: bson.A{}},
		{Key: "observed_at", Value: legacyInventoryCompletedAt},
		{Key: "schema_version", Value: 1},
	}); err != nil {
		t.Fatalf("seed legacy runtime inventory resource: %v", err)
	}
	runner := migration.NewRunner(client.Database(), "integration-test")
	if err := runner.Run(ctx, migration.Default()); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	if err := runner.Run(ctx, migration.Default()); err != nil {
		t.Fatalf("rerun migrations: %v", err)
	}
	for collection, resourceID := range map[string]string{
		"product_applications": "legacy-application",
		"environments":         "legacy-environment",
	} {
		var document struct {
			Status string `bson:"status"`
		}
		if err := client.Database().Collection(collection).FindOne(
			ctx, bson.D{{Key: "_id", Value: resourceID}},
		).Decode(&document); err != nil || document.Status != "active" {
			t.Fatalf("%s lifecycle backfill = %+v/%v", collection, document, err)
		}
	}
	var legacyTerminalScope struct {
		ApplicationID string `bson:"application_id"`
		EnvironmentID string `bson:"environment_id"`
	}
	if err := client.Database().Collection("terminal_sessions").FindOne(
		ctx, bson.D{{Key: "_id", Value: "legacy-terminal-session"}},
	).Decode(&legacyTerminalScope); err != nil ||
		legacyTerminalScope.ApplicationID != "legacy-application" ||
		legacyTerminalScope.EnvironmentID != "legacy-environment" {
		t.Fatalf("legacy TerminalSession product scope = %+v/%v", legacyTerminalScope, err)
	}
	assertRuntimeInventoryViewIndexes(t, ctx, client.Database())
	assertBuildLogIndexes(t, ctx, client.Database())
	assertBuildRetirementIndex(t, ctx, client.Database())
	assertAutomaticDeploymentIndex(t, ctx, client.Database())
	assertUserInvitationIndexes(t, ctx, client.Database())
	assertProjectMemberIndexes(t, ctx, client.Database())
	assertIngressRateLimitIndex(t, ctx, client.Database())
	assertTerminalIndexes(t, ctx, client.Database())
	assertArtifactEvidenceIndexes(t, ctx, client.Database())
	assertArtifactEvidenceJobIndexes(t, ctx, client.Database())
	assertEvidenceVerificationIndexes(t, ctx, client.Database())
	assertSignatureSigningProfileIndexes(t, ctx, client.Database())
	assertVulnerabilityObservationIndexes(t, ctx, client.Database())
	assertVulnerabilityWaiverIndexes(t, ctx, client.Database())
	assertDeploymentPolicyIndexes(t, ctx, client.Database())
	assertArtifactIndexes(t, ctx, client.Database())
	verifyIngressRateLimitIntegration(t, ctx, client.Database())
	verifyTerminalPersistenceIntegration(t, ctx, client.Database())
	verifyBuildWorkerSIGKILLRecovery(t, ctx, uri, client)
	verifyBuildRetirementQueryIntegration(t, ctx, client.Database())
	verifyBuildSourceRepositoryIntegration(t, ctx, client)
	verifyArtifactEvidenceIntegration(t, ctx, client.Database())
	verifyArtifactEvidenceFenceIntegration(t, ctx, client.Database())
	verifySignatureVerificationFenceIntegration(t, ctx, client.Database())
	verifyVulnerabilityObservationIntegration(t, ctx, client.Database())
	verifyVulnerabilityWaiverIntegration(t, ctx, client.Database())
	verifyDeploymentPolicyIntegration(t, ctx, client.Database())
	verifyExternalArtifactPersistenceIntegration(t, ctx, client.Database())
	var migratedArtifact struct {
		Origin               string `bson:"origin"`
		Producer             string `bson:"producer"`
		ProducerVerification string `bson:"producer_verification"`
	}
	if err := client.Database().Collection("artifacts").FindOne(ctx,
		bson.D{{Key: "_id", Value: "legacy-artifact"}}).Decode(&migratedArtifact); err != nil {
		t.Fatalf("read migrated Artifact: %v", err)
	}
	if migratedArtifact.Origin != "owndock_build" || migratedArtifact.Producer != "owndock-build-worker" ||
		migratedArtifact.ProducerVerification != "verified" {
		t.Fatalf("migrated Artifact producer = %+v", migratedArtifact)
	}
	var migratedRegistryCredential struct {
		AuthenticationMode registryauth.Mode `bson:"authentication_mode"`
	}
	if err := client.Database().Collection("registry_credentials").FindOne(ctx,
		bson.D{{Key: "_id", Value: "legacy-registry"}}).Decode(&migratedRegistryCredential); err != nil {
		t.Fatalf("read migrated Registry Credential: %v", err)
	}
	if migratedRegistryCredential.AuthenticationMode != registryauth.ModeBasic {
		t.Fatalf("migrated Registry authentication mode = %q", migratedRegistryCredential.AuthenticationMode)
	}
	var backfilledInventory bson.M
	if err := client.Database().Collection("runtime_inventory_current").FindOne(ctx, bson.D{
		{Key: "runtime_target_id", Value: "legacy-inventory-target"},
		{Key: "runtime_id", Value: "legacy-inventory-container"},
	}).Decode(&backfilledInventory); err != nil {
		t.Fatalf("find backfilled runtime inventory current state: %v", err)
	}
	if backfilledInventory["presence"] != "present" ||
		backfilledInventory["generation"] != int64(9) ||
		backfilledInventory["first_seen_at"] == nil {
		t.Fatalf("backfilled runtime inventory current state = %#v", backfilledInventory)
	}
	for _, collection := range []string{
		"runtime_inventory_heads", "runtime_inventory_resources", "runtime_inventory_current",
	} {
		if _, err := client.Database().Collection(collection).DeleteMany(ctx, bson.D{
			{Key: "runtime_target_id", Value: "legacy-inventory-target"},
		}); err != nil {
			t.Fatalf("clean legacy runtime inventory %s: %v", collection, err)
		}
	}
	verifyRuntimeInventoryIntegration(t, ctx, client.Database())
	verifyRuntimeInventoryViewsIntegration(t, ctx, client.Database())
	verifyRuntimeInventoryScheduleIntegration(t, ctx, client.Database())
	var migratedDeployment struct {
		OrganizationID  string `bson:"organization_id"`
		Status          string `bson:"status"`
		TriggerSource   string `bson:"trigger_source"`
		CutoverSequence uint64 `bson:"cutover_sequence"`
	}
	if err := client.Database().Collection("deployments").FindOne(
		ctx, bson.D{{Key: "_id", Value: "legacy-deployment"}},
	).Decode(&migratedDeployment); err != nil {
		t.Fatalf("read migrated deployment: %v", err)
	}
	if migratedDeployment.OrganizationID != "legacy-organization" ||
		migratedDeployment.Status != "preparing" ||
		migratedDeployment.TriggerSource != "manual" ||
		migratedDeployment.CutoverSequence == 0 {
		t.Fatalf("migrated deployment = %+v", migratedDeployment)
	}
	var migratedFailure struct {
		OrganizationID  string `bson:"organization_id"`
		FailureCategory string `bson:"failure_category"`
	}
	if err := client.Database().Collection("deployments").FindOne(
		ctx, bson.D{{Key: "_id", Value: "legacy-failed-deployment"}},
	).Decode(&migratedFailure); err != nil {
		t.Fatalf("read migrated failed deployment: %v", err)
	}
	if migratedFailure.OrganizationID != "legacy-organization" ||
		migratedFailure.FailureCategory != "unknown" {
		t.Fatalf("migrated failed deployment = %+v", migratedFailure)
	}
	var migratedRelease struct {
		RuntimeSpec struct {
			Resources struct {
				CPUMilli    int64 `bson:"cpu_milli"`
				MemoryBytes int64 `bson:"memory_bytes"`
			} `bson:"resources"`
		} `bson:"runtime_spec"`
	}
	if err := client.Database().Collection("releases").FindOne(
		ctx, bson.D{{Key: "_id", Value: "legacy-release"}},
	).Decode(&migratedRelease); err != nil {
		t.Fatalf("read migrated release: %v", err)
	}
	if migratedRelease.RuntimeSpec.Resources.CPUMilli != runtimespec.DefaultCPUMilli ||
		migratedRelease.RuntimeSpec.Resources.MemoryBytes != runtimespec.DefaultMemoryBytes {
		t.Fatalf("migrated release = %+v", migratedRelease)
	}
	if _, err := client.Database().Collection("deployments").DeleteMany(
		ctx, bson.D{{Key: "_id", Value: bson.D{{Key: "$in", Value: bson.A{
			"legacy-deployment", "legacy-failed-deployment",
		}}}}},
	); err != nil {
		t.Fatalf("delete legacy deployment fixtures: %v", err)
	}
	if _, err := client.Database().Collection("projects").DeleteOne(
		ctx, bson.D{{Key: "_id", Value: "legacy-project"}},
	); err != nil {
		t.Fatalf("delete legacy project fixture: %v", err)
	}
	if _, err := client.Database().Collection("releases").DeleteOne(
		ctx, bson.D{{Key: "_id", Value: "legacy-release"}},
	); err != nil {
		t.Fatalf("delete legacy release fixture: %v", err)
	}
	if _, err := client.Database().Collection("artifacts").DeleteOne(
		ctx, bson.D{{Key: "_id", Value: "legacy-artifact"}},
	); err != nil {
		t.Fatalf("delete legacy Artifact fixture: %v", err)
	}
	auditStore := platformaudit.NewMongoStore(client.Database())
	passwords, err := identitydata.NewPasswordHasher()
	if err != nil {
		t.Fatalf("password hasher: %v", err)
	}
	identityRepository := identitydata.NewMongoRepository(
		client.Database(),
	)
	identityNow := time.Now().UTC()
	identityUseCase := identitybiz.NewUseCase(
		identityRepository,
		client,
		auditStore,
		passwords,
		identitydata.SessionTokens{},
		id.New,
		func() time.Time { return identityNow },
		time.Hour,
	).WithLoginProtection(
		identityRepository,
		3,
		time.Minute,
	).WithSessionPolicy(3).
		WithInvitationPolicy(identityRepository, 24*time.Hour).
		WithAdministrativeSessions(identityRepository)
	bootstrap, err := identityUseCase.Bootstrap(
		ctx, "Integration Company", "owner@example.com", "integration-password", "bootstrap-request",
	)
	if err != nil {
		t.Fatalf("bootstrap identity: %v", err)
	}
	principal, err := identityUseCase.Authenticate(ctx, bootstrap.AccessToken)
	if err != nil {
		t.Fatalf("authenticate bootstrap token: %v", err)
	}
	invitation, err := identityUseCase.CreateInvitation(ctx, principal,
		"member@example.com", "invitation-create-request")
	if err != nil || invitation.Token == "" || invitation.Invitation.TokenHash != "" {
		t.Fatalf("create user invitation = %+v/%v", invitation, err)
	}
	var invitationDocument bson.M
	if err := client.Database().Collection("user_invitations").FindOne(ctx,
		bson.D{{Key: "_id", Value: invitation.Invitation.ID}}).Decode(&invitationDocument); err != nil {
		t.Fatalf("read user invitation: %v", err)
	}
	if invitationDocument["token_hash"] == invitation.Token || invitationDocument["token_hash"] == "" {
		t.Fatalf("invitation token was not one-way stored: %#v", invitationDocument)
	}
	memberCredentials, err := identityUseCase.AcceptInvitation(ctx, invitation.Token,
		"member-integration-password", "invitation-accept-request")
	if err != nil || memberCredentials.User.Role != security.RoleViewer || memberCredentials.AccessToken == "" {
		t.Fatalf("accept user invitation = %+v/%v", memberCredentials, err)
	}
	if _, err := identityUseCase.AcceptInvitation(ctx, invitation.Token,
		"member-integration-password", "invitation-replay-request"); !errors.Is(err, identitybiz.ErrInvalidInvitation) {
		t.Fatalf("replay user invitation error = %v", err)
	}
	memberPrincipal, err := identityUseCase.Authenticate(ctx, memberCredentials.AccessToken)
	if err != nil {
		t.Fatalf("authenticate invited user: %v", err)
	}
	storedInvitations, err := identityUseCase.ListInvitations(ctx, principal)
	if err != nil || len(storedInvitations) != 1 || storedInvitations[0].TokenHash != "" ||
		storedInvitations[0].Status != identitybiz.InvitationStatusAccepted {
		t.Fatalf("safe invitation list = %+v/%v", storedInvitations, err)
	}
	storedUsers, err := identityUseCase.ListUsers(ctx, principal)
	if err != nil || len(storedUsers) != 2 {
		t.Fatalf("organization users = %+v/%v", storedUsers, err)
	}
	for _, user := range storedUsers {
		if user.PasswordHash != "" {
			t.Fatalf("user list exposed password hash: %+v", user)
		}
	}
	for attempt := 1; attempt <= 3; attempt++ {
		if _, err := identityUseCase.Login(
			ctx,
			"owner@example.com",
			"wrong-password",
			"failed-login-request",
		); !errors.Is(err, identitybiz.ErrInvalidCredentials) {
			t.Fatalf(
				"failed login attempt %d error = %v",
				attempt,
				err,
			)
		}
	}
	if _, err := identityUseCase.Login(
		ctx,
		"owner@example.com",
		"integration-password",
		"limited-login-request",
	); !errors.Is(err, identitybiz.ErrLoginRateLimited) {
		t.Fatalf("rate-limited login error = %v", err)
	}
	identityNow = identityNow.Add(2 * time.Minute)
	login, err := identityUseCase.Login(ctx, "owner@example.com", "integration-password", "login-request")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	loginPrincipal, err := identityUseCase.Authenticate(ctx, login.AccessToken)
	if err != nil {
		t.Fatalf("authenticate login token: %v", err)
	}
	loginAttemptCount, err := client.Database().
		Collection("login_attempts").
		CountDocuments(ctx, bson.D{})
	if err != nil {
		t.Fatalf("count login attempts: %v", err)
	}
	if loginAttemptCount != 0 {
		t.Fatalf(
			"login attempt count after successful login = %d",
			loginAttemptCount,
		)
	}
	const concurrentLoginAttempts = 12
	var loginAttemptWait sync.WaitGroup
	allowedAttempts := make(chan bool, concurrentLoginAttempts)
	loginAttemptErrors := make(chan error, concurrentLoginAttempts)
	for range concurrentLoginAttempts {
		loginAttemptWait.Add(1)
		go func() {
			defer loginAttemptWait.Done()
			allowed, _, reserveErr :=
				identityRepository.ReserveLoginAttempt(
					ctx,
					strings.Repeat("a", 64),
					identityNow,
					3,
					time.Minute,
				)
			allowedAttempts <- allowed
			loginAttemptErrors <- reserveErr
		}()
	}
	loginAttemptWait.Wait()
	close(allowedAttempts)
	close(loginAttemptErrors)
	for reserveErr := range loginAttemptErrors {
		if reserveErr != nil {
			t.Fatalf("reserve concurrent login attempt: %v", reserveErr)
		}
	}
	allowedCount := 0
	for allowed := range allowedAttempts {
		if allowed {
			allowedCount++
		}
	}
	if allowedCount != 3 {
		t.Fatalf(
			"concurrent allowed login attempts = %d, want 3",
			allowedCount,
		)
	}
	if err := identityRepository.ResetLoginAttempts(
		ctx,
		strings.Repeat("a", 64),
	); err != nil {
		t.Fatalf("reset concurrent login attempts: %v", err)
	}
	latestAccessToken := login.AccessToken
	for index := 0; index < 2; index++ {
		credentials, err := identityUseCase.Login(
			ctx,
			"owner@example.com",
			"integration-password",
			"session-cap-login-request",
		)
		if err != nil {
			t.Fatalf(
				"create capped session %d: %v",
				index,
				err,
			)
		}
		latestAccessToken = credentials.AccessToken
	}
	latestPrincipal, err := identityUseCase.Authenticate(
		ctx,
		latestAccessToken,
	)
	if err != nil {
		t.Fatalf("authenticate latest capped session: %v", err)
	}
	activeSessions, err := identityUseCase.ListSessions(
		ctx,
		loginPrincipal,
	)
	if err != nil {
		t.Fatalf("list active sessions: %v", err)
	}
	if len(activeSessions) != 3 {
		t.Fatalf(
			"active sessions after cap = %d, want 3",
			len(activeSessions),
		)
	}
	if _, err := identityUseCase.Authenticate(
		ctx,
		bootstrap.AccessToken,
	); !errors.Is(err, security.ErrUnauthenticated) {
		t.Fatalf("evicted oldest bootstrap session error = %v", err)
	}
	var revokedSessionID string
	for _, session := range activeSessions {
		if session.ID != loginPrincipal.SessionID &&
			session.ID != latestPrincipal.SessionID {
			revokedSessionID = session.ID
			break
		}
	}
	if err := identityUseCase.RevokeSession(
		ctx,
		loginPrincipal,
		revokedSessionID,
		"session-revoke-request",
	); err != nil {
		t.Fatalf("revoke active session: %v", err)
	}
	activeSessions, err = identityUseCase.ListSessions(
		ctx,
		loginPrincipal,
	)
	if err != nil || len(activeSessions) != 2 {
		t.Fatalf(
			"active sessions after revoke = %d, %v; want 2",
			len(activeSessions),
			err,
		)
	}

	var storedSession struct {
		TokenHash string `bson:"token_hash"`
	}
	if err := client.Database().Collection("sessions").
		FindOne(ctx, bson.D{{Key: "_id", Value: loginPrincipal.SessionID}}).
		Decode(&storedSession); err != nil {
		t.Fatalf("read stored session: %v", err)
	}
	if storedSession.TokenHash == "" || storedSession.TokenHash == login.AccessToken {
		t.Fatal("session token was not stored as a one-way hash")
	}

	controlPlaneStore := controlplanedata.NewMongoStore(client.Database())
	managedHostStore := managedhostdata.NewMongoRepository(client.Database())
	managedHostUseCase := managedhostbiz.NewUseCase(
		managedHostStore, client, auditStore, id.New, time.Now,
	)
	controlPlaneUseCase := controlplanebiz.NewUseCaseWithResources(
		controlPlaneStore, controlPlaneStore, controlPlaneStore, controlPlaneStore, controlPlaneStore, controlPlaneStore,
		client, auditStore, auditStore, id.New, time.Now,
	).WithManagedHosts(managedHostStore).
		WithProjectMembers(controlPlaneStore).
		WithTemplates(controlplanedata.NewBuiltInTemplateCatalog()).
		WithRuntimeTargetProbe(controlPlaneStore, readyRuntimeTargetProber{}).
		WithRuntimeTargetRetirement(controlPlaneStore, completedRuntimeTargetRetirer{})
	host, err := managedHostUseCase.Create(
		ctx, principal, "Production Host", runtimeaccess.ModeDirectDocker,
		managedhostbiz.DirectSSHConfiguration{}, "host-request",
	)
	if err != nil {
		t.Fatalf("create managed host: %v", err)
	}
	agentHost, err := managedHostUseCase.Create(
		ctx, principal, "Private Agent Host", runtimeaccess.ModeAgent,
		managedhostbiz.DirectSSHConfiguration{}, "agent-host-request",
	)
	if err != nil {
		t.Fatalf("create agent managed host: %v", err)
	}
	enrollmentNow := time.Now().UTC()
	rawEnrollmentToken, enrollmentTokenHash, err :=
		(managedhostdata.EnrollmentTokens{}).New()
	if err != nil {
		t.Fatalf("generate agent enrollment: %v", err)
	}
	enrollmentID, err := id.New()
	if err != nil {
		t.Fatalf("generate agent enrollment ID: %v", err)
	}
	enrollment, err := managedhostbiz.NewEnrollment(
		enrollmentID, agentHost, enrollmentTokenHash, principal.UserID,
		enrollmentNow, 15*time.Minute,
	)
	if err != nil {
		t.Fatalf("create agent enrollment model: %v", err)
	}
	if err := client.WithinTransaction(ctx, func(transactionContext context.Context) error {
		return managedHostStore.CreateEnrollment(transactionContext, enrollment)
	}); err != nil {
		t.Fatalf("persist agent enrollment: %v", err)
	}
	var storedEnrollment struct {
		TokenHash string `bson:"token_hash"`
	}
	if err := client.Database().Collection("agent_enrollments").
		FindOne(ctx, bson.D{{Key: "_id", Value: enrollment.ID}}).
		Decode(&storedEnrollment); err != nil {
		t.Fatalf("read stored agent enrollment: %v", err)
	}
	if storedEnrollment.TokenHash == "" ||
		storedEnrollment.TokenHash == rawEnrollmentToken {
		t.Fatal("agent enrollment token was not stored as a one-way hash")
	}
	foundEnrollment, err := managedHostStore.FindAvailableEnrollment(
		ctx,
		(managedhostdata.EnrollmentTokens{}).Hash(rawEnrollmentToken),
		enrollmentNow,
	)
	if err != nil {
		t.Fatalf("find agent enrollment: %v", err)
	}
	agentIdentityID, err := id.New()
	if err != nil {
		t.Fatalf("generate agent identity ID: %v", err)
	}
	agentIdentity, err := managedhostbiz.NewAgentIdentity(
		agentIdentityID,
		foundEnrollment,
		"instance-integration",
		"1.0.0",
		"v1",
		[]string{"docker"},
		managedhostbiz.IssuedCertificate{
			Serial:    "integration-agent-serial",
			SHA256:    "integration-agent-fingerprint",
			ExpiresAt: enrollmentNow.Add(24 * time.Hour),
		},
		enrollmentNow,
	)
	if err != nil {
		t.Fatalf("create agent identity model: %v", err)
	}
	mismatchedAgentIdentity := agentIdentity
	mismatchedAgentIdentity.ManagedHostID = host.ID
	if err := client.WithinTransaction(ctx, func(transactionContext context.Context) error {
		return managedHostStore.ActivateAgent(
			transactionContext,
			foundEnrollment.ID,
			foundEnrollment.TokenHash,
			enrollmentNow,
			mismatchedAgentIdentity,
		)
	}); !errors.Is(err, managedhostbiz.ErrInvalidEnrollment) {
		t.Fatalf("cross-host agent enrollment error = %v", err)
	}
	if err := client.WithinTransaction(ctx, func(transactionContext context.Context) error {
		return managedHostStore.ActivateAgentRecoverable(
			transactionContext,
			foundEnrollment.ID,
			foundEnrollment.TokenHash,
			enrollmentNow,
			agentIdentity,
			managedhostbiz.EnrollmentRecovery{
				RequestSHA256:    strings.Repeat("a", 64),
				RecoverUntil:     enrollmentNow.Add(10 * time.Minute),
				CertificatePEM:   []byte("issued-certificate"),
				CACertificatePEM: []byte("issued-ca"),
			},
		)
	}); err != nil {
		t.Fatalf("activate agent identity: %v", err)
	}
	recoveredEnrollment, recovered, err := managedHostStore.RecoverAgentEnrollment(
		ctx, foundEnrollment.TokenHash, strings.Repeat("a", 64), enrollmentNow,
	)
	if err != nil || !recovered || recoveredEnrollment.Identity.ID != agentIdentity.ID ||
		string(recoveredEnrollment.CertificatePEM) != "issued-certificate" {
		t.Fatalf("recovered enrollment = %+v, found = %t, error = %v", recoveredEnrollment, recovered, err)
	}
	if _, recovered, err := managedHostStore.RecoverAgentEnrollment(
		ctx, foundEnrollment.TokenHash, strings.Repeat("b", 64), enrollmentNow,
	); err != nil || recovered {
		t.Fatalf("conflicting enrollment recovery found = %t, error = %v", recovered, err)
	}
	if err := client.WithinTransaction(ctx, func(transactionContext context.Context) error {
		return managedHostStore.ActivateAgent(
			transactionContext,
			foundEnrollment.ID,
			foundEnrollment.TokenHash,
			enrollmentNow,
			agentIdentity,
		)
	}); !errors.Is(err, managedhostbiz.ErrInvalidEnrollment) {
		t.Fatalf("replay agent enrollment error = %v", err)
	}
	activatedAgentHost, err := managedHostStore.Get(
		ctx, principal.OrganizationID, agentHost.ID,
	)
	if err != nil ||
		activatedAgentHost.AgentIdentityID != agentIdentity.ID ||
		activatedAgentHost.AgentInstanceID != agentIdentity.InstanceID ||
		activatedAgentHost.AgentCertificateExpiresAt.UnixMilli() !=
			agentIdentity.CertificateExpires.UnixMilli() ||
		activatedAgentHost.Status != managedhostbiz.StatusOffline {
		t.Fatalf("activated agent host = %+v, error = %v", activatedAgentHost, err)
	}
	managedHostUseCase.WithAgentControl(
		managedHostStore, nil, []string{"v1", "v1.1"},
	)
	agentCertificateIdentity := managedhostbiz.AgentCertificateIdentity{
		OrganizationID:    agentIdentity.OrganizationID,
		ManagedHostID:     agentIdentity.ManagedHostID,
		IdentityID:        agentIdentity.ID,
		InstanceID:        agentIdentity.InstanceID,
		CertificateSerial: agentIdentity.CertificateSerial,
		CertificateSHA256: agentIdentity.CertificateSHA256,
	}
	agentHello := managedhostbiz.AgentHello{
		OrganizationID:  agentIdentity.OrganizationID,
		ManagedHostID:   agentIdentity.ManagedHostID,
		IdentityID:      agentIdentity.ID,
		InstanceID:      agentIdentity.InstanceID,
		BootID:          "integration-boot-1",
		AgentVersion:    "1.1.0",
		ProtocolVersion: "v1",
		Capabilities:    []string{"docker"},
	}
	firstAgentSession, err := managedHostUseCase.OpenAgentSession(
		ctx, agentCertificateIdentity, agentHello, "agent-connect-request",
	)
	if err != nil {
		t.Fatalf("open Agent session: %v", err)
	}
	if err := managedHostUseCase.HeartbeatAgentSession(
		ctx, firstAgentSession,
	); err != nil {
		t.Fatalf("heartbeat Agent session: %v", err)
	}
	agentHello.BootID = "integration-boot-2"
	secondAgentSession, err := managedHostUseCase.OpenAgentSession(
		ctx, agentCertificateIdentity, agentHello, "agent-reconnect-request",
	)
	if err != nil {
		t.Fatalf("reconnect Agent session: %v", err)
	}
	if err := managedHostUseCase.CloseAgentSession(
		ctx, firstAgentSession, "stale-agent-disconnect",
	); err != nil {
		t.Fatalf("close stale Agent session: %v", err)
	}
	onlineAgentHost, err := managedHostStore.Get(
		ctx, principal.OrganizationID, agentHost.ID,
	)
	if err != nil || onlineAgentHost.Status != managedhostbiz.StatusOnline ||
		onlineAgentHost.AgentSessionID != secondAgentSession.ID ||
		onlineAgentHost.AgentBootID != agentHello.BootID ||
		onlineAgentHost.LastSeenAt.IsZero() {
		t.Fatalf("online Agent host = %+v, error = %v", onlineAgentHost, err)
	}
	disabledAgentHost, err := managedHostUseCase.Disable(
		ctx, principal, agentHost.ID, "disable-agent-host-request",
	)
	if err != nil || disabledAgentHost.Status != managedhostbiz.StatusDisabled ||
		disabledAgentHost.AgentSessionID != "" ||
		disabledAgentHost.AgentBootID != "" {
		t.Fatalf("disable agent host = %+v, error = %v", disabledAgentHost, err)
	}
	var storedAgentIdentity struct {
		RevokedAt time.Time `bson:"revoked_at"`
	}
	if err := client.Database().Collection("agent_identities").
		FindOne(ctx, bson.D{{Key: "_id", Value: agentIdentity.ID}}).
		Decode(&storedAgentIdentity); err != nil {
		t.Fatalf("read disabled agent identity: %v", err)
	}
	if storedAgentIdentity.RevokedAt.IsZero() {
		t.Fatal("disabling an agent host did not persist identity revocation")
	}
	if err := managedHostUseCase.HeartbeatAgentSession(
		ctx, secondAgentSession,
	); !errors.Is(err, managedhostbiz.ErrInvalidAgentIdentity) {
		t.Fatalf("disabled Agent heartbeat error = %v", err)
	}
	project, err := controlPlaneUseCase.CreateProject(ctx, principal, "Delivery", "project-request")
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	memberProjects, err := controlPlaneUseCase.ListProjects(ctx, memberPrincipal)
	if err != nil || len(memberProjects) != 0 {
		t.Fatalf("unbound member projects = %+v/%v", memberProjects, err)
	}
	projectMember, err := controlPlaneUseCase.CreateProjectMember(
		ctx, principal, project.ID, memberCredentials.User.Email,
		security.RoleDeveloper, "project-member-create-request",
	)
	if err != nil || projectMember.Version != 1 || projectMember.Role != security.RoleDeveloper {
		t.Fatalf("create project member = %+v/%v", projectMember, err)
	}
	projectMember, err = controlPlaneUseCase.UpdateProjectMember(
		ctx, principal, project.ID, projectMember.UserID,
		security.RoleMaintainer, projectMember.Version, "project-member-update-request",
	)
	if err != nil || projectMember.Version != 2 || projectMember.Role != security.RoleMaintainer {
		t.Fatalf("update project member = %+v/%v", projectMember, err)
	}
	if _, err := controlPlaneUseCase.UpdateProjectMember(
		ctx, principal, project.ID, projectMember.UserID,
		security.RoleViewer, 1, "project-member-stale-request",
	); !errors.Is(err, controlplanebiz.ErrProjectMemberConflict) {
		t.Fatalf("stale project member update error = %v", err)
	}
	memberProjects, err = controlPlaneUseCase.ListProjects(ctx, memberPrincipal)
	if err != nil || len(memberProjects) != 1 || memberProjects[0].ID != project.ID {
		t.Fatalf("bound member projects = %+v/%v", memberProjects, err)
	}
	application, err := controlPlaneUseCase.CreateApplicationFromTemplate(
		ctx, principal, project.ID, "API", "http-service", "application-request",
	)
	if err != nil {
		t.Fatalf("create application: %v", err)
	}
	applications, err := controlPlaneUseCase.ListApplications(
		ctx, principal, project.ID,
	)
	if err != nil || len(applications) != 1 ||
		applications[0].TemplateSnapshot == nil ||
		applications[0].TemplateSnapshot.TemplateID != "http-service" ||
		applications[0].TemplateSnapshot.TemplateVersion != 1 ||
		applications[0].TemplateSnapshot.RuntimeSpec.Ports[0].ContainerPort != 8080 {
		t.Fatalf("persisted application snapshot = %+v, error = %v", applications, err)
	}
	if _, err := client.Database().Collection("product_applications").InsertOne(
		ctx,
		bson.D{
			{Key: "_id", Value: "invalid-template-snapshot"},
			{Key: "project_id", Value: project.ID},
			{Key: "name", Value: "Invalid Snapshot"},
			{Key: "name_normalized", Value: "invalid snapshot"},
			{Key: "status", Value: "active"},
			{Key: "template_snapshot", Value: bson.D{
				{Key: "template_id", Value: "http-service"},
				{Key: "template_version", Value: 1},
				{Key: "dockerfile_path", Value: "../Dockerfile"},
				{Key: "context_path", Value: "."},
				{Key: "runtime_spec", Value: bson.D{}},
			}},
			{Key: "created_by", Value: principal.UserID},
			{Key: "created_at", Value: time.Now().UTC()},
		},
	); err != nil {
		t.Fatalf("insert invalid application snapshot fixture: %v", err)
	}
	if _, err := controlPlaneUseCase.ListApplications(
		ctx, principal, project.ID,
	); !errors.Is(err, controlplanebiz.ErrInvalidTemplate) {
		t.Fatalf("invalid stored application snapshot error = %v", err)
	}
	if _, err := client.Database().Collection("product_applications").DeleteOne(
		ctx,
		bson.D{{Key: "_id", Value: "invalid-template-snapshot"}},
	); err != nil {
		t.Fatalf("remove invalid application snapshot fixture: %v", err)
	}
	registryCredential, err := controlPlaneUseCase.CreateRegistryCredential(
		ctx, principal, project.ID, "Private Registry", "registry.example.com",
		registryauth.ModeBasic, "robot", "secret://registry-password", "registry-request",
	)
	if err != nil {
		t.Fatalf("create registry credential: %v", err)
	}
	anonymousRegistryCredential, err := controlPlaneUseCase.CreateRegistryCredential(
		ctx, principal, project.ID, "Public Registry", "registry-1.docker.io",
		registryauth.ModeAnonymous, "", "", "anonymous-registry-request",
	)
	if err != nil || anonymousRegistryCredential.AuthenticationMode != registryauth.ModeAnonymous {
		t.Fatalf("create anonymous Registry Credential = %+v, %v", anonymousRegistryCredential, err)
	}
	var storedAnonymousRegistry bson.M
	if err := client.Database().Collection("registry_credentials").FindOne(ctx,
		bson.D{{Key: "_id", Value: anonymousRegistryCredential.ID}}).Decode(&storedAnonymousRegistry); err != nil {
		t.Fatalf("read anonymous Registry Credential: %v", err)
	}
	if storedAnonymousRegistry["authentication_mode"] != string(registryauth.ModeAnonymous) ||
		storedAnonymousRegistry["username"] != nil || storedAnonymousRegistry["password_ref"] != nil {
		t.Fatalf("stored anonymous Registry Credential = %#v", storedAnonymousRegistry)
	}
	release, err := controlPlaneUseCase.CreateReleaseWithRuntimeSpec(
		ctx, principal, project.ID, application.ID,
		"registry.example.com/team/api@sha256:"+strings.Repeat("a", 64),
		registryCredential.ID,
		runtimespec.Spec{
			Ports:           []runtimespec.Port{{Name: "http", ContainerPort: 8080}},
			EnvironmentKeys: []string{"DATABASE_URL"},
			HealthCheck:     &runtimespec.HealthCheck{Command: []string{"/healthcheck"}},
		},
		"release-request",
	)
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	target, err := controlPlaneUseCase.CreateRuntimeTarget(
		ctx, principal, project.ID, "production", host.ID,
		runtimeaccess.ModeDirectDocker,
		"tcp://docker.example.com:2376", "docker.example.com", "secret://docker-production",
		"target-request",
	)
	if err != nil {
		t.Fatalf("create runtime target: %v", err)
	}
	target, err = controlPlaneUseCase.ProbeRuntimeTarget(
		ctx, principal, project.ID, target.ID, "target-probe-request",
	)
	if err != nil || target.Status != controlplanebiz.RuntimeTargetStatusReady ||
		target.LastProbedAt.IsZero() {
		t.Fatalf("probe runtime target = %+v, error = %v", target, err)
	}
	environment, err := controlPlaneUseCase.CreateEnvironmentWithVariables(
		ctx, principal, project.ID, "Production", "production",
		map[string]string{"DATABASE_URL": "secret://database-url"},
		"environment-request",
	)
	if err != nil {
		t.Fatalf("create environment: %v", err)
	}
	anonymousRelease, err := controlPlaneUseCase.CreateReleaseWithRuntimeSpec(
		ctx, principal, project.ID, application.ID,
		"registry-1.docker.io/library/busybox@sha256:"+strings.Repeat("b", 64),
		anonymousRegistryCredential.ID, runtimespec.Spec{}, "anonymous-release-request",
	)
	if err != nil {
		t.Fatalf("create anonymous Registry release: %v", err)
	}
	if release.ApplicationID != application.ID || target.ProjectID != project.ID || environment.ProjectID != project.ID {
		t.Fatalf("release=%+v target=%+v environment=%+v", release, target, environment)
	}
	executionPlan, err := deploymentdata.NewExecutionResolver(controlPlaneStore).ResolveExecution(
		ctx,
		deploymentbiz.Deployment{
			ID: "execution-probe", ProjectID: project.ID, ApplicationID: application.ID,
			ReleaseID: release.ID, EnvironmentID: environment.ID, RuntimeTargetID: target.ID,
		},
	)
	if err != nil ||
		executionPlan.RegistryPasswordRef != "secret://registry-password" ||
		executionPlan.EnvironmentBindings["DATABASE_URL"] != "secret://database-url" ||
		executionPlan.RuntimeSpec.Resources.CPUMilli != runtimespec.DefaultCPUMilli {
		t.Fatalf("execution plan = %+v, error = %v", executionPlan, err)
	}
	anonymousExecutionPlan, err := deploymentdata.NewExecutionResolver(controlPlaneStore).ResolveExecution(
		ctx,
		deploymentbiz.Deployment{
			ID: "anonymous-execution-probe", ProjectID: project.ID, ApplicationID: application.ID,
			ReleaseID: anonymousRelease.ID, EnvironmentID: environment.ID, RuntimeTargetID: target.ID,
		},
	)
	if err != nil || anonymousExecutionPlan.RegistryServer != "registry-1.docker.io" ||
		anonymousExecutionPlan.RegistryUsername != "" || anonymousExecutionPlan.RegistryPasswordRef != "" {
		t.Fatalf("anonymous execution plan = %+v, error = %v", anonymousExecutionPlan, err)
	}

	deploymentStore := deploymentdata.NewMongoRepository(client.Database())
	deploymentUseCase := deploymentbiz.NewUseCase(deploymentStore, nil, nil, id.New, time.Now).
		WithFormalReferences(deploymentdata.NewFormalReferenceLookup(controlPlaneStore)).
		WithFormalSecurity(client, auditStore).
		WithAdmissionEvaluator(staticAdmissionEvaluator{stage: "production"})
	deployment, err := deploymentUseCase.CreateFormal(
		ctx, principal, project.ID, release.ID, application.ID, environment.ID, target.ID,
		"integration-deployment", "deployment-request",
	)
	if err != nil {
		t.Fatalf("create formal deployment: %v", err)
	}
	if deployment.CutoverSequence == 0 {
		t.Fatal("formal deployment has no cutover sequence")
	}
	if deployment.Admission.Decision != deploymentbiz.AdmissionNotConfigured ||
		deployment.Admission.EvaluationDigest == "" || deployment.Admission.Validate() != nil {
		t.Fatalf("formal deployment admission = %+v", deployment.Admission)
	}
	storedDeployment, err := deploymentStore.Get(ctx, project.ID, deployment.ID)
	if err != nil || storedDeployment.Admission.EvaluationDigest != deployment.Admission.EvaluationDigest ||
		storedDeployment.Admission.Validate() != nil {
		t.Fatalf("stored deployment admission = %+v, err = %v", storedDeployment.Admission, err)
	}
	replayed, err := deploymentUseCase.CreateFormal(
		ctx, principal, project.ID, release.ID, application.ID, environment.ID, target.ID,
		"integration-deployment", "deployment-replay-request",
	)
	if err != nil || replayed.ID != deployment.ID ||
		replayed.Admission.EvaluationDigest != deployment.Admission.EvaluationDigest {
		t.Fatalf("replay deployment = %+v, err = %v", replayed, err)
	}
	duplicateID := deployment
	duplicateID.IdempotencyKey = "integration-id-collision"
	if _, err := deploymentStore.Create(ctx, duplicateID); !errors.Is(err, deploymentbiz.ErrConflict) {
		t.Fatalf("duplicate deployment ID error = %v", err)
	}
	duplicateKey := deployment
	duplicateKey.ID, err = id.New()
	if err != nil {
		t.Fatalf("generate duplicate-key probe ID: %v", err)
	}
	if _, err := deploymentStore.Create(ctx, duplicateKey); !errors.Is(err, deploymentbiz.ErrDuplicateIdempotency) {
		t.Fatalf("duplicate deployment idempotency error = %v", err)
	}
	claimNow := time.Now().UTC()
	claimed, ok, err := deploymentStore.ClaimNext(ctx, deploymentbiz.Claim{
		WorkerID: "integration-worker", Now: claimNow, ExpiresAt: claimNow.Add(time.Minute),
	})
	if err != nil || !ok {
		t.Fatalf("claim deployment = %+v, %t, %v", claimed, ok, err)
	}
	if claimed.Lease.Generation == 0 {
		t.Fatalf("claim fence generation = %d", claimed.Lease.Generation)
	}
	claimGeneration := claimed.Lease.Generation
	if err := claimed.Transition(deploymentbiz.StatusPreparing, claimNow.Add(time.Second)); err != nil {
		t.Fatalf("transition preparing: %v", err)
	}
	claimed, err = deploymentStore.SaveClaimed(ctx, claimed, claimed.Version, "integration-worker", claimNow.Add(time.Second))
	if err != nil {
		t.Fatalf("save preparing: %v", err)
	}
	if err := deploymentStore.ValidateFence(
		ctx, claimed.ProjectID, claimed.ID, "integration-worker",
		claimGeneration, claimNow.Add(time.Second),
	); err != nil {
		t.Fatalf("validate active deployment fence: %v", err)
	}
	if err := claimed.Transition(deploymentbiz.StatusDeploying, claimNow.Add(2*time.Second)); err != nil {
		t.Fatalf("transition deploying: %v", err)
	}
	claimed, err = deploymentStore.SaveClaimed(ctx, claimed, claimed.Version, "integration-worker", claimNow.Add(2*time.Second))
	if err != nil {
		t.Fatalf("save deploying: %v", err)
	}
	if err := claimed.Transition(deploymentbiz.StatusSucceeded, claimNow.Add(3*time.Second)); err != nil {
		t.Fatalf("transition succeeded: %v", err)
	}
	completed, err := deploymentStore.SaveClaimed(ctx, claimed, claimed.Version, "integration-worker", claimNow.Add(3*time.Second))
	if err != nil || completed.Status != deploymentbiz.StatusSucceeded {
		t.Fatalf("save terminal deployment = %+v, err = %v", completed, err)
	}
	if err := deploymentStore.ValidateFence(
		ctx, completed.ProjectID, completed.ID, "integration-worker",
		claimGeneration, claimNow.Add(3*time.Second),
	); !errors.Is(err, deploymentbiz.ErrStaleExecution) {
		t.Fatalf("terminal deployment fence error = %v", err)
	}
	cancelCandidate, err := deploymentUseCase.CreateFormal(
		ctx, principal, project.ID, release.ID, application.ID, environment.ID, target.ID,
		"integration-cancel", "cancel-create-request",
	)
	if err != nil {
		t.Fatalf("create cancel candidate: %v", err)
	}
	cancelCandidate, err = deploymentUseCase.CancelFormal(
		ctx, principal, project.ID, cancelCandidate.ID, "cancel-request",
	)
	if err != nil || cancelCandidate.Status != deploymentbiz.StatusCanceling {
		t.Fatalf("request cancel = %+v, err = %v", cancelCandidate, err)
	}
	cancelRunner, err := deploymentworker.NewRunner(
		deploymentStore, deploymentworker.NoopExecutor{}, "cancel-worker", time.Minute, time.Now,
	)
	if err != nil {
		t.Fatalf("create cancel runner: %v", err)
	}
	cancelRunner.WithAudit(client, auditStore, id.New)
	if err := cancelRunner.RunOnce(ctx); err != nil {
		t.Fatalf("run cancellation: %v", err)
	}
	canceled, err := deploymentStore.Get(ctx, project.ID, cancelCandidate.ID)
	if err != nil || canceled.Status != deploymentbiz.StatusCanceled {
		t.Fatalf("canceled deployment = %+v, err = %v", canceled, err)
	}

	newerRelease, err := controlPlaneUseCase.CreateRelease(
		ctx, principal, project.ID, application.ID,
		"registry.example.com/team/api@sha256:"+strings.Repeat("b", 64),
		"newer-release-request",
	)
	if err != nil {
		t.Fatalf("create newer release: %v", err)
	}
	failedSource, err := deploymentUseCase.CreateFormal(
		ctx, principal, project.ID, newerRelease.ID, application.ID, environment.ID, target.ID,
		"integration-failed-source", "failed-source-request",
	)
	if err != nil {
		t.Fatalf("create failed source: %v", err)
	}
	failureNow := time.Now().UTC()
	failedSource, ok, err = deploymentStore.ClaimNext(ctx, deploymentbiz.Claim{
		WorkerID: "failure-worker", Now: failureNow, ExpiresAt: failureNow.Add(time.Minute),
	})
	if err != nil || !ok {
		t.Fatalf("claim failed source = %+v, %t, %v", failedSource, ok, err)
	}
	if err := failedSource.Transition(deploymentbiz.StatusPreparing, failureNow.Add(time.Second)); err != nil {
		t.Fatalf("transition failed source to preparing: %v", err)
	}
	failedSource, err = deploymentStore.SaveClaimed(
		ctx, failedSource, failedSource.Version, "failure-worker", failureNow.Add(time.Second),
	)
	if err != nil {
		t.Fatalf("save failed source preparing: %v", err)
	}
	if err := failedSource.Fail(deploymentbiz.FailureRuntime, failureNow.Add(2*time.Second)); err != nil {
		t.Fatalf("fail source: %v", err)
	}
	failedSource, err = deploymentStore.SaveClaimed(
		ctx, failedSource, failedSource.Version, "failure-worker", failureNow.Add(2*time.Second),
	)
	if err != nil {
		t.Fatalf("save failed source: %v", err)
	}
	storedFailedSource, err := deploymentStore.Get(ctx, project.ID, failedSource.ID)
	if err != nil || storedFailedSource.OrganizationID != principal.OrganizationID ||
		storedFailedSource.FailureCategory != deploymentbiz.FailureRuntime {
		t.Fatalf("stored failed source = %+v, err = %v", storedFailedSource, err)
	}

	retried, err := deploymentUseCase.RetryFormal(
		ctx, principal, project.ID, failedSource.ID, "integration-retry", "retry-request",
	)
	if err != nil {
		t.Fatalf("retry failed deployment: %v", err)
	}
	retriedReplay, err := deploymentUseCase.RetryFormal(
		ctx, principal, project.ID, failedSource.ID, "integration-retry", "retry-replay-request",
	)
	if err != nil || retriedReplay.ID != retried.ID {
		t.Fatalf("retry replay = %+v, err = %v", retriedReplay, err)
	}
	storedRetry, err := deploymentStore.Get(ctx, project.ID, retried.ID)
	if err != nil || storedRetry.Operation != deploymentbiz.OperationRetry ||
		storedRetry.SourceDeploymentID != failedSource.ID {
		t.Fatalf("stored retry = %+v, err = %v", storedRetry, err)
	}

	rolledBack, err := deploymentUseCase.RollbackFormal(
		ctx, principal, project.ID, failedSource.ID, release.ID,
		"integration-rollback", "rollback-request",
	)
	if err != nil {
		t.Fatalf("rollback deployment: %v", err)
	}
	storedRollback, err := deploymentStore.Get(ctx, project.ID, rolledBack.ID)
	if err != nil || storedRollback.Operation != deploymentbiz.OperationRollback ||
		storedRollback.SourceDeploymentID != failedSource.ID || storedRollback.ReleaseID != release.ID {
		t.Fatalf("stored rollback = %+v, err = %v", storedRollback, err)
	}

	events, err := controlPlaneUseCase.ListAuditEvents(ctx, principal, "", 100)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) < 7 {
		t.Fatalf("audit event count = %d, want at least 7", len(events))
	}
	foundWorkerAudit := false
	for _, event := range events {
		if event.Action == deploymentbiz.AuditActionCanceled &&
			event.ResourceID == cancelCandidate.ID &&
			event.ActorID == "system:cancel-worker" {
			foundWorkerAudit = true
			break
		}
	}
	if !foundWorkerAudit {
		t.Fatalf("worker cancellation audit was not persisted: %+v", events)
	}

	identityHTTP := identityservice.NewHTTP(identityUseCase, func() (string, error) {
		return "integration-bootstrap-token", nil
	})
	controlPlaneHTTP := controlplaneservice.NewHTTP(controlPlaneUseCase)
	projectAccess := controlplaneservice.NewProjectAccess(controlPlaneStore)
	authenticateProject := func(next http.Handler) http.Handler {
		return identityHTTP.Authenticate(projectAccess.Authorize(next))
	}
	productAPI, err := server.NewProductAPI(identityHTTP, controlPlaneHTTP, authenticateProject)
	if err != nil {
		t.Fatalf("create product API: %v", err)
	}
	unauthenticatedRequest := httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil)
	unauthenticatedResponse := httptest.NewRecorder()
	productAPI.ServeHTTP(unauthenticatedResponse, unauthenticatedRequest)
	if unauthenticatedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated product API status = %d", unauthenticatedResponse.Code)
	}
	authenticatedRequest := httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil)
	authenticatedRequest.Header.Set("Authorization", "Bearer "+latestAccessToken)
	authenticatedResponse := httptest.NewRecorder()
	productAPI.ServeHTTP(authenticatedResponse, authenticatedRequest)
	if authenticatedResponse.Code != http.StatusOK || !strings.Contains(authenticatedResponse.Body.String(), `"name":"Delivery"`) {
		t.Fatalf("authenticated product API status=%d body=%s", authenticatedResponse.Code, authenticatedResponse.Body.String())
	}
	memberRequest := httptest.NewRequest(http.MethodGet,
		"/api/v1/projects/"+project.ID+"/applications", nil)
	memberRequest.Header.Set("Authorization", "Bearer "+memberCredentials.AccessToken)
	memberResponse := httptest.NewRecorder()
	productAPI.ServeHTTP(memberResponse, memberRequest)
	if memberResponse.Code != http.StatusOK {
		t.Fatalf("project member API status=%d body=%s", memberResponse.Code, memberResponse.Body.String())
	}
	if err := controlPlaneUseCase.DeleteProjectMember(
		ctx, principal, project.ID, projectMember.UserID,
		projectMember.Version, "project-member-delete-request",
	); err != nil {
		t.Fatalf("delete project member: %v", err)
	}
	removedMemberRequest := httptest.NewRequest(http.MethodGet,
		"/api/v1/projects/"+project.ID+"/applications", nil)
	removedMemberRequest.Header.Set("Authorization", "Bearer "+memberCredentials.AccessToken)
	removedMemberResponse := httptest.NewRecorder()
	productAPI.ServeHTTP(removedMemberResponse, removedMemberRequest)
	if removedMemberResponse.Code != http.StatusNotFound {
		t.Fatalf("removed member API status=%d body=%s", removedMemberResponse.Code, removedMemberResponse.Body.String())
	}
	memberSessions, err := identityUseCase.ListUserSessions(ctx, principal, memberCredentials.User.ID)
	if err != nil || len(memberSessions) != 1 || memberSessions[0].TokenHash != "" {
		t.Fatalf("administrative member sessions = %+v/%v", memberSessions, err)
	}
	revokedMemberSessions, err := identityUseCase.RevokeAllUserSessions(
		ctx, principal, memberCredentials.User.ID, "member-session-revoke-all-request",
	)
	if err != nil || revokedMemberSessions != 1 {
		t.Fatalf("administrative member session revocation = %d/%v", revokedMemberSessions, err)
	}
	if _, err := identityUseCase.Authenticate(ctx, memberCredentials.AccessToken); !errors.Is(err, security.ErrUnauthenticated) {
		t.Fatalf("revoked member session authentication error = %v", err)
	}
	const concurrentSessionCreates = 8
	var sessionCreateWait sync.WaitGroup
	sessionCreateErrors := make(
		chan error,
		concurrentSessionCreates,
	)
	for index := 0; index < concurrentSessionCreates; index++ {
		sessionID, err := id.New()
		if err != nil {
			t.Fatalf("create concurrent session ID: %v", err)
		}
		tokenHash, err := id.New()
		if err != nil {
			t.Fatalf("create concurrent token hash: %v", err)
		}
		session := identitybiz.Session{
			ID:        sessionID,
			UserID:    principal.UserID,
			TokenHash: tokenHash,
			CreatedAt: identityNow.Add(
				time.Duration(index+1) * time.Second,
			),
			ExpiresAt: identityNow.Add(time.Hour),
		}
		sessionCreateWait.Add(1)
		go func() {
			defer sessionCreateWait.Done()
			sessionCreateErrors <- client.WithinTransaction(
				ctx,
				func(transactionContext context.Context) error {
					return identityRepository.CreateSession(
						transactionContext,
						session,
						identityNow,
						3,
					)
				},
			)
		}()
	}
	sessionCreateWait.Wait()
	close(sessionCreateErrors)
	for createErr := range sessionCreateErrors {
		if createErr != nil {
			t.Fatalf(
				"create concurrent capped session: %v",
				createErr,
			)
		}
	}
	activeSessions, err = identityUseCase.ListSessions(ctx, principal)
	if err != nil || len(activeSessions) != 3 {
		t.Fatalf(
			"concurrent active sessions = %d, %v; want 3",
			len(activeSessions),
			err,
		)
	}

	rollbackUseCase := controlplanebiz.NewUseCase(
		controlPlaneStore, controlPlaneStore, controlPlaneStore, controlPlaneStore,
		client, failingAudit{}, auditStore, id.New, time.Now,
	)
	if _, err := rollbackUseCase.CreateProject(ctx, principal, "Must Roll Back", "rollback-request"); !errors.Is(err, errAuditProbe) {
		t.Fatalf("create project with failed audit error = %v, want %v", err, errAuditProbe)
	}
	projects, err := controlPlaneUseCase.ListProjects(ctx, principal)
	if err != nil {
		t.Fatalf("list projects: %v", err)
	}
	for _, item := range projects {
		if item.Name == "Must Roll Back" {
			t.Fatal("resource write committed despite audit failure")
		}
	}

	targetDeleted, err := controlPlaneUseCase.DeleteRuntimeTarget(
		ctx, principal, project.ID, target.ID, "target-delete-request",
	)
	if err != nil || !targetDeleted {
		t.Fatalf("delete runtime target = %t, %v", targetDeleted, err)
	}
	targetDeleted, err = controlPlaneUseCase.DeleteRuntimeTarget(
		ctx, principal, project.ID, target.ID, "target-delete-replay",
	)
	if err != nil || !targetDeleted {
		t.Fatalf("replay runtime target delete = %t, %v", targetDeleted, err)
	}
	if _, err := controlPlaneStore.GetRuntimeTarget(
		ctx, project.ID, target.ID,
	); !errors.Is(err, controlplanebiz.ErrNotFound) {
		t.Fatalf("deleted runtime target lookup = %v", err)
	}
	resumableTarget, err := controlPlaneUseCase.CreateRuntimeTarget(
		ctx, principal, project.ID, "resumable retirement", host.ID,
		runtimeaccess.ModeDirectDocker,
		"tcp://docker.example.com:2376", "docker.example.com",
		"secret://docker-production", "resumable-target-request",
	)
	if err != nil {
		t.Fatalf("create resumable runtime target: %v", err)
	}
	retirement := controlplanebiz.RuntimeTargetRetirement{
		OrganizationID: principal.OrganizationID, ActorID: principal.UserID,
		RequestID: "resumable-delete-request", StartedAt: time.Now().UTC(),
	}
	retiringTarget, changed, err := controlPlaneStore.BeginRuntimeTargetRetirement(
		ctx, project.ID, resumableTarget.ID, retirement,
	)
	if err != nil || !changed || retiringTarget.Retirement == nil {
		t.Fatalf("begin resumable retirement = %+v/%t/%v", retiringTarget, changed, err)
	}
	retiringTargets, err := controlPlaneStore.ListRetiringRuntimeTargets(ctx, 10)
	if err != nil || len(retiringTargets) != 1 ||
		retiringTargets[0].ID != resumableTarget.ID ||
		retiringTargets[0].Retirement == nil ||
		retiringTargets[0].Retirement.RequestID != retirement.RequestID {
		t.Fatalf("retiring runtime targets = %+v/%v", retiringTargets, err)
	}
	if err := controlPlaneStore.DeleteRetiringRuntimeTarget(
		ctx, project.ID, resumableTarget.ID,
	); err != nil {
		t.Fatalf("delete resumable runtime target: %v", err)
	}

	retiringApplication, err := controlPlaneUseCase.CreateApplication(
		ctx, principal, project.ID, "Retiring Application", "retiring-application-create",
	)
	if err != nil {
		t.Fatalf("create retiring Application fixture: %v", err)
	}
	retiringEnvironment, err := controlPlaneUseCase.CreateEnvironment(
		ctx, principal, project.ID, "Retiring Environment", "staging", "retiring-environment-create",
	)
	if err != nil {
		t.Fatalf("create retiring Environment fixture: %v", err)
	}
	if err := client.WithinTransaction(ctx, func(transactionContext context.Context) error {
		active, fenceErr := controlPlaneStore.FenceProductResourceAdmission(
			transactionContext, project.ID, retiringApplication.ID, retiringEnvironment.ID,
		)
		if fenceErr != nil {
			return fenceErr
		}
		if !active {
			return errors.New("active product resource admission fence was closed")
		}
		return nil
	}); err != nil {
		t.Fatalf("fence active product resources: %v", err)
	}
	resourceRetirement := controlplanebiz.ProductResourceRetirement{
		OrganizationID: principal.OrganizationID, ActorID: principal.UserID,
		RequestID: "resource-retirement-request", StartedAt: time.Now().UTC(),
	}
	retiringApplication, changed, err = controlPlaneStore.BeginApplicationRetirement(
		ctx, project.ID, retiringApplication.ID, resourceRetirement,
	)
	if err != nil || !changed || retiringApplication.Retirement == nil {
		t.Fatalf("begin Application retirement = %+v/%t/%v", retiringApplication, changed, err)
	}
	retiringEnvironment, changed, err = controlPlaneStore.BeginEnvironmentRetirement(
		ctx, project.ID, retiringEnvironment.ID, resourceRetirement,
	)
	if err != nil || !changed || retiringEnvironment.Retirement == nil {
		t.Fatalf("begin Environment retirement = %+v/%t/%v", retiringEnvironment, changed, err)
	}
	queuedApplications, err := controlPlaneStore.ListRetiringApplications(ctx, 10)
	if err != nil || len(queuedApplications) != 1 || queuedApplications[0].ID != retiringApplication.ID {
		t.Fatalf("retiring Application queue = %+v/%v", queuedApplications, err)
	}
	queuedEnvironments, err := controlPlaneStore.ListRetiringEnvironments(ctx, 10)
	if err != nil || len(queuedEnvironments) != 1 || queuedEnvironments[0].ID != retiringEnvironment.ID {
		t.Fatalf("retiring Environment queue = %+v/%v", queuedEnvironments, err)
	}
	if exists, existsErr := controlPlaneStore.ApplicationExists(ctx, project.ID, retiringApplication.ID); existsErr != nil || exists {
		t.Fatalf("retiring Application admission = %t/%v", exists, existsErr)
	}
	if exists, existsErr := controlPlaneStore.EnvironmentExists(ctx, project.ID, retiringEnvironment.ID); existsErr != nil || exists {
		t.Fatalf("retiring Environment admission = %t/%v", exists, existsErr)
	}
	if active, fenceErr := controlPlaneStore.FenceProductResourceAdmission(
		ctx, project.ID, retiringApplication.ID, "",
	); fenceErr != nil || active {
		t.Fatalf("retiring Application transaction fence = %t/%v", active, fenceErr)
	}
	if active, fenceErr := controlPlaneStore.FenceProductResourceAdmission(
		ctx, project.ID, retiringApplication.ID, retiringEnvironment.ID,
	); fenceErr != nil || active {
		t.Fatalf("retiring product resources transaction fence = %t/%v", active, fenceErr)
	}
	retiredAt := time.Now().UTC()
	if err := controlPlaneStore.CompleteApplicationRetirement(ctx, project.ID, retiringApplication.ID, retiredAt); err != nil {
		t.Fatalf("complete Application retirement: %v", err)
	}
	if err := controlPlaneStore.CompleteEnvironmentRetirement(ctx, project.ID, retiringEnvironment.ID, retiredAt); err != nil {
		t.Fatalf("complete Environment retirement: %v", err)
	}
	if exists, existsErr := controlPlaneStore.ApplicationExistsAnyStatus(ctx, project.ID, retiringApplication.ID); existsErr != nil || !exists {
		t.Fatalf("retired Application history = %t/%v", exists, existsErr)
	}
	if _, err := controlPlaneUseCase.CreateApplication(
		ctx, principal, project.ID, "Retiring Application", "replacement-application-create",
	); err != nil {
		t.Fatalf("reuse retired Application name: %v", err)
	}
	if _, err := controlPlaneUseCase.CreateEnvironment(
		ctx, principal, project.ID, "Retiring Environment", "staging", "replacement-environment-create",
	); err != nil {
		t.Fatalf("reuse retired Environment name: %v", err)
	}

	if err := identityUseCase.Logout(ctx, loginPrincipal, "logout-request"); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, err := identityUseCase.Authenticate(ctx, login.AccessToken); err == nil {
		t.Fatal("logged-out session remained valid")
	}

	closeContext, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer closeCancel()
	if err := client.Close(closeContext); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := client.Close(closeContext); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

func TestBuildWorkerSIGKILLHelper(t *testing.T) {
	if os.Getenv("OWNDOCK_BUILD_SIGKILL_HELPER") != "1" {
		t.Skip("helper process only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := Open(ctx, config.Mongo{
		Enabled: true, URIEnv: "OWNDOCK_BUILD_SIGKILL_MONGODB_URI", Database: "owndock_integration",
		ConnectTimeout: "10s", OperationTimeout: "5s", MaxIdleTime: "1m", MaxPoolSize: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close(context.Background()) }()
	repository := builddata.NewMongoRepository(client.Database())
	controller, err := buildworker.NewController(
		repository, client, platformaudit.NewMongoStore(client.Database()),
		func() (string, error) { return "build-sigkill-helper-audit", nil }, time.Now, 2*time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	controller.WithClaimStatuses(buildbiz.BuildStatusQueued, buildbiz.BuildStatusCheckingOut)
	item, claimed, err := controller.Claim(ctx, "build-sigkill-worker-old")
	if err != nil || !claimed {
		t.Fatalf("helper Claim() = %+v/%t/%v", item, claimed, err)
	}
	if _, err := controller.Advance(ctx, item, "build-sigkill-worker-old", buildbiz.BuildStatusCheckingOut); err != nil {
		t.Fatal(err)
	}
	select {}
}

func verifyBuildWorkerSIGKILLRecovery(t *testing.T, ctx context.Context, uri string, client *Client) {
	t.Helper()
	repository := builddata.NewMongoRepository(client.Database())
	configuration, err := buildbiz.NewBuildConfiguration(
		"build-sigkill-configuration", "build-sigkill-project", "build-sigkill-application",
		"SIGKILL recovery", "build-sigkill-source", "Dockerfile", ".", []string{"refs/heads/main"},
		"build-sigkill-registry", "registry.example.com/team/recovery", buildbiz.BuildPlatformLinuxAMD64,
		buildbiz.BuildResources{}, 60, 1, false, "build-sigkill-user", time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := buildbiz.NewSourceRevision(
		"build-sigkill-source", "refs/heads/main", "a975c10d68a2d7461634f13b15c52a2efba72d16",
	)
	if err != nil {
		t.Fatal(err)
	}
	item, err := buildbiz.NewBuild(
		"build-sigkill-build", "build-sigkill-organization", "build-sigkill-project",
		"build-sigkill-application", configuration, revision, buildbiz.BuildTriggerSourceManual,
		"", "build-sigkill-request", "build-sigkill-user", time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CreateBuild(ctx, item); err != nil {
		t.Fatalf("seed SIGKILL Build: %v", err)
	}
	t.Cleanup(func() {
		cleanupContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = client.Database().Collection("builds").DeleteOne(cleanupContext,
			bson.D{{Key: "_id", Value: item.ID}})
		_, _ = client.Database().Collection("audit_events").DeleteMany(cleanupContext,
			bson.D{{Key: "project_id", Value: item.ProjectID}})
	})
	command := exec.Command(os.Args[0], "-test.run=^TestBuildWorkerSIGKILLHelper$", "-test.v")
	command.Env = append(os.Environ(),
		"OWNDOCK_BUILD_SIGKILL_HELPER=1",
		"OWNDOCK_BUILD_SIGKILL_MONGODB_URI="+uri,
	)
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatalf("start Build Worker SIGKILL helper: %v", err)
	}
	killed := false
	defer func() {
		if !killed && command.Process != nil {
			_ = command.Process.Kill()
			_, _ = command.Process.Wait()
		}
	}()
	deadline := time.Now().Add(15 * time.Second)
	var claimed buildbiz.Build
	for time.Now().Before(deadline) {
		stored, getErr := repository.GetBuild(ctx, item.ProjectID, item.ID)
		if getErr == nil && stored.Status == buildbiz.BuildStatusCheckingOut &&
			stored.Lease.Owner == "build-sigkill-worker-old" {
			claimed = stored
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if claimed.Lease.Owner == "" {
		_ = command.Process.Kill()
		_, _ = command.Process.Wait()
		killed = true
		t.Fatalf("Build Worker helper did not claim Build: %s", output.String())
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatalf("SIGKILL Build Worker helper: %v", err)
	}
	_, _ = command.Process.Wait()
	killed = true
	for time.Now().Before(claimed.Lease.ExpiresAt.Add(100 * time.Millisecond)) {
		time.Sleep(25 * time.Millisecond)
	}
	recovery, err := buildworker.NewController(
		repository, client, platformaudit.NewMongoStore(client.Database()),
		func() (string, error) { return "build-sigkill-recovery-audit", nil }, time.Now, 2*time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	recovery.WithClaimStatuses(buildbiz.BuildStatusCheckingOut)
	recovered, found, err := recovery.Claim(ctx, "build-sigkill-worker-new")
	if err != nil || !found || recovered.ID != item.ID ||
		recovered.Lease.Owner != "build-sigkill-worker-new" ||
		recovered.Lease.Generation != claimed.Lease.Generation+1 {
		t.Fatalf("recover SIGKILL Build = %+v/%t/%v, old=%+v", recovered, found, err, claimed.Lease)
	}
	if _, err := client.Database().Collection("builds").DeleteOne(ctx,
		bson.D{{Key: "_id", Value: item.ID}}); err != nil {
		t.Fatalf("clean recovered SIGKILL Build: %v", err)
	}
	if _, err := client.Database().Collection("audit_events").DeleteMany(ctx,
		bson.D{{Key: "project_id", Value: item.ProjectID}}); err != nil {
		t.Fatalf("clean recovered SIGKILL audit: %v", err)
	}
}

func verifyRuntimeInventoryViewsIntegration(
	t *testing.T,
	ctx context.Context,
	database *drivermongo.Database,
) {
	t.Helper()
	const (
		organizationID = "inventory-view-organization"
		projectID      = "inventory-view-project"
		hostID         = "inventory-view-host"
		targetID       = "inventory-view-target"
		deploymentID   = "inventory-view-deployment"
		applicationID  = "inventory-view-application"
		unmanagedCount = 1200
		resourceCount  = unmanagedCount + 2 // one managed container and one image
	)
	for collection, filter := range map[string]bson.D{
		"projects":                       {{Key: "organization_id", Value: organizationID}},
		"managed_hosts":                  {{Key: "organization_id", Value: organizationID}},
		"runtime_targets":                {{Key: "_id", Value: targetID}},
		"deployments":                    {{Key: "organization_id", Value: organizationID}},
		"runtime_inventory_observations": {{Key: "organization_id", Value: organizationID}},
		"runtime_inventory_resources":    {{Key: "organization_id", Value: organizationID}},
		"runtime_inventory_current":      {{Key: "organization_id", Value: organizationID}},
		"runtime_inventory_heads":        {{Key: "organization_id", Value: organizationID}},
		"runtime_inventory_counters":     {{Key: "organization_id", Value: organizationID}},
	} {
		collection, filter := collection, filter
		defer func() {
			_, _ = database.Collection(collection).DeleteMany(context.Background(), filter)
		}()
	}
	if _, err := database.Collection("projects").InsertOne(ctx, bson.D{
		{Key: "_id", Value: projectID},
		{Key: "organization_id", Value: organizationID},
	}); err != nil {
		t.Fatalf("seed inventory view project: %v", err)
	}
	if _, err := database.Collection("managed_hosts").InsertOne(ctx, bson.D{
		{Key: "_id", Value: hostID},
		{Key: "organization_id", Value: organizationID},
	}); err != nil {
		t.Fatalf("seed inventory view host: %v", err)
	}
	if _, err := database.Collection("runtime_targets").InsertOne(ctx, bson.D{
		{Key: "_id", Value: targetID},
		{Key: "project_id", Value: projectID},
		{Key: "managed_host_id", Value: hostID},
		{Key: "status", Value: controlplanebiz.RuntimeTargetStatusReady},
		{Key: "created_at", Value: time.Now().UTC()},
	}); err != nil {
		t.Fatalf("seed inventory view target: %v", err)
	}
	if _, err := database.Collection("deployments").InsertOne(ctx, bson.D{
		{Key: "_id", Value: deploymentID},
		{Key: "organization_id", Value: organizationID},
		{Key: "project_id", Value: projectID},
		{Key: "application_id", Value: applicationID},
		{Key: "runtime_target_id", Value: targetID},
		{Key: "status", Value: "succeeded"},
	}); err != nil {
		t.Fatalf("seed inventory view deployment: %v", err)
	}

	startedAt := time.Now().UTC().Truncate(time.Millisecond).Add(-time.Minute)
	expectedChunks := (resourceCount + runtimeinventorybiz.MaxResourcesPerChunk - 1) /
		runtimeinventorybiz.MaxResourcesPerChunk
	observation, err := runtimeinventorybiz.NewObservation(
		"inventory-view-observation", organizationID, hostID, targetID,
		expectedChunks, resourceCount, startedAt,
	)
	if err != nil {
		t.Fatalf("NewObservation() error = %v", err)
	}
	resources := make([]runtimeinventorybiz.Resource, 0, resourceCount)
	for index := 0; index <= unmanagedCount; index++ {
		name := fmt.Sprintf("external-%04d", index)
		if index == 0 {
			name = "managed-api"
		} else if index == 1 {
			name = "forged-api"
		}
		resource, resourceErr := runtimeinventorybiz.NewResource(
			observation, runtimeinventorybiz.KindContainer,
			fmt.Sprintf("inventory-view-container-%d", index), name, startedAt,
		)
		if resourceErr != nil {
			t.Fatalf("NewResource(container) error = %v", resourceErr)
		}
		resource.Container = &runtimeinventorybiz.ContainerSummary{State: "running"}
		if index < 2 {
			resource.Labels = map[string]string{
				"net.owndock.deployment_id":  deploymentID,
				"net.owndock.project_id":     projectID,
				"net.owndock.application_id": applicationID,
			}
		}
		if index == 1 {
			resource.Labels["net.owndock.application_id"] = "forged-application"
		}
		resources = append(resources, resource)
	}
	imageResource, err := runtimeinventorybiz.NewResource(
		observation, runtimeinventorybiz.KindImage,
		"inventory-view-image", "example/api:1", startedAt,
	)
	if err != nil {
		t.Fatalf("NewResource(image) error = %v", err)
	}
	imageResource.Image = &runtimeinventorybiz.ImageSummary{
		RepoTags: []string{"example/api:1"}, RepoDigests: []string{},
	}
	resources = append(resources, imageResource)
	repository := runtimeinventorydata.NewMongoRepository(database).
		WithOwnershipVerifier(runtimeinventorydata.NewMongoOwnershipVerifier(database))
	if err := repository.Begin(ctx, observation); err != nil {
		t.Fatalf("Begin(view observation) error = %v", err)
	}
	for index, first := 0, 0; first < len(resources); index++ {
		last := min(first+runtimeinventorybiz.MaxResourcesPerChunk, len(resources))
		chunk, chunkErr := runtimeinventorybiz.NewChunk(
			observation, index, resources[first:last],
		)
		if chunkErr != nil {
			t.Fatalf("NewChunk(%d) error = %v", index, chunkErr)
		}
		if err := repository.Append(ctx, chunk); err != nil {
			t.Fatalf("Append(view observation chunk %d) error = %v", index, err)
		}
		first = last
	}
	if err := repository.Complete(ctx, observation.ID, targetID, startedAt.Add(time.Second)); err != nil {
		t.Fatalf("Complete(view observation) error = %v", err)
	}

	views := runtimeinventorydata.NewMongoViewRepository(database)
	projectPage, err := views.ListProject(ctx, organizationID, projectID, runtimeinventorybiz.ViewQuery{Limit: 100})
	if err != nil {
		t.Fatalf("ListProject() error = %v", err)
	}
	if len(projectPage.Items) != 1 || !projectPage.Items[0].Managed ||
		projectPage.Items[0].DeploymentID != deploymentID ||
		projectPage.Items[0].Name != "managed-api" ||
		len(projectPage.Items[0].Labels) != 0 ||
		len(projectPage.Items[0].Attributes) != 0 {
		t.Fatalf("project inventory = %+v", projectPage)
	}
	seen := make(map[string]struct{}, resourceCount)
	cursor := ""
	foundForged := false
	for pageNumber := 1; ; pageNumber++ {
		page, pageErr := views.ListHost(ctx, organizationID, hostID, runtimeinventorybiz.ViewQuery{
			Limit: runtimeinventorybiz.MaximumPageSize, Cursor: cursor,
		})
		if pageErr != nil {
			t.Fatalf("ListHost(page %d) error = %v", pageNumber, pageErr)
		}
		for _, state := range page.Items {
			key := string(state.Kind) + "\x00" + state.RuntimeID
			if _, duplicate := seen[key]; duplicate {
				t.Fatalf("duplicate host inventory item %q across pages", key)
			}
			seen[key] = struct{}{}
			if state.Name == "forged-api" {
				foundForged = true
				if state.Managed || state.ProjectID != "" || state.DeploymentID != "" {
					t.Fatalf("forged ownership was accepted: %+v", state)
				}
			}
		}
		cursor = page.NextCursor
		if cursor == "" {
			break
		}
		if pageNumber > 10 {
			t.Fatal("host inventory pagination did not terminate")
		}
	}
	if len(seen) != resourceCount || !foundForged {
		t.Fatalf("host inventory count/forged = %d/%t, want %d/true", len(seen), foundForged, resourceCount)
	}
	if _, err := views.ListProject(ctx, "other-organization", projectID, runtimeinventorybiz.ViewQuery{Limit: 100}); !errors.Is(err, runtimeinventorybiz.ErrNotFound) {
		t.Fatalf("cross-organization ListProject() error = %v", err)
	}

	empty, err := runtimeinventorybiz.NewObservation(
		"inventory-view-empty-observation", organizationID, hostID, targetID,
		0, 0, startedAt.Add(2*time.Second),
	)
	if err != nil {
		t.Fatalf("NewObservation(empty) error = %v", err)
	}
	if err := repository.Begin(ctx, empty); err != nil {
		t.Fatalf("Begin(empty view observation) error = %v", err)
	}
	if err := repository.Complete(ctx, empty.ID, targetID, startedAt.Add(3*time.Second)); err != nil {
		t.Fatalf("Complete(empty view observation) error = %v", err)
	}
	present, err := views.ListHost(ctx, organizationID, hostID, runtimeinventorybiz.ViewQuery{Limit: 100})
	if err != nil || len(present.Items) != 0 {
		t.Fatalf("present host inventory after empty observation = %+v/%v", present, err)
	}
	absentProject, err := views.ListProject(ctx, organizationID, projectID, runtimeinventorybiz.ViewQuery{
		IncludeAbsent: true, Limit: 100,
	})
	if err != nil || len(absentProject.Items) != 1 ||
		absentProject.Items[0].Presence != runtimeinventorybiz.PresenceAbsent {
		t.Fatalf("absent project inventory = %+v/%v", absentProject, err)
	}

	recovery, err := runtimeinventorybiz.NewObservation(
		"inventory-view-recovery-observation", organizationID, hostID, targetID,
		1, 1, startedAt.Add(4*time.Second),
	)
	if err != nil {
		t.Fatalf("NewObservation(recovery) error = %v", err)
	}
	restored, err := runtimeinventorybiz.NewResource(
		recovery, runtimeinventorybiz.KindContainer,
		"inventory-view-container-0", "managed-api", startedAt.Add(4*time.Second),
	)
	if err != nil {
		t.Fatalf("NewResource(recovery) error = %v", err)
	}
	restored.Container = &runtimeinventorybiz.ContainerSummary{State: "running"}
	restored.Labels = map[string]string{
		"net.owndock.deployment_id":  deploymentID,
		"net.owndock.project_id":     projectID,
		"net.owndock.application_id": applicationID,
	}
	recoveryChunk, err := runtimeinventorybiz.NewChunk(
		recovery, 0, []runtimeinventorybiz.Resource{restored},
	)
	if err != nil {
		t.Fatalf("NewChunk(recovery) error = %v", err)
	}
	failingRepository := runtimeinventorydata.NewMongoRepository(database).
		WithOwnershipVerifier(ownershipFailureVerifier{})
	if err := failingRepository.Begin(ctx, recovery); err != nil {
		t.Fatalf("Begin(recovery) error = %v", err)
	}
	if err := failingRepository.Append(ctx, recoveryChunk); err != nil {
		t.Fatalf("Append(recovery) error = %v", err)
	}
	if err := failingRepository.Complete(
		ctx, recovery.ID, targetID, startedAt.Add(5*time.Second),
	); !errors.Is(err, errOwnershipProbe) {
		t.Fatalf("Complete(recovery failure) error = %v", err)
	}
	stillAbsent, err := views.ListProject(ctx, organizationID, projectID, runtimeinventorybiz.ViewQuery{
		IncludeAbsent: true, Limit: 100,
	})
	if err != nil || len(stillAbsent.Items) != 1 ||
		stillAbsent.Items[0].Presence != runtimeinventorybiz.PresenceAbsent {
		t.Fatalf("view changed after failed ownership transaction = %+v/%v", stillAbsent, err)
	}
	var failedObservation struct {
		Status runtimeinventorybiz.ObservationStatus `bson:"status"`
	}
	if err := database.Collection("runtime_inventory_observations").FindOne(
		ctx, bson.D{{Key: "_id", Value: recovery.ID}},
	).Decode(&failedObservation); err != nil ||
		failedObservation.Status != runtimeinventorybiz.ObservationOpen {
		t.Fatalf("failed observation status = %+v/%v", failedObservation, err)
	}
	if err := repository.Complete(
		ctx, recovery.ID, targetID, startedAt.Add(6*time.Second),
	); err != nil {
		t.Fatalf("retry Complete(recovery) error = %v", err)
	}
	recovered, err := views.ListProject(ctx, organizationID, projectID, runtimeinventorybiz.ViewQuery{Limit: 100})
	if err != nil || len(recovered.Items) != 1 ||
		recovered.Items[0].Presence != runtimeinventorybiz.PresencePresent ||
		!recovered.Items[0].FirstSeenAt.Equal(projectPage.Items[0].FirstSeenAt) {
		t.Fatalf("recovered project inventory = %+v/%v", recovered, err)
	}
	late, err := runtimeinventorybiz.NewObservation(
		"inventory-view-late-observation", organizationID, hostID, targetID,
		0, 0, startedAt.Add(7*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Begin(ctx, late); err != nil {
		t.Fatalf("begin late inventory observation: %v", err)
	}
	if _, err := database.Collection("runtime_targets").UpdateOne(
		ctx,
		bson.D{{Key: "_id", Value: targetID}},
		bson.D{{Key: "$set", Value: bson.D{{Key: "status", Value: "retiring"}}}},
	); err != nil {
		t.Fatalf("retire inventory target fixture: %v", err)
	}
	if err := repository.Complete(
		ctx, late.ID, targetID, startedAt.Add(8*time.Second),
	); !errors.Is(err, runtimeinventorybiz.ErrNotFound) {
		t.Fatalf("retiring target accepted inventory completion: %v", err)
	}
	rejected, err := runtimeinventorybiz.NewObservation(
		"inventory-view-rejected-observation", organizationID, hostID, targetID,
		0, 0, startedAt.Add(9*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Begin(ctx, rejected); !errors.Is(
		err, runtimeinventorybiz.ErrNotFound,
	) {
		t.Fatalf("retiring target accepted inventory observation: %v", err)
	}
	cleanupBatchFixtures := make([]any, 257)
	for index := range cleanupBatchFixtures {
		cleanupBatchFixtures[index] = bson.D{
			{Key: "_id", Value: fmt.Sprintf("inventory-cleanup-%03d", index)},
			{Key: "organization_id", Value: organizationID},
			{Key: "managed_host_id", Value: hostID},
			{Key: "runtime_target_id", Value: targetID},
			{Key: "started_at", Value: startedAt.Add(time.Duration(index) * time.Millisecond)},
		}
	}
	if _, err := database.Collection("runtime_inventory_observations").InsertMany(
		ctx, cleanupBatchFixtures,
	); err != nil {
		t.Fatalf("seed bounded inventory cleanup: %v", err)
	}
	convergence := runtimeinventorydata.NewRuntimeTargetConvergence(database)
	pending, err := convergence.ConvergeRuntimeTarget(
		ctx, organizationID, projectID, targetID, "owner-1", "request-1",
	)
	if err != nil || !pending {
		t.Fatalf("first inventory convergence = %t/%v", pending, err)
	}
	pending, err = convergence.ConvergeRuntimeTarget(
		ctx, organizationID, projectID, targetID, "owner-1", "request-1",
	)
	if err != nil || pending {
		t.Fatalf("completed inventory convergence = %t/%v", pending, err)
	}
	for _, collection := range []string{
		"runtime_inventory_observations", "runtime_inventory_chunks",
		"runtime_inventory_resources", "runtime_inventory_current",
		"runtime_inventory_heads", "runtime_inventory_counters",
		"runtime_inventory_schedule", "runtime_inventory_event_hints",
	} {
		filter := bson.D{{Key: "runtime_target_id", Value: targetID}}
		switch collection {
		case "runtime_inventory_chunks":
			filter = bson.D{{Key: "observation_id", Value: bson.D{{
				Key: "$in", Value: bson.A{observation.ID, empty.ID, recovery.ID},
			}}}}
		case "runtime_inventory_schedule":
			filter = bson.D{{Key: "_id", Value: targetID}}
		}
		count, countErr := database.Collection(collection).CountDocuments(ctx, filter)
		if countErr != nil || count != 0 {
			t.Fatalf("converged %s count = %d/%v", collection, count, countErr)
		}
	}
}

var errOwnershipProbe = errors.New("ownership verification probe failure")

type ownershipFailureVerifier struct{}

func (ownershipFailureVerifier) VerifyContainers(
	context.Context,
	[]runtimeinventorybiz.Resource,
) (map[string]runtimeinventorybiz.Ownership, error) {
	return nil, errOwnershipProbe
}

var errAuditProbe = errors.New("audit probe failure")

type failingAudit struct{}

func (failingAudit) Record(context.Context, sharedaudit.Event) error {
	return errAuditProbe
}

func directConnectionURI(t *testing.T, value string) string {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatalf("parse MongoDB connection string: %v", err)
	}
	query := parsed.Query()
	query.Set("directConnection", "true")
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func verifyArtifactEvidenceIntegration(
	t *testing.T,
	ctx context.Context,
	database *drivermongo.Database,
) {
	t.Helper()
	repository := supplychaindata.NewMongoRepository(database)
	item, err := supplychainbiz.NewEvidence(supplychainbiz.EvidenceInput{
		ID: "evidence-integration-sbom", OrganizationID: "evidence-integration-organization",
		ProjectID: "evidence-integration-project", ArtifactID: "evidence-integration-artifact",
		SubjectDigest: "sha256:" + strings.Repeat("a", 64),
		Kind:          supplychainbiz.EvidenceKindSBOM, MediaType: "application/vnd.cyclonedx+json",
		FormatVersion: "1.6", Producer: "integration-worker/1.0.0",
		RegistryRepository: "registry.example.com/team/api",
		DescriptorDigest:   "sha256:" + strings.Repeat("b", 64),
		VerificationStatus: supplychainbiz.VerificationVerified, CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("create artifact evidence fixture: %v", err)
	}
	if _, err := repository.CreateEvidence(ctx, item); err != nil {
		t.Fatalf("persist artifact evidence: %v", err)
	}
	if _, err := repository.CreateEvidence(ctx, item); !errors.Is(err, supplychainbiz.ErrDuplicate) {
		t.Fatalf("duplicate artifact evidence error = %v", err)
	}
	items, err := repository.ListEvidence(ctx, item.ProjectID, item.ArtifactID)
	if err != nil || len(items) != 1 || items[0].DescriptorDigest != item.DescriptorDigest {
		t.Fatalf("list artifact evidence = %+v, %v", items, err)
	}
	if _, err := database.Collection("artifact_evidence").UpdateOne(ctx,
		bson.D{{Key: "_id", Value: item.ID}},
		bson.D{{Key: "$set", Value: bson.D{{Key: "descriptor_digest", Value: "corrupt"}}}},
	); err != nil {
		t.Fatalf("corrupt artifact evidence fixture: %v", err)
	}
	if _, err := repository.GetEvidence(ctx, item.ProjectID, item.ArtifactID, item.ID); !errors.Is(err, supplychainbiz.ErrInvalidEvidence) {
		t.Fatalf("corrupt artifact evidence error = %v", err)
	}
	if _, err := database.Collection("artifact_evidence").DeleteOne(ctx, bson.D{{Key: "_id", Value: item.ID}}); err != nil {
		t.Fatalf("delete artifact evidence fixture: %v", err)
	}
}

func assertArtifactEvidenceIndexes(
	t *testing.T,
	ctx context.Context,
	database *drivermongo.Database,
) {
	t.Helper()
	cursor, err := database.Collection("artifact_evidence").Indexes().List(ctx)
	if err != nil {
		t.Fatalf("list artifact evidence indexes: %v", err)
	}
	defer cursor.Close(ctx)
	var documents []bson.M
	if err := cursor.All(ctx, &documents); err != nil {
		t.Fatalf("decode artifact evidence indexes: %v", err)
	}
	names := make(map[string]bool, len(documents))
	for _, document := range documents {
		name, _ := document["name"].(string)
		names[name] = true
	}
	for _, name := range []string{
		"idx_artifact_evidence_list", "uniq_artifact_evidence_descriptor",
		"idx_artifact_evidence_digest",
	} {
		if !names[name] {
			t.Errorf("artifact evidence index %q is missing: %#v", name, names)
		}
	}
}

func assertArtifactEvidenceJobIndexes(
	t *testing.T,
	ctx context.Context,
	database *drivermongo.Database,
) {
	t.Helper()
	cursor, err := database.Collection("artifact_evidence_jobs").Indexes().List(ctx)
	if err != nil {
		t.Fatalf("list artifact evidence job indexes: %v", err)
	}
	defer cursor.Close(ctx)
	var documents []bson.M
	if err := cursor.All(ctx, &documents); err != nil {
		t.Fatalf("decode artifact evidence job indexes: %v", err)
	}
	names := make(map[string]bool, len(documents))
	for _, document := range documents {
		name, _ := document["name"].(string)
		names[name] = true
	}
	for _, name := range []string{
		"idx_artifact_evidence_job_queue", "uniq_artifact_evidence_job_idempotency",
	} {
		if !names[name] {
			t.Errorf("artifact evidence job index %q is missing: %#v", name, names)
		}
	}
}

func assertEvidenceVerificationIndexes(t *testing.T, ctx context.Context, database *drivermongo.Database) {
	t.Helper()
	cursor, err := database.Collection("evidence_verifications").Indexes().List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer cursor.Close(ctx)
	var documents []bson.M
	if err := cursor.All(ctx, &documents); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, document := range documents {
		name, _ := document["name"].(string)
		names[name] = true
	}
	for _, name := range []string{"idx_evidence_verification_list", "uniq_evidence_verification_snapshot"} {
		if !names[name] {
			t.Errorf("evidence verification index %q is missing: %#v", name, names)
		}
	}
}

func assertVulnerabilityObservationIndexes(t *testing.T, ctx context.Context, database *drivermongo.Database) {
	t.Helper()
	cursor, err := database.Collection("vulnerability_observations").Indexes().List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer cursor.Close(ctx)
	var documents []bson.M
	if err := cursor.All(ctx, &documents); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, document := range documents {
		name, _ := document["name"].(string)
		names[name] = true
	}
	for _, name := range []string{"uniq_vulnerability_observation_latest",
		"idx_vulnerability_observation_policy", "idx_vulnerability_observation_evidence"} {
		if !names[name] {
			t.Errorf("vulnerability observation index %q is missing: %#v", name, names)
		}
	}
}

func assertVulnerabilityWaiverIndexes(t *testing.T, ctx context.Context, database *drivermongo.Database) {
	t.Helper()
	cursor, err := database.Collection("vulnerability_waivers").Indexes().List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer cursor.Close(ctx)
	var documents []bson.M
	if err := cursor.All(ctx, &documents); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, document := range documents {
		name, _ := document["name"].(string)
		names[name] = true
	}
	for _, name := range []string{"idx_vulnerability_waiver_list", "idx_vulnerability_waiver_applicability"} {
		if !names[name] {
			t.Errorf("vulnerability waiver index %q is missing: %#v", name, names)
		}
	}
}

func assertDeploymentPolicyIndexes(t *testing.T, ctx context.Context, database *drivermongo.Database) {
	t.Helper()
	cursor, err := database.Collection("deployment_policies").Indexes().List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer cursor.Close(ctx)
	var documents []bson.M
	if err := cursor.All(ctx, &documents); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, document := range documents {
		name, _ := document["name"].(string)
		names[name] = true
	}
	for _, name := range []string{"uniq_deployment_policy_scope", "idx_deployment_policy_evaluation"} {
		if !names[name] {
			t.Errorf("deployment policy index %q is missing: %#v", name, names)
		}
	}
}

func assertArtifactIndexes(t *testing.T, ctx context.Context, database *drivermongo.Database) {
	t.Helper()
	cursor, err := database.Collection("artifacts").Indexes().List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer cursor.Close(ctx)
	var documents []bson.M
	if err := cursor.All(ctx, &documents); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, document := range documents {
		name, _ := document["name"].(string)
		names[name] = true
	}
	for _, name := range []string{"uniq_artifact_build", "uniq_external_artifact_registration",
		"idx_artifact_project_origin", "idx_artifact_project_created", "idx_artifact_release_queue",
		"idx_artifact_image"} {
		if !names[name] {
			t.Errorf("Artifact index %q is missing: %#v", name, names)
		}
	}
}

func verifyExternalArtifactPersistenceIntegration(t *testing.T, ctx context.Context,
	database *drivermongo.Database) {
	t.Helper()
	repository := builddata.NewMongoRepository(database)
	createdAt := time.Now().UTC()
	create := func(id, key, digestCharacter string) buildbiz.Artifact {
		item, err := buildbiz.NewExternalArtifact(buildbiz.ExternalArtifactInput{
			ID: id, OrganizationID: "external-organization", ProjectID: "external-project",
			ApplicationID: "external-application", RegistryCredentialID: "external-registry",
			ImageDigest:    "registry.example.com/team/external@sha256:" + strings.Repeat(digestCharacter, 64),
			TargetPlatform: buildbiz.BuildPlatformLinuxAMD64, Producer: "github-actions/team/external",
			RegistrationKey: key, CreatedAt: createdAt,
		})
		if err != nil {
			t.Fatal(err)
		}
		return item
	}
	first, second := create("external-artifact-1", "external-delivery-1", "a"),
		create("external-artifact-2", "external-delivery-2", "b")
	defer func() {
		_, _ = database.Collection("artifacts").DeleteMany(ctx, bson.D{{Key: "_id", Value: bson.D{
			{Key: "$in", Value: bson.A{first.ID, second.ID, "external-artifact-duplicate"}},
		}}})
	}()
	if _, err := repository.CreateArtifact(ctx, first); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CreateArtifact(ctx, second); err != nil {
		t.Fatalf("second external Artifact without Build ID: %v", err)
	}
	stored, err := repository.GetArtifactByRegistrationKey(ctx, first.ProjectID, first.RegistrationKey)
	if err != nil || stored.Origin != buildbiz.ArtifactOriginExternal ||
		stored.ProducerVerification != buildbiz.ArtifactProducerDeclared || stored.BuildID != "" ||
		stored.ImageDigest != first.ImageDigest {
		t.Fatalf("stored external Artifact = %+v/%v", stored, err)
	}
	duplicate := create("external-artifact-duplicate", first.RegistrationKey, "c")
	if _, err := repository.CreateArtifact(ctx, duplicate); !errors.Is(err, buildbiz.ErrDuplicateArtifact) {
		t.Fatalf("duplicate external registration error = %v", err)
	}
	var raw bson.M
	if err := database.Collection("artifacts").FindOne(ctx,
		bson.D{{Key: "_id", Value: first.ID}}).Decode(&raw); err != nil {
		t.Fatal(err)
	}
	if _, present := raw["build_id"]; present {
		t.Fatalf("external Artifact unexpectedly persisted build_id: %#v", raw)
	}
}

func assertSignatureSigningProfileIndexes(t *testing.T, ctx context.Context, database *drivermongo.Database) {
	t.Helper()
	cursor, err := database.Collection("signature_signing_profiles").Indexes().List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer cursor.Close(ctx)
	var documents []bson.M
	if err := cursor.All(ctx, &documents); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, document := range documents {
		name, _ := document["name"].(string)
		names[name] = true
	}
	for _, name := range []string{"uniq_signature_signing_profile_name",
		"uniq_signature_signing_profile_policy", "idx_signature_signing_profile_list"} {
		if !names[name] {
			t.Errorf("signature signing profile index %q is missing: %#v", name, names)
		}
	}
}

func verifySignatureVerificationFenceIntegration(t *testing.T, ctx context.Context,
	database *drivermongo.Database) {
	t.Helper()
	repository := supplychaindata.NewMongoRepository(database)
	base := time.Now().UTC().Add(-time.Minute)
	snapshot := supplychainbiz.SignatureTrustSnapshot{PolicyID: "signature-policy-1", PolicyVersion: 2,
		Mode: supplychainbiz.SignatureTrustKeyless, TrustedRootID: "offline-root-1",
		TrustedRootHash:     "sha256:" + strings.Repeat("a", 64),
		CertificateIdentity: "https://git.example.com/team/api/.ci/release@refs/tags/v1.0.0",
		OIDCIssuer:          "https://issuer.example.com"}
	job, err := supplychainbiz.NewEvidenceJob(supplychainbiz.EvidenceJobInput{ID: "signature-fence-job",
		OrganizationID: "signature-organization", ProjectID: "signature-project", ArtifactID: "signature-artifact",
		SubjectDigest: "sha256:" + strings.Repeat("b", 64), RegistryRepository: "registry.example.com/team/signed",
		RegistryCredentialID: "signature-registry", Kind: supplychainbiz.EvidenceKindSignature,
		FormatVersion: supplychainbiz.CosignSignatureFormatV03, Producer: "cosign/3.0.6",
		Signature: snapshot, CreatedAt: base})
	if err != nil {
		t.Fatal(err)
	}
	if job, err = repository.CreateEvidenceJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	claimed, found, err := repository.ClaimNextEvidenceJob(ctx, supplychainbiz.EvidenceClaim{
		WorkerID: "signature-worker-1", Now: base.Add(time.Second), ExpiresAt: base.Add(2 * time.Minute),
		Kinds: []supplychainbiz.EvidenceKind{supplychainbiz.EvidenceKindSignature}})
	if err != nil || !found {
		t.Fatalf("claim signature job = %+v/%v/%v", claimed, found, err)
	}
	if err := claimed.Transition(supplychainbiz.EvidenceJobVerifying, base.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	claimed, err = repository.SaveClaimedEvidenceJob(ctx, claimed, claimed.Version,
		"signature-worker-1", claimed.Lease.Generation, base.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	verification, err := supplychainbiz.NewEvidenceVerification(supplychainbiz.EvidenceVerification{
		ID: "signature-verification-1", OrganizationID: job.OrganizationID, ProjectID: job.ProjectID,
		ArtifactID: job.ArtifactID, SubjectDigest: job.SubjectDigest, PolicyID: snapshot.PolicyID,
		PolicyVersion: snapshot.PolicyVersion, TrustMode: snapshot.Mode, TrustRootHash: snapshot.TrustedRootHash,
		SignerIdentity: snapshot.CertificateIdentity, OIDCIssuer: snapshot.OIDCIssuer,
		BundleSetDigest: "sha256:" + strings.Repeat("c", 64), Verifier: "cosign", VerifierVersion: "3.0.6",
		VerificationStatus: supplychainbiz.VerificationVerified, CreatedAt: base.Add(3 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	generation := claimed.Lease.Generation
	if err := claimed.Transition(supplychainbiz.EvidenceJobSucceeded, base.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	completed, published, err := repository.PublishClaimedSignatureVerification(ctx, claimed, verification,
		claimed.Version, "signature-worker-1", generation, base.Add(3*time.Second))
	if err != nil || completed.Status != supplychainbiz.EvidenceJobSucceeded || published.ID != verification.ID {
		t.Fatalf("publish signature verification = %+v/%+v/%v", completed, published, err)
	}
	items, err := repository.ListEvidenceVerifications(ctx, job.ProjectID, job.ArtifactID)
	if err != nil || len(items) != 1 || items[0].BundleSetDigest != verification.BundleSetDigest {
		t.Fatalf("list signature verifications = %+v/%v", items, err)
	}
}

func verifyArtifactEvidenceFenceIntegration(
	t *testing.T,
	ctx context.Context,
	database *drivermongo.Database,
) {
	t.Helper()
	repository := supplychaindata.NewMongoRepository(database)
	base := time.Now().UTC().Add(-time.Minute)
	job, err := supplychainbiz.NewEvidenceJob(supplychainbiz.EvidenceJobInput{
		ID: "evidence-fence-job", OrganizationID: "evidence-fence-organization",
		ProjectID: "evidence-fence-project", ArtifactID: "evidence-fence-artifact",
		SubjectDigest:      "sha256:" + strings.Repeat("c", 64),
		RegistryRepository: "registry.example.com/team/fenced", Kind: supplychainbiz.EvidenceKindSBOM,
		RegistryCredentialID: "evidence-registry-1",
		FormatVersion:        "1.6", Producer: "integration-evidence-worker/1.0.0", CreatedAt: base,
	})
	if err != nil {
		t.Fatalf("create evidence job fixture: %v", err)
	}
	if job, err = repository.CreateEvidenceJob(ctx, job); err != nil {
		t.Fatalf("persist evidence job: %v", err)
	}
	duplicateRequest := job
	duplicateRequest.ID = "evidence-fence-job-duplicate-request"
	if _, err := repository.CreateEvidenceJob(ctx, duplicateRequest); !errors.Is(err, supplychainbiz.ErrDuplicate) {
		t.Fatalf("duplicate evidence job idempotency error = %v", err)
	}
	workerOne, found, err := repository.ClaimNextEvidenceJob(ctx, supplychainbiz.EvidenceClaim{
		WorkerID: "evidence-worker-1", Now: base.Add(time.Second), ExpiresAt: base.Add(10 * time.Second),
	})
	if err != nil || !found || workerOne.Lease.Generation != 1 {
		t.Fatalf("first evidence claim = %+v/%v/%v", workerOne, found, err)
	}
	if err := workerOne.Transition(supplychainbiz.EvidenceJobGenerating, base.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	workerOne, err = repository.SaveClaimedEvidenceJob(ctx, workerOne, workerOne.Version,
		"evidence-worker-1", workerOne.Lease.Generation, base.Add(2*time.Second))
	if err != nil {
		t.Fatalf("save generating evidence job: %v", err)
	}
	if err := workerOne.Transition(supplychainbiz.EvidenceJobPublishing, base.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	workerOne, err = repository.SaveClaimedEvidenceJob(ctx, workerOne, workerOne.Version,
		"evidence-worker-1", workerOne.Lease.Generation, base.Add(3*time.Second))
	if err != nil {
		t.Fatalf("save publishing evidence job: %v", err)
	}
	workerTwo, found, err := repository.ClaimNextEvidenceJob(ctx, supplychainbiz.EvidenceClaim{
		WorkerID: "evidence-worker-2", Now: base.Add(11 * time.Second), ExpiresAt: base.Add(30 * time.Second),
	})
	if err != nil || !found || workerTwo.Lease.Generation != 2 {
		t.Fatalf("recovered evidence claim = %+v/%v/%v", workerTwo, found, err)
	}
	evidence, err := supplychainbiz.NewEvidence(supplychainbiz.EvidenceInput{
		ID: "evidence-fence-result", OrganizationID: job.OrganizationID, ProjectID: job.ProjectID,
		ArtifactID: job.ArtifactID, SubjectDigest: job.SubjectDigest, Kind: job.Kind,
		MediaType: "application/vnd.cyclonedx+json", FormatVersion: job.FormatVersion,
		Producer: job.Producer, RegistryRepository: job.RegistryRepository,
		DescriptorDigest:   "sha256:" + strings.Repeat("d", 64),
		VerificationStatus: supplychainbiz.VerificationUnverified, CreatedAt: base.Add(12 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	stale := workerOne
	if err := stale.Transition(supplychainbiz.EvidenceJobSucceeded, base.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repository.PublishClaimedEvidence(ctx, stale, evidence, workerOne.Version,
		"evidence-worker-1", 1, base.Add(4*time.Second)); !errors.Is(err, supplychainbiz.ErrEvidenceLeaseExpired) {
		t.Fatalf("stale evidence publish error = %v", err)
	}
	count, err := database.Collection("artifact_evidence").CountDocuments(ctx,
		bson.D{{Key: "_id", Value: evidence.ID}})
	if err != nil || count != 0 {
		t.Fatalf("stale transaction evidence count = %d, %v", count, err)
	}
	if err := workerTwo.Transition(supplychainbiz.EvidenceJobSucceeded, base.Add(12*time.Second)); err != nil {
		t.Fatal(err)
	}
	completed, published, err := repository.PublishClaimedEvidence(ctx, workerTwo, evidence, workerTwo.Version,
		"evidence-worker-2", 2, base.Add(12*time.Second))
	if err != nil || completed.Status != supplychainbiz.EvidenceJobSucceeded || published.ID != evidence.ID {
		t.Fatalf("fenced evidence publication = %+v/%+v/%v", completed, published, err)
	}
}

func verifyVulnerabilityObservationIntegration(t *testing.T, ctx context.Context,
	database *drivermongo.Database) {
	t.Helper()
	repository := supplychaindata.NewMongoRepository(database)
	base := time.Now().UTC().Add(-time.Minute)
	job, err := supplychainbiz.NewEvidenceJob(supplychainbiz.EvidenceJobInput{
		ID: "vulnerability-integration-job", OrganizationID: "vulnerability-integration-organization",
		ProjectID: "vulnerability-integration-project", ArtifactID: "vulnerability-integration-artifact",
		SubjectDigest: "sha256:" + strings.Repeat("7", 64), RegistryRepository: "registry.example.com/team/scanned",
		RegistryCredentialID: "vulnerability-registry-1",
		Kind:                 supplychainbiz.EvidenceKindVulnerabilityReport,
		FormatVersion:        supplychainbiz.TrivyReportFormatVersion, Producer: "trivy/0.74.0", CreatedAt: base})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repository.CreateEvidenceJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	claimed, found, err := repository.ClaimNextEvidenceJob(ctx, supplychainbiz.EvidenceClaim{
		WorkerID: "vulnerability-worker-1", Now: base.Add(time.Second), ExpiresAt: base.Add(time.Minute)})
	if err != nil || !found {
		t.Fatalf("claim vulnerability job = %+v/%v/%v", claimed, found, err)
	}
	if err := claimed.Transition(supplychainbiz.EvidenceJobGenerating, base.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	claimed, err = repository.SaveClaimedEvidenceJob(ctx, claimed, claimed.Version,
		"vulnerability-worker-1", claimed.Lease.Generation, base.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := claimed.Transition(supplychainbiz.EvidenceJobPublishing, base.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	claimed, err = repository.SaveClaimedEvidenceJob(ctx, claimed, claimed.Version,
		"vulnerability-worker-1", claimed.Lease.Generation, base.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := supplychainbiz.NewEvidence(supplychainbiz.EvidenceInput{
		ID: "vulnerability-integration-evidence", OrganizationID: job.OrganizationID, ProjectID: job.ProjectID,
		ArtifactID: job.ArtifactID, SubjectDigest: job.SubjectDigest, Kind: job.Kind,
		MediaType: supplychainbiz.TrivyReportMediaType, FormatVersion: job.FormatVersion, Producer: job.Producer,
		RegistryRepository: job.RegistryRepository, DescriptorDigest: "sha256:" + strings.Repeat("8", 64),
		VerificationStatus: supplychainbiz.VerificationUnverified, CreatedAt: base.Add(4 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	observationID, _ := supplychainbiz.VulnerabilityObservationID(job.ArtifactID, "trivy")
	observation, err := supplychainbiz.NewVulnerabilityObservation(supplychainbiz.VulnerabilityObservation{
		ID: observationID, OrganizationID: job.OrganizationID, ProjectID: job.ProjectID,
		ArtifactID: job.ArtifactID, SubjectDigest: job.SubjectDigest, EvidenceID: evidence.ID,
		DescriptorDigest: evidence.DescriptorDigest, Scanner: "trivy", ScannerVersion: "0.74.0",
		Database: supplychainbiz.VulnerabilityDatabase{SchemaVersion: 2, UpdatedAt: base.Add(-time.Hour),
			DownloadedAt: base.Add(-30 * time.Minute), NextUpdate: base.Add(6 * time.Hour)},
		ScannedAt: base, FreshUntil: base.Add(6 * time.Hour),
		Counts:          supplychainbiz.VulnerabilityCounts{High: 1, Total: 1, Fixable: 1},
		HighestSeverity: supplychainbiz.VulnerabilitySeverityHigh})
	if err != nil {
		t.Fatal(err)
	}
	generation, expectedVersion := claimed.Lease.Generation, claimed.Version
	if err := claimed.Transition(supplychainbiz.EvidenceJobSucceeded, base.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	completed, _, published, err := repository.PublishClaimedVulnerabilityObservation(ctx, claimed,
		evidence, observation, expectedVersion, "vulnerability-worker-1", generation, base.Add(4*time.Second))
	if err != nil || completed.Status != supplychainbiz.EvidenceJobSucceeded || published.EvidenceID != evidence.ID {
		t.Fatalf("publish vulnerability observation = %+v/%+v/%v", completed, published, err)
	}
	latest, err := repository.GetLatestVulnerabilityObservation(ctx, job.ProjectID, job.ArtifactID)
	if err != nil || latest.Counts.High != 1 || latest.DescriptorDigest != evidence.DescriptorDigest {
		t.Fatalf("latest vulnerability observation = %+v/%v", latest, err)
	}
}

func verifyVulnerabilityWaiverIntegration(t *testing.T, ctx context.Context,
	database *drivermongo.Database) {
	t.Helper()
	repository := supplychaindata.NewMongoRepository(database)
	now := time.Now().UTC().Truncate(time.Millisecond)
	newWaiver := func(id string, scope supplychainbiz.VulnerabilityWaiverScope,
		createdAt, expiresAt time.Time) supplychainbiz.VulnerabilityWaiver {
		input := supplychainbiz.VulnerabilityWaiverInput{ID: id,
			OrganizationID: "waiver-integration-organization", ProjectID: "waiver-integration-project",
			Scope: scope, VulnerabilityID: "CVE-2026-12345", Reason: "Integration-approved exception.",
			ApprovedBy: "waiver-integration-maintainer", ExpiresAt: expiresAt,
			Version: 1, CreatedAt: createdAt}
		if scope == supplychainbiz.VulnerabilityWaiverScopeArtifact {
			input.ArtifactID = "waiver-integration-artifact"
			input.SubjectDigest = "sha256:" + strings.Repeat("9", 64)
		}
		item, err := supplychainbiz.NewVulnerabilityWaiver(input)
		if err != nil {
			t.Fatal(err)
		}
		return item
	}
	items := []supplychainbiz.VulnerabilityWaiver{
		newWaiver("waiver-integration-newest", supplychainbiz.VulnerabilityWaiverScopeArtifact,
			now.Add(-time.Hour), now.Add(24*time.Hour)),
		newWaiver("waiver-integration-project", supplychainbiz.VulnerabilityWaiverScopeProject,
			now.Add(-2*time.Hour), now.Add(24*time.Hour)),
		newWaiver("waiver-integration-expired", supplychainbiz.VulnerabilityWaiverScopeProject,
			now.Add(-48*time.Hour), now.Add(-24*time.Hour)),
	}
	for _, item := range items {
		if _, err := repository.CreateVulnerabilityWaiver(ctx, item); err != nil {
			t.Fatal(err)
		}
	}
	all, _ := (supplychainbiz.VulnerabilityWaiverQuery{Limit: 2}).Normalize(now)
	first, err := repository.ListVulnerabilityWaivers(ctx, items[0].OrganizationID, items[0].ProjectID, all)
	if err != nil || len(first.Items) != 2 || first.NextCursor == "" ||
		first.Items[0].ID != items[0].ID || first.Items[1].ID != items[1].ID {
		t.Fatalf("first waiver page = %+v/%v", first, err)
	}
	all.Cursor = first.NextCursor
	second, err := repository.ListVulnerabilityWaivers(ctx, items[0].OrganizationID, items[0].ProjectID, all)
	if err != nil || len(second.Items) != 1 || second.NextCursor != "" || second.Items[0].ID != items[2].ID {
		t.Fatalf("second waiver page = %+v/%v", second, err)
	}
	active, _ := (supplychainbiz.VulnerabilityWaiverQuery{Limit: 100, ActiveOnly: true}).Normalize(now)
	activePage, err := repository.ListVulnerabilityWaivers(ctx, items[0].OrganizationID, items[0].ProjectID, active)
	if err != nil || len(activePage.Items) != 2 {
		t.Fatalf("active waiver page = %+v/%v", activePage, err)
	}
	applicable, err := repository.ListApplicableVulnerabilityWaivers(ctx,
		items[0].OrganizationID, items[0].ProjectID, items[0].ArtifactID, items[0].SubjectDigest, now)
	if err != nil || len(applicable) != 2 || applicable[0].ID != items[1].ID ||
		applicable[1].ID != items[0].ID {
		t.Fatalf("applicable vulnerability waivers = %+v/%v", applicable, err)
	}
	nonMatching, err := repository.ListApplicableVulnerabilityWaivers(ctx,
		items[0].OrganizationID, items[0].ProjectID, "another-artifact", items[0].SubjectDigest, now)
	if err != nil || len(nonMatching) != 1 || nonMatching[0].ID != items[1].ID {
		t.Fatalf("non-matching artifact vulnerability waivers = %+v/%v", nonMatching, err)
	}
	if _, err := repository.GetVulnerabilityWaiver(ctx, "another-organization", items[0].ProjectID,
		items[0].ID); !errors.Is(err, supplychainbiz.ErrNotFound) {
		t.Fatalf("cross-organization GetVulnerabilityWaiver() error = %v", err)
	}
	revocation := supplychainbiz.VulnerabilityWaiverInput{ID: items[0].ID,
		OrganizationID: items[0].OrganizationID, ProjectID: items[0].ProjectID,
		Scope: items[0].Scope, ArtifactID: items[0].ArtifactID, SubjectDigest: items[0].SubjectDigest,
		VulnerabilityID: items[0].VulnerabilityID, Reason: items[0].Reason, ApprovedBy: items[0].ApprovedBy,
		ExpiresAt: items[0].ExpiresAt, Version: 2, CreatedAt: items[0].CreatedAt,
		RevokedAt: now, RevokedBy: "waiver-integration-maintainer", RevocationReason: "Patch deployed."}
	revoked, err := supplychainbiz.NewVulnerabilityWaiver(revocation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.SaveVulnerabilityWaiver(ctx, revoked, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.SaveVulnerabilityWaiver(ctx, revoked, 1); !errors.Is(err, supplychainbiz.ErrVulnerabilityWaiverConflict) {
		t.Fatalf("second SaveVulnerabilityWaiver() error = %v", err)
	}
}

func verifyDeploymentPolicyIntegration(t *testing.T, ctx context.Context,
	database *drivermongo.Database) {
	t.Helper()
	repository := supplychaindata.NewMongoRepository(database)
	now := time.Now().UTC().Truncate(time.Millisecond)
	newPolicy := func(id string, scope supplychainbiz.DeploymentPolicyScope,
		environmentID string) supplychainbiz.DeploymentPolicy {
		item, err := supplychainbiz.NewDeploymentPolicy(supplychainbiz.DeploymentPolicyInput{
			ID: id, OrganizationID: "policy-integration-organization", ProjectID: "policy-integration-project",
			Name: "Integration baseline", Scope: scope, EnvironmentID: environmentID,
			Mode: supplychainbiz.DeploymentPolicyEnforced, Requirements: supplychainbiz.DeploymentPolicyRequirements{
				RequireSBOM: true, RequireProvenance: true,
				AllowedSignaturePolicyIDs:    []string{"policy-integration-trust"},
				MaximumVulnerabilitySeverity: supplychainbiz.VulnerabilitySeverityHigh,
				MaximumScanAge:               24 * time.Hour,
			}, Enabled: true, Version: 1, CreatedBy: "policy-integration-maintainer",
			UpdatedBy: "policy-integration-maintainer", CreatedAt: now, UpdatedAt: now,
		})
		if err != nil {
			t.Fatal(err)
		}
		return item
	}
	projectPolicy := newPolicy("policy-integration-project-policy",
		supplychainbiz.DeploymentPolicyScopeProject, "")
	if _, err := repository.CreateDeploymentPolicy(ctx, projectPolicy); err != nil {
		t.Fatal(err)
	}
	duplicateScope := projectPolicy
	duplicateScope.ID = "policy-integration-duplicate-scope"
	if _, err := repository.CreateDeploymentPolicy(ctx, duplicateScope); !errors.Is(err, supplychainbiz.ErrDeploymentPolicyConflict) {
		t.Fatalf("duplicate scope error = %v", err)
	}
	environmentPolicy := newPolicy("policy-integration-environment-policy",
		supplychainbiz.DeploymentPolicyScopeEnvironment, "policy-integration-environment")
	if _, err := repository.CreateDeploymentPolicy(ctx, environmentPolicy); err != nil {
		t.Fatal(err)
	}
	items, err := repository.ListDeploymentPolicies(ctx, projectPolicy.OrganizationID, projectPolicy.ProjectID)
	if err != nil || len(items) != 2 {
		t.Fatalf("ListDeploymentPolicies() = %+v, %v", items, err)
	}
	if _, err := repository.GetDeploymentPolicy(ctx, "another-organization", projectPolicy.ProjectID,
		projectPolicy.ID); !errors.Is(err, supplychainbiz.ErrNotFound) {
		t.Fatalf("cross-organization GetDeploymentPolicy() error = %v", err)
	}
	projectPolicy.Name = "Updated integration baseline"
	projectPolicy.Version = 2
	projectPolicy.UpdatedAt = now.Add(time.Second)
	updated, err := repository.SaveDeploymentPolicy(ctx, projectPolicy, 1)
	if err != nil || updated.Version != 2 || updated.Name != projectPolicy.Name {
		t.Fatalf("SaveDeploymentPolicy() = %+v, %v", updated, err)
	}
	if _, err := repository.SaveDeploymentPolicy(ctx, projectPolicy, 1); !errors.Is(err, supplychainbiz.ErrDeploymentPolicyConflict) {
		t.Fatalf("stale SaveDeploymentPolicy() error = %v", err)
	}
}

func verifyBuildSourceRepositoryIntegration(
	t *testing.T,
	ctx context.Context,
	client *Client,
) {
	t.Helper()
	database := client.Database()
	const (
		organizationID  = "build-integration-organization"
		projectID       = "build-integration-project"
		applicationID   = "build-integration-application"
		registryID      = "build-integration-registry"
		developmentID   = "build-integration-development"
		stagingID       = "build-integration-staging"
		runtimeTargetID = "build-integration-target"
		secretReference = "secret://build-integration-token"
	)
	if _, err := database.Collection("projects").InsertOne(ctx, bson.D{
		{Key: "_id", Value: projectID},
		{Key: "organization_id", Value: organizationID},
		{Key: "name", Value: "Build integration"},
		{Key: "name_normalized", Value: "build integration"},
		{Key: "created_by", Value: "build-user"},
		{Key: "created_at", Value: time.Now().UTC()},
	}); err != nil {
		t.Fatalf("seed build integration project: %v", err)
	}
	if _, err := database.Collection("product_applications").InsertOne(ctx, bson.D{
		{Key: "_id", Value: applicationID},
		{Key: "project_id", Value: projectID},
		{Key: "name", Value: "Build application"},
		{Key: "name_normalized", Value: "build application"},
		{Key: "status", Value: "active"},
		{Key: "created_by", Value: "build-user"},
		{Key: "created_at", Value: time.Now().UTC()},
	}); err != nil {
		t.Fatalf("seed build application: %v", err)
	}
	if _, err := database.Collection("registry_credentials").InsertOne(ctx, bson.D{
		{Key: "_id", Value: registryID},
		{Key: "project_id", Value: projectID},
		{Key: "name", Value: "Build registry"},
		{Key: "name_normalized", Value: "build registry"},
		{Key: "server", Value: "registry.example.com"},
		{Key: "username", Value: "builder"},
		{Key: "password_ref", Value: "secret://build-registry"},
		{Key: "created_by", Value: "build-user"},
		{Key: "created_at", Value: time.Now().UTC()},
	}); err != nil {
		t.Fatalf("seed build registry: %v", err)
	}
	for _, environment := range []bson.D{
		{{Key: "_id", Value: developmentID}, {Key: "project_id", Value: projectID},
			{Key: "name", Value: "Development"}, {Key: "name_normalized", Value: "development"},
			{Key: "status", Value: "active"},
			{Key: "stage", Value: "development"}, {Key: "variables", Value: bson.D{}},
			{Key: "created_by", Value: "build-user"}, {Key: "created_at", Value: time.Now().UTC()}},
		{{Key: "_id", Value: stagingID}, {Key: "project_id", Value: projectID},
			{Key: "name", Value: "Staging"}, {Key: "name_normalized", Value: "staging"},
			{Key: "status", Value: "active"},
			{Key: "stage", Value: "staging"}, {Key: "variables", Value: bson.D{}},
			{Key: "created_by", Value: "build-user"}, {Key: "created_at", Value: time.Now().UTC()}},
	} {
		if _, err := database.Collection("environments").InsertOne(ctx, environment); err != nil {
			t.Fatalf("seed build environment: %v", err)
		}
	}
	if _, err := database.Collection("runtime_targets").InsertOne(ctx, bson.D{
		{Key: "_id", Value: runtimeTargetID}, {Key: "project_id", Value: projectID},
		{Key: "name", Value: "Build target"}, {Key: "name_normalized", Value: "build target"},
		{Key: "managed_host_id", Value: "build-integration-host"},
		{Key: "connection_mode", Value: "agent"}, {Key: "status", Value: "ready"},
		{Key: "created_by", Value: "build-user"}, {Key: "created_at", Value: time.Now().UTC()},
	}); err != nil {
		t.Fatalf("seed build Runtime Target: %v", err)
	}
	t.Cleanup(func() {
		cleanupContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, collection := range []string{
			"repository_credentials", "source_repositories", "build_configurations", "build_triggers", "build_hooks", "webhook_deliveries", "builds", "build_log_streams", "build_log_chunks", "artifacts", "releases", "deployments", "deployment_cutover_sequences", "audit_events",
		} {
			_, _ = database.Collection(collection).DeleteMany(cleanupContext, bson.D{
				{Key: "project_id", Value: projectID},
			})
		}
		_, _ = database.Collection("build_trigger_rate_limits").DeleteMany(cleanupContext, bson.D{
			{Key: "_id", Value: bson.D{{Key: "$regex", Value: "^build-integration-"}}},
		})
		_, _ = database.Collection("projects").DeleteOne(
			cleanupContext, bson.D{{Key: "_id", Value: projectID}},
		)
		_, _ = database.Collection("product_applications").DeleteOne(
			cleanupContext, bson.D{{Key: "_id", Value: applicationID}},
		)
		_, _ = database.Collection("registry_credentials").DeleteOne(
			cleanupContext, bson.D{{Key: "_id", Value: registryID}},
		)
		_, _ = database.Collection("environments").DeleteMany(cleanupContext, bson.D{{Key: "project_id", Value: projectID}})
		_, _ = database.Collection("runtime_targets").DeleteMany(cleanupContext, bson.D{{Key: "project_id", Value: projectID}})
	})
	repository := builddata.NewMongoRepository(database)
	controlStore := controlplanedata.NewMongoStore(database)
	references := builddata.NewConfigurationReferenceLookup(controlStore)
	webhookVerifier := &readyWebhookVerifier{event: buildbiz.WebhookEvent{
		Supported: true, Ref: "refs/heads/main", CommitSHA: "a975c10d68a2d7461634f13b15c52a2efba72d16",
	}}
	sequence := 0
	useCase := buildbiz.NewUseCase(
		controlStore, repository, client,
		platformaudit.NewMongoStore(database),
		func() (string, error) {
			sequence++
			return fmt.Sprintf("build-integration-%d", sequence), nil
		},
		time.Now,
	).WithSourceProber(readySourceRepositoryProber{}).
		WithSourceRevisionResolver(readySourceRepositoryProber{}).
		WithWebhookVerifier(webhookVerifier).
		WithWebhookAdmission(repository, 2, time.Minute).
		WithBuildTriggerAutomation(builddata.BuildTriggerTokens{}, repository, 60, time.Minute).
		WithConfigurationReferences(references, references).
		WithAutomaticDeploymentReferences(references)
	principal := security.Principal{
		UserID: "build-user", OrganizationID: organizationID,
		SessionID: "build-session", Role: security.RoleMaintainer,
	}
	credential, err := useCase.CreateCredential(
		ctx, principal, projectID, "Git token",
		buildbiz.CredentialTypeHTTPSAccessToken,
		"builder", secretReference, "", "build-request-1",
	)
	if err != nil || !credential.SecretConfigured {
		t.Fatalf("create build repository credential = %+v/%v", credential, err)
	}
	listed, err := useCase.ListCredentials(ctx, principal, projectID)
	if err != nil || len(listed) != 1 || !listed[0].SecretConfigured {
		t.Fatalf("list build repository credentials = %+v/%v", listed, err)
	}
	var rawCredential bson.M
	if err := database.Collection("repository_credentials").FindOne(
		ctx, bson.D{{Key: "_id", Value: credential.ID}},
	).Decode(&rawCredential); err != nil || rawCredential["secret_ref"] != secretReference {
		t.Fatalf("stored build repository credential = %#v/%v", rawCredential, err)
	}
	if _, err := useCase.CreateCredential(
		ctx, principal, projectID, "git TOKEN",
		buildbiz.CredentialTypeHTTPSAccessToken,
		"", "secret://another-token", "", "build-request-duplicate",
	); !errors.Is(err, buildbiz.ErrDuplicateName) {
		t.Fatalf("duplicate repository credential error = %v", err)
	}
	source, err := useCase.CreateSource(
		ctx, principal, projectID, "API",
		"https://git.example.com/team/api.git", "main", credential.ID, "",
		"build-request-2",
	)
	if err != nil || source.Status != buildbiz.SourceRepositoryStatusPending {
		t.Fatalf("create source repository = %+v/%v", source, err)
	}
	probed, err := useCase.ProbeSource(
		ctx, principal, projectID, source.ID, "build-request-3",
	)
	if err != nil || probed.Status != buildbiz.SourceRepositoryStatusReady ||
		probed.LastProbedAt.IsZero() {
		t.Fatalf("probe source repository = %+v/%v", probed, err)
	}
	var probeAudit bson.M
	if err := database.Collection("audit_events").FindOne(ctx, bson.D{
		{Key: "project_id", Value: projectID},
		{Key: "action", Value: "source_repository.probe"},
		{Key: "resource_id", Value: source.ID},
	}).Decode(&probeAudit); err != nil {
		t.Fatalf("source repository probe audit = %#v/%v", probeAudit, err)
	}
	configuration, err := useCase.CreateBuildConfigurationWithDeliverySpec(
		ctx, principal, projectID, applicationID, "API build", source.ID,
		"", "", nil, registryID, "registry.example.com/team/api", "",
		buildbiz.BuildResources{}, 0, 0, true, runtimespec.Spec{},
		[]buildbiz.AutomaticDeploymentRule{{
			EnvironmentID: developmentID, RuntimeTargetID: runtimeTargetID,
		}}, "build-request-4",
	)
	if err != nil || configuration.Version != 1 ||
		configuration.DockerfilePath != "Dockerfile" ||
		len(configuration.AllowedRefs) != 1 || configuration.AllowedRefs[0] != "refs/heads/main" ||
		len(configuration.AutomaticDeployments) != 1 {
		t.Fatalf("create build configuration = %+v/%v", configuration, err)
	}
	if _, err := useCase.CreateBuildConfigurationWithDeliverySpec(
		ctx, principal, projectID, applicationID, "Staging auto build", source.ID,
		"", "", nil, registryID, "registry.example.com/team/staging", "",
		buildbiz.BuildResources{}, 0, 0, true, runtimespec.Spec{},
		[]buildbiz.AutomaticDeploymentRule{{EnvironmentID: stagingID, RuntimeTargetID: runtimeTargetID}},
		"build-request-staging-auto",
	); !errors.Is(err, buildbiz.ErrAutomaticDeploymentDenied) {
		t.Fatalf("staging automatic deployment configuration error = %v", err)
	}
	if _, err := useCase.CreateBuildConfiguration(
		ctx, principal, projectID, applicationID, "api BUILD", source.ID,
		"Dockerfile", ".", []string{"refs/heads/main"},
		registryID, "registry.example.com/team/api", buildbiz.BuildPlatformLinuxAMD64,
		buildbiz.BuildResources{}, 0, 0, false, "build-request-duplicate-configuration",
	); !errors.Is(err, buildbiz.ErrDuplicateName) {
		t.Fatalf("duplicate build configuration error = %v", err)
	}
	timeout := int64(900)
	updatedConfiguration, err := useCase.UpdateBuildConfiguration(
		ctx, principal, projectID, applicationID, configuration.ID, configuration.Version,
		buildbiz.BuildConfigurationPatch{TimeoutSeconds: &timeout}, "build-request-5",
	)
	if err != nil || updatedConfiguration.Version != 2 || updatedConfiguration.TimeoutSeconds != timeout {
		t.Fatalf("update build configuration = %+v/%v", updatedConfiguration, err)
	}
	if _, err := useCase.UpdateBuildConfiguration(
		ctx, principal, projectID, applicationID, configuration.ID, configuration.Version,
		buildbiz.BuildConfigurationPatch{TimeoutSeconds: &timeout}, "build-request-stale",
	); !errors.Is(err, buildbiz.ErrVersionConflict) {
		t.Fatalf("stale build configuration update error = %v", err)
	}
	if _, err := repository.GetBuildConfiguration(
		ctx, projectID, "other-application", configuration.ID,
	); !errors.Is(err, buildbiz.ErrNotFound) {
		t.Fatalf("cross-application build configuration error = %v", err)
	}
	triggerCredential, err := useCase.CreateBuildTrigger(
		ctx, principal, projectID, applicationID, configuration.ID, "Git automation",
		[]string{"refs/heads/main"}, "build-request-trigger-create",
	)
	if err != nil || triggerCredential.Token == "" || triggerCredential.Trigger.TokenHash != "" {
		t.Fatalf("create build trigger = %+v/%v", triggerCredential, err)
	}
	if _, err := useCase.CreateBuildTrigger(
		ctx, principal, projectID, applicationID, configuration.ID, "git AUTOMATION",
		[]string{"refs/heads/main"}, "build-request-trigger-duplicate",
	); !errors.Is(err, buildbiz.ErrDuplicateName) {
		t.Fatalf("duplicate build trigger name error = %v", err)
	}
	var rawTrigger bson.M
	if err := database.Collection("build_triggers").FindOne(ctx, bson.D{
		{Key: "_id", Value: triggerCredential.Trigger.ID},
	}).Decode(&rawTrigger); err != nil || rawTrigger["token_hash"] == triggerCredential.Token ||
		len(fmt.Sprint(rawTrigger["token_hash"])) != 64 {
		t.Fatalf("stored build trigger token = %#v/%v", rawTrigger, err)
	}
	listedTriggers, err := useCase.ListBuildTriggers(ctx, principal, projectID, applicationID, configuration.ID)
	if err != nil || len(listedTriggers) != 1 || listedTriggers[0].TokenHash != "" {
		t.Fatalf("safe build trigger list = %+v/%v", listedTriggers, err)
	}
	hook, err := useCase.CreateBuildHook(
		ctx, principal, projectID, applicationID, configuration.ID, "GitHub webhook",
		buildbiz.WebhookProviderGitHub, []string{"refs/heads/main"},
		"secret://build-webhook", "build-request-hook-create",
	)
	if err != nil || !hook.SecretConfigured || hook.Status != buildbiz.BuildHookStatusActive {
		t.Fatalf("create build hook = %+v/%v", hook, err)
	}
	if _, err := useCase.CreateBuildHook(
		ctx, principal, projectID, applicationID, configuration.ID, "github WEBHOOK",
		buildbiz.WebhookProviderGitHub, []string{"refs/heads/main"},
		"secret://another-webhook", "build-request-hook-duplicate",
	); !errors.Is(err, buildbiz.ErrDuplicateName) {
		t.Fatalf("duplicate build hook name error = %v", err)
	}
	var rawHook bson.M
	if err := database.Collection("build_hooks").FindOne(ctx, bson.D{{Key: "_id", Value: hook.ID}}).Decode(&rawHook); err != nil || rawHook["secret_ref"] != "secret://build-webhook" {
		t.Fatalf("stored build hook = %#v/%v", rawHook, err)
	}
	listedHooks, err := useCase.ListBuildHooks(ctx, principal, projectID, applicationID, configuration.ID)
	if err != nil || len(listedHooks) != 1 || !listedHooks[0].SecretConfigured {
		t.Fatalf("safe build hook list = %+v/%v", listedHooks, err)
	}
	webhookEnvelope := buildbiz.WebhookEnvelope{DeliveryID: "integration-delivery-1", Event: "push", Body: []byte("signed")}
	webhookBuild, err := useCase.HandleWebhook(ctx, buildbiz.WebhookProviderGitHub, hook.ID, webhookEnvelope, "build-request-webhook")
	if err != nil || webhookBuild.Status != buildbiz.WebhookDeliveryStatusAccepted || webhookBuild.BuildID == "" {
		t.Fatalf("handle webhook = %+v/%v", webhookBuild, err)
	}
	webhookReplay, err := useCase.HandleWebhook(ctx, buildbiz.WebhookProviderGitHub, hook.ID, webhookEnvelope, "build-request-webhook-replay")
	if err != nil || webhookReplay != webhookBuild {
		t.Fatalf("replay webhook = %+v/%v", webhookReplay, err)
	}
	webhookVerifier.event = buildbiz.WebhookEvent{Supported: false}
	ignoredWebhook, err := useCase.HandleWebhook(ctx, buildbiz.WebhookProviderGitHub, hook.ID,
		buildbiz.WebhookEnvelope{DeliveryID: "integration-delivery-2", Event: "issues", Body: []byte("signed")}, "build-request-webhook-ignored")
	if err != nil || ignoredWebhook.Status != buildbiz.WebhookDeliveryStatusIgnored || ignoredWebhook.BuildID != "" {
		t.Fatalf("ignored webhook = %+v/%v", ignoredWebhook, err)
	}
	if _, err := useCase.HandleWebhook(ctx, buildbiz.WebhookProviderGitHub, hook.ID,
		buildbiz.WebhookEnvelope{DeliveryID: "integration-delivery-3", Event: "issues", Body: []byte("signed")},
		"build-request-webhook-limited"); !errors.Is(err, buildbiz.ErrWebhookRateLimited) {
		t.Fatalf("third unique webhook error = %v", err)
	}
	deliveryCount, err := database.Collection("webhook_deliveries").CountDocuments(ctx, bson.D{{Key: "hook_id", Value: hook.ID}})
	if err != nil || deliveryCount != 2 {
		t.Fatalf("webhook delivery count = %d/%v", deliveryCount, err)
	}
	const webhookFloodRequests = 64
	const webhookFloodLimit = 10
	floodResults := make(chan bool, webhookFloodRequests)
	floodErrors := make(chan error, webhookFloodRequests)
	var floodWait sync.WaitGroup
	floodNow := time.Now().UTC()
	for range webhookFloodRequests {
		floodWait.Add(1)
		go func() {
			defer floodWait.Done()
			allowed, _, reserveErr := repository.ReserveBuildWebhook(
				ctx, "integration-flood-hook", floodNow, webhookFloodLimit, time.Minute,
			)
			if reserveErr != nil {
				floodErrors <- reserveErr
				return
			}
			floodResults <- allowed
		}()
	}
	floodWait.Wait()
	close(floodResults)
	close(floodErrors)
	for reserveErr := range floodErrors {
		t.Fatalf("concurrent webhook admission: %v", reserveErr)
	}
	admitted := 0
	for allowed := range floodResults {
		if allowed {
			admitted++
		}
	}
	if admitted != webhookFloodLimit {
		t.Fatalf("concurrent webhook admissions = %d, want %d", admitted, webhookFloodLimit)
	}
	const networkWebhookSecret = "network-webhook-flood-secret"
	useCase.WithWebhookAdmission(repository, webhookFloodLimit, time.Minute).
		WithWebhookVerifier(builddata.NewWebhookVerifier(integrationWebhookSecrets{
			secret: []byte(networkWebhookSecret),
		}))
	networkHook, err := useCase.CreateBuildHook(
		ctx, principal, projectID, applicationID, configuration.ID, "Network flood webhook",
		buildbiz.WebhookProviderGitHub, []string{"refs/heads/main"},
		"secret://network-webhook", "build-request-network-hook",
	)
	if err != nil {
		t.Fatalf("create network flood Hook: %v", err)
	}
	server := httptest.NewServer(buildservice.NewHTTP(useCase))
	defer server.Close()
	networkResults := make(chan int, webhookFloodRequests)
	networkErrors := make(chan error, webhookFloodRequests)
	floodBody := []byte(`{"ref":"refs/heads/main","after":"a975c10d68a2d7461634f13b15c52a2efba72d16"}`)
	mac := hmac.New(sha256.New, []byte(networkWebhookSecret))
	_, _ = mac.Write(floodBody)
	signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	var networkWait sync.WaitGroup
	for index := range webhookFloodRequests {
		networkWait.Add(1)
		go func() {
			defer networkWait.Done()
			request, requestErr := http.NewRequestWithContext(
				ctx, http.MethodPost, server.URL+"/api/v1/build-hooks/github/"+networkHook.ID,
				bytes.NewReader(floodBody),
			)
			if requestErr != nil {
				networkErrors <- requestErr
				return
			}
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-GitHub-Delivery", fmt.Sprintf("network-delivery-%03d", index))
			request.Header.Set("X-GitHub-Event", "push")
			request.Header.Set("X-Hub-Signature-256", signature)
			response, requestErr := server.Client().Do(request)
			if requestErr != nil {
				networkErrors <- requestErr
				return
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
			_ = response.Body.Close()
			networkResults <- response.StatusCode
		}()
	}
	networkWait.Wait()
	close(networkResults)
	close(networkErrors)
	for requestErr := range networkErrors {
		t.Fatalf("network Webhook flood: %v", requestErr)
	}
	networkAccepted, networkLimited := 0, 0
	for status := range networkResults {
		switch status {
		case http.StatusAccepted:
			networkAccepted++
		case http.StatusTooManyRequests:
			networkLimited++
		default:
			t.Fatalf("network Webhook flood status = %d", status)
		}
	}
	if networkAccepted != webhookFloodLimit || networkLimited != webhookFloodRequests-webhookFloodLimit {
		t.Fatalf("network Webhook flood accepted/limited = %d/%d", networkAccepted, networkLimited)
	}
	if _, err := database.Collection("builds").DeleteMany(ctx, bson.D{
		{Key: "trigger_id", Value: networkHook.ID},
	}); err != nil {
		t.Fatalf("clean network flood Builds: %v", err)
	}
	orderingHook, err := useCase.CreateBuildHook(
		ctx, principal, projectID, applicationID, configuration.ID, "Webhook ordering guard",
		buildbiz.WebhookProviderGitHub, []string{"refs/heads/main"},
		"secret://webhook-ordering", "build-request-ordering-hook",
	)
	if err != nil {
		t.Fatalf("create ordering Hook: %v", err)
	}
	sendSignedPush := func(deliveryID, commitSHA string) (int, string) {
		t.Helper()
		body := []byte(fmt.Sprintf(`{"ref":"refs/heads/main","after":%q}`, commitSHA))
		digest := hmac.New(sha256.New, []byte(networkWebhookSecret))
		_, _ = digest.Write(body)
		request, requestErr := http.NewRequestWithContext(
			ctx, http.MethodPost, server.URL+"/api/v1/build-hooks/github/"+orderingHook.ID,
			bytes.NewReader(body),
		)
		if requestErr != nil {
			t.Fatalf("create ordering Webhook request: %v", requestErr)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-GitHub-Delivery", deliveryID)
		request.Header.Set("X-GitHub-Event", "push")
		request.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(digest.Sum(nil)))
		response, requestErr := server.Client().Do(request)
		if requestErr != nil {
			t.Fatalf("send ordering Webhook request: %v", requestErr)
		}
		responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, 64*1024))
		_ = response.Body.Close()
		if readErr != nil {
			t.Fatalf("read ordering Webhook response: %v", readErr)
		}
		return response.StatusCode, string(responseBody)
	}
	currentCommit := "a975c10d68a2d7461634f13b15c52a2efba72d16"
	staleCommit := "b975c10d68a2d7461634f13b15c52a2efba72d16"
	currentStatus, currentBody := sendSignedPush("ordering-current", currentCommit)
	staleStatus, staleBody := sendSignedPush("ordering-stale", staleCommit)
	if currentStatus != http.StatusAccepted || !strings.Contains(currentBody, `"status":"accepted"`) ||
		staleStatus != http.StatusAccepted || !strings.Contains(staleBody, `"status":"ignored"`) {
		t.Fatalf("ordered/stale Webhooks = %d/%s, %d/%s", currentStatus, currentBody, staleStatus, staleBody)
	}
	orderedBuildCount, err := database.Collection("builds").CountDocuments(ctx, bson.D{
		{Key: "trigger_id", Value: orderingHook.ID},
	})
	if err != nil || orderedBuildCount != 1 {
		t.Fatalf("ordering Hook Build count = %d/%v", orderedBuildCount, err)
	}
	ignoredDeliveryCount, err := database.Collection("webhook_deliveries").CountDocuments(ctx, bson.D{
		{Key: "hook_id", Value: orderingHook.ID},
		{Key: "status", Value: buildbiz.WebhookDeliveryStatusIgnored},
	})
	if err != nil || ignoredDeliveryCount != 1 {
		t.Fatalf("ordering Hook ignored delivery count = %d/%v", ignoredDeliveryCount, err)
	}
	if _, err := database.Collection("builds").DeleteMany(ctx, bson.D{
		{Key: "trigger_id", Value: orderingHook.ID},
	}); err != nil {
		t.Fatalf("clean ordering Hook Builds: %v", err)
	}
	if allowed, _, err := repository.ReserveBuildTrigger(ctx, "integration-shared-id", floodNow, 1, time.Minute); err != nil || !allowed {
		t.Fatalf("trigger namespace admission = %t/%v", allowed, err)
	}
	if allowed, _, err := repository.ReserveBuildWebhook(ctx, "integration-shared-id", floodNow, 1, time.Minute); err != nil || !allowed {
		t.Fatalf("webhook namespace admission = %t/%v", allowed, err)
	}
	externalBuild, err := useCase.TriggerExternalBuild(
		ctx, triggerCredential.Trigger.ID, triggerCredential.Token, "refs/heads/main",
		"a975c10d68a2d7461634f13b15c52a2efba72d16", "integration-external-build",
		"build-request-external",
	)
	if err != nil || externalBuild.TriggerSource != buildbiz.BuildTriggerSourceTriggerAPI ||
		externalBuild.TriggerID != triggerCredential.Trigger.ID {
		t.Fatalf("trigger external build = %+v/%v", externalBuild, err)
	}
	rateNow := time.Now().UTC()
	allowed, _, err := repository.ReserveBuildTrigger(
		ctx, triggerCredential.Trigger.ID, rateNow, 2, time.Minute,
	)
	if err != nil || !allowed {
		t.Fatalf("second shared trigger admission = %t/%v", allowed, err)
	}
	allowed, retryAt, err := repository.ReserveBuildTrigger(
		ctx, triggerCredential.Trigger.ID, rateNow, 2, time.Minute,
	)
	if err != nil || allowed || !retryAt.After(rateNow) {
		t.Fatalf("limited shared trigger admission = %t/%s/%v", allowed, retryAt, err)
	}
	build, err := useCase.TriggerManualBuild(
		ctx, principal, projectID, applicationID, configuration.ID,
		"refs/heads/main", "a975c10d68a2d7461634f13b15c52a2efba72d16",
		"integration-manual-build", "build-request-6",
	)
	if err != nil || build.Status != buildbiz.BuildStatusQueued ||
		build.Configuration.ConfigurationVersion != updatedConfiguration.Version ||
		build.Configuration.TimeoutSeconds != timeout ||
		build.Revision.CommitSHA != "a975c10d68a2d7461634f13b15c52a2efba72d16" {
		t.Fatalf("trigger manual build = %+v/%v", build, err)
	}
	replayedBuild, err := useCase.TriggerManualBuild(
		ctx, principal, projectID, applicationID, configuration.ID,
		"refs/heads/main", "a975c10d68a2d7461634f13b15c52a2efba72d16",
		"integration-manual-build", "build-request-replay",
	)
	if err != nil || replayedBuild.ID != build.ID {
		t.Fatalf("replay manual build = %+v/%v", replayedBuild, err)
	}
	if _, err := useCase.TriggerManualBuild(
		ctx, principal, projectID, applicationID, configuration.ID,
		"refs/heads/main", "b975c10d68a2d7461634f13b15c52a2efba72d16",
		"integration-manual-build", "build-request-mismatch",
	); !errors.Is(err, buildbiz.ErrIdempotencyMismatch) {
		t.Fatalf("build idempotency mismatch error = %v", err)
	}
	listedBuilds, err := useCase.ListBuilds(ctx, principal, projectID)
	if err != nil || len(listedBuilds) != 3 {
		t.Fatalf("list builds = %+v/%v", listedBuilds, err)
	}
	queueNow := time.Now().UTC()
	workerClock := func() time.Time { return queueNow }
	queueController, err := buildworker.NewController(
		repository, client, platformaudit.NewMongoStore(database),
		func() (string, error) {
			sequence++
			return fmt.Sprintf("build-integration-%d", sequence), nil
		},
		workerClock, 10*time.Second,
	)
	if err != nil {
		t.Fatalf("create build queue controller: %v", err)
	}
	queueController.WithArtifacts(repository)

	// Cancellation remains cooperative: the API records canceling and the
	// current (or reclaiming) worker fences its generation before recording
	// the terminal canceled state.
	cancelingExternal, err := useCase.CancelBuild(
		ctx, principal, projectID, externalBuild.ID, "build-request-cancel-external",
	)
	if err != nil || cancelingExternal.Status != buildbiz.BuildStatusCanceling {
		t.Fatalf("cancel external build = %+v/%v", cancelingExternal, err)
	}
	claimedCancel, found, err := queueController.Claim(ctx, "build-cancel-worker")
	if err != nil || !found || claimedCancel.ID != externalBuild.ID {
		t.Fatalf("claim canceled build = %+v/%t/%v", claimedCancel, found, err)
	}
	queueNow = queueNow.Add(time.Second)
	canceledExternal, err := queueController.Advance(
		ctx, claimedCancel, "build-cancel-worker", buildbiz.BuildStatusCanceled,
	)
	if err != nil || canceledExternal.Status != buildbiz.BuildStatusCanceled {
		t.Fatalf("finish canceled build = %+v/%v", canceledExternal, err)
	}

	if _, err := useCase.CancelBuild(
		ctx, principal, projectID, build.ID, "build-request-cancel-manual",
	); err != nil {
		t.Fatalf("cancel manual build: %v", err)
	}
	claimedCancel, found, err = queueController.Claim(ctx, "build-cancel-worker")
	if err != nil || !found || claimedCancel.ID != build.ID {
		t.Fatalf("claim second canceled build = %+v/%t/%v", claimedCancel, found, err)
	}
	queueNow = queueNow.Add(time.Second)
	if _, err := queueController.Advance(
		ctx, claimedCancel, "build-cancel-worker", buildbiz.BuildStatusCanceled,
	); err != nil {
		t.Fatalf("finish second canceled build: %v", err)
	}

	// Only the Webhook build remains queued. Concurrent Mongo claims must
	// produce exactly one owner for it.
	claimNow := queueNow.Add(time.Second)
	const claimers = 8
	type claimResult struct {
		item  buildbiz.Build
		found bool
		err   error
	}
	claimResults := make(chan claimResult, claimers)
	var claimWait sync.WaitGroup
	for index := 0; index < claimers; index++ {
		workerID := fmt.Sprintf("build-worker-%d", index)
		claimWait.Add(1)
		go func() {
			defer claimWait.Done()
			item, claimed, claimErr := repository.ClaimNextBuild(ctx, buildbiz.BuildClaim{
				WorkerID: workerID, Now: claimNow, ExpiresAt: claimNow.Add(10 * time.Second),
			})
			claimResults <- claimResult{item: item, found: claimed, err: claimErr}
		}()
	}
	claimWait.Wait()
	close(claimResults)
	var activeClaim buildbiz.Build
	claimedCount := 0
	for result := range claimResults {
		if result.err != nil {
			t.Fatalf("concurrent build claim: %v", result.err)
		}
		if result.found {
			claimedCount++
			activeClaim = result.item
		}
	}
	if claimedCount != 1 || activeClaim.ID != webhookBuild.BuildID || activeClaim.Lease.Generation != 1 {
		t.Fatalf("concurrent claims = %d, active = %+v", claimedCount, activeClaim)
	}

	heartbeatAt := claimNow.Add(time.Second)
	heartbeated, err := repository.RenewBuildLease(
		ctx, activeClaim.ID, activeClaim.Lease.Owner, activeClaim.Lease.Generation,
		activeClaim.Version, heartbeatAt, heartbeatAt.Add(10*time.Second),
	)
	if err != nil || heartbeated.Version != activeClaim.Version+1 {
		t.Fatalf("heartbeat build lease = %+v/%v", heartbeated, err)
	}
	if err := repository.ValidateBuildFence(
		ctx, heartbeated.ID, heartbeated.Lease.Owner, heartbeated.Lease.Generation,
		heartbeatAt.Add(time.Second),
	); err != nil {
		t.Fatalf("validate live build fence: %v", err)
	}

	reclaimAt := heartbeated.Lease.ExpiresAt.Add(time.Millisecond)
	reclaimed, found, err := repository.ClaimNextBuild(ctx, buildbiz.BuildClaim{
		WorkerID: "build-recovery-worker", Now: reclaimAt, ExpiresAt: reclaimAt.Add(10 * time.Second),
	})
	if err != nil || !found || reclaimed.ID != activeClaim.ID ||
		reclaimed.Lease.Generation != activeClaim.Lease.Generation+1 {
		t.Fatalf("reclaim expired build = %+v/%t/%v", reclaimed, found, err)
	}
	if err := repository.ValidateBuildFence(
		ctx, activeClaim.ID, activeClaim.Lease.Owner, activeClaim.Lease.Generation, reclaimAt,
	); !errors.Is(err, buildbiz.ErrBuildLeaseExpired) {
		t.Fatalf("stale build fence error = %v", err)
	}

	queueNow = reclaimAt.Add(time.Second)
	reclaimed, err = queueController.Advance(
		ctx, reclaimed, "build-recovery-worker", buildbiz.BuildStatusCheckingOut,
	)
	if err != nil || reclaimed.Status != buildbiz.BuildStatusCheckingOut {
		t.Fatalf("advance reclaimed build = %+v/%v", reclaimed, err)
	}
	queueNow = queueNow.Add(time.Second)
	failedBuild, err := queueController.Fail(
		ctx, reclaimed, "build-recovery-worker", buildbiz.BuildFailureCheckout,
	)
	if err != nil || failedBuild.Status != buildbiz.BuildStatusFailed ||
		failedBuild.FailureCategory != buildbiz.BuildFailureCheckout {
		t.Fatalf("fail reclaimed build = %+v/%v", failedBuild, err)
	}
	retriedBuild, err := useCase.RetryBuild(
		ctx, principal, projectID, failedBuild.ID, "integration-build-retry", "build-request-retry",
	)
	if err != nil || retriedBuild.Status != buildbiz.BuildStatusQueued ||
		retriedBuild.SourceBuildID != failedBuild.ID || retriedBuild.Revision != failedBuild.Revision {
		t.Fatalf("retry failed build = %+v/%v", retriedBuild, err)
	}
	retriedReplay, err := useCase.RetryBuild(
		ctx, principal, projectID, failedBuild.ID, "integration-build-retry", "build-request-retry-replay",
	)
	if err != nil || retriedReplay.ID != retriedBuild.ID {
		t.Fatalf("replay build retry = %+v/%v", retriedReplay, err)
	}

	// A failed audit must roll the state transition back with it.
	rollbackClaimAt := queueNow.Add(time.Second)
	rollbackClaim, found, err := repository.ClaimNextBuild(ctx, buildbiz.BuildClaim{
		WorkerID: "build-audit-worker", Now: rollbackClaimAt, ExpiresAt: rollbackClaimAt.Add(10 * time.Second),
	})
	if err != nil || !found || rollbackClaim.ID != retriedBuild.ID {
		t.Fatalf("claim audit rollback build = %+v/%t/%v", rollbackClaim, found, err)
	}
	queueNow = rollbackClaimAt.Add(time.Second)
	rollbackController, err := buildworker.NewController(
		repository, client, failingAudit{}, id.New, workerClock, 10*time.Second,
	)
	if err != nil {
		t.Fatalf("create rollback build controller: %v", err)
	}
	if _, err := rollbackController.Advance(
		ctx, rollbackClaim, "build-audit-worker", buildbiz.BuildStatusCheckingOut,
	); !errors.Is(err, errAuditProbe) {
		t.Fatalf("failed build audit transaction error = %v", err)
	}
	storedRollbackBuild, err := repository.GetBuild(ctx, projectID, rollbackClaim.ID)
	if err != nil || storedRollbackBuild.Status != buildbiz.BuildStatusQueued ||
		storedRollbackBuild.Version != rollbackClaim.Version {
		t.Fatalf("build after audit rollback = %+v/%v", storedRollbackBuild, err)
	}

	// A pushed digest is published exactly once as an Artifact under the live
	// Build generation. Release creation is separately idempotent by Artifact,
	// so coordinator retry never rebuilds or pushes the image again.
	artifactBuild := retriedBuild
	artifactBuild.ID = "build-artifact-integration"
	artifactBuild.IdempotencyKey = "artifact-integration"
	artifactBuild.Status = buildbiz.BuildStatusPushing
	artifactBuild.Version = 1
	artifactBuild.SourceBuildID = ""
	artifactBuild.Configuration.ReleaseRuntimeSpec = runtimespec.Spec{
		Ports:           []runtimespec.Port{{Name: "http", ContainerPort: 8080, Protocol: "tcp"}},
		EnvironmentKeys: []string{"DATABASE_URL"},
		Resources:       runtimespec.Resources{CPUMilli: 750, MemoryBytes: 384 * 1024 * 1024},
	}
	artifactBuild.ImageDigest = "registry.example.com/team/api@sha256:" + strings.Repeat("e", 64)
	artifactBuild.ArtifactID = ""
	artifactBuild.Lease = buildbiz.BuildLease{}
	artifactBuild.CreatedAt, artifactBuild.UpdatedAt = queueNow, queueNow
	if _, err := repository.CreateBuild(ctx, artifactBuild); err != nil {
		t.Fatalf("create pushed Build fixture: %v", err)
	}
	queueController.WithClaimStatuses(buildbiz.BuildStatusPushing)
	artifactClaim, found, err := queueController.Claim(ctx, "artifact-worker")
	if err != nil || !found || artifactClaim.ID != artifactBuild.ID {
		t.Fatalf("claim pushed Build = %+v/%t/%v", artifactClaim, found, err)
	}
	queueNow = queueNow.Add(time.Second)
	succeededBuild, artifact, err := queueController.PublishArtifact(ctx, artifactClaim, "artifact-worker")
	if err != nil || succeededBuild.Status != buildbiz.BuildStatusSucceeded ||
		artifact.ReleaseStatus != buildbiz.ArtifactReleasePending || succeededBuild.ArtifactID != artifact.ID {
		t.Fatalf("publish Artifact = %+v/%+v/%v", succeededBuild, artifact, err)
	}
	storedArtifact, err := repository.GetArtifactByBuild(ctx, artifactBuild.ID)
	if err != nil || storedArtifact.ImageDigest != artifactBuild.ImageDigest ||
		len(storedArtifact.ReleaseRuntimeSpec.Ports) != 1 ||
		storedArtifact.ReleaseRuntimeSpec.Resources.CPUMilli != 750 ||
		len(storedArtifact.AutomaticDeployments) != 1 ||
		storedArtifact.AutomaticDeployments[0].EnvironmentID != developmentID {
		t.Fatalf("stored Artifact = %+v/%v", storedArtifact, err)
	}
	if _, err := repository.CreateArtifact(ctx, artifact); !errors.Is(err, buildbiz.ErrDuplicateArtifact) {
		t.Fatalf("duplicate Build Artifact error = %v", err)
	}
	artifactControlPlane := controlplanebiz.NewUseCaseWithResources(
		controlStore, controlStore, controlStore, controlStore, controlStore, controlStore,
		client, platformaudit.NewMongoStore(database), platformaudit.NewMongoStore(database),
		id.New, time.Now,
	).WithArtifactReleases(controlStore)
	deploymentStore := deploymentdata.NewMongoRepository(database)
	deploymentReferences := deploymentdata.NewFormalReferenceLookup(controlStore)
	automaticDeployments := deploymentbiz.NewUseCase(deploymentStore, nil, nil, id.New, time.Now).
		WithFormalReferences(deploymentReferences).
		WithAutomaticReferences(deploymentReferences).
		WithFormalSecurity(client, platformaudit.NewMongoStore(database)).
		WithAdmissionEvaluator(staticAdmissionEvaluator{stage: "development"})
	releaseAdapter := builddata.NewArtifactReleaseAdapter(artifactControlPlane).
		WithAutomaticDeployments(automaticDeployments)
	releaseID, err := releaseAdapter.CreateArtifactRelease(ctx, buildbiz.ArtifactReleaseRequest{
		ArtifactID: artifact.ID, OrganizationID: artifact.OrganizationID,
		ProjectID: artifact.ProjectID, ApplicationID: artifact.ApplicationID,
		RegistryCredentialID: artifact.RegistryCredentialID,
		ImageDigest:          artifact.ImageDigest, RuntimeSpec: artifact.ReleaseRuntimeSpec,
		AutomaticDeployments: artifact.AutomaticDeployments, BuildID: artifact.BuildID,
		BuildConfigurationID: artifact.BuildConfigurationID,
		ActorID:              "system:artifact-worker",
	})
	if err != nil {
		t.Fatalf("create Artifact Release: %v", err)
	}
	replayedReleaseID, err := releaseAdapter.CreateArtifactRelease(ctx, buildbiz.ArtifactReleaseRequest{
		ArtifactID: artifact.ID, OrganizationID: artifact.OrganizationID,
		ProjectID: artifact.ProjectID, ApplicationID: artifact.ApplicationID,
		RegistryCredentialID: artifact.RegistryCredentialID,
		ImageDigest:          artifact.ImageDigest, RuntimeSpec: artifact.ReleaseRuntimeSpec,
		AutomaticDeployments: artifact.AutomaticDeployments, BuildID: artifact.BuildID,
		BuildConfigurationID: artifact.BuildConfigurationID,
		ActorID:              "system:artifact-worker",
	})
	if err != nil || replayedReleaseID != releaseID {
		t.Fatalf("replay Artifact Release = %q/%v", replayedReleaseID, err)
	}
	queueNow = queueNow.Add(time.Second)
	releasedArtifact, err := queueController.RecordArtifactRelease(ctx, artifact, "artifact-worker", releaseID)
	if err != nil || releasedArtifact.ReleaseStatus != buildbiz.ArtifactReleaseCreated || releasedArtifact.ReleaseID != releaseID {
		t.Fatalf("record Artifact Release = %+v/%v", releasedArtifact, err)
	}
	storedRelease, err := controlStore.GetReleaseByArtifact(ctx, projectID, artifact.ID)
	if err != nil || storedRelease.ID != releaseID || storedRelease.SourceArtifactID != artifact.ID ||
		storedRelease.ImageDigest != artifact.ImageDigest ||
		len(storedRelease.RuntimeSpec.Ports) != 1 || storedRelease.RuntimeSpec.Ports[0].ContainerPort != 8080 ||
		storedRelease.RuntimeSpec.Resources.CPUMilli != 750 {
		t.Fatalf("stored Artifact Release = %+v/%v", storedRelease, err)
	}
	automaticItems, err := deploymentStore.List(ctx, projectID, applicationID, developmentID)
	if err != nil || len(automaticItems) != 1 ||
		automaticItems[0].TriggerSource != deploymentbiz.TriggerSourceAutomatic ||
		automaticItems[0].SourceArtifactID != artifact.ID ||
		automaticItems[0].SourceBuildID != artifact.BuildID ||
		automaticItems[0].BuildConfigurationID != artifact.BuildConfigurationID ||
		automaticItems[0].ReleaseID != releaseID || automaticItems[0].RuntimeTargetID != runtimeTargetID {
		t.Fatalf("automatic Deployment = %+v/%v", automaticItems, err)
	}
	var automaticAudit bson.M
	if err := database.Collection("audit_events").FindOne(ctx, bson.D{
		{Key: "project_id", Value: projectID},
		{Key: "action", Value: deploymentbiz.AuditActionAutomatic},
		{Key: "resource_id", Value: automaticItems[0].ID},
	}).Decode(&automaticAudit); err != nil || automaticAudit["actor_id"] != "system:auto-deployment" {
		t.Fatalf("automatic Deployment audit = %#v/%v", automaticAudit, err)
	}
	if _, err := database.Collection("deployments").DeleteMany(ctx, bson.D{
		{Key: "project_id", Value: projectID}, {Key: "trigger_source", Value: "automatic"},
	}); err != nil {
		t.Fatalf("clean automatic Deployment fixture: %v", err)
	}
	if _, err := database.Collection("deployment_cutover_sequences").DeleteMany(ctx,
		bson.D{{Key: "project_id", Value: projectID}}); err != nil {
		t.Fatalf("clean automatic Deployment sequence fixture: %v", err)
	}

	// Build logs are ordered, cursor-readable, byte bounded, explicitly
	// truncated and assigned a shared TTL without exposing another Project.
	repository.WithBuildLogLimits(time.Hour, 32, 8)
	logTime := queueNow.Add(time.Second)
	for _, message := range []string{"alpha-123456", "beta-1234567890", "discarded"} {
		if err := repository.AppendBuildLog(ctx, buildbiz.BuildLogAppend{
			BuildID: artifactBuild.ID, ProjectID: projectID, Stage: buildbiz.BuildLogStageBuild,
			Message: message, CreatedAt: logTime,
		}); err != nil {
			t.Fatalf("append bounded Build log: %v", err)
		}
		logTime = logTime.Add(time.Second)
	}
	firstLogPage, err := repository.ReadBuildLogs(ctx, projectID, artifactBuild.ID,
		buildbiz.BuildLogQuery{Limit: 1})
	if err != nil || len(firstLogPage.Entries) != 1 || firstLogPage.NextSequence != 1 ||
		!firstLogPage.Truncated || firstLogPage.ExpiresAt.IsZero() {
		t.Fatalf("first Build log page = %+v/%v", firstLogPage, err)
	}
	nextLogPage, err := repository.ReadBuildLogs(ctx, projectID, artifactBuild.ID,
		buildbiz.BuildLogQuery{AfterSequence: firstLogPage.NextSequence, Limit: 10})
	if err != nil || len(nextLogPage.Entries) != 3 || nextLogPage.NextSequence != 4 ||
		!nextLogPage.Truncated {
		t.Fatalf("next Build log page = %+v/%v", nextLogPage, err)
	}
	logExpiryCursor, err := database.Collection("build_log_chunks").Find(ctx,
		bson.D{{Key: "build_id", Value: artifactBuild.ID}},
		options.Find().SetProjection(bson.D{{Key: "expires_at", Value: 1}}),
	)
	if err != nil {
		t.Fatalf("find Build log expirations: %v", err)
	}
	var logExpirations []struct {
		ExpiresAt time.Time `bson:"expires_at"`
	}
	if err := logExpiryCursor.All(ctx, &logExpirations); err != nil {
		_ = logExpiryCursor.Close(ctx)
		t.Fatalf("decode Build log expirations: %v", err)
	}
	_ = logExpiryCursor.Close(ctx)
	if len(logExpirations) != 4 {
		t.Fatalf("Build log expiration count = %d, want 4", len(logExpirations))
	}
	for _, document := range logExpirations {
		if !document.ExpiresAt.Equal(firstLogPage.ExpiresAt) {
			t.Fatalf("Build log chunk expiration = %s, stream = %s", document.ExpiresAt, firstLogPage.ExpiresAt)
		}
	}
	foreignLogPage, err := repository.ReadBuildLogs(ctx, "project-foreign", artifactBuild.ID,
		buildbiz.BuildLogQuery{})
	if err != nil || len(foreignLogPage.Entries) != 0 {
		t.Fatalf("foreign Build log page = %+v/%v", foreignLogPage, err)
	}
	var buildAudit bson.M
	if err := database.Collection("audit_events").FindOne(ctx, bson.D{
		{Key: "project_id", Value: projectID},
		{Key: "action", Value: "build.trigger_manual"},
		{Key: "resource_id", Value: build.ID},
	}).Decode(&buildAudit); err != nil {
		t.Fatalf("manual build audit = %#v/%v", buildAudit, err)
	}
	failedProbeUseCase := buildbiz.NewUseCase(
		controlplanedata.NewMongoStore(database), repository, client,
		failingAudit{},
		func() (string, error) {
			sequence++
			return fmt.Sprintf("build-integration-%d", sequence), nil
		},
		time.Now,
	).WithSourceProber(readySourceRepositoryProber{})
	if _, err := failedProbeUseCase.ProbeSource(
		ctx, principal, projectID, source.ID, "build-request-probe-rollback",
	); !errors.Is(err, errAuditProbe) {
		t.Fatalf("failed probe transaction error = %v", err)
	}
	storedAfterFailedProbe, err := repository.GetSource(ctx, projectID, source.ID)
	if err != nil || storedAfterFailedProbe.Status != probed.Status ||
		!storedAfterFailedProbe.LastProbedAt.Equal(probed.LastProbedAt) {
		t.Fatalf("source after failed probe transaction = %+v/%v", storedAfterFailedProbe, err)
	}
	if _, err := repository.GetSource(ctx, "other-project", source.ID); !errors.Is(err, buildbiz.ErrNotFound) {
		t.Fatalf("cross-project source lookup error = %v", err)
	}
	failedUseCase := buildbiz.NewUseCase(
		controlStore, repository, client,
		failingAudit{},
		func() (string, error) {
			sequence++
			return fmt.Sprintf("build-integration-%d", sequence), nil
		},
		time.Now,
	).WithConfigurationReferences(references, references).
		WithSourceRevisionResolver(readySourceRepositoryProber{})
	failed, err := failedUseCase.CreateCredential(
		ctx, principal, projectID, "Rolled back token",
		buildbiz.CredentialTypeHTTPSAccessToken,
		"", "secret://rolled-back-token", "", "build-request-failed",
	)
	if !errors.Is(err, errAuditProbe) {
		t.Fatalf("failed credential transaction = %+v/%v", failed, err)
	}
	count, err := database.Collection("repository_credentials").CountDocuments(
		ctx, bson.D{{Key: "project_id", Value: projectID}},
	)
	if err != nil || count != 1 {
		t.Fatalf("repository credentials after rollback = %d/%v", count, err)
	}
	rolledBackConfiguration, err := failedUseCase.CreateBuildConfiguration(
		ctx, principal, projectID, applicationID, "Rolled back build", source.ID,
		"Dockerfile", ".", []string{"refs/heads/main"},
		registryID, "registry.example.com/team/rollback", buildbiz.BuildPlatformLinuxAMD64,
		buildbiz.BuildResources{}, 0, 0, false, "build-request-rollback-configuration",
	)
	if !errors.Is(err, errAuditProbe) {
		t.Fatalf("failed build configuration transaction = %+v/%v", rolledBackConfiguration, err)
	}
	configurationCount, err := database.Collection("build_configurations").CountDocuments(
		ctx, bson.D{{Key: "project_id", Value: projectID}},
	)
	if err != nil || configurationCount != 1 {
		t.Fatalf("build configurations after rollback = %d/%v", configurationCount, err)
	}
	rolledBackBuild, err := failedUseCase.TriggerManualBuild(
		ctx, principal, projectID, applicationID, configuration.ID,
		"refs/heads/main", "", "integration-rollback-build", "build-request-rollback-build",
	)
	if !errors.Is(err, errAuditProbe) {
		t.Fatalf("failed build transaction = %+v/%v", rolledBackBuild, err)
	}
	buildCount, err := database.Collection("builds").CountDocuments(
		ctx, bson.D{{Key: "project_id", Value: projectID}},
	)
	if err != nil || buildCount != 5 {
		t.Fatalf("builds after rollback = %d/%v", buildCount, err)
	}
	assertProjectDocumentsExcludeSecrets(t, ctx, database, projectID, []string{triggerCredential.Token})
}

func assertProjectDocumentsExcludeSecrets(t *testing.T, ctx context.Context,
	database *drivermongo.Database, projectID string, forbidden []string) {
	t.Helper()
	for _, collection := range []string{
		"repository_credentials", "source_repositories", "build_configurations", "build_triggers",
		"build_hooks", "webhook_deliveries", "builds", "build_log_streams", "build_log_chunks",
		"artifacts", "releases", "deployments", "audit_events",
	} {
		cursor, err := database.Collection(collection).Find(ctx, bson.D{{Key: "project_id", Value: projectID}})
		if err != nil {
			t.Fatalf("scan %s for plaintext secrets: %v", collection, err)
		}
		for cursor.Next(ctx) {
			var document bson.Raw
			if err := cursor.Decode(&document); err != nil {
				_ = cursor.Close(ctx)
				t.Fatalf("decode %s during secret scan: %v", collection, err)
			}
			serialized, err := bson.MarshalExtJSON(document, false, false)
			if err != nil {
				_ = cursor.Close(ctx)
				t.Fatalf("serialize %s during secret scan: %v", collection, err)
			}
			for _, secret := range forbidden {
				if secret != "" && bytes.Contains(serialized, []byte(secret)) {
					_ = cursor.Close(ctx)
					t.Fatalf("plaintext secret found in %s document", collection)
				}
			}
		}
		if err := cursor.Err(); err != nil {
			_ = cursor.Close(ctx)
			t.Fatalf("scan %s for plaintext secrets: %v", collection, err)
		}
		_ = cursor.Close(ctx)
	}
}

func verifyRuntimeInventoryIntegration(
	t *testing.T,
	ctx context.Context,
	database *drivermongo.Database,
) {
	t.Helper()
	if _, err := database.Collection("runtime_targets").InsertOne(ctx, bson.D{
		{Key: "_id", Value: "inventory-target"},
		{Key: "project_id", Value: "inventory-project"},
		{Key: "managed_host_id", Value: "inventory-host"},
		{Key: "status", Value: controlplanebiz.RuntimeTargetStatusReady},
		{Key: "created_at", Value: time.Now().UTC()},
	}); err != nil {
		t.Fatalf("seed runtime inventory target: %v", err)
	}
	defer func() {
		_, _ = database.Collection("runtime_targets").DeleteOne(
			context.Background(), bson.D{{Key: "_id", Value: "inventory-target"}},
		)
	}()
	repository := runtimeinventorydata.NewMongoRepository(database)
	startedAt := time.Now().UTC().Add(-time.Minute)
	first, err := runtimeinventorybiz.NewObservation(
		"inventory-observation-1",
		"inventory-organization",
		"inventory-host",
		"inventory-target",
		1,
		1,
		startedAt,
	)
	if err != nil {
		t.Fatalf("create runtime inventory observation: %v", err)
	}
	delayed, err := runtimeinventorybiz.NewObservation(
		"inventory-observation-delayed",
		first.OrganizationID,
		first.ManagedHostID,
		first.RuntimeTargetID,
		0,
		0,
		startedAt.Add(10*time.Minute),
	)
	if err != nil {
		t.Fatalf("create delayed runtime inventory observation: %v", err)
	}
	if err := repository.Begin(ctx, delayed); err != nil {
		t.Fatalf("begin delayed runtime inventory observation: %v", err)
	}
	if err := repository.Begin(ctx, first); err != nil {
		t.Fatalf("begin runtime inventory observation: %v", err)
	}
	assertRuntimeInventoryExpiry(
		t, ctx,
		database.Collection("runtime_inventory_observations"),
		bson.D{{Key: "_id", Value: first.ID}},
		true,
	)
	resource, err := runtimeinventorybiz.NewResource(
		first,
		runtimeinventorybiz.KindContainer,
		"container-1",
		"api",
		startedAt.Add(time.Second),
	)
	if err != nil {
		t.Fatalf("create runtime inventory resource: %v", err)
	}
	resource.Managed = true
	resource.ProjectID = "inventory-project"
	resource.DeploymentID = "inventory-deployment"
	resource.Container = &runtimeinventorybiz.ContainerSummary{
		ImageReference: "registry.example.com/team/api@sha256:" +
			strings.Repeat("a", 64),
		ImageDigest: "sha256:" + strings.Repeat("a", 64),
		State:       "running",
		Health:      "healthy",
	}
	resource.Labels["net.owndock.deployment_id"] = resource.DeploymentID
	chunk, err := runtimeinventorybiz.NewChunk(
		first,
		0,
		[]runtimeinventorybiz.Resource{resource},
	)
	if err != nil {
		t.Fatalf("create runtime inventory chunk: %v", err)
	}
	if err := repository.Append(ctx, chunk); err != nil {
		t.Fatalf("append runtime inventory chunk: %v", err)
	}
	assertRuntimeInventoryExpiry(
		t, ctx,
		database.Collection("runtime_inventory_chunks"),
		bson.D{{Key: "observation_id", Value: first.ID}},
		true,
	)
	assertRuntimeInventoryExpiry(
		t, ctx,
		database.Collection("runtime_inventory_resources"),
		bson.D{{Key: "observation_id", Value: first.ID}},
		true,
	)
	if err := repository.Append(ctx, chunk); err != nil {
		t.Fatalf("replay runtime inventory chunk: %v", err)
	}
	query := runtimeinventorybiz.Query{
		OrganizationID:  first.OrganizationID,
		RuntimeTargetID: first.RuntimeTargetID,
	}
	if _, err := repository.Current(ctx, query); !errors.Is(
		err,
		runtimeinventorybiz.ErrNotFound,
	) {
		t.Fatalf("incomplete runtime inventory visibility error = %v", err)
	}
	if err := repository.Complete(
		ctx,
		first.ID,
		first.RuntimeTargetID,
		startedAt.Add(2*time.Second),
	); err != nil {
		t.Fatalf("complete runtime inventory observation: %v", err)
	}
	for _, collection := range []string{
		"runtime_inventory_observations",
		"runtime_inventory_chunks",
		"runtime_inventory_resources",
	} {
		filter := bson.D{{Key: "observation_id", Value: first.ID}}
		if collection == "runtime_inventory_observations" {
			filter = bson.D{{Key: "_id", Value: first.ID}}
		}
		assertRuntimeInventoryExpiry(
			t, ctx, database.Collection(collection), filter, false,
		)
	}
	current, err := repository.Current(ctx, query)
	if err != nil {
		t.Fatalf("read current runtime inventory: %v", err)
	}
	if len(current) != 1 ||
		current[0].RuntimeID != resource.RuntimeID ||
		current[0].Managed || current[0].ProjectID != "" ||
		current[0].DeploymentID != "" {
		t.Fatalf("current runtime inventory = %+v", current)
	}
	stateQuery := runtimeinventorybiz.StateQuery{
		OrganizationID: first.OrganizationID, RuntimeTargetID: first.RuntimeTargetID,
		IncludeAbsent: true,
	}
	states, err := repository.CurrentState(ctx, stateQuery)
	if err != nil || len(states) != 1 ||
		states[0].Presence != runtimeinventorybiz.PresencePresent ||
		states[0].Generation == 0 || states[0].FirstSeenAt.IsZero() ||
		!states[0].AbsentAt.IsZero() || states[0].Managed ||
		states[0].ProjectID != "" || states[0].DeploymentID != "" {
		t.Fatalf("present runtime inventory state = %+v, %v", states, err)
	}
	firstSeenAt := states[0].FirstSeenAt
	partial, err := runtimeinventorybiz.NewObservation(
		"inventory-observation-partial",
		first.OrganizationID,
		first.ManagedHostID,
		first.RuntimeTargetID,
		2,
		2,
		startedAt.Add(3*time.Second),
	)
	if err != nil {
		t.Fatalf("create partial runtime inventory observation: %v", err)
	}
	partialResource := resource
	partialResource.ObservationID = partial.ID
	partialResource.ObservedAt = startedAt.Add(3 * time.Second)
	partialChunk, err := runtimeinventorybiz.NewChunk(
		partial, 0, []runtimeinventorybiz.Resource{partialResource},
	)
	if err != nil {
		t.Fatalf("create partial runtime inventory chunk: %v", err)
	}
	if err := repository.Begin(ctx, partial); err != nil {
		t.Fatalf("begin partial runtime inventory observation: %v", err)
	}
	if err := repository.Append(ctx, partialChunk); err != nil {
		t.Fatalf("append partial runtime inventory chunk: %v", err)
	}
	if err := repository.Complete(
		ctx, partial.ID, partial.RuntimeTargetID, startedAt.Add(4*time.Second),
	); !errors.Is(err, runtimeinventorybiz.ErrConflict) {
		t.Fatalf("partial runtime inventory completion error = %v", err)
	}
	states, err = repository.CurrentState(ctx, stateQuery)
	if err != nil || len(states) != 1 ||
		states[0].Presence != runtimeinventorybiz.PresencePresent ||
		!states[0].FirstSeenAt.Equal(firstSeenAt) {
		t.Fatalf("state changed by partial observation = %+v, %v", states, err)
	}

	if err := repository.Complete(
		ctx,
		delayed.ID,
		delayed.RuntimeTargetID,
		startedAt.Add(11*time.Minute),
	); !errors.Is(err, runtimeinventorybiz.ErrConflict) {
		t.Fatalf("delayed runtime inventory completion error = %v", err)
	}

	second, err := runtimeinventorybiz.NewObservation(
		"inventory-observation-2",
		first.OrganizationID,
		first.ManagedHostID,
		first.RuntimeTargetID,
		0,
		0,
		startedAt.Add(4*time.Second),
	)
	if err != nil {
		t.Fatalf("create empty runtime inventory observation: %v", err)
	}
	if err := repository.Begin(ctx, second); err != nil {
		t.Fatalf("begin empty runtime inventory observation: %v", err)
	}
	if err := repository.Complete(
		ctx,
		second.ID,
		second.RuntimeTargetID,
		startedAt.Add(5*time.Second),
	); err != nil {
		t.Fatalf("complete empty runtime inventory observation: %v", err)
	}
	current, err = repository.Current(ctx, query)
	if err != nil || len(current) != 0 {
		t.Fatalf("empty current runtime inventory = %+v, %v", current, err)
	}
	states, err = repository.CurrentState(ctx, stateQuery)
	if err != nil || len(states) != 1 ||
		states[0].Presence != runtimeinventorybiz.PresenceAbsent ||
		!states[0].FirstSeenAt.Equal(firstSeenAt) || states[0].AbsentAt.IsZero() {
		t.Fatalf("absent runtime inventory state = %+v, %v", states, err)
	}
	if err := states[0].Validate(); err != nil {
		t.Fatalf("validate absent runtime inventory state: %v", err)
	}

	third, err := runtimeinventorybiz.NewObservation(
		"inventory-observation-3",
		first.OrganizationID,
		first.ManagedHostID,
		first.RuntimeTargetID,
		1,
		1,
		startedAt.Add(6*time.Second),
	)
	if err != nil {
		t.Fatalf("create restoring runtime inventory observation: %v", err)
	}
	restored := resource
	restored.ObservationID = third.ID
	restored.ObservedAt = startedAt.Add(6 * time.Second)
	restored.Container = &runtimeinventorybiz.ContainerSummary{
		ImageReference: resource.Container.ImageReference,
		ImageDigest:    resource.Container.ImageDigest,
		State:          "running", Health: "healthy",
	}
	restoredChunk, err := runtimeinventorybiz.NewChunk(
		third, 0, []runtimeinventorybiz.Resource{restored},
	)
	if err != nil {
		t.Fatalf("create restoring runtime inventory chunk: %v", err)
	}
	if err := repository.Begin(ctx, third); err != nil {
		t.Fatalf("begin restoring runtime inventory observation: %v", err)
	}
	if err := repository.Append(ctx, restoredChunk); err != nil {
		t.Fatalf("append restoring runtime inventory chunk: %v", err)
	}
	if err := repository.Complete(
		ctx, third.ID, third.RuntimeTargetID, startedAt.Add(7*time.Second),
	); err != nil {
		t.Fatalf("complete restoring runtime inventory observation: %v", err)
	}
	states, err = repository.CurrentState(ctx, stateQuery)
	if err != nil || len(states) != 1 ||
		states[0].Presence != runtimeinventorybiz.PresencePresent ||
		!states[0].FirstSeenAt.Equal(firstSeenAt) || !states[0].AbsentAt.IsZero() {
		t.Fatalf("restored runtime inventory state = %+v, %v", states, err)
	}
	if err := states[0].Validate(); err != nil {
		t.Fatalf("validate restored runtime inventory state: %v", err)
	}
	for _, collection := range []string{
		"runtime_inventory_observations",
		"runtime_inventory_chunks",
		"runtime_inventory_resources",
		"runtime_inventory_heads",
		"runtime_inventory_counters",
		"runtime_inventory_current",
	} {
		if _, err := database.Collection(collection).DeleteMany(ctx, bson.D{}); err != nil {
			t.Fatalf("clean runtime inventory collection %s: %v", collection, err)
		}
	}
}

func verifyRuntimeInventoryScheduleIntegration(
	t *testing.T,
	ctx context.Context,
	database *drivermongo.Database,
) {
	t.Helper()
	if _, err := database.Collection("managed_hosts").InsertOne(ctx, bson.D{
		{Key: "_id", Value: "inventory-schedule-host"},
		{Key: "organization_id", Value: "legacy-organization"},
		{Key: "status", Value: managedhostbiz.StatusOnline},
	}); err != nil {
		t.Fatalf("seed runtime inventory schedule host: %v", err)
	}
	if _, err := database.Collection("runtime_targets").InsertOne(ctx, bson.D{
		{Key: "_id", Value: "inventory-schedule-target"},
		{Key: "project_id", Value: "legacy-project"},
		{Key: "managed_host_id", Value: "inventory-schedule-host"},
		{Key: "connection_mode", Value: runtimeaccess.ModeDirectDocker},
		{Key: "endpoint", Value: "tcp://runtime.example:2376"},
		{Key: "tls_server_name", Value: "runtime.example"},
		{Key: "credential_ref", Value: "secret://inventory-schedule"},
		{Key: "status", Value: controlplanebiz.RuntimeTargetStatusReady},
		{Key: "created_at", Value: time.Now().UTC()},
	}); err != nil {
		t.Fatalf("seed runtime inventory schedule target: %v", err)
	}
	repository := runtimeinventorydata.NewMongoScheduleRepository(database)
	targets, err := repository.ListReadyTargets(ctx, 10, time.Now().UTC())
	if err != nil {
		t.Fatalf("list runtime inventory schedule targets: %v", err)
	}
	var target runtimeinventorybiz.Target
	for _, candidate := range targets {
		if candidate.RuntimeTargetID == "inventory-schedule-target" {
			target = candidate
			break
		}
	}
	if target.RuntimeTargetID == "" ||
		target.OrganizationID != "legacy-organization" {
		t.Fatalf("runtime inventory schedule target = %+v", target)
	}
	verifyConcurrentInventoryRunners(t, ctx, database, repository)

	now := time.Now().UTC()
	type claimResult struct {
		lease    runtimeinventorybiz.ScheduleLease
		acquired bool
		err      error
	}
	results := make(chan claimResult, 2)
	for _, owner := range []string{"inventory-server-a", "inventory-server-b"} {
		go func(ownerID string) {
			lease, acquired, claimErr := repository.TryAcquire(
				ctx, target, ownerID, now, now.Add(time.Minute),
			)
			results <- claimResult{lease: lease, acquired: acquired, err: claimErr}
		}(owner)
	}
	var winner runtimeinventorybiz.ScheduleLease
	acquiredCount := 0
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatalf("claim runtime inventory schedule: %v", result.err)
		}
		if result.acquired {
			acquiredCount++
			winner = result.lease
		}
	}
	if acquiredCount != 1 {
		t.Fatalf("concurrent runtime inventory claims = %d, want 1", acquiredCount)
	}
	if dueTargets, listErr := repository.ListReadyTargets(ctx, 10, now); listErr != nil {
		t.Fatalf("list leased runtime inventory targets: %v", listErr)
	} else if containsInventoryTarget(dueTargets, target.RuntimeTargetID) {
		t.Fatal("actively leased runtime inventory target remained due")
	}
	nextDueAt := now.Add(5 * time.Minute)
	if err := repository.Finish(
		ctx, winner, now.Add(time.Second), nextDueAt, true,
	); err != nil {
		t.Fatalf("finish runtime inventory schedule: %v", err)
	}
	if _, acquired, err := repository.TryAcquire(
		ctx,
		target,
		"inventory-server-c",
		now.Add(2*time.Second),
		now.Add(2*time.Minute),
	); err != nil || acquired {
		t.Fatalf("early runtime inventory claim = %v, %v", acquired, err)
	}
	if dueTargets, listErr := repository.ListReadyTargets(
		ctx,
		10,
		now.Add(2*time.Second),
	); listErr != nil {
		t.Fatalf("list early runtime inventory targets: %v", listErr)
	} else if containsInventoryTarget(dueTargets, target.RuntimeTargetID) {
		t.Fatal("runtime inventory target was listed before next_due_at")
	}
	if dueTargets, listErr := repository.ListReadyTargets(
		ctx,
		10,
		nextDueAt,
	); listErr != nil {
		t.Fatalf("list due runtime inventory targets: %v", listErr)
	} else if !containsInventoryTarget(dueTargets, target.RuntimeTargetID) {
		t.Fatal("runtime inventory target was not listed at next_due_at")
	}
	second, acquired, err := repository.TryAcquire(
		ctx,
		target,
		"inventory-server-c",
		nextDueAt,
		nextDueAt.Add(time.Minute),
	)
	if err != nil || !acquired || second.Token <= winner.Token {
		t.Fatalf("due runtime inventory claim = %+v, %v, %v", second, acquired, err)
	}
	if err := repository.Finish(
		ctx, winner, nextDueAt, nextDueAt.Add(time.Minute), false,
	); !errors.Is(err, runtimeinventorybiz.ErrLeaseLost) {
		t.Fatalf("stale runtime inventory lease finish error = %v", err)
	}
	eventReceivedAt := nextDueAt.Add(500 * time.Millisecond)
	hint, err := runtimeinventorybiz.NewEventHint(
		target.OrganizationID,
		target.RuntimeTargetID,
		runtimeinventorybiz.KindContainer,
		"inventory-event-container",
		runtimeinventorybiz.EventActionDestroy,
		nextDueAt.Add(250*time.Millisecond),
		eventReceivedAt,
	)
	if err != nil {
		t.Fatalf("create runtime inventory event hint: %v", err)
	}
	if err := repository.RecordEventHint(ctx, hint); err != nil {
		t.Fatalf("record runtime inventory event hint: %v", err)
	}
	// A replay may arrive later but must retain one summary and can only make
	// reconciliation earlier, never mutate current presence directly.
	replayedHint, err := runtimeinventorybiz.NewEventHint(
		target.OrganizationID,
		target.RuntimeTargetID,
		runtimeinventorybiz.KindContainer,
		"inventory-event-container",
		runtimeinventorybiz.EventActionDestroy,
		nextDueAt.Add(250*time.Millisecond),
		eventReceivedAt.Add(100*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("create replayed runtime inventory event hint: %v", err)
	}
	if err := repository.RecordEventHint(ctx, replayedHint); err != nil {
		t.Fatalf("record replayed runtime inventory event hint: %v", err)
	}
	finishAfterEvent := nextDueAt.Add(time.Second)
	if err := repository.Finish(
		ctx, second, finishAfterEvent, finishAfterEvent.Add(5*time.Minute), true,
	); err != nil {
		t.Fatalf("finish event-interrupted runtime inventory schedule: %v", err)
	}
	if dueTargets, listErr := repository.ListReadyTargets(
		ctx, 10, finishAfterEvent,
	); listErr != nil {
		t.Fatalf("list event-due runtime inventory targets: %v", listErr)
	} else if !containsInventoryTarget(dueTargets, target.RuntimeTargetID) {
		t.Fatal("event received during collection was overwritten by Finish")
	}
	if count, countErr := database.Collection("runtime_inventory_event_hints").
		CountDocuments(ctx, bson.D{{Key: "_id", Value: hint.ID}}); countErr != nil || count != 1 {
		t.Fatalf("runtime inventory event hint count = %d, %v", count, countErr)
	}
	verifyRuntimeInventoryEventScheduleIntegration(t, ctx, database, target)
	if _, err := database.Collection("runtime_inventory_schedule").DeleteOne(
		ctx,
		bson.D{{Key: "_id", Value: target.RuntimeTargetID}},
	); err != nil {
		t.Fatalf("clean runtime inventory schedule: %v", err)
	}
	if _, err := database.Collection("runtime_targets").DeleteOne(
		ctx,
		bson.D{{Key: "_id", Value: target.RuntimeTargetID}},
	); err != nil {
		t.Fatalf("clean runtime inventory schedule target: %v", err)
	}
	if _, err := database.Collection("managed_hosts").DeleteOne(
		ctx,
		bson.D{{Key: "_id", Value: target.ManagedHostID}},
	); err != nil {
		t.Fatalf("clean runtime inventory schedule host: %v", err)
	}
	if _, err := database.Collection("runtime_inventory_event_hints").DeleteMany(
		ctx,
		bson.D{{Key: "runtime_target_id", Value: target.RuntimeTargetID}},
	); err != nil {
		t.Fatalf("clean runtime inventory event hints: %v", err)
	}
}

func verifyRuntimeInventoryEventScheduleIntegration(
	t *testing.T,
	ctx context.Context,
	database *drivermongo.Database,
	target runtimeinventorybiz.Target,
) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Millisecond).Add(time.Minute)
	left := runtimeinventorydata.NewMongoScheduleRepository(database)
	right := runtimeinventorydata.NewMongoScheduleRepository(database)
	targets, err := left.ListEventTargets(ctx, 10, now)
	if err != nil {
		t.Fatalf("list runtime inventory event targets: %v", err)
	}
	if !containsInventoryTarget(targets, target.RuntimeTargetID) {
		t.Fatal("runtime inventory target was not eligible for event polling")
	}
	type result struct {
		lease    runtimeinventorybiz.EventScheduleLease
		acquired bool
		err      error
	}
	results := make(chan result, 2)
	for index, repository := range []*runtimeinventorydata.MongoScheduleRepository{left, right} {
		go func(
			worker int,
			repository *runtimeinventorydata.MongoScheduleRepository,
		) {
			lease, acquired, claimErr := repository.TryAcquireEvents(
				ctx,
				target,
				fmt.Sprintf("inventory-event-server-%d", worker),
				now,
				now.Add(time.Minute),
			)
			results <- result{lease: lease, acquired: acquired, err: claimErr}
		}(index, repository)
	}
	var first runtimeinventorybiz.EventScheduleLease
	winners := 0
	for range 2 {
		claim := <-results
		if claim.err != nil {
			t.Fatalf("claim runtime inventory event schedule: %v", claim.err)
		}
		if claim.acquired {
			winners++
			first = claim.lease
		}
	}
	if winners != 1 {
		t.Fatalf("concurrent runtime inventory event claims = %d, want 1", winners)
	}
	eventCursor := now.Add(250 * time.Millisecond)
	nextPollAt := now.Add(2 * time.Second)
	if err := left.FinishEvents(
		ctx,
		first,
		now.Add(time.Second),
		eventCursor,
		nextPollAt,
		true,
	); err != nil {
		t.Fatalf("finish runtime inventory event schedule: %v", err)
	}
	second, acquired, err := right.TryAcquireEvents(
		ctx,
		target,
		"inventory-event-server-next",
		nextPollAt,
		nextPollAt.Add(time.Minute),
	)
	if err != nil || !acquired || !second.CursorAt.Equal(eventCursor) ||
		second.Token <= first.Token {
		t.Fatalf("reclaimed runtime inventory event lease = %+v, %v, %v", second, acquired, err)
	}
	if err := right.FinishEvents(
		ctx,
		first,
		nextPollAt,
		eventCursor,
		nextPollAt.Add(time.Second),
		true,
	); !errors.Is(err, runtimeinventorybiz.ErrLeaseLost) {
		t.Fatalf("stale runtime inventory event lease finish error = %v", err)
	}
	retryAt := nextPollAt.Add(2 * time.Second)
	if err := right.FinishEvents(
		ctx,
		second,
		nextPollAt.Add(time.Second),
		eventCursor.Add(time.Minute),
		retryAt,
		false,
	); err != nil {
		t.Fatalf("finish failed runtime inventory event poll: %v", err)
	}
	third, acquired, err := left.TryAcquireEvents(
		ctx,
		target,
		"inventory-event-server-retry",
		retryAt,
		retryAt.Add(time.Minute),
	)
	if err != nil || !acquired || !third.CursorAt.Equal(eventCursor) {
		t.Fatalf("failed event poll advanced cursor: %+v, %v, %v", third, acquired, err)
	}
	if err := left.FinishEvents(
		ctx,
		third,
		retryAt.Add(time.Second),
		eventCursor,
		retryAt.Add(2*time.Second),
		true,
	); err != nil {
		t.Fatalf("release runtime inventory event retry lease: %v", err)
	}
}

type integrationInventoryCollector struct {
	mu    sync.Mutex
	calls int
}

func (c *integrationInventoryCollector) Collect(
	context.Context,
	runtimeinventorybiz.Target,
) error {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	return nil
}

func (c *integrationInventoryCollector) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func verifyConcurrentInventoryRunners(
	t *testing.T,
	ctx context.Context,
	database *drivermongo.Database,
	repository *runtimeinventorydata.MongoScheduleRepository,
) {
	t.Helper()
	now := time.Now().UTC()
	collector := &integrationInventoryCollector{}
	runners := make([]*runtimeinventoryworker.Runner, 2)
	for index, workerID := range []string{"inventory-runner-a", "inventory-runner-b"} {
		runner, err := runtimeinventoryworker.NewRunner(
			repository,
			collector,
			workerID,
			time.Minute,
			5*time.Minute,
			30*time.Second,
			10,
			func() time.Time { return now },
		)
		if err != nil {
			t.Fatalf("create concurrent inventory runner: %v", err)
		}
		runners[index] = runner
	}
	start := make(chan struct{})
	results := make(chan error, len(runners))
	for _, runner := range runners {
		go func(runner *runtimeinventoryworker.Runner) {
			<-start
			results <- runner.RunOnce(ctx)
		}(runner)
	}
	close(start)
	for range runners {
		if err := <-results; err != nil {
			t.Fatalf("run concurrent inventory worker: %v", err)
		}
	}
	if collector.count() != 1 {
		t.Fatalf("concurrent inventory runner collections = %d, want 1", collector.count())
	}
	if _, err := database.Collection("runtime_inventory_schedule").DeleteOne(
		ctx,
		bson.D{{Key: "_id", Value: "inventory-schedule-target"}},
	); err != nil {
		t.Fatalf("reset runtime inventory runner schedule: %v", err)
	}
}

func containsInventoryTarget(
	targets []runtimeinventorybiz.Target,
	targetID string,
) bool {
	for _, target := range targets {
		if target.RuntimeTargetID == targetID {
			return true
		}
	}
	return false
}

func assertRuntimeInventoryViewIndexes(
	t *testing.T,
	ctx context.Context,
	database *drivermongo.Database,
) {
	t.Helper()
	type indexDocument struct {
		Name string `bson:"name"`
		Key  bson.D `bson:"key"`
	}
	cursor, err := database.Collection("runtime_inventory_current").Indexes().List(ctx)
	if err != nil {
		t.Fatalf("list runtime inventory indexes: %v", err)
	}
	defer cursor.Close(ctx)
	var documents []indexDocument
	if err := cursor.All(ctx, &documents); err != nil {
		t.Fatalf("decode runtime inventory indexes: %v", err)
	}
	expected := map[string][]string{
		"idx_runtime_inventory_project_view": {
			"organization_id", "project_id", "managed", "runtime_target_id",
			"kind", "name", "runtime_id", "presence",
		},
		"idx_runtime_inventory_host_view": {
			"organization_id", "managed_host_id", "runtime_target_id", "kind",
			"name", "runtime_id", "presence",
		},
	}
	for _, document := range documents {
		want, relevant := expected[document.Name]
		if !relevant {
			continue
		}
		if len(document.Key) != len(want) {
			t.Fatalf("runtime inventory index %s keys = %v, want %v", document.Name, document.Key, want)
		}
		for position, element := range document.Key {
			if element.Key != want[position] {
				t.Fatalf("runtime inventory index %s keys = %v, want %v", document.Name, document.Key, want)
			}
		}
		delete(expected, document.Name)
	}
	if len(expected) != 0 {
		t.Fatalf("missing runtime inventory view indexes: %v", expected)
	}
}

func assertBuildLogIndexes(
	t *testing.T,
	ctx context.Context,
	database *drivermongo.Database,
) {
	t.Helper()
	type indexDocument struct {
		Name               string `bson:"name"`
		ExpireAfterSeconds *int64 `bson:"expireAfterSeconds,omitempty"`
	}
	for collection, expected := range map[string]map[string]bool{
		"build_log_streams": {
			"idx_build_log_stream_project": false,
			"ttl_build_log_stream":         true,
		},
		"build_log_chunks": {
			"uniq_build_log_sequence": false,
			"idx_build_log_read":      false,
			"ttl_build_log_chunk":     true,
		},
	} {
		cursor, err := database.Collection(collection).Indexes().List(ctx)
		if err != nil {
			t.Fatalf("list %s indexes: %v", collection, err)
		}
		var documents []indexDocument
		if err := cursor.All(ctx, &documents); err != nil {
			_ = cursor.Close(ctx)
			t.Fatalf("decode %s indexes: %v", collection, err)
		}
		_ = cursor.Close(ctx)
		for _, document := range documents {
			wantTTL, found := expected[document.Name]
			if !found {
				continue
			}
			if wantTTL && (document.ExpireAfterSeconds == nil || *document.ExpireAfterSeconds != 0) {
				t.Fatalf("%s index %s TTL = %v, want 0", collection, document.Name, document.ExpireAfterSeconds)
			}
			delete(expected, document.Name)
		}
		if len(expected) != 0 {
			t.Fatalf("missing %s indexes: %v", collection, expected)
		}
	}
}

func assertBuildRetirementIndex(
	t *testing.T,
	ctx context.Context,
	database *drivermongo.Database,
) {
	t.Helper()
	type indexDocument struct {
		Name string `bson:"name"`
		Key  bson.D `bson:"key"`
	}
	for _, expectation := range []struct {
		collection string
		name       string
		statusKey  string
	}{
		{collection: "builds", name: "idx_build_application_retirement", statusKey: "status"},
		{collection: "artifacts", name: "idx_artifact_application_release_retirement", statusKey: "release_status"},
	} {
		cursor, err := database.Collection(expectation.collection).Indexes().List(ctx)
		if err != nil {
			t.Fatalf("list %s indexes: %v", expectation.collection, err)
		}
		var documents []indexDocument
		if err := cursor.All(ctx, &documents); err != nil {
			_ = cursor.Close(ctx)
			t.Fatalf("decode %s indexes: %v", expectation.collection, err)
		}
		_ = cursor.Close(ctx)
		want := []string{
			"organization_id", "project_id", "application_id",
			expectation.statusKey, "created_at", "_id",
		}
		found := false
		for _, document := range documents {
			if document.Name != expectation.name {
				continue
			}
			found = true
			if len(document.Key) != len(want) {
				t.Fatalf("%s keys = %v", expectation.name, document.Key)
			}
			for index, element := range document.Key {
				if element.Key != want[index] {
					t.Fatalf("%s keys = %v, want %v", expectation.name, document.Key, want)
				}
			}
		}
		if !found {
			t.Fatalf("missing %s", expectation.name)
		}
	}
}

func verifyBuildRetirementQueryIntegration(
	t *testing.T,
	ctx context.Context,
	database *drivermongo.Database,
) {
	t.Helper()
	repository := builddata.NewMongoRepository(database)
	now := time.Now().UTC()
	configuration, err := buildbiz.NewBuildConfiguration(
		"retirement-configuration", "retirement-project", "retirement-application",
		"Retirement Build", "retirement-source", "Dockerfile", ".",
		[]string{"refs/heads/main"}, "retirement-registry",
		"registry.example.com/team/retirement", buildbiz.BuildPlatformLinuxAMD64,
		buildbiz.BuildResources{}, 60, 1, false, "retirement-owner", now,
	)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := buildbiz.NewSourceRevision(
		"retirement-source", "refs/heads/main", strings.Repeat("a", 40),
	)
	if err != nil {
		t.Fatal(err)
	}
	makeBuild := func(id, organizationID, applicationID string, createdAt time.Time) buildbiz.Build {
		config := configuration
		config.ApplicationID = applicationID
		item, buildErr := buildbiz.NewBuild(
			id, organizationID, "retirement-project", applicationID, config, revision,
			buildbiz.BuildTriggerSourceManual, "", id+"-request", "retirement-owner", createdAt,
		)
		if buildErr != nil {
			t.Fatal(buildErr)
		}
		return item
	}
	queued := makeBuild("retirement-build-queued", "retirement-organization", "retirement-application", now)
	canceling := makeBuild("retirement-build-canceling", "retirement-organization", "retirement-application", now.Add(time.Second))
	if err := canceling.Cancel(now.Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	otherApplication := makeBuild("retirement-build-other-app", "retirement-organization", "retirement-other-app", now)
	otherOrganization := makeBuild("retirement-build-other-org", "retirement-other-org", "retirement-application", now)
	for _, item := range []buildbiz.Build{queued, canceling, otherApplication, otherOrganization} {
		if _, err := repository.CreateBuild(ctx, item); err != nil {
			t.Fatalf("seed Build retirement query: %v", err)
		}
	}
	defer func() {
		_, _ = database.Collection("builds").DeleteMany(
			context.Background(), bson.D{{Key: "project_id", Value: "retirement-project"}},
		)
		_, _ = database.Collection("artifacts").DeleteMany(
			context.Background(), bson.D{{Key: "project_id", Value: "retirement-project"}},
		)
	}()
	limited, err := repository.ListActiveBuildsForApplication(
		ctx, "retirement-organization", "retirement-project", "retirement-application", 1,
	)
	if err != nil || len(limited) != 1 || limited[0].ID != queued.ID {
		t.Fatalf("limited active Builds = %+v/%v", limited, err)
	}
	items, err := repository.ListActiveBuildsForApplication(
		ctx, "retirement-organization", "retirement-project", "retirement-application", 10,
	)
	if err != nil || len(items) != 2 || items[0].ID != queued.ID || items[1].ID != canceling.ID {
		t.Fatalf("active Application Builds = %+v/%v", items, err)
	}
	artifactBuild := makeBuild(
		"retirement-artifact-build", "retirement-organization", "retirement-application", now,
	)
	artifactBuild.Status = buildbiz.BuildStatusPushing
	artifactBuild.Configuration.AutoCreateRelease = true
	artifactBuild.ImageDigest = "registry.example.com/team/retirement@sha256:" + strings.Repeat("b", 64)
	pendingArtifact, err := buildbiz.NewArtifact("retirement-artifact-pending", artifactBuild, now)
	if err != nil {
		t.Fatal(err)
	}
	secondPending := pendingArtifact
	secondPending.ID, secondPending.BuildID, secondPending.CreatedAt =
		"retirement-artifact-second", "retirement-artifact-build-second", now.Add(time.Second)
	otherArtifact := pendingArtifact
	otherArtifact.ID, otherArtifact.BuildID, otherArtifact.ApplicationID =
		"retirement-artifact-other", "retirement-artifact-build-other", "retirement-other-app"
	availableArtifact := pendingArtifact
	availableArtifact.ID, availableArtifact.BuildID, availableArtifact.ReleaseStatus =
		"retirement-artifact-available", "retirement-artifact-build-available", buildbiz.ArtifactReleaseAvailable
	for _, item := range []buildbiz.Artifact{pendingArtifact, secondPending, otherArtifact, availableArtifact} {
		if _, err := repository.CreateArtifact(ctx, item); err != nil {
			t.Fatalf("seed Artifact retirement query: %v", err)
		}
	}
	limitedArtifacts, err := repository.ListPendingReleaseArtifactsForApplication(
		ctx, "retirement-organization", "retirement-project", "retirement-application", 1,
	)
	if err != nil || len(limitedArtifacts) != 1 || limitedArtifacts[0].ID != pendingArtifact.ID {
		t.Fatalf("limited pending Artifact releases = %+v/%v", limitedArtifacts, err)
	}
	pendingArtifacts, err := repository.ListPendingReleaseArtifactsForApplication(
		ctx, "retirement-organization", "retirement-project", "retirement-application", 10,
	)
	if err != nil || len(pendingArtifacts) != 2 || pendingArtifacts[0].ID != pendingArtifact.ID ||
		pendingArtifacts[1].ID != secondPending.ID {
		t.Fatalf("pending Application Artifact releases = %+v/%v", pendingArtifacts, err)
	}
}

func assertUserInvitationIndexes(t *testing.T, ctx context.Context, database *drivermongo.Database) {
	t.Helper()
	type indexDocument struct {
		Name               string `bson:"name"`
		Unique             bool   `bson:"unique,omitempty"`
		ExpireAfterSeconds *int64 `bson:"expireAfterSeconds,omitempty"`
	}
	cursor, err := database.Collection("user_invitations").Indexes().List(ctx)
	if err != nil {
		t.Fatalf("list user invitation indexes: %v", err)
	}
	defer cursor.Close(ctx)
	var documents []indexDocument
	if err := cursor.All(ctx, &documents); err != nil {
		t.Fatalf("decode user invitation indexes: %v", err)
	}
	expected := map[string]string{
		"uniq_user_invitation_token_hash":          "unique",
		"idx_user_invitation_organization_created": "ordinary",
		"ttl_active_user_invitation":               "ttl",
	}
	for _, document := range documents {
		kind, ok := expected[document.Name]
		if !ok {
			continue
		}
		if kind == "unique" && !document.Unique {
			t.Fatalf("user invitation token index is not unique")
		}
		if kind == "ttl" && (document.ExpireAfterSeconds == nil || *document.ExpireAfterSeconds != 0) {
			t.Fatalf("user invitation TTL index = %v, want 0", document.ExpireAfterSeconds)
		}
		delete(expected, document.Name)
	}
	if len(expected) != 0 {
		t.Fatalf("missing user invitation indexes: %v", expected)
	}
}

func assertProjectMemberIndexes(t *testing.T, ctx context.Context, database *drivermongo.Database) {
	t.Helper()
	type indexDocument struct {
		Name   string `bson:"name"`
		Unique bool   `bson:"unique,omitempty"`
	}
	cursor, err := database.Collection("project_members").Indexes().List(ctx)
	if err != nil {
		t.Fatalf("list project member indexes: %v", err)
	}
	defer cursor.Close(ctx)
	var documents []indexDocument
	if err := cursor.All(ctx, &documents); err != nil {
		t.Fatalf("decode project member indexes: %v", err)
	}
	expected := map[string]bool{
		"uniq_project_member_user":         true,
		"uniq_project_member_email":        true,
		"idx_project_member_user_projects": false,
	}
	for _, document := range documents {
		wantUnique, ok := expected[document.Name]
		if !ok {
			continue
		}
		if document.Unique != wantUnique {
			t.Fatalf("project member index %s unique = %v, want %v", document.Name, document.Unique, wantUnique)
		}
		delete(expected, document.Name)
	}
	if len(expected) != 0 {
		t.Fatalf("missing project member indexes: %v", expected)
	}
}

func assertIngressRateLimitIndex(t *testing.T, ctx context.Context, database *drivermongo.Database) {
	t.Helper()
	type indexDocument struct {
		Name               string `bson:"name"`
		ExpireAfterSeconds *int64 `bson:"expireAfterSeconds,omitempty"`
	}
	cursor, err := database.Collection("ingress_rate_limits").Indexes().List(ctx)
	if err != nil {
		t.Fatalf("list ingress rate limit indexes: %v", err)
	}
	defer cursor.Close(ctx)
	var documents []indexDocument
	if err := cursor.All(ctx, &documents); err != nil {
		t.Fatalf("decode ingress rate limit indexes: %v", err)
	}
	for _, document := range documents {
		if document.Name == "ttl_ingress_rate_limit" {
			if document.ExpireAfterSeconds == nil || *document.ExpireAfterSeconds != 0 {
				t.Fatalf("ingress rate limit TTL = %v, want 0", document.ExpireAfterSeconds)
			}
			return
		}
	}
	t.Fatal("ingress rate limit TTL index is missing")
}

func assertTerminalIndexes(t *testing.T, ctx context.Context, database *drivermongo.Database) {
	t.Helper()
	type indexDocument struct {
		Name   string `bson:"name"`
		Unique bool   `bson:"unique,omitempty"`
	}
	for collection, expected := range map[string]map[string]bool{
		"terminal_access_policies": {
			"uniq_terminal_project_policy":      true,
			"uniq_terminal_organization_policy": true,
		},
		"terminal_sessions": {
			"uniq_terminal_ticket_hash":                  true,
			"uniq_active_terminal_user_slot":             true,
			"uniq_active_terminal_target_slot":           true,
			"idx_terminal_project_created":               false,
			"idx_terminal_actor_created":                 false,
			"idx_terminal_expiry_reconciliation":         false,
			"idx_terminal_authentication_session_active": false,
			"idx_terminal_runtime_target_active":         false,
			"idx_terminal_application_active":            false,
			"idx_terminal_environment_active":            false,
		},
	} {
		cursor, err := database.Collection(collection).Indexes().List(ctx)
		if err != nil {
			t.Fatalf("list %s indexes: %v", collection, err)
		}
		var documents []indexDocument
		if err := cursor.All(ctx, &documents); err != nil {
			_ = cursor.Close(ctx)
			t.Fatalf("decode %s indexes: %v", collection, err)
		}
		_ = cursor.Close(ctx)
		for _, document := range documents {
			wantUnique, ok := expected[document.Name]
			if !ok {
				continue
			}
			if document.Unique != wantUnique {
				t.Fatalf("%s index %s unique = %v, want %v", collection, document.Name, document.Unique, wantUnique)
			}
			delete(expected, document.Name)
		}
		if len(expected) != 0 {
			t.Fatalf("missing %s indexes: %v", collection, expected)
		}
	}
}

func verifyTerminalPersistenceIntegration(t *testing.T, ctx context.Context, database *drivermongo.Database) {
	t.Helper()
	if _, err := database.Collection("terminal_access_policies").DeleteMany(ctx, bson.D{}); err != nil {
		t.Fatalf("clear terminal policy fixtures: %v", err)
	}
	if _, err := database.Collection("terminal_sessions").DeleteMany(ctx, bson.D{}); err != nil {
		t.Fatalf("clear terminal session fixtures: %v", err)
	}
	if _, err := database.Collection("product_applications").InsertOne(ctx, bson.D{
		{Key: "_id", Value: "terminal-application"},
		{Key: "project_id", Value: "terminal-project"},
		{Key: "name", Value: "Terminal Application"},
		{Key: "name_normalized", Value: "terminal application"},
		{Key: "status", Value: "active"},
	}); err != nil {
		t.Fatalf("seed terminal Application: %v", err)
	}
	if _, err := database.Collection("environments").InsertOne(ctx, bson.D{
		{Key: "_id", Value: "terminal-environment"},
		{Key: "project_id", Value: "terminal-project"},
		{Key: "name", Value: "Terminal Environment"},
		{Key: "name_normalized", Value: "terminal environment"},
		{Key: "stage", Value: "development"},
		{Key: "status", Value: "active"},
	}); err != nil {
		t.Fatalf("seed terminal Environment: %v", err)
	}
	repository := terminaldata.NewMongoRepository(database)
	now := time.Now().UTC().Truncate(time.Millisecond)
	policy, err := terminalbiz.NewProjectPolicy(
		"terminal-policy-1", "terminal-organization", "terminal-project", "terminal-owner",
		terminalbiz.PolicyInput{
			Enabled: true, AllowedRoles: []security.Role{security.RoleOwner, security.RoleMaintainer},
			EnvironmentStages: []string{"development", "staging"},
			IdleTimeout:       5 * time.Minute, MaximumDuration: time.Hour,
			MaximumPerUser: 1, MaximumPerTarget: 1,
			RevocationGracePeriod: 30 * time.Second,
		}, now,
	)
	if err != nil {
		t.Fatalf("new terminal policy: %v", err)
	}
	if _, err := repository.SavePolicy(ctx, policy, 0); err != nil {
		t.Fatalf("save terminal policy: %v", err)
	}
	loadedPolicy, err := repository.GetProjectPolicy(ctx, policy.OrganizationID, policy.ProjectID)
	if err != nil || loadedPolicy.Version != 1 || loadedPolicy.MaximumDuration != time.Hour {
		t.Fatalf("loaded terminal policy = %+v, error = %v", loadedPolicy, err)
	}
	if _, err := repository.SavePolicy(ctx, policy, 0); !errors.Is(err, terminalbiz.ErrPolicyConflict) {
		t.Fatalf("duplicate terminal policy error = %v", err)
	}
	target := terminalbiz.Target{
		Kind: terminalbiz.KindContainer, OrganizationID: policy.OrganizationID, ProjectID: policy.ProjectID,
		ApplicationID: "terminal-application", EnvironmentID: "terminal-environment",
		ManagedHostID: "terminal-host", RuntimeTargetID: "terminal-target",
		DeploymentID: "terminal-deployment", RunningInstanceID: "terminal-deployment:1",
		InstanceGeneration: 1, EnvironmentStage: "development",
		ConnectionMode: runtimeaccess.ModeDirectDocker,
	}
	first, err := terminalbiz.NewTerminalSession(
		"terminal-session-1", "terminal-owner", "terminal-login-session", strings.Repeat("a", 64),
		"192.0.2.10", "OwnDock-Integration/1.0", "terminal-request-1", target, policy, now,
	)
	if err != nil {
		t.Fatalf("new terminal session: %v", err)
	}
	first.UserConcurrencySlot, first.TargetConcurrencySlot = 1, 1
	if _, err := repository.CreateContainerSession(ctx, first); err != nil {
		t.Fatalf("create terminal session: %v", err)
	}
	second := first
	second.ID, second.ActorID, second.TicketHash, second.RequestID =
		"terminal-session-2", "terminal-owner-2", strings.Repeat("b", 64), "terminal-request-2"
	if _, err := repository.CreateSession(ctx, second); !errors.Is(err, terminalbiz.ErrSessionSlotConflict) {
		t.Fatalf("occupied target slot error = %v", err)
	}
	connected, err := repository.ConsumeTicket(
		ctx, first.OrganizationID, first.ID, first.TicketHash, now.Add(time.Second),
	)
	if err != nil {
		t.Fatalf("consume terminal ticket: %v", err)
	}
	if connected.Status != terminalbiz.StatusOpen || connected.TicketHash != "" {
		t.Fatalf("connected terminal session = %+v", connected)
	}
	if _, err := repository.ConsumeTicket(
		ctx, first.OrganizationID, first.ID, first.TicketHash, now.Add(2*time.Second),
	); !errors.Is(err, terminalbiz.ErrInvalidTicket) {
		t.Fatalf("replayed terminal ticket error = %v", err)
	}
	closed, err := connected.Close(terminalbiz.CloseReasonUserRequested, "", now.Add(3*time.Second))
	if err != nil {
		t.Fatalf("close terminal session: %v", err)
	}
	if _, err := repository.SaveSession(ctx, closed, connected.Version); err != nil {
		t.Fatalf("save terminal close: %v", err)
	}
	if _, err := repository.CreateSession(ctx, second); err != nil {
		t.Fatalf("reuse released terminal slot: %v", err)
	}
	activeForTarget, err := repository.ListActiveSessionsForRuntimeTarget(
		ctx, second.OrganizationID, second.ProjectID, second.RuntimeTargetID, 10,
	)
	if err != nil || len(activeForTarget) != 1 || activeForTarget[0].ID != second.ID {
		t.Fatalf("active terminal sessions for target = %+v/%v", activeForTarget, err)
	}
	activeForApplication, err := repository.ListActiveSessionsForProductResource(
		ctx, second.OrganizationID, second.ProjectID, second.ApplicationID, "", 10,
	)
	if err != nil || len(activeForApplication) != 1 || activeForApplication[0].ID != second.ID {
		t.Fatalf("active terminal sessions for Application = %+v/%v", activeForApplication, err)
	}
	activeForEnvironment, err := repository.ListActiveSessionsForProductResource(
		ctx, second.OrganizationID, second.ProjectID, "", second.EnvironmentID, 10,
	)
	if err != nil || len(activeForEnvironment) != 1 || activeForEnvironment[0].ID != second.ID {
		t.Fatalf("active terminal sessions for Environment = %+v/%v", activeForEnvironment, err)
	}
	if _, err := database.Collection("product_applications").UpdateOne(
		ctx,
		bson.D{{Key: "_id", Value: first.ApplicationID}},
		bson.D{{Key: "$set", Value: bson.D{{Key: "status", Value: "retiring"}}}},
	); err != nil {
		t.Fatalf("retire terminal Application fixture: %v", err)
	}
	blocked := first
	blocked.ID, blocked.TicketHash = "terminal-session-blocked", strings.Repeat("c", 64)
	blocked.UserConcurrencySlot, blocked.TargetConcurrencySlot = 2, 2
	if _, err := repository.CreateContainerSession(ctx, blocked); !errors.Is(err, terminalbiz.ErrTargetUnavailable) {
		t.Fatalf("retiring Application terminal admission error = %v", err)
	}
	if _, err := database.Collection("product_applications").DeleteOne(
		ctx, bson.D{{Key: "_id", Value: first.ApplicationID}},
	); err != nil {
		t.Fatalf("remove terminal Application fixture: %v", err)
	}
	if _, err := database.Collection("environments").DeleteOne(
		ctx, bson.D{{Key: "_id", Value: first.EnvironmentID}},
	); err != nil {
		t.Fatalf("remove terminal Environment fixture: %v", err)
	}
	stored, err := repository.GetSession(ctx, first.OrganizationID, first.ID)
	if err != nil || stored.Active || stored.TicketHash != "" || stored.CloseReason != terminalbiz.CloseReasonUserRequested {
		t.Fatalf("stored closed terminal session = %+v, error = %v", stored, err)
	}
}

func verifyIngressRateLimitIntegration(t *testing.T, ctx context.Context, database *drivermongo.Database) {
	t.Helper()
	if _, err := database.Collection("ingress_rate_limits").DeleteMany(ctx, bson.D{}); err != nil {
		t.Fatalf("clear ingress rate limit fixtures: %v", err)
	}
	guard := platformingress.NewMongoGuard(database)
	const requests, limit = 32, 10
	results := make(chan bool, requests)
	errorsFound := make(chan error, requests)
	var wait sync.WaitGroup
	now := time.Now().UTC()
	for range requests {
		wait.Add(1)
		go func() {
			defer wait.Done()
			allowed, _, reserveErr := guard.Reserve(
				ctx, strings.Repeat("c", 64), now, limit, time.Minute,
			)
			results <- allowed
			errorsFound <- reserveErr
		}()
	}
	wait.Wait()
	close(results)
	close(errorsFound)
	for reserveErr := range errorsFound {
		if reserveErr != nil {
			t.Fatalf("reserve concurrent ingress request: %v", reserveErr)
		}
	}
	allowed := 0
	for accepted := range results {
		if accepted {
			allowed++
		}
	}
	if allowed != limit {
		t.Fatalf("concurrent ingress admissions = %d, want %d", allowed, limit)
	}
	var stored struct {
		ID       string `bson:"_id"`
		Requests int    `bson:"requests"`
	}
	if err := database.Collection("ingress_rate_limits").FindOne(
		ctx, bson.D{{Key: "_id", Value: strings.Repeat("c", 64)}},
	).Decode(&stored); err != nil {
		t.Fatalf("read ingress admission state: %v", err)
	}
	if len(stored.ID) != 64 || stored.Requests != limit {
		t.Fatalf("stored ingress admission state = %+v", stored)
	}
}

func assertAutomaticDeploymentIndex(
	t *testing.T,
	ctx context.Context,
	database *drivermongo.Database,
) {
	t.Helper()
	type indexDocument struct {
		Name string `bson:"name"`
		Key  bson.D `bson:"key"`
	}
	cursor, err := database.Collection("deployments").Indexes().List(ctx)
	if err != nil {
		t.Fatalf("list Deployment indexes: %v", err)
	}
	defer cursor.Close(ctx)
	var documents []indexDocument
	if err := cursor.All(ctx, &documents); err != nil {
		t.Fatalf("decode Deployment indexes: %v", err)
	}
	for _, document := range documents {
		if document.Name != "idx_automatic_deployment_artifact" {
			continue
		}
		want := []string{"project_id", "source_artifact_id", "environment_id", "runtime_target_id"}
		if len(document.Key) != len(want) {
			t.Fatalf("automatic Deployment index keys = %v", document.Key)
		}
		for index, key := range document.Key {
			if key.Key != want[index] {
				t.Fatalf("automatic Deployment index keys = %v", document.Key)
			}
		}
		return
	}
	t.Fatal("automatic Deployment index is missing")
}

func assertRuntimeInventoryExpiry(
	t *testing.T,
	ctx context.Context,
	collection *drivermongo.Collection,
	filter bson.D,
	expected bool,
) {
	t.Helper()
	var document bson.M
	if err := collection.FindOne(ctx, filter).Decode(&document); err != nil {
		t.Fatalf("find runtime inventory TTL document: %v", err)
	}
	_, present := document["expires_at"]
	if present != expected {
		t.Fatalf(
			"runtime inventory %s expires_at present = %v, want %v",
			collection.Name(),
			present,
			expected,
		)
	}
}
