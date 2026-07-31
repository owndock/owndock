package mongo

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

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
	platformaudit "github.com/owndock/owndock/internal/platform/audit"
	"github.com/owndock/owndock/internal/platform/config"
	"github.com/owndock/owndock/internal/platform/id"
	"github.com/owndock/owndock/internal/platform/migration"
	"github.com/owndock/owndock/internal/server"
	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/runtimespec"
	"github.com/owndock/owndock/internal/shared/security"
	"github.com/testcontainers/testcontainers-go"
	testmongo "github.com/testcontainers/testcontainers-go/modules/mongodb"
	"go.mongodb.org/mongo-driver/v2/bson"
	drivermongo "go.mongodb.org/mongo-driver/v2/mongo"
)

const integrationImage = "mongo:8.3.7-noble@sha256:8444a416f2fc991f15064df9f6ea31ee02877607a70fd352ea998e6dbb5714b3"

type readyRuntimeTargetProber struct{}

func (readyRuntimeTargetProber) ProbeRuntimeTarget(
	context.Context,
	controlplanebiz.RuntimeTarget,
) (controlplanebiz.RuntimeTargetStatus, error) {
	return controlplanebiz.RuntimeTargetStatusReady, nil
}

func TestOpenRejectsDisabledConfig(t *testing.T) {
	if _, err := Open(context.Background(), config.Mongo{}); err == nil {
		t.Fatal("Open() error = nil, want an error")
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
	if _, err := client.Database().Collection("releases").InsertOne(ctx, bson.D{
		{Key: "_id", Value: "legacy-release"},
		{Key: "project_id", Value: "legacy-project"},
		{Key: "application_id", Value: "legacy-application"},
		{Key: "image_digest", Value: "registry.example.com/api@sha256:" + strings.Repeat("f", 64)},
	}); err != nil {
		t.Fatalf("seed legacy release: %v", err)
	}
	if _, err := client.Database().Collection("deployments").InsertOne(ctx, bson.D{
		{Key: "_id", Value: "legacy-deployment"},
		{Key: "project_id", Value: "legacy-project"},
		{Key: "idempotency_key", Value: "legacy-key"},
		{Key: "status", Value: "building"},
		{Key: "created_at", Value: time.Now().UTC()},
	}); err != nil {
		t.Fatalf("seed legacy deployment: %v", err)
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
	verifyRuntimeInventoryScheduleIntegration(t, ctx, client.Database())
	var migratedDeployment struct {
		OrganizationID  string `bson:"organization_id"`
		Status          string `bson:"status"`
		CutoverSequence uint64 `bson:"cutover_sequence"`
	}
	if err := client.Database().Collection("deployments").FindOne(
		ctx, bson.D{{Key: "_id", Value: "legacy-deployment"}},
	).Decode(&migratedDeployment); err != nil {
		t.Fatalf("read migrated deployment: %v", err)
	}
	if migratedDeployment.OrganizationID != "legacy-organization" ||
		migratedDeployment.Status != "preparing" ||
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
	).WithSessionPolicy(3)
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
		WithRuntimeTargetProbe(controlPlaneStore, readyRuntimeTargetProber{})
	host, err := managedHostUseCase.Create(
		ctx, principal, "Production Host", runtimeaccess.ModeDirectDocker,
		"", "host-request",
	)
	if err != nil {
		t.Fatalf("create managed host: %v", err)
	}
	agentHost, err := managedHostUseCase.Create(
		ctx, principal, "Private Agent Host", runtimeaccess.ModeAgent,
		"", "agent-host-request",
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
		return managedHostStore.ActivateAgent(
			transactionContext,
			foundEnrollment.ID,
			foundEnrollment.TokenHash,
			enrollmentNow,
			agentIdentity,
		)
	}); err != nil {
		t.Fatalf("activate agent identity: %v", err)
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
	application, err := controlPlaneUseCase.CreateApplication(ctx, principal, project.ID, "API", "application-request")
	if err != nil {
		t.Fatalf("create application: %v", err)
	}
	registryCredential, err := controlPlaneUseCase.CreateRegistryCredential(
		ctx, principal, project.ID, "Private Registry", "registry.example.com",
		"robot", "secret://registry-password", "registry-request",
	)
	if err != nil {
		t.Fatalf("create registry credential: %v", err)
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

	deploymentStore := deploymentdata.NewMongoRepository(client.Database())
	deploymentUseCase := deploymentbiz.NewUseCase(deploymentStore, nil, nil, id.New, time.Now).
		WithFormalReferences(deploymentdata.NewFormalReferenceLookup(controlPlaneStore)).
		WithFormalSecurity(client, auditStore)
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
	replayed, err := deploymentUseCase.CreateFormal(
		ctx, principal, project.ID, release.ID, application.ID, environment.ID, target.ID,
		"integration-deployment", "deployment-replay-request",
	)
	if err != nil || replayed.ID != deployment.ID {
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
	productAPI, err := server.NewProductAPI(identityHTTP, controlPlaneHTTP, identityHTTP.Authenticate)
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

func verifyRuntimeInventoryIntegration(
	t *testing.T,
	ctx context.Context,
	database *drivermongo.Database,
) {
	t.Helper()
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
		current[0].DeploymentID != resource.DeploymentID {
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
		!states[0].AbsentAt.IsZero() {
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
