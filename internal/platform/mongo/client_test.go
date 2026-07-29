package mongo

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
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
	platformaudit "github.com/owndock/owndock/internal/platform/audit"
	"github.com/owndock/owndock/internal/platform/config"
	"github.com/owndock/owndock/internal/platform/id"
	"github.com/owndock/owndock/internal/platform/migration"
	"github.com/owndock/owndock/internal/server"
	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/runtimespec"
	"github.com/testcontainers/testcontainers-go"
	testmongo "github.com/testcontainers/testcontainers-go/modules/mongodb"
	"go.mongodb.org/mongo-driver/v2/bson"
)

const integrationImage = "mongo:8.3.7-noble@sha256:8444a416f2fc991f15064df9f6ea31ee02877607a70fd352ea998e6dbb5714b3"

type readyRuntimeTargetProber struct{}

func (readyRuntimeTargetProber) ProbeRuntimeTarget(
	context.Context,
	controlplanebiz.RuntimeTarget,
) controlplanebiz.RuntimeTargetStatus {
	return controlplanebiz.RuntimeTargetStatusReady
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
	runner := migration.NewRunner(client.Database(), "integration-test")
	if err := runner.Run(ctx, migration.Default()); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	if err := runner.Run(ctx, migration.Default()); err != nil {
		t.Fatalf("rerun migrations: %v", err)
	}
	var migratedDeployment struct {
		OrganizationID string `bson:"organization_id"`
		Status         string `bson:"status"`
	}
	if err := client.Database().Collection("deployments").FindOne(
		ctx, bson.D{{Key: "_id", Value: "legacy-deployment"}},
	).Decode(&migratedDeployment); err != nil {
		t.Fatalf("read migrated deployment: %v", err)
	}
	if migratedDeployment.OrganizationID != "legacy-organization" ||
		migratedDeployment.Status != "preparing" {
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
	identityUseCase := identitybiz.NewUseCase(
		identitydata.NewMongoRepository(client.Database()),
		client,
		auditStore,
		passwords,
		identitydata.SessionTokens{},
		id.New,
		time.Now,
		time.Hour,
	)
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
	login, err := identityUseCase.Login(ctx, "owner@example.com", "integration-password", "login-request")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	loginPrincipal, err := identityUseCase.Authenticate(ctx, login.AccessToken)
	if err != nil {
		t.Fatalf("authenticate login token: %v", err)
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
	authenticatedRequest.Header.Set("Authorization", "Bearer "+bootstrap.AccessToken)
	authenticatedResponse := httptest.NewRecorder()
	productAPI.ServeHTTP(authenticatedResponse, authenticatedRequest)
	if authenticatedResponse.Code != http.StatusOK || !strings.Contains(authenticatedResponse.Body.String(), `"name":"Delivery"`) {
		t.Fatalf("authenticated product API status=%d body=%s", authenticatedResponse.Code, authenticatedResponse.Body.String())
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
