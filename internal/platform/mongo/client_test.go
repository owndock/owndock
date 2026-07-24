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
	identitybiz "github.com/owndock/owndock/internal/modules/identity/biz"
	identitydata "github.com/owndock/owndock/internal/modules/identity/data"
	identityservice "github.com/owndock/owndock/internal/modules/identity/service"
	platformaudit "github.com/owndock/owndock/internal/platform/audit"
	"github.com/owndock/owndock/internal/platform/config"
	"github.com/owndock/owndock/internal/platform/id"
	"github.com/owndock/owndock/internal/platform/migration"
	"github.com/owndock/owndock/internal/server"
	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/testcontainers/testcontainers-go"
	testmongo "github.com/testcontainers/testcontainers-go/modules/mongodb"
	"go.mongodb.org/mongo-driver/v2/bson"
)

const integrationImage = "mongo:8.3.7-noble@sha256:8444a416f2fc991f15064df9f6ea31ee02877607a70fd352ea998e6dbb5714b3"

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

	runner := migration.NewRunner(client.Database(), "integration-test")
	if err := runner.Run(ctx, migration.Default()); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	if err := runner.Run(ctx, migration.Default()); err != nil {
		t.Fatalf("rerun migrations: %v", err)
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
	controlPlaneUseCase := controlplanebiz.NewUseCaseWithEnvironment(
		controlPlaneStore, controlPlaneStore, controlPlaneStore, controlPlaneStore, controlPlaneStore,
		client, auditStore, auditStore, id.New, time.Now,
	)
	project, err := controlPlaneUseCase.CreateProject(ctx, principal, "Delivery", "project-request")
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	application, err := controlPlaneUseCase.CreateApplication(ctx, principal, project.ID, "API", "application-request")
	if err != nil {
		t.Fatalf("create application: %v", err)
	}
	release, err := controlPlaneUseCase.CreateRelease(
		ctx, principal, project.ID, application.ID,
		"registry.example.com/team/api@sha256:"+strings.Repeat("a", 64),
		"release-request",
	)
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	target, err := controlPlaneUseCase.CreateRuntimeTarget(
		ctx, principal, project.ID, "production",
		"tcp://docker.example.com:2376", "docker.example.com", "secret://docker-production",
		"target-request",
	)
	if err != nil {
		t.Fatalf("create runtime target: %v", err)
	}
	environment, err := controlPlaneUseCase.CreateEnvironment(ctx, principal, project.ID, "Production", "production", "environment-request")
	if err != nil {
		t.Fatalf("create environment: %v", err)
	}
	if release.ApplicationID != application.ID || target.ProjectID != project.ID || environment.ProjectID != project.ID {
		t.Fatalf("release=%+v target=%+v environment=%+v", release, target, environment)
	}
	events, err := controlPlaneUseCase.ListAuditEvents(ctx, principal, "", 100)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) < 7 {
		t.Fatalf("audit event count = %d, want at least 7", len(events))
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
