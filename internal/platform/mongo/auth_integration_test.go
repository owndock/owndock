package mongo

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/platform/config"
	"github.com/testcontainers/testcontainers-go"
	testmongo "github.com/testcontainers/testcontainers-go/modules/mongodb"
	"go.mongodb.org/mongo-driver/v2/bson"
	drivermongo "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

func TestMongoAuthenticatedReplicaSetIntegration(t *testing.T) {
	if os.Getenv("OWNDOCK_RUN_MONGO_INTEGRATION") != "1" {
		t.Skip("set OWNDOCK_RUN_MONGO_INTEGRATION=1 to run the MongoDB integration test")
	}

	const (
		rootUsername = "owndock-integration-root"
		rootPassword = "root-password-integration-sentinel"
		appUsername  = "owndock-integration-app"
		appPassword  = "app-password-integration-sentinel"
		databaseName = "owndock_auth_integration"
	)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	container, err := testmongo.Run(
		ctx,
		integrationImage,
		testmongo.WithReplicaSet("rs0"),
		testmongo.WithUsername(rootUsername),
		testmongo.WithPassword(rootPassword),
	)
	if err != nil {
		t.Fatalf("start authenticated MongoDB container: %v", err)
	}
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if err := testcontainers.TerminateContainer(container, testcontainers.StopContext(cleanupContext)); err != nil {
			t.Errorf("terminate authenticated MongoDB container: %v", err)
		}
	})

	rootURI, err := container.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("authenticated MongoDB connection string: %v", err)
	}
	rootURI = directConnectionURI(t, rootURI)
	rootClient, err := drivermongo.Connect(options.Client().ApplyURI(rootURI))
	if err != nil {
		t.Fatalf("create root MongoDB client: %v", err)
	}
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if err := rootClient.Disconnect(cleanupContext); err != nil {
			t.Errorf("disconnect root MongoDB client: %v", err)
		}
	})
	if err := rootClient.Ping(ctx, readpref.Primary()); err != nil {
		t.Fatalf("authenticate root MongoDB client: %v", err)
	}
	if err := rootClient.Database(databaseName).RunCommand(ctx, bson.D{
		{Key: "createUser", Value: appUsername},
		{Key: "pwd", Value: appPassword},
		{Key: "roles", Value: bson.A{bson.D{
			{Key: "role", Value: "readWrite"},
			{Key: "db", Value: databaseName},
		}}},
	}).Err(); err != nil {
		t.Fatalf("create least-privilege MongoDB application user: %v", err)
	}

	appURI := authenticatedMongoURI(t, rootURI, appUsername, appPassword, databaseName)
	t.Setenv("OWNDOCK_TEST_AUTHENTICATED_MONGODB_URI", appURI)
	client, err := Open(ctx, authenticatedMongoConfig("OWNDOCK_TEST_AUTHENTICATED_MONGODB_URI", databaseName))
	if err != nil {
		t.Fatalf("Open() authenticated application client: %v", err)
	}
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if err := client.Close(cleanupContext); err != nil {
			t.Errorf("close authenticated application client: %v", err)
		}
	})

	if err := client.WithinTransaction(ctx, func(transactionContext context.Context) error {
		_, err := client.Database().Collection("authentication_probe").InsertOne(
			transactionContext,
			bson.D{{Key: "status", Value: "authorized"}},
		)
		return err
	}); err != nil {
		t.Fatalf("least-privilege application transaction: %v", err)
	}
	count, err := client.Database().Collection("authentication_probe").CountDocuments(ctx, bson.D{})
	if err != nil || count != 1 {
		t.Fatalf("authenticated application result count = %d, error = %v", count, err)
	}

	_, err = client.Database().Client().Database("admin").Collection("forbidden_probe").InsertOne(
		ctx,
		bson.D{{Key: "status", Value: "must-not-write"}},
	)
	if err == nil {
		t.Fatal("least-privilege application user wrote to the admin database")
	}
	assertMongoErrorOmitsCredentials(t, err, appURI, appUsername, appPassword)

	const wrongPassword = "wrong-password-integration-sentinel"
	wrongURI := authenticatedMongoURI(t, rootURI, appUsername, wrongPassword, databaseName)
	t.Setenv("OWNDOCK_TEST_REJECTED_MONGODB_URI", wrongURI)
	_, err = Open(ctx, authenticatedMongoConfig("OWNDOCK_TEST_REJECTED_MONGODB_URI", databaseName))
	if err == nil {
		t.Fatal("Open() accepted an invalid MongoDB application password")
	}
	assertMongoErrorOmitsCredentials(t, err, wrongURI, appUsername, wrongPassword)
}

func authenticatedMongoConfig(environment, database string) config.Mongo {
	return config.Mongo{
		Enabled:          true,
		URIEnv:           environment,
		Database:         database,
		ConnectTimeout:   "5s",
		OperationTimeout: "5s",
		MaxIdleTime:      "1m",
		MaxPoolSize:      5,
	}
}

func authenticatedMongoURI(
	t *testing.T,
	value, username, password, authenticationDatabase string,
) string {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatalf("parse authenticated MongoDB connection string: %v", err)
	}
	parsed.User = url.UserPassword(username, password)
	query := parsed.Query()
	query.Set("authSource", authenticationDatabase)
	parsed.RawQuery = query.Encode()
	return strings.TrimSpace(parsed.String())
}
