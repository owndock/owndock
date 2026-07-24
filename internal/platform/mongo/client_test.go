package mongo

import (
	"context"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/platform/config"
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

	closeContext, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer closeCancel()
	if err := client.Close(closeContext); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := client.Close(closeContext); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
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
