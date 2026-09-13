package mongo

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	runtimeinventorybiz "github.com/owndock/owndock/internal/modules/runtimeinventory/biz"
	runtimeinventorydata "github.com/owndock/owndock/internal/modules/runtimeinventory/data"
	"github.com/testcontainers/testcontainers-go"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.mongodb.org/mongo-driver/v2/bson"
	drivermongo "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

const mongoContainerPort = "27017/tcp"

type mappedMongoDialer struct {
	addresses map[string]string
	dialer    net.Dialer
}

func (d *mappedMongoDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if mapped, ok := d.addresses[address]; ok {
		address = mapped
	}
	return d.dialer.DialContext(ctx, network, address)
}

func TestMongoPrimaryFailoverIntegration(t *testing.T) {
	if os.Getenv("OWNDOCK_RUN_MONGO_INTEGRATION") != "1" {
		t.Skip("set OWNDOCK_RUN_MONGO_INTEGRATION=1 to run the MongoDB integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	network, err := tcnetwork.New(ctx, tcnetwork.WithDriver("bridge"))
	if err != nil {
		t.Fatalf("create MongoDB network: %v", err)
	}
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if err := network.Remove(cleanupContext); err != nil {
			t.Errorf("remove MongoDB network: %v", err)
		}
	})

	aliases := []string{"mongo1", "mongo2", "mongo3"}
	containers := make(map[string]testcontainers.Container, len(aliases))
	dialer := &mappedMongoDialer{
		addresses: make(map[string]string, len(aliases)),
		dialer: net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		},
	}
	for _, alias := range aliases {
		container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image:        integrationImage,
				ExposedPorts: []string{mongoContainerPort},
				Cmd:          []string{"mongod", "--replSet", "rs0", "--bind_ip_all", "--port", "27017"},
				Networks:     []string{network.Name},
				NetworkAliases: map[string][]string{
					network.Name: {alias},
				},
				WaitingFor: wait.ForListeningPort(mongoContainerPort).WithStartupTimeout(45 * time.Second),
			},
			Started: true,
		})
		if err != nil {
			t.Fatalf("start MongoDB member %s: %v", alias, err)
		}
		t.Cleanup(func() {
			cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cleanupCancel()
			if err := container.Terminate(
				cleanupContext,
				testcontainers.StopContext(cleanupContext),
				testcontainers.StopTimeout(time.Second),
			); err != nil {
				t.Errorf("terminate MongoDB member %s: %v", alias, err)
			}
		})
		containers[alias] = container

		host, err := container.Host(ctx)
		if err != nil {
			t.Fatalf("resolve MongoDB member %s host: %v", alias, err)
		}
		port, err := container.MappedPort(ctx, mongoContainerPort)
		if err != nil {
			t.Fatalf("resolve MongoDB member %s port: %v", alias, err)
		}
		dialer.addresses[net.JoinHostPort(alias, "27017")] = net.JoinHostPort(host, port.Port())
	}

	bootstrapClient, err := drivermongo.Connect(options.Client().
		ApplyURI("mongodb://mongo1:27017/?directConnection=true").
		SetDialer(dialer).
		SetServerSelectionTimeout(30 * time.Second))
	if err != nil {
		t.Fatalf("create replica set bootstrap client: %v", err)
	}
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if err := bootstrapClient.Disconnect(cleanupContext); err != nil {
			t.Errorf("disconnect replica set bootstrap client: %v", err)
		}
	})

	members := bson.A{}
	for index, alias := range aliases {
		members = append(members, bson.D{
			{Key: "_id", Value: index},
			{Key: "host", Value: net.JoinHostPort(alias, "27017")},
		})
	}
	if err := bootstrapClient.Database("admin").RunCommand(ctx, bson.D{
		{Key: "replSetInitiate", Value: bson.D{
			{Key: "_id", Value: "rs0"},
			{Key: "members", Value: members},
		}},
	}).Err(); err != nil {
		t.Fatalf("initiate MongoDB replica set: %v", err)
	}

	seedURI := "mongodb://" + strings.Join([]string{
		"mongo1:27017",
		"mongo2:27017",
		"mongo3:27017",
	}, ",") + "/?replicaSet=rs0"
	driverClient, err := drivermongo.Connect(options.Client().
		ApplyURI(seedURI).
		SetDialer(dialer).
		SetConnectTimeout(30 * time.Second).
		SetServerSelectionTimeout(30 * time.Second).
		SetTimeout(10 * time.Second))
	if err != nil {
		t.Fatalf("create MongoDB replica set client: %v", err)
	}
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if err := driverClient.Disconnect(cleanupContext); err != nil {
			t.Errorf("disconnect MongoDB replica set client: %v", err)
		}
	})

	wrapper := &Client{
		client:           driverClient,
		database:         driverClient.Database("owndock_failover_integration"),
		operationTimeout: 10 * time.Second,
	}
	firstPrimary := waitForMongoPrimary(t, ctx, wrapper, "")
	waitForMongoReplicaSetMembers(t, ctx, wrapper, 1, 2)
	insertTransactionalProbe(t, ctx, wrapper, "before-failover")
	inventoryRepository, inventoryObservation, inventoryChunk := beginRuntimeInventoryFailoverProbe(t, ctx, wrapper)

	primaryAlias, err := aliasFromMongoAddress(firstPrimary)
	if err != nil {
		t.Fatal(err)
	}
	stopTimeout := 5 * time.Second
	if err := containers[primaryAlias].Stop(ctx, &stopTimeout); err != nil {
		t.Fatalf("stop primary %s: %v", primaryAlias, err)
	}

	secondPrimary := waitForMongoPrimary(t, ctx, wrapper, firstPrimary)
	if secondPrimary == firstPrimary {
		t.Fatalf("primary after failover = %q, want a different member", secondPrimary)
	}
	insertTransactionalProbe(t, ctx, wrapper, "after-failover")
	if err := inventoryRepository.Append(ctx, inventoryChunk); err != nil {
		t.Fatalf("append runtime inventory after failover: %v", err)
	}
	if err := inventoryRepository.Complete(
		ctx,
		inventoryObservation.ID,
		inventoryObservation.RuntimeTargetID,
		time.Now().UTC(),
	); err != nil {
		t.Fatalf("complete runtime inventory after failover: %v", err)
	}
	page, err := runtimeinventorydata.NewMongoViewRepository(wrapper.Database()).ListHost(
		ctx,
		inventoryObservation.OrganizationID,
		inventoryObservation.ManagedHostID,
		runtimeinventorybiz.ViewQuery{Limit: 10},
	)
	if err != nil {
		t.Fatalf("read runtime inventory after failover: %v", err)
	}
	if len(page.Items) != 1 || page.Items[0].RuntimeID != "failover-container" ||
		page.Items[0].Presence != runtimeinventorybiz.PresencePresent {
		t.Fatalf("runtime inventory after failover = %+v, want one present container", page)
	}

	count, err := wrapper.Database().Collection("failover_probe").CountDocuments(ctx, bson.D{})
	if err != nil {
		t.Fatalf("count failover probes: %v", err)
	}
	if count != 2 {
		t.Fatalf("failover probe count = %d, want 2", count)
	}
}

func beginRuntimeInventoryFailoverProbe(
	t *testing.T,
	ctx context.Context,
	client *Client,
) (*runtimeinventorydata.MongoRepository, runtimeinventorybiz.Observation, runtimeinventorybiz.Chunk) {
	t.Helper()
	const (
		organizationID = "failover-organization"
		projectID      = "failover-project"
		hostID         = "failover-host"
		targetID       = "failover-target"
	)
	if _, err := client.Database().Collection("managed_hosts").InsertOne(ctx, bson.D{
		{Key: "_id", Value: hostID},
		{Key: "organization_id", Value: organizationID},
	}); err != nil {
		t.Fatalf("seed managed host for failover: %v", err)
	}
	if _, err := client.Database().Collection("runtime_targets").InsertOne(ctx, bson.D{
		{Key: "_id", Value: targetID},
		{Key: "organization_id", Value: organizationID},
		{Key: "project_id", Value: projectID},
		{Key: "managed_host_id", Value: hostID},
		{Key: "status", Value: "ready"},
	}); err != nil {
		t.Fatalf("seed runtime target for failover: %v", err)
	}
	startedAt := time.Now().UTC()
	observation, err := runtimeinventorybiz.NewObservation(
		"failover-observation",
		organizationID,
		hostID,
		targetID,
		1,
		1,
		startedAt,
	)
	if err != nil {
		t.Fatalf("create failover observation: %v", err)
	}
	resource, err := runtimeinventorybiz.NewResource(
		observation,
		runtimeinventorybiz.KindContainer,
		"failover-container",
		"api",
		startedAt,
	)
	if err != nil {
		t.Fatalf("create failover inventory resource: %v", err)
	}
	resource.Container = &runtimeinventorybiz.ContainerSummary{State: "running"}
	chunk, err := runtimeinventorybiz.NewChunk(
		observation,
		0,
		[]runtimeinventorybiz.Resource{resource},
	)
	if err != nil {
		t.Fatalf("create failover inventory chunk: %v", err)
	}
	repository := runtimeinventorydata.NewMongoRepository(client.Database())
	if err := repository.Begin(ctx, observation); err != nil {
		t.Fatalf("begin runtime inventory before failover: %v", err)
	}
	return repository, observation, chunk
}

func waitForMongoPrimary(t *testing.T, ctx context.Context, client *Client, previous string) string {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := client.Ping(ctx); err != nil {
			lastErr = err
			time.Sleep(250 * time.Millisecond)
			continue
		}
		var hello bson.M
		err := client.Database().Client().Database("admin").RunCommand(
			ctx,
			bson.D{{Key: "hello", Value: 1}},
			options.RunCmd().SetReadPreference(readpref.Primary()),
		).Decode(&hello)
		if err != nil {
			lastErr = err
			time.Sleep(250 * time.Millisecond)
			continue
		}
		primary, _ := hello["primary"].(string)
		if primary != "" && primary != previous {
			return primary
		}
		lastErr = fmt.Errorf("primary = %q, waiting for a member other than %q", primary, previous)
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("wait for MongoDB primary: %v", lastErr)
	return ""
}

func insertTransactionalProbe(t *testing.T, ctx context.Context, client *Client, phase string) {
	t.Helper()
	if err := client.WithinTransaction(ctx, func(transactionContext context.Context) error {
		_, err := client.Database().Collection("failover_probe").InsertOne(
			transactionContext,
			bson.D{{Key: "phase", Value: phase}, {Key: "created_at", Value: time.Now().UTC()}},
		)
		return err
	}); err != nil {
		t.Fatalf("write %s transactional probe: %v", phase, err)
	}
}

func waitForMongoReplicaSetMembers(
	t *testing.T,
	ctx context.Context,
	client *Client,
	wantPrimary, wantSecondary int,
) {
	t.Helper()
	type memberStatus struct {
		State string `bson:"stateStr"`
	}
	type replicaSetStatus struct {
		Members []memberStatus `bson:"members"`
	}

	deadline := time.Now().Add(60 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		var status replicaSetStatus
		err := client.Database().Client().Database("admin").RunCommand(
			ctx,
			bson.D{{Key: "replSetGetStatus", Value: 1}},
			options.RunCmd().SetReadPreference(readpref.Primary()),
		).Decode(&status)
		if err != nil {
			lastErr = err
			time.Sleep(250 * time.Millisecond)
			continue
		}
		primary, secondary := 0, 0
		for _, member := range status.Members {
			switch member.State {
			case "PRIMARY":
				primary++
			case "SECONDARY":
				secondary++
			}
		}
		if primary == wantPrimary && secondary == wantSecondary {
			return
		}
		lastErr = fmt.Errorf(
			"replica set members = %d primary/%d secondary, want %d/%d",
			primary,
			secondary,
			wantPrimary,
			wantSecondary,
		)
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("wait for MongoDB replica set members: %v", lastErr)
}

func aliasFromMongoAddress(address string) (string, error) {
	alias, _, err := net.SplitHostPort(address)
	if err != nil {
		return "", fmt.Errorf("parse MongoDB member address %q: %w", address, err)
	}
	if alias == "" {
		return "", fmt.Errorf("MongoDB member address %q has no host", address)
	}
	return alias, nil
}
