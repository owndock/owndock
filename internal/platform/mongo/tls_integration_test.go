package mongo

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	testmongo "github.com/testcontainers/testcontainers-go/modules/mongodb"
	"go.mongodb.org/mongo-driver/v2/bson"
	drivermongo "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

const (
	tlsContainerCAFile     = "/tmp/owndock-mongodb-ca.pem"
	tlsContainerServerFile = "/tmp/owndock-mongodb-server.pem"
)

func TestMongoTLSReplicaSetIntegration(t *testing.T) {
	if os.Getenv("OWNDOCK_RUN_MONGO_INTEGRATION") != "1" {
		t.Skip("set OWNDOCK_RUN_MONGO_INTEGRATION=1 to run the MongoDB integration test")
	}

	const (
		rootUsername = "owndock-tls-integration-root"
		rootPassword = "tls-root-password-integration-sentinel"
		appUsername  = "owndock-tls-integration-app"
		appPassword  = "tls-app-password-integration-sentinel"
		databaseName = "owndock_tls_integration"
	)
	caFile, serverFile := writeMongoTLSMaterials(t, "owndock-mongodb-integration")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	container, err := testmongo.Run(
		ctx,
		integrationImage,
		testmongo.WithReplicaSet("rs0"),
		testmongo.WithUsername(rootUsername),
		testmongo.WithPassword(rootPassword),
		testcontainers.WithFiles(
			testcontainers.ContainerFile{
				HostFilePath: caFile, ContainerFilePath: tlsContainerCAFile, FileMode: 0o444,
			},
			testcontainers.ContainerFile{
				HostFilePath: serverFile, ContainerFilePath: tlsContainerServerFile, FileMode: 0o444,
			},
		),
		testcontainers.WithCmdArgs(
			"--tlsMode", "allowTLS",
			"--tlsCAFile", tlsContainerCAFile,
			"--tlsCertificateKeyFile", tlsContainerServerFile,
			"--tlsAllowConnectionsWithoutCertificates",
		),
	)
	if err != nil {
		t.Fatalf("start TLS MongoDB container: %v", err)
	}
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if err := testcontainers.TerminateContainer(container, testcontainers.StopContext(cleanupContext)); err != nil {
			t.Errorf("terminate TLS MongoDB container: %v", err)
		}
	})

	plainURI, err := container.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("TLS MongoDB connection string: %v", err)
	}
	plainURI = directConnectionURI(t, plainURI)
	tlsURI := mongoTLSURI(t, plainURI, caFile)
	t.Setenv("OWNDOCK_TEST_TLS_MONGODB_URI", tlsURI)
	rootClient, err := Open(ctx, authenticatedMongoConfig("OWNDOCK_TEST_TLS_MONGODB_URI", databaseName))
	if err != nil {
		logs, logErr := container.Logs(ctx)
		if logErr != nil {
			t.Fatalf("Open() TLS MongoDB client: %v; read container logs: %v", err, logErr)
		}
		defer func() { _ = logs.Close() }()
		output, _ := io.ReadAll(io.LimitReader(logs, 1024*1024))
		t.Fatalf("Open() TLS MongoDB client: %v; MongoDB TLS logs: %s", err, mongoTLSDiagnostics(output))
	}
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if err := rootClient.Close(cleanupContext); err != nil {
			t.Errorf("close TLS root MongoDB client: %v", err)
		}
	})
	if err := rootClient.Database().RunCommand(ctx, bson.D{
		{Key: "createUser", Value: appUsername},
		{Key: "pwd", Value: appPassword},
		{Key: "roles", Value: bson.A{bson.D{
			{Key: "role", Value: "readWrite"},
			{Key: "db", Value: databaseName},
		}}},
	}).Err(); err != nil {
		t.Fatalf("create TLS MongoDB application user: %v", err)
	}
	appTLSURI := authenticatedMongoURI(t, tlsURI, appUsername, appPassword, databaseName)
	t.Setenv("OWNDOCK_TEST_TLS_APP_MONGODB_URI", appTLSURI)
	appClient, err := Open(ctx, authenticatedMongoConfig("OWNDOCK_TEST_TLS_APP_MONGODB_URI", databaseName))
	if err != nil {
		t.Fatalf("Open() TLS application MongoDB client: %v", err)
	}
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if err := appClient.Close(cleanupContext); err != nil {
			t.Errorf("close TLS application MongoDB client: %v", err)
		}
	})

	for _, mode := range []string{"preferTLS", "requireTLS"} {
		if err := rootClient.Database().Client().Database("admin").RunCommand(ctx, bson.D{
			{Key: "setParameter", Value: 1},
			{Key: "tlsMode", Value: mode},
		}).Err(); err != nil {
			t.Fatalf("set MongoDB tlsMode=%s after Replica Set initialization: %v", mode, err)
		}
	}
	if err := appClient.Ping(ctx); err != nil {
		t.Fatalf("Ping() after requiring MongoDB TLS: %v", err)
	}
	if err := appClient.WithinTransaction(ctx, func(transactionContext context.Context) error {
		_, err := appClient.Database().Collection("tls_probe").InsertOne(
			transactionContext,
			bson.D{{Key: "transport", Value: "tls"}},
		)
		return err
	}); err != nil {
		t.Fatalf("MongoDB TLS transaction: %v", err)
	}

	appPlainURI := authenticatedMongoURI(t, plainURI, appUsername, appPassword, databaseName)
	plainClient, err := drivermongo.Connect(options.Client().
		ApplyURI(appPlainURI).
		SetConnectTimeout(time.Second).
		SetServerSelectionTimeout(time.Second))
	if err != nil {
		t.Fatalf("create plaintext MongoDB rejection probe: %v", err)
	}
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		if err := plainClient.Disconnect(cleanupContext); err != nil {
			t.Errorf("disconnect plaintext MongoDB probe: %v", err)
		}
	})
	plainContext, plainCancel := context.WithTimeout(ctx, 2*time.Second)
	defer plainCancel()
	if err := plainClient.Ping(plainContext, readpref.Primary()); err == nil {
		t.Fatal("MongoDB accepted a plaintext connection after tlsMode=requireTLS")
	}

	wrongCAFile, _ := writeMongoTLSMaterials(t, "owndock-mongodb-wrong-ca")
	wrongTLSURI := mongoTLSURI(t, appPlainURI, wrongCAFile)
	t.Setenv("OWNDOCK_TEST_WRONG_CA_MONGODB_URI", wrongTLSURI)
	_, err = Open(ctx, authenticatedMongoConfig("OWNDOCK_TEST_WRONG_CA_MONGODB_URI", "owndock_tls_integration"))
	if err == nil {
		t.Fatal("Open() accepted a MongoDB server signed by an untrusted CA")
	}
	assertMongoErrorOmitsCredentials(t, err, wrongTLSURI, appUsername, appPassword)
}

func mongoTLSDiagnostics(output []byte) string {
	var selected []string
	for _, line := range strings.Split(string(output), "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "tls") || strings.Contains(lower, "ssl") ||
			strings.Contains(lower, "error") || strings.Contains(lower, "certificate") {
			selected = append(selected, line)
		}
	}
	return strings.Join(selected, "\n")
}

func mongoTLSURI(t *testing.T, value, caFile string) string {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatalf("parse TLS MongoDB connection string: %v", err)
	}
	query := parsed.Query()
	query.Set("tls", "true")
	query.Set("tlsCAFile", caFile)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func writeMongoTLSMaterials(t *testing.T, commonName string) (string, string) {
	t.Helper()
	now := time.Now().UTC()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName + " CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(30 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	serverPublic, serverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	serverDER, err := x509.CreateCertificate(
		rand.Reader,
		serverTemplate,
		caCertificate,
		serverPublic,
		caPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	serverKeyDER, err := x509.MarshalPKCS8PrivateKey(serverPrivate)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	caFile := filepath.Join(directory, "ca.pem")
	serverFile := filepath.Join(directory, "server.pem")
	if err := os.WriteFile(
		caFile,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	serverPEM := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKeyDER})...,
	)
	defer func() {
		for index := range serverPEM {
			serverPEM[index] = 0
		}
	}()
	if err := os.WriteFile(serverFile, serverPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return caFile, serverFile
}
