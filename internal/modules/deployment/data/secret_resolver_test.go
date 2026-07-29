package data

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/owndock/owndock/internal/shared/runtimeaccess"
)

func resolverConnection(reference string) runtimeaccess.Connection {
	return runtimeaccess.Connection{
		Mode: runtimeaccess.ModeDirectDocker,
		DirectDocker: &runtimeaccess.DirectDocker{
			Endpoint:      "tcp://docker.example.com:2376",
			TLSServerName: "docker.example.com",
			CredentialRef: reference,
		},
	}
}

func TestEnvironmentSecretResolverUsesConstrainedAlias(t *testing.T) {
	values := map[string]string{
		"OWNDOCK_RUNTIME_DOCKER_PRODUCTION_CA_PEM":   "ca",
		"OWNDOCK_RUNTIME_DOCKER_PRODUCTION_CERT_PEM": "cert",
		"OWNDOCK_RUNTIME_DOCKER_PRODUCTION_KEY_PEM":  "key",
	}
	resolver := &EnvironmentSecretResolver{lookup: func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}}
	credential, err := resolver.ResolveCredential(
		t.Context(), resolverConnection("secret://docker-production"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if credential.DirectDocker == nil ||
		string(credential.DirectDocker.CACertificate) != "ca" ||
		string(credential.DirectDocker.ClientCertificate) != "cert" ||
		string(credential.DirectDocker.ClientKey) != "key" {
		t.Fatalf("credential = %+v", credential)
	}
}

func TestEnvironmentSecretResolverBuildsRegistryAuthorization(t *testing.T) {
	resolver := &EnvironmentSecretResolver{lookup: func(name string) (string, bool) {
		return "password-value", name == "OWNDOCK_REGISTRY_PRIVATE_REGISTRY_PASSWORD"
	}}
	authorization, err := resolver.ResolveRegistryAuthorization(
		t.Context(), "registry.example.com", "robot", "secret://private-registry",
	)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.URLEncoding.DecodeString(string(authorization))
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]string
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["username"] != "robot" || decoded["password"] != "password-value" ||
		decoded["serveraddress"] != "registry.example.com" {
		t.Fatalf("authorization = %v", decoded)
	}
}

func TestEnvironmentSecretResolverResolvesConfigurationReferences(t *testing.T) {
	resolver := &EnvironmentSecretResolver{lookup: func(name string) (string, bool) {
		return "mongodb://database", name == "OWNDOCK_CONFIG_DATABASE_URL_VALUE"
	}}
	value, err := resolver.ResolveConfigurationValue(t.Context(), "secret://database-url")
	if err != nil || value != "mongodb://database" {
		t.Fatalf("value = %q, error = %v", value, err)
	}
	value, err = resolver.ResolveConfigurationValue(t.Context(), "plain-value")
	if err != nil || value != "plain-value" {
		t.Fatalf("literal value = %q, error = %v", value, err)
	}
}

func TestEnvironmentSecretResolverRejectsArbitraryEnvironmentAccess(t *testing.T) {
	resolver := NewEnvironmentSecretResolver()
	for _, reference := range []string{
		"env://AWS_SECRET_ACCESS_KEY",
		"secret://../token",
		"secret://UPPERCASE",
		"secret://",
	} {
		if _, err := resolver.ResolveCredential(
			t.Context(), resolverConnection(reference),
		); !errors.Is(err, ErrInvalidCredentialRef) {
			t.Errorf("%q error = %v", reference, err)
		}
	}
}

func TestEnvironmentSecretResolverDoesNotIncludeSecretValueInErrors(t *testing.T) {
	resolver := &EnvironmentSecretResolver{lookup: func(string) (string, bool) {
		return "sensitive-value", false
	}}
	_, err := resolver.ResolveCredential(
		t.Context(), resolverConnection("secret://production"),
	)
	if !errors.Is(err, ErrCredentialUnavailable) || strings.Contains(err.Error(), "sensitive-value") {
		t.Fatalf("error = %v", err)
	}
}

func TestEnvironmentSecretResolverDoesNotResolvePerOperationSecretForAgent(t *testing.T) {
	lookups := 0
	resolver := &EnvironmentSecretResolver{lookup: func(string) (string, bool) {
		lookups++
		return "", false
	}}
	connection, err := runtimeaccess.NewAgent("host-1")
	if err != nil {
		t.Fatal(err)
	}
	credential, err := resolver.ResolveCredential(t.Context(), connection)
	if err != nil || credential.DirectDocker != nil || lookups != 0 {
		t.Fatalf("credential = %+v, lookups = %d, error = %v", credential, lookups, err)
	}
}
