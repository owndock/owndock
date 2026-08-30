package data

import (
	"context"
	"errors"
	"strings"
	"testing"

	controlplanebiz "github.com/owndock/owndock/internal/modules/controlplane/biz"
	"github.com/owndock/owndock/internal/modules/supplychain/biz"
	"github.com/owndock/owndock/internal/shared/registryauth"
)

type registryCredentialSourceStub struct {
	credential controlplanebiz.RegistryCredential
	err        error
}

func (s registryCredentialSourceStub) GetRegistryCredential(
	context.Context, string, string,
) (controlplanebiz.RegistryCredential, error) {
	return s.credential, s.err
}

func TestEnvironmentRegistryCredentialProviderResolvesBoundSecret(t *testing.T) {
	provider := NewEnvironmentRegistryCredentialProvider(registryCredentialSourceStub{
		credential: controlplanebiz.RegistryCredential{
			ID: "registry-1", ProjectID: "project-1", Server: "registry.example.com:5443",
			AuthenticationMode: registryauth.ModeBasic,
			Username:           "publisher", PasswordRef: "secret://production-registry",
		},
	})
	provider.lookup = func(name string) (string, bool) {
		if name != "OWNDOCK_REGISTRY_PRODUCTION_REGISTRY_PASSWORD" {
			t.Fatalf("unexpected environment lookup %q", name)
		}
		return "registry-password", true
	}
	credential, err := provider.ResolveRegistryCredential(
		t.Context(), "project-1", "registry-1", "registry.example.com:5443",
	)
	if err != nil || credential.Username != "publisher" || string(credential.Password) != "registry-password" {
		t.Fatalf("ResolveRegistryCredential() = %+v, %v", credential, err)
	}
	clear(credential.Password)
}

func TestEnvironmentRegistryCredentialProviderResolvesAnonymousWithoutSecretLookup(t *testing.T) {
	provider := NewEnvironmentRegistryCredentialProvider(registryCredentialSourceStub{
		credential: controlplanebiz.RegistryCredential{
			ID: "registry-1", ProjectID: "project-1", Server: "registry.example.com",
			AuthenticationMode: registryauth.ModeAnonymous,
		},
	})
	provider.lookup = func(string) (string, bool) {
		t.Fatal("anonymous Registry connection attempted a secret lookup")
		return "", false
	}
	credential, err := provider.ResolveRegistryCredential(
		t.Context(), "project-1", "registry-1", "registry.example.com",
	)
	if err != nil || credential.AuthenticationMode != registryauth.ModeAnonymous ||
		credential.Username != "" || len(credential.Password) != 0 {
		t.Fatalf("ResolveRegistryCredential() = %+v, %v", credential, err)
	}
}

func TestEnvironmentRegistryCredentialProviderFailsClosedWithoutLeakingMetadata(t *testing.T) {
	secretSentinel := "do-not-leak-password"
	valid := controlplanebiz.RegistryCredential{
		ID: "registry-1", ProjectID: "project-1", Server: "registry.example.com",
		AuthenticationMode: registryauth.ModeBasic,
		Username:           "publisher", PasswordRef: "secret://customer-production",
	}
	tests := []struct {
		name       string
		provider   *EnvironmentRegistryCredentialProvider
		projectID  string
		credential string
		registry   string
	}{
		{name: "nil source", provider: NewEnvironmentRegistryCredentialProvider(nil), projectID: "project-1", credential: "registry-1", registry: "registry.example.com"},
		{name: "wrong project", provider: NewEnvironmentRegistryCredentialProvider(registryCredentialSourceStub{credential: valid}), projectID: "project-2", credential: "registry-1", registry: "registry.example.com"},
		{name: "wrong Registry", provider: NewEnvironmentRegistryCredentialProvider(registryCredentialSourceStub{credential: valid}), projectID: "project-1", credential: "registry-1", registry: "another.example.com"},
		{name: "missing secret", provider: NewEnvironmentRegistryCredentialProvider(registryCredentialSourceStub{credential: valid}), projectID: "project-1", credential: "registry-1", registry: "registry.example.com"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.provider.lookup = func(string) (string, bool) { return secretSentinel, test.name != "missing secret" }
			credential, err := test.provider.ResolveRegistryCredential(
				t.Context(), test.projectID, test.credential, test.registry,
			)
			if !errors.Is(err, biz.ErrRegistryAuthentication) || len(credential.Password) != 0 {
				t.Fatalf("result = %+v, %v", credential, err)
			}
			message := err.Error()
			for _, forbidden := range []string{secretSentinel, "customer-production", "OWNDOCK_REGISTRY"} {
				if strings.Contains(message, forbidden) {
					t.Fatalf("error leaked %q: %v", forbidden, err)
				}
			}
		})
	}
}

func TestEnvironmentRegistryCredentialProviderHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	provider := NewEnvironmentRegistryCredentialProvider(registryCredentialSourceStub{})
	if _, err := provider.ResolveRegistryCredential(
		ctx, "project-1", "registry-1", "registry.example.com",
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context error = %v", err)
	}
}
