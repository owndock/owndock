package service

import (
	"reflect"
	"testing"

	"github.com/owndock/owndock/internal/modules/controlplane/biz"
)

func TestSecretBackedResourcesExposeConfigurationStateWithoutReferences(t *testing.T) {
	registry := registryCredentialResponseFromDomain(biz.RegistryCredential{
		PasswordRef: "secret://registry-production",
	})
	if !registry.PasswordConfigured {
		t.Fatal("registry password was not reported as configured")
	}
	target := runtimeTargetResponseFromDomain(biz.RuntimeTarget{
		CredentialRef: "secret://docker-production",
	})
	if !target.CredentialConfigured {
		t.Fatal("runtime target credential was not reported as configured")
	}
	environment := environmentResponseFromDomain(biz.Environment{Variables: map[string]string{
		"Z_LAST": "plain-secret", "DATABASE_URL": "secret://database-production",
	}})
	if !reflect.DeepEqual(environment.VariableKeys, []string{"DATABASE_URL", "Z_LAST"}) {
		t.Fatalf("environment variable keys = %#v", environment.VariableKeys)
	}
}
