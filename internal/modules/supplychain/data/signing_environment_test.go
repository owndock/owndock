package data

import (
	"testing"

	"github.com/owndock/owndock/internal/modules/supplychain/biz"
)

func TestEnvironmentSigningEnvironmentResolverUsesProviderAllowlist(t *testing.T) {
	t.Setenv("VAULT_ADDR", "https://vault.example.com")
	t.Setenv("VAULT_TOKEN", "vault-token")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "must-not-cross-provider")
	values, err := (EnvironmentSigningEnvironmentResolver{}).ResolveSigningEnvironment(
		t.Context(), "project-1", "profile-1", biz.SigningKeyVault)
	if err != nil || string(values["VAULT_TOKEN"]) != "vault-token" || values["AWS_SECRET_ACCESS_KEY"] != nil {
		t.Fatalf("resolved environment = %#v, %v", values, err)
	}
	if _, err := (EnvironmentSigningEnvironmentResolver{}).ResolveSigningEnvironment(
		t.Context(), "project-1", "profile-1", "unknown"); err == nil {
		t.Fatal("unknown signing provider was accepted")
	}
}

func TestVaultSigningEnvironmentRequiresExactHTTPSOriginAndAbsoluteCAFile(t *testing.T) {
	for name, values := range map[string]map[string][]byte{
		"valid origin": {"VAULT_ADDR": []byte("https://vault.example.com"), "VAULT_TOKEN": []byte("token"),
			"VAULT_CACERT": []byte("/etc/owndock/kms/vault-ca.pem")},
		"valid root slash": {"VAULT_ADDR": []byte("https://vault.example.com/"), "VAULT_TOKEN": []byte("token")},
		"http":             {"VAULT_ADDR": []byte("http://vault.example.com"), "VAULT_TOKEN": []byte("token")},
		"path":             {"VAULT_ADDR": []byte("https://vault.example.com/v1"), "VAULT_TOKEN": []byte("token")},
		"relative CA":      {"VAULT_ADDR": []byte("https://vault.example.com"), "VAULT_TOKEN": []byte("token"), "VAULT_CACERT": []byte("vault-ca.pem")},
	} {
		t.Run(name, func(t *testing.T) {
			valid := validSigningEnvironment(biz.SigningKeyVault, values)
			want := name == "valid origin" || name == "valid root slash"
			if valid != want {
				t.Fatalf("validSigningEnvironment() = %t, want %t", valid, want)
			}
		})
	}
}
