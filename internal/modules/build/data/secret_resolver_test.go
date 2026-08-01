package data

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/owndock/owndock/internal/modules/build/biz"
)

func TestEnvironmentRepositorySecretResolverUsesCredentialSpecificNames(t *testing.T) {
	t.Setenv("OWNDOCK_GIT_CUSTOMER_API_TOKEN", "token-value")
	t.Setenv("OWNDOCK_GIT_CUSTOMER_API_PRIVATE_KEY_PEM", "private-key-value")
	resolver := NewEnvironmentRepositorySecretResolver()

	for _, test := range []struct {
		credentialType biz.CredentialType
		want           string
	}{
		{credentialType: biz.CredentialTypeHTTPSAccessToken, want: "token-value"},
		{credentialType: biz.CredentialTypeSSHDeployKey, want: "private-key-value"},
	} {
		credential := biz.RepositoryCredential{
			Type: test.credentialType, SecretRef: "secret://customer-api",
		}
		secret, err := resolver.ResolveRepositoryCredential(context.Background(), credential)
		if err != nil || string(secret) != test.want {
			t.Fatalf("ResolveRepositoryCredential(%s) = %q, %v", test.credentialType, secret, err)
		}
	}
}

func TestEnvironmentRepositorySecretResolverDoesNotLeakReference(t *testing.T) {
	resolver := NewEnvironmentRepositorySecretResolver()
	_, err := resolver.ResolveRepositoryCredential(context.Background(), biz.RepositoryCredential{
		Type: biz.CredentialTypeHTTPSAccessToken, SecretRef: "secret://missing-token",
	})
	if !errors.Is(err, ErrRepositoryCredentialUnavailable) {
		t.Fatalf("error = %v", err)
	}
	if strings.Contains(err.Error(), "missing-token") || strings.Contains(err.Error(), "OWNDOCK_GIT") {
		t.Fatalf("error leaked credential metadata: %v", err)
	}
}

func TestEnvironmentRepositorySecretResolverHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewEnvironmentRepositorySecretResolver().ResolveRepositoryCredential(
		ctx,
		biz.RepositoryCredential{
			Type: biz.CredentialTypeHTTPSAccessToken, SecretRef: "secret://token",
		},
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
}
