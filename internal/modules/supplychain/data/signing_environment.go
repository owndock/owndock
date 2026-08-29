package data

import (
	"context"
	"os"

	"github.com/owndock/owndock/internal/modules/supplychain/biz"
)

type EnvironmentSigningEnvironmentResolver struct{}

func (EnvironmentSigningEnvironmentResolver) ResolveSigningEnvironment(_ context.Context, _, _ string,
	provider biz.SigningKeyProvider) (map[string][]byte, error) {
	names := map[biz.SigningKeyProvider][]string{
		biz.SigningKeyAWSKMS: {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_REGION",
			"AWS_DEFAULT_REGION", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE"},
		biz.SigningKeyGCPKMS:     {"GOOGLE_APPLICATION_CREDENTIALS"},
		biz.SigningKeyAzureKMS:   {"AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_FEDERATED_TOKEN_FILE"},
		biz.SigningKeyVault:      {"VAULT_ADDR", "VAULT_TOKEN", "VAULT_NAMESPACE", "VAULT_CACERT"},
		biz.SigningKeyKubernetes: {"KUBECONFIG"},
	}[provider]
	if names == nil {
		return nil, biz.ErrInvalidSigningKey
	}
	result := make(map[string][]byte)
	for _, name := range names {
		if value, ok := os.LookupEnv(name); ok {
			result[name] = []byte(value)
		}
	}
	return result, nil
}

var _ biz.SigningEnvironmentResolver = EnvironmentSigningEnvironmentResolver{}
