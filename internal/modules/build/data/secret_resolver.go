package data

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/owndock/owndock/internal/modules/build/biz"
	"github.com/owndock/owndock/internal/shared/secretref"
)

var ErrRepositoryCredentialUnavailable = errors.New("repository credential is unavailable")

type RepositorySecretResolver interface {
	ResolveRepositoryCredential(context.Context, biz.RepositoryCredential) ([]byte, error)
}

type EnvironmentRepositorySecretResolver struct {
	lookup func(string) (string, bool)
}

func NewEnvironmentRepositorySecretResolver() *EnvironmentRepositorySecretResolver {
	return &EnvironmentRepositorySecretResolver{lookup: os.LookupEnv}
}

func (r *EnvironmentRepositorySecretResolver) ResolveRepositoryCredential(
	ctx context.Context,
	credential biz.RepositoryCredential,
) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	alias, err := secretref.Alias(credential.SecretRef)
	if err != nil || !credential.Type.Valid() {
		return nil, ErrRepositoryCredentialUnavailable
	}
	prefix := "OWNDOCK_GIT_" + strings.ToUpper(strings.ReplaceAll(alias, "-", "_"))
	var suffix string
	switch credential.Type {
	case biz.CredentialTypeHTTPSAccessToken:
		suffix = "_TOKEN"
	case biz.CredentialTypeSSHDeployKey:
		suffix = "_PRIVATE_KEY_PEM"
	default:
		return nil, ErrRepositoryCredentialUnavailable
	}
	value, found := r.lookup(prefix + suffix)
	if !found || strings.TrimSpace(value) == "" {
		// Do not include the reference, environment variable name, or secret in
		// the error. Probe results and logs only need a stable safe category.
		return nil, ErrRepositoryCredentialUnavailable
	}
	return []byte(value), nil
}
