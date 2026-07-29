package data

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/owndock/owndock/internal/modules/deployment/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/secretref"
)

var (
	ErrInvalidCredentialRef  = errors.New("credential reference is invalid")
	ErrCredentialUnavailable = errors.New("runtime credential is unavailable")
)

type EnvironmentSecretResolver struct {
	lookup func(string) (string, bool)
}

func (r *EnvironmentSecretResolver) ResolveRegistryAuthorization(
	ctx context.Context,
	server, username, passwordReference string,
) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	server = strings.TrimSpace(server)
	username = strings.TrimSpace(username)
	if server == "" || username == "" {
		return nil, ErrInvalidCredentialRef
	}
	alias, err := secretref.Alias(passwordReference)
	if err != nil {
		return nil, ErrInvalidCredentialRef
	}
	name := "OWNDOCK_REGISTRY_" +
		strings.ToUpper(strings.ReplaceAll(alias, "-", "_")) +
		"_PASSWORD"
	password, ok := r.lookup(name)
	if !ok || password == "" {
		return nil, fmt.Errorf("%w: %s is not configured", ErrCredentialUnavailable, name)
	}
	payload, err := json.Marshal(struct {
		Username      string `json:"username"`
		Password      string `json:"password"`
		ServerAddress string `json:"serveraddress"`
	}{
		Username: username, Password: password, ServerAddress: server,
	})
	if err != nil {
		return nil, fmt.Errorf("encode registry authorization: %w", err)
	}
	authorization := make([]byte, base64.URLEncoding.EncodedLen(len(payload)))
	base64.URLEncoding.Encode(authorization, payload)
	for i := range payload {
		payload[i] = 0
	}
	return authorization, nil
}

func (r *EnvironmentSecretResolver) ResolveConfigurationValue(
	ctx context.Context,
	value string,
) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if !strings.HasPrefix(value, "secret://") {
		return value, nil
	}
	alias, err := secretref.Alias(value)
	if err != nil {
		return "", ErrInvalidCredentialRef
	}
	name := "OWNDOCK_CONFIG_" +
		strings.ToUpper(strings.ReplaceAll(alias, "-", "_")) +
		"_VALUE"
	resolved, ok := r.lookup(name)
	if !ok {
		return "", fmt.Errorf("%w: %s is not configured", ErrCredentialUnavailable, name)
	}
	return resolved, nil
}

func NewEnvironmentSecretResolver() *EnvironmentSecretResolver {
	return &EnvironmentSecretResolver{lookup: os.LookupEnv}
}

func (r *EnvironmentSecretResolver) ResolveCredential(
	ctx context.Context,
	connection runtimeaccess.Connection,
) (biz.RuntimeCredential, error) {
	if err := ctx.Err(); err != nil {
		return biz.RuntimeCredential{}, err
	}
	if err := connection.Validate(); err != nil {
		return biz.RuntimeCredential{}, ErrInvalidCredentialRef
	}
	if connection.Mode == runtimeaccess.ModeAgent {
		// Agent transport authentication belongs to the Agent connection
		// registry. It is not a per-operation secret resolved by this adapter.
		return biz.RuntimeCredential{}, nil
	}
	reference := connection.DirectDocker.CredentialRef
	alias, err := secretref.Alias(reference)
	if err != nil {
		return biz.RuntimeCredential{}, ErrInvalidCredentialRef
	}
	environmentPrefix := "OWNDOCK_RUNTIME_" +
		strings.ToUpper(strings.ReplaceAll(alias, "-", "_"))
	values := make([]string, 3)
	for index, suffix := range []string{"_CA_PEM", "_CERT_PEM", "_KEY_PEM"} {
		name := environmentPrefix + suffix
		value, ok := r.lookup(name)
		if !ok || strings.TrimSpace(value) == "" {
			return biz.RuntimeCredential{}, fmt.Errorf("%w: %s is not configured", ErrCredentialUnavailable, name)
		}
		values[index] = value
	}
	return biz.RuntimeCredential{
		DirectDocker: &biz.DirectDockerCredential{
			CACertificate:     []byte(values[0]),
			ClientCertificate: []byte(values[1]),
			ClientKey:         []byte(values[2]),
		},
	}, nil
}
