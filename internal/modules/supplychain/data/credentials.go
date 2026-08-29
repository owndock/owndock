package data

import (
	"context"
	"errors"
	"os"
	"strings"

	controlplanebiz "github.com/owndock/owndock/internal/modules/controlplane/biz"
	"github.com/owndock/owndock/internal/modules/supplychain/biz"
	"github.com/owndock/owndock/internal/shared/secretref"
)

type registryCredentialSource interface {
	GetRegistryCredential(context.Context, string, string) (controlplanebiz.RegistryCredential, error)
}

// EnvironmentRegistryCredentialProvider resolves only the credential selected
// by the Evidence Job. MongoDB supplies non-secret metadata; the password is
// read for one operation from the external secret reference and returned as a
// mutable byte slice so the publisher can clear it immediately after use.
type EnvironmentRegistryCredentialProvider struct {
	source registryCredentialSource
	lookup func(string) (string, bool)
}

func NewEnvironmentRegistryCredentialProvider(
	source registryCredentialSource,
) *EnvironmentRegistryCredentialProvider {
	return &EnvironmentRegistryCredentialProvider{source: source, lookup: os.LookupEnv}
}

func (p *EnvironmentRegistryCredentialProvider) ResolveRegistryCredential(
	ctx context.Context,
	projectID, credentialID, registry string,
) (biz.RegistryCredential, error) {
	if err := ctx.Err(); err != nil {
		return biz.RegistryCredential{}, err
	}
	projectID = strings.TrimSpace(projectID)
	credentialID = strings.TrimSpace(credentialID)
	registry = strings.ToLower(strings.TrimSpace(registry))
	if p == nil || p.source == nil || p.lookup == nil || projectID == "" ||
		credentialID == "" || registry == "" {
		return biz.RegistryCredential{}, biz.ErrRegistryAuthentication
	}
	credential, err := p.source.GetRegistryCredential(ctx, projectID, credentialID)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return biz.RegistryCredential{}, err
		}
		return biz.RegistryCredential{}, biz.ErrRegistryAuthentication
	}
	if credential.ID != credentialID || credential.ProjectID != projectID ||
		strings.ToLower(strings.TrimSpace(credential.Server)) != registry ||
		strings.TrimSpace(credential.Username) == "" || len(credential.Username) > 255 {
		return biz.RegistryCredential{}, biz.ErrRegistryAuthentication
	}
	alias, err := secretref.Alias(credential.PasswordRef)
	if err != nil {
		return biz.RegistryCredential{}, biz.ErrRegistryAuthentication
	}
	name := "OWNDOCK_REGISTRY_" +
		strings.ToUpper(strings.ReplaceAll(alias, "-", "_")) + "_PASSWORD"
	password, found := p.lookup(name)
	if !found || password == "" || len(password) > 64*1024 {
		return biz.RegistryCredential{}, biz.ErrRegistryAuthentication
	}
	return biz.RegistryCredential{
		Username: strings.TrimSpace(credential.Username), Password: []byte(password),
	}, nil
}

var _ biz.RegistryCredentialProvider = (*EnvironmentRegistryCredentialProvider)(nil)
