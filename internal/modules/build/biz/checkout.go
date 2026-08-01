package biz

import (
	"context"
	"errors"
	"strings"
)

var (
	ErrCheckoutAuthentication = errors.New("source checkout authentication failed")
	ErrCheckoutUnreachable    = errors.New("source checkout is unreachable")
	ErrCheckoutRevision       = errors.New("source checkout revision does not match")
	ErrCheckoutResourceLimit  = errors.New("source checkout resource limit exceeded")
	ErrCheckoutFailed         = errors.New("source checkout failed")
)

type CheckoutRequest struct {
	Source      SourceRepository
	Credential  *RepositoryCredential
	Revision    SourceRevision
	Destination string
}

func (r CheckoutRequest) Validate() error {
	protocol, protocolErr := validateRepositoryURL(strings.TrimSpace(r.Source.RepositoryURL))
	if strings.TrimSpace(r.Destination) == "" || r.Source.ID == "" ||
		r.Source.ProjectID == "" || r.Revision.SourceRepositoryID != r.Source.ID ||
		!commitSHAPattern.MatchString(r.Revision.CommitSHA) || !validExactRef(r.Revision.Ref) ||
		protocolErr != nil || protocol != r.Source.Protocol {
		return ErrCheckoutFailed
	}
	if r.Source.CredentialID == "" {
		if r.Credential != nil || r.Source.Protocol == RepositoryProtocolSSH {
			return ErrCheckoutAuthentication
		}
		return nil
	}
	if r.Credential == nil || r.Credential.ID != r.Source.CredentialID ||
		r.Credential.ProjectID != r.Source.ProjectID ||
		!CredentialSupportsProtocol(*r.Credential, r.Source.Protocol) {
		return ErrCheckoutAuthentication
	}
	return nil
}

type CheckoutGateway interface {
	Checkout(context.Context, CheckoutRequest) error
}

type ExecutionSourceRepository interface {
	GetSource(context.Context, string, string) (SourceRepository, error)
	GetCredential(context.Context, string, string) (RepositoryCredential, error)
}
