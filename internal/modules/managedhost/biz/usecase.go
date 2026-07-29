package biz

import (
	"context"
	"strings"
	"time"

	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/security"
	"github.com/owndock/owndock/internal/shared/transaction"
)

type IDGenerator func() (string, error)
type Clock func() time.Time

type UseCase struct {
	repository              Repository
	enrollments             EnrollmentRepository
	transaction             transaction.Manager
	audit                   sharedaudit.Recorder
	tokens                  EnrollmentTokens
	issuer                  CertificateIssuer
	enrollmentTTL           time.Duration
	agentConnections        AgentConnectionRepository
	connectionCloser        AgentConnectionCloser
	supportedAgentProtocols map[string]struct{}
	newID                   IDGenerator
	now                     Clock
}

func (u *UseCase) WithAgentControl(
	repository AgentConnectionRepository,
	closer AgentConnectionCloser,
	supportedProtocols []string,
) *UseCase {
	u.agentConnections = repository
	u.connectionCloser = closer
	u.supportedAgentProtocols = make(map[string]struct{}, len(supportedProtocols))
	for _, protocol := range supportedProtocols {
		protocol = strings.TrimSpace(protocol)
		if protocol != "" {
			u.supportedAgentProtocols[protocol] = struct{}{}
		}
	}
	return u
}

func NewUseCase(
	repository Repository,
	transaction transaction.Manager,
	audit sharedaudit.Recorder,
	newID IDGenerator,
	now Clock,
) *UseCase {
	return &UseCase{
		repository: repository, transaction: transaction, audit: audit,
		newID: newID, now: now,
	}
}

func (u *UseCase) WithEnrollment(
	repository EnrollmentRepository,
	tokens EnrollmentTokens,
	issuer CertificateIssuer,
	enrollmentTTL time.Duration,
) *UseCase {
	u.enrollments = repository
	u.tokens = tokens
	u.issuer = issuer
	u.enrollmentTTL = enrollmentTTL
	return u
}

func (u *UseCase) List(
	ctx context.Context,
	principal security.Principal,
) ([]ManagedHost, error) {
	if err := principal.Require(security.PermissionManagedHostRead); err != nil {
		return nil, err
	}
	return u.repository.List(ctx, principal.OrganizationID)
}

func (u *UseCase) Get(
	ctx context.Context,
	principal security.Principal,
	hostID string,
) (ManagedHost, error) {
	if err := principal.Require(security.PermissionManagedHostRead); err != nil {
		return ManagedHost{}, err
	}
	return u.repository.Get(ctx, principal.OrganizationID, hostID)
}

func (u *UseCase) Create(
	ctx context.Context,
	principal security.Principal,
	name string,
	connectionMode runtimeaccess.Mode,
	directSSHRef, requestID string,
) (ManagedHost, error) {
	if err := principal.Require(security.PermissionManagedHostWrite); err != nil {
		return ManagedHost{}, err
	}
	id, err := u.newID()
	if err != nil {
		return ManagedHost{}, err
	}
	auditID, err := u.newID()
	if err != nil {
		return ManagedHost{}, err
	}
	now := u.now().UTC()
	item, err := NewManagedHost(
		id, principal.OrganizationID, name, connectionMode,
		directSSHRef, principal.UserID, now,
	)
	if err != nil {
		return ManagedHost{}, err
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		created, createErr := u.repository.Create(transactionContext, item)
		if createErr != nil {
			return createErr
		}
		item = created
		return u.audit.Record(transactionContext, sharedaudit.Event{
			ID: auditID, OrganizationID: principal.OrganizationID,
			ActorID: principal.UserID, Action: "managed_host.create",
			ResourceType: "managed_host", ResourceID: item.ID,
			RequestID: requestID, CreatedAt: now,
		})
	})
	return item, err
}

func (u *UseCase) Disable(
	ctx context.Context,
	principal security.Principal,
	hostID, requestID string,
) (ManagedHost, error) {
	if err := principal.Require(security.PermissionManagedHostWrite); err != nil {
		return ManagedHost{}, err
	}
	auditID, err := u.newID()
	if err != nil {
		return ManagedHost{}, err
	}
	now := u.now().UTC()
	var item ManagedHost
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		disabled, disableErr := u.repository.Disable(
			transactionContext, principal.OrganizationID, hostID, now,
		)
		if disableErr != nil {
			return disableErr
		}
		item = disabled
		return u.audit.Record(transactionContext, sharedaudit.Event{
			ID: auditID, OrganizationID: principal.OrganizationID,
			ActorID: principal.UserID, Action: "managed_host.disable",
			ResourceType: "managed_host", ResourceID: item.ID,
			RequestID: requestID, CreatedAt: now,
		})
	})
	if err == nil && u.connectionCloser != nil {
		u.connectionCloser.DisconnectHost(item.ID)
	}
	return item, err
}

func (u *UseCase) CreateEnrollment(
	ctx context.Context,
	principal security.Principal,
	hostID, requestID string,
) (EnrollmentCredential, error) {
	if err := principal.Require(security.PermissionManagedHostWrite); err != nil {
		return EnrollmentCredential{}, err
	}
	if !u.enrollmentReady() {
		return EnrollmentCredential{}, ErrEnrollmentUnavailable
	}
	host, err := u.repository.Get(ctx, principal.OrganizationID, hostID)
	if err != nil {
		return EnrollmentCredential{}, err
	}
	if host.ConnectionMode != runtimeaccess.ModeAgent ||
		host.Status == StatusDisabled ||
		host.AgentIdentityID != "" {
		return EnrollmentCredential{}, ErrEnrollmentNotAllowed
	}
	enrollmentID, err := u.newID()
	if err != nil {
		return EnrollmentCredential{}, err
	}
	auditID, err := u.newID()
	if err != nil {
		return EnrollmentCredential{}, err
	}
	rawToken, tokenHash, err := u.tokens.New()
	if err != nil {
		return EnrollmentCredential{}, err
	}
	now := u.now().UTC()
	enrollment, err := NewEnrollment(
		enrollmentID, host, tokenHash, principal.UserID, now, u.enrollmentTTL,
	)
	if err != nil {
		return EnrollmentCredential{}, err
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		if createErr := u.enrollments.CreateEnrollment(
			transactionContext, enrollment,
		); createErr != nil {
			return createErr
		}
		return u.audit.Record(transactionContext, sharedaudit.Event{
			ID: auditID, OrganizationID: principal.OrganizationID,
			ActorID: principal.UserID, Action: "agent_enrollment.create",
			ResourceType: "managed_host", ResourceID: host.ID,
			RequestID: requestID, CreatedAt: now,
		})
	})
	if err != nil {
		return EnrollmentCredential{}, err
	}
	return EnrollmentCredential{
		EnrollmentID: enrollment.ID, ManagedHostID: host.ID,
		Token: rawToken, ExpiresAt: enrollment.ExpiresAt,
	}, nil
}

func (u *UseCase) ExchangeEnrollment(
	ctx context.Context,
	rawToken, instanceID, agentVersion, protocolVersion string,
	capabilities []string,
	csrPEM []byte,
	requestID string,
) (AgentCredentials, error) {
	if !u.enrollmentReady() {
		return AgentCredentials{}, ErrEnrollmentUnavailable
	}
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" || len(csrPEM) == 0 {
		return AgentCredentials{}, ErrInvalidEnrollment
	}
	instanceID, agentVersion, protocolVersion, capabilities, err :=
		validateAgentMetadata(instanceID, agentVersion, protocolVersion, capabilities)
	if err != nil {
		return AgentCredentials{}, err
	}
	now := u.now().UTC()
	tokenHash := u.tokens.Hash(rawToken)
	enrollment, err := u.enrollments.FindAvailableEnrollment(ctx, tokenHash, now)
	if err != nil {
		return AgentCredentials{}, err
	}
	identityID, err := u.newID()
	if err != nil {
		return AgentCredentials{}, err
	}
	certificate, err := u.issuer.Issue(
		ctx,
		AgentCertificateClaim{
			OrganizationID: enrollment.OrganizationID,
			ManagedHostID:  enrollment.ManagedHostID,
			IdentityID:     identityID,
			InstanceID:     strings.TrimSpace(instanceID),
		},
		csrPEM,
		now,
	)
	if err != nil {
		return AgentCredentials{}, ErrInvalidEnrollment
	}
	identity, err := NewAgentIdentity(
		identityID, enrollment, instanceID, agentVersion, protocolVersion,
		capabilities, certificate, now,
	)
	if err != nil {
		return AgentCredentials{}, err
	}
	auditID, err := u.newID()
	if err != nil {
		return AgentCredentials{}, err
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		if activateErr := u.enrollments.ActivateAgent(
			transactionContext,
			enrollment.ID,
			tokenHash,
			now,
			identity,
		); activateErr != nil {
			return activateErr
		}
		return u.audit.Record(transactionContext, sharedaudit.Event{
			ID: auditID, OrganizationID: enrollment.OrganizationID,
			ActorID: "agent:" + identity.ID,
			Action:  "agent_identity.issue", ResourceType: "managed_host",
			ResourceID: enrollment.ManagedHostID,
			RequestID:  requestID, CreatedAt: now,
		})
	})
	if err != nil {
		return AgentCredentials{}, err
	}
	return AgentCredentials{
		Identity:         identity,
		CertificatePEM:   certificate.CertificatePEM,
		CACertificatePEM: certificate.CACertificatePEM,
	}, nil
}

func (u *UseCase) enrollmentReady() bool {
	return u.enrollments != nil && u.tokens != nil && u.issuer != nil &&
		u.enrollmentTTL > 0
}
