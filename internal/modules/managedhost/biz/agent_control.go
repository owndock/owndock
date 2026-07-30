package biz

import (
	"context"
	"strings"

	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
)

func (u *UseCase) OpenAgentSession(
	ctx context.Context,
	certificate AgentCertificateIdentity,
	hello AgentHello,
	requestID string,
) (AgentSession, error) {
	if u.agentConnections == nil || len(u.supportedAgentProtocols) == 0 {
		return AgentSession{}, ErrAgentControlUnavailable
	}
	normalizedHello, err := normalizeAgentHello(hello)
	if err != nil {
		return AgentSession{}, err
	}
	certificate = normalizeCertificateIdentity(certificate)
	if certificate.OrganizationID != normalizedHello.OrganizationID ||
		certificate.ManagedHostID != normalizedHello.ManagedHostID ||
		certificate.IdentityID != normalizedHello.IdentityID ||
		certificate.InstanceID != normalizedHello.InstanceID ||
		certificate.CertificateSerial == "" ||
		certificate.CertificateSHA256 == "" {
		return AgentSession{}, ErrInvalidAgentIdentity
	}
	if _, supported := u.supportedAgentProtocols[normalizedHello.ProtocolVersion]; !supported {
		return AgentSession{}, ErrAgentProtocolUnsupported
	}
	now := u.now().UTC()
	identity, err := u.agentConnections.AuthenticateAgent(ctx, certificate, now)
	if err != nil {
		return AgentSession{}, err
	}
	if identity.ID != certificate.IdentityID ||
		identity.OrganizationID != certificate.OrganizationID ||
		identity.ManagedHostID != certificate.ManagedHostID ||
		identity.InstanceID != certificate.InstanceID ||
		identity.CertificateSerial != certificate.CertificateSerial ||
		identity.CertificateSHA256 != certificate.CertificateSHA256 ||
		!identity.CertificateExpires.After(now) ||
		!identity.RevokedAt.IsZero() {
		return AgentSession{}, ErrInvalidAgentIdentity
	}
	if !capabilitiesAreSubset(
		normalizedHello.Capabilities,
		identity.Capabilities,
	) {
		return AgentSession{}, ErrInvalidAgentIdentity
	}
	sessionID, err := u.newID()
	if err != nil {
		return AgentSession{}, err
	}
	auditID, err := u.newID()
	if err != nil {
		return AgentSession{}, err
	}
	session := AgentSession{
		ID: sessionID, OrganizationID: identity.OrganizationID,
		ManagedHostID: identity.ManagedHostID, IdentityID: identity.ID,
		InstanceID: identity.InstanceID, BootID: normalizedHello.BootID,
		AgentVersion:    normalizedHello.AgentVersion,
		ProtocolVersion: normalizedHello.ProtocolVersion,
		Capabilities:    normalizedHello.Capabilities,
		ConnectedAt:     now,
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		if connectErr := u.agentConnections.ConnectAgent(
			transactionContext, session, now,
		); connectErr != nil {
			return connectErr
		}
		return u.audit.Record(transactionContext, sharedaudit.Event{
			ID: auditID, OrganizationID: session.OrganizationID,
			ActorID: "agent:" + session.IdentityID,
			Action:  "agent_session.connect", ResourceType: "managed_host",
			ResourceID: session.ManagedHostID,
			RequestID:  requestID, CreatedAt: now,
		})
	})
	return session, err
}

func (u *UseCase) HeartbeatAgentSession(
	ctx context.Context,
	session AgentSession,
) error {
	if u.agentConnections == nil || strings.TrimSpace(session.ID) == "" {
		return ErrAgentSessionInvalid
	}
	return u.agentConnections.HeartbeatAgent(ctx, session, u.now().UTC())
}

func (u *UseCase) CloseAgentSession(
	ctx context.Context,
	session AgentSession,
	requestID string,
) error {
	if u.agentConnections == nil || strings.TrimSpace(session.ID) == "" {
		return ErrAgentSessionInvalid
	}
	auditID, err := u.newID()
	if err != nil {
		return err
	}
	now := u.now().UTC()
	return u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		disconnected, disconnectErr := u.agentConnections.DisconnectAgent(
			transactionContext, session, now,
		)
		if disconnectErr != nil || !disconnected {
			return disconnectErr
		}
		return u.audit.Record(transactionContext, sharedaudit.Event{
			ID: auditID, OrganizationID: session.OrganizationID,
			ActorID: "agent:" + session.IdentityID,
			Action:  "agent_session.disconnect", ResourceType: "managed_host",
			ResourceID: session.ManagedHostID,
			RequestID:  requestID, CreatedAt: now,
		})
	})
}

func normalizeAgentHello(hello AgentHello) (AgentHello, error) {
	hello.OrganizationID = strings.TrimSpace(hello.OrganizationID)
	hello.ManagedHostID = strings.TrimSpace(hello.ManagedHostID)
	hello.IdentityID = strings.TrimSpace(hello.IdentityID)
	hello.BootID = strings.TrimSpace(hello.BootID)
	instanceID, agentVersion, protocolVersion, capabilities, err :=
		validateAgentMetadata(
			hello.InstanceID,
			hello.AgentVersion,
			hello.ProtocolVersion,
			hello.Capabilities,
		)
	if err != nil || !validIdentitySegment(hello.OrganizationID) ||
		!validIdentitySegment(hello.ManagedHostID) ||
		!validIdentitySegment(hello.IdentityID) ||
		!validIdentitySegment(hello.BootID) {
		return AgentHello{}, ErrAgentSessionInvalid
	}
	hello.InstanceID = instanceID
	hello.AgentVersion = agentVersion
	hello.ProtocolVersion = protocolVersion
	hello.Capabilities = capabilities
	return hello, nil
}

func normalizeCertificateIdentity(
	identity AgentCertificateIdentity,
) AgentCertificateIdentity {
	identity.OrganizationID = strings.TrimSpace(identity.OrganizationID)
	identity.ManagedHostID = strings.TrimSpace(identity.ManagedHostID)
	identity.IdentityID = strings.TrimSpace(identity.IdentityID)
	identity.InstanceID = strings.TrimSpace(identity.InstanceID)
	identity.CertificateSerial = strings.TrimSpace(identity.CertificateSerial)
	identity.CertificateSHA256 = strings.ToLower(
		strings.TrimSpace(identity.CertificateSHA256),
	)
	return identity
}

func capabilitiesAreSubset(
	requested, granted []string,
) bool {
	allowed := make(map[string]struct{}, len(granted))
	for _, capability := range granted {
		allowed[capability] = struct{}{}
	}
	for _, capability := range requested {
		if _, exists := allowed[capability]; !exists {
			return false
		}
	}
	return true
}
