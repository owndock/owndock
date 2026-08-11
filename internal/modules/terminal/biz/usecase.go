package biz

import (
	"context"
	"errors"
	"strings"
	"time"

	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/security"
	"github.com/owndock/owndock/internal/shared/transaction"
)

var ErrTerminalUnavailable = errors.New("terminal service is unavailable")

type PolicyRepository interface {
	GetProjectPolicy(context.Context, string, string) (AccessPolicy, error)
	GetOrganizationPolicy(context.Context, string) (AccessPolicy, error)
	SavePolicy(context.Context, AccessPolicy, uint64) (AccessPolicy, error)
}

type SessionRepository interface {
	GetSession(context.Context, string, string) (TerminalSession, error)
	GetSessionForConnect(context.Context, string) (TerminalSession, error)
	CreateSession(context.Context, TerminalSession) (TerminalSession, error)
	SaveSession(context.Context, TerminalSession, uint64) (TerminalSession, error)
	ConsumeTicket(context.Context, string, string, string, time.Time) (TerminalSession, error)
}

type PrincipalResolver interface {
	ResolveTerminalPrincipal(context.Context, string, string, string) (security.Principal, error)
}

// ConnectSession atomically consumes the short-lived ticket before any
// terminal bytes are opened. The WSS transport must call this exactly once
// after authenticating the current user and validating Origin.
func (u *UseCase) ConnectSession(
	ctx context.Context,
	principal security.Principal,
	sessionID, rawTicket, requestID string,
) (TerminalSession, error) {
	session, err := u.sessions.GetSession(ctx, principal.OrganizationID, strings.TrimSpace(sessionID))
	if err != nil {
		return TerminalSession{}, err
	}
	if session.ActorID != principal.UserID {
		return TerminalSession{}, ErrInvalidTicket
	}
	if err := u.authorizeConnect(ctx, principal, session); err != nil {
		return TerminalSession{}, err
	}
	ticketHash := u.tickets.Hash(rawTicket)
	if !validTicketHash(ticketHash) || strings.TrimSpace(rawTicket) == "" {
		return TerminalSession{}, ErrInvalidTicket
	}
	now := u.now().UTC()
	auditID, err := u.newID()
	if err != nil {
		return TerminalSession{}, err
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		connected, consumeErr := u.sessions.ConsumeTicket(
			transactionContext, principal.OrganizationID, session.ID, ticketHash, now,
		)
		if consumeErr != nil {
			return consumeErr
		}
		session = connected
		return u.audit.Record(transactionContext, sharedaudit.Event{
			ID: auditID, OrganizationID: principal.OrganizationID,
			ProjectID: session.ProjectID, ActorID: principal.UserID,
			Action: "terminal_session.connect", ResourceType: "terminal_session",
			ResourceID: session.ID, RequestID: requestID, CreatedAt: now,
		})
	})
	return session, err
}

func (u *UseCase) authorizeConnect(
	ctx context.Context, principal security.Principal, session TerminalSession,
) error {
	if principal.OrganizationID != session.OrganizationID {
		return ErrInvalidTicket
	}
	role := principal.Role
	if session.Kind == KindContainer {
		if principal.Role != security.RoleOwner {
			resolved, err := u.sessionRole(ctx, principal, session)
			if err != nil {
				return err
			}
			role = resolved
		}
		principal.Role = role
		if err := principal.Require(security.PermissionTerminalContainerOpen); err != nil {
			return err
		}
		target, err := u.targets.ResolveContainer(
			ctx, session.OrganizationID, session.ProjectID, session.DeploymentID,
		)
		if err != nil {
			return err
		}
		if target.RunningInstanceID != session.RunningInstanceID ||
			target.InstanceGeneration != session.InstanceGeneration ||
			target.RuntimeTargetID != session.RuntimeTargetID ||
			target.ManagedHostID != session.ManagedHostID {
			return ErrTargetUnavailable
		}
		policy, err := u.effectiveProjectPolicy(ctx, session.OrganizationID, session.ProjectID)
		if err != nil {
			return err
		}
		if !policy.AllowsContainer(role, target.EnvironmentStage, target.RuntimeTargetID) {
			return ErrAccessDenied
		}
		return nil
	}
	principal.Role = role
	if err := principal.Require(security.PermissionTerminalHostOpen); err != nil {
		return err
	}
	target, err := u.targets.ResolveHost(ctx, session.OrganizationID, session.ManagedHostID)
	if err != nil {
		return err
	}
	if target.ConnectionMode != session.ConnectionMode {
		return ErrTargetUnavailable
	}
	policy, err := u.effectiveOrganizationPolicy(ctx, session.OrganizationID)
	if err != nil {
		return err
	}
	if !policy.AllowsHost(role, session.ManagedHostID) {
		return ErrAccessDenied
	}
	return nil
}

type TargetResolver interface {
	ProjectExists(context.Context, string, string) (bool, error)
	ResolveContainer(context.Context, string, string, string) (Target, error)
	ResolveHost(context.Context, string, string) (Target, error)
}

type ProjectRoleResolver interface {
	ResolveTerminalProjectRole(context.Context, string, string, string) (security.Role, error)
}

type TicketTokens interface {
	New() (string, string, error)
	Hash(string) string
}

type UseCase struct {
	policies     PolicyRepository
	sessions     SessionRepository
	targets      TargetResolver
	projectRoles ProjectRoleResolver
	principals   PrincipalResolver
	containers   ContainerGateway
	hosts        HostGateway
	transaction  transaction.Manager
	audit        sharedaudit.Recorder
	tickets      TicketTokens
	newID        func() (string, error)
	now          func() time.Time
}

func (u *UseCase) WithContainerGateway(gateway ContainerGateway) *UseCase {
	u.containers = gateway
	return u
}

func (u *UseCase) WithHostGateway(gateway HostGateway) *UseCase {
	u.hosts = gateway
	return u
}

func (u *UseCase) WithPrincipalResolver(resolver PrincipalResolver) *UseCase {
	u.principals = resolver
	return u
}

// ReviewConnectedSession revalidates an open terminal against authoritative
// session, login, role, policy and target state. It is intentionally read-only:
// the streaming transport closes and persists the final lifecycle transition.
func (u *UseCase) ReviewConnectedSession(
	ctx context.Context,
	connected TerminalSession,
) (ConnectionReview, error) {
	if u.principals == nil {
		return ConnectionReview{}, ErrTerminalUnavailable
	}
	current, err := u.sessions.GetSession(
		ctx,
		connected.OrganizationID,
		connected.ID,
	)
	if err != nil {
		return ConnectionReview{}, err
	}
	if current.OrganizationID != connected.OrganizationID ||
		current.ActorID != connected.ActorID || current.Kind != connected.Kind ||
		current.ManagedHostID != connected.ManagedHostID ||
		current.RuntimeTargetID != connected.RuntimeTargetID ||
		current.DeploymentID != connected.DeploymentID ||
		current.RunningInstanceID != connected.RunningInstanceID ||
		current.InstanceGeneration != connected.InstanceGeneration ||
		current.ConnectionMode != connected.ConnectionMode {
		return ConnectionReview{}, ErrSessionNotFound
	}
	if current.Status != StatusOpen {
		reason := current.CloseReason
		if !reason.Valid() {
			reason = CloseReasonUserRequested
		}
		return ConnectionReview{Terminate: true, Reason: reason}, nil
	}
	policy, err := u.connectedSessionPolicy(ctx, current)
	if err != nil {
		return ConnectionReview{}, err
	}
	principal, err := u.principals.ResolveTerminalPrincipal(
		ctx,
		current.OrganizationID,
		current.ActorID,
		current.AuthenticationSessionID,
	)
	if err != nil || !principal.Valid() ||
		principal.OrganizationID != current.OrganizationID ||
		principal.UserID != current.ActorID ||
		principal.SessionID != current.AuthenticationSessionID {
		return permissionRevokedReview(policy), nil
	}
	if err := u.authorizeConnect(ctx, principal, current); err != nil {
		switch {
		case errors.Is(err, ErrTargetNotFound), errors.Is(err, ErrTargetUnavailable):
			return ConnectionReview{
				Terminate: true,
				Reason:    CloseReasonTargetUnavailable,
			}, nil
		case errors.Is(err, ErrAccessDenied), errors.Is(err, ErrSessionNotFound),
			errors.Is(err, security.ErrForbidden),
			errors.Is(err, security.ErrUnauthenticated):
			return permissionRevokedReview(policy), nil
		default:
			return ConnectionReview{}, err
		}
	}
	return ConnectionReview{}, nil
}

func (u *UseCase) connectedSessionPolicy(
	ctx context.Context,
	session TerminalSession,
) (AccessPolicy, error) {
	if session.Kind == KindContainer {
		return u.effectiveProjectPolicy(
			ctx,
			session.OrganizationID,
			session.ProjectID,
		)
	}
	return u.effectiveOrganizationPolicy(ctx, session.OrganizationID)
}

func permissionRevokedReview(policy AccessPolicy) ConnectionReview {
	return ConnectionReview{
		Terminate:   true,
		Reason:      CloseReasonPermissionRevoked,
		GracePeriod: policy.RevocationGracePeriod,
	}
}

// ConnectContainerWithTicket is the browser WSS entry point. The one-time
// path-scoped cookie proves possession of the TerminalSession credential; the
// login session bound at creation is resolved again so logout/revocation takes
// effect without exposing the Bearer token to the WebSocket handshake.
func (u *UseCase) ConnectContainerWithTicket(
	ctx context.Context,
	sessionID, rawTicket, requestID string,
	size TerminalSize,
) (TerminalSession, TerminalStream, error) {
	if u.principals == nil {
		return TerminalSession{}, nil, ErrTerminalUnavailable
	}
	session, err := u.sessions.GetSessionForConnect(ctx, strings.TrimSpace(sessionID))
	if err != nil {
		return TerminalSession{}, nil, ErrInvalidTicket
	}
	principal, err := u.principals.ResolveTerminalPrincipal(
		ctx,
		session.OrganizationID,
		session.ActorID,
		session.AuthenticationSessionID,
	)
	if err != nil || !principal.Valid() ||
		principal.OrganizationID != session.OrganizationID ||
		principal.UserID != session.ActorID ||
		principal.SessionID != session.AuthenticationSessionID {
		return TerminalSession{}, nil, ErrInvalidTicket
	}
	return u.ConnectContainer(ctx, principal, session.ID, rawTicket, requestID, size)
}

// ConnectWithTicket is the shared browser WSS entry point. The persisted
// TerminalSession kind selects a server-configured gateway; the caller cannot
// switch a container session into a host shell or vice versa.
func (u *UseCase) ConnectWithTicket(
	ctx context.Context,
	sessionID, rawTicket, requestID string,
	size TerminalSize,
) (TerminalSession, TerminalStream, error) {
	if u.principals == nil {
		return TerminalSession{}, nil, ErrTerminalUnavailable
	}
	session, err := u.sessions.GetSessionForConnect(ctx, strings.TrimSpace(sessionID))
	if err != nil {
		return TerminalSession{}, nil, ErrInvalidTicket
	}
	principal, err := u.principals.ResolveTerminalPrincipal(
		ctx,
		session.OrganizationID,
		session.ActorID,
		session.AuthenticationSessionID,
	)
	if err != nil || !principal.Valid() ||
		principal.OrganizationID != session.OrganizationID ||
		principal.UserID != session.ActorID ||
		principal.SessionID != session.AuthenticationSessionID {
		return TerminalSession{}, nil, ErrInvalidTicket
	}
	return u.Connect(ctx, principal, session.ID, rawTicket, requestID, size)
}

func (u *UseCase) Connect(
	ctx context.Context,
	principal security.Principal,
	sessionID, rawTicket, requestID string,
	size TerminalSize,
) (TerminalSession, TerminalStream, error) {
	if err := size.Validate(); err != nil {
		return TerminalSession{}, nil, err
	}
	connected, err := u.ConnectSession(ctx, principal, sessionID, rawTicket, requestID)
	if err != nil {
		return TerminalSession{}, nil, err
	}
	var target Target
	switch connected.Kind {
	case KindContainer:
		if u.containers == nil {
			err = ErrTerminalUnavailable
			break
		}
		target, err = u.targets.ResolveContainer(
			ctx, connected.OrganizationID, connected.ProjectID, connected.DeploymentID,
		)
		if err == nil && !sessionMatchesTarget(connected, target) {
			err = ErrTargetUnavailable
		}
		if err == nil {
			var stream TerminalStream
			stream, err = u.containers.OpenContainer(ctx, connected.ID, target, size)
			if err == nil {
				return connected.Redacted(), stream, nil
			}
		}
	case KindHost:
		if u.hosts == nil {
			err = ErrTerminalUnavailable
			break
		}
		target, err = u.targets.ResolveHost(
			ctx, connected.OrganizationID, connected.ManagedHostID,
		)
		if err == nil && !sessionMatchesTarget(connected, target) {
			err = ErrTargetUnavailable
		}
		if err == nil {
			var stream TerminalStream
			stream, err = u.hosts.OpenHost(ctx, connected.ID, target, size)
			if err == nil {
				return connected.Redacted(), stream, nil
			}
		}
	default:
		err = ErrTargetUnavailable
	}
	cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	cleanupError := u.failConnectedSession(cleanupContext, principal, connected, requestID, err)
	return connected.Redacted(), nil, errors.Join(err, cleanupError)
}

// ConnectContainer consumes the one-time ticket and only then opens the
// server-resolved runtime stream. A failed gateway connection is persisted as
// a failed session so consumed tickets never leave an apparently active row.
func (u *UseCase) ConnectContainer(
	ctx context.Context,
	principal security.Principal,
	sessionID, rawTicket, requestID string,
	size TerminalSize,
) (TerminalSession, TerminalStream, error) {
	if u.containers == nil {
		return TerminalSession{}, nil, ErrTerminalUnavailable
	}
	if err := size.Validate(); err != nil {
		return TerminalSession{}, nil, err
	}
	connected, err := u.ConnectSession(ctx, principal, sessionID, rawTicket, requestID)
	if err != nil {
		return TerminalSession{}, nil, err
	}
	if connected.Kind != KindContainer {
		err = ErrTargetUnavailable
	} else {
		var target Target
		target, err = u.targets.ResolveContainer(
			ctx, connected.OrganizationID, connected.ProjectID, connected.DeploymentID,
		)
		if err == nil && !sessionMatchesTarget(connected, target) {
			err = ErrTargetUnavailable
		}
		if err == nil {
			var stream TerminalStream
			stream, err = u.containers.OpenContainer(ctx, connected.ID, target, size)
			if err == nil {
				return connected.Redacted(), stream, nil
			}
		}
	}
	cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	cleanupError := u.failConnectedSession(cleanupContext, principal, connected, requestID, err)
	return connected.Redacted(), nil, errors.Join(err, cleanupError)
}

func sessionMatchesTarget(session TerminalSession, target Target) bool {
	if session.Kind == KindHost {
		return target.Kind == KindHost &&
			target.OrganizationID == session.OrganizationID &&
			target.ManagedHostID == session.ManagedHostID &&
			target.ConnectionMode == session.ConnectionMode
	}
	return target.Kind == KindContainer &&
		target.OrganizationID == session.OrganizationID &&
		target.ProjectID == session.ProjectID &&
		target.ManagedHostID == session.ManagedHostID &&
		target.RuntimeTargetID == session.RuntimeTargetID &&
		target.DeploymentID == session.DeploymentID &&
		target.RunningInstanceID == session.RunningInstanceID &&
		target.InstanceGeneration == session.InstanceGeneration &&
		target.ConnectionMode == session.ConnectionMode
}

func (u *UseCase) failConnectedSession(
	ctx context.Context,
	principal security.Principal,
	session TerminalSession,
	requestID string,
	cause error,
) error {
	reason, safeCode := CloseReasonConnectionFailed, "terminal_connection_failed"
	if errors.Is(cause, ErrTargetUnavailable) {
		reason, safeCode = CloseReasonTargetUnavailable, "terminal_target_unavailable"
	}
	failed, err := session.Close(reason, safeCode, u.now().UTC())
	if err != nil {
		return err
	}
	auditID, err := u.newID()
	if err != nil {
		return err
	}
	return u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		saved, saveErr := u.sessions.SaveSession(transactionContext, failed, session.Version)
		if saveErr != nil {
			return saveErr
		}
		failed = saved
		return u.audit.Record(transactionContext, sharedaudit.Event{
			ID: auditID, OrganizationID: session.OrganizationID,
			ProjectID: session.ProjectID, ActorID: principal.UserID,
			Action: "terminal_session.fail", ResourceType: "terminal_session",
			ResourceID: session.ID, RequestID: requestID, CreatedAt: failed.EndedAt,
		})
	})
}

// CloseConnectedSession is used by the trusted streaming transport after it
// has stopped forwarding bytes. It persists only lifecycle metadata and never
// receives terminal payloads.
func (u *UseCase) CloseConnectedSession(
	ctx context.Context,
	session TerminalSession,
	reason CloseReason,
	safeErrorCode, requestID string,
) (TerminalSession, error) {
	current, err := u.sessions.GetSession(ctx, session.OrganizationID, session.ID)
	if err != nil {
		return TerminalSession{}, err
	}
	if current.ActorID != session.ActorID || current.Kind != session.Kind {
		return TerminalSession{}, ErrSessionNotFound
	}
	closed, err := current.Close(reason, safeErrorCode, u.now().UTC())
	if err != nil {
		return TerminalSession{}, err
	}
	if closed.Version == current.Version {
		return closed.Redacted(), nil
	}
	auditID, err := u.newID()
	if err != nil {
		return TerminalSession{}, err
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		saved, saveErr := u.sessions.SaveSession(transactionContext, closed, current.Version)
		if saveErr != nil {
			return saveErr
		}
		closed = saved
		return u.audit.Record(transactionContext, sharedaudit.Event{
			ID: auditID, OrganizationID: current.OrganizationID,
			ProjectID: current.ProjectID, ActorID: current.ActorID,
			Action: "terminal_session.close", ResourceType: "terminal_session",
			ResourceID: current.ID, RequestID: requestID, CreatedAt: closed.EndedAt,
		})
	})
	return closed.Redacted(), err
}

func NewUseCase(
	policies PolicyRepository,
	sessions SessionRepository,
	targets TargetResolver,
	projectRoles ProjectRoleResolver,
	transaction transaction.Manager,
	audit sharedaudit.Recorder,
	tickets TicketTokens,
	newID func() (string, error),
	now func() time.Time,
) (*UseCase, error) {
	if policies == nil || sessions == nil || targets == nil || projectRoles == nil ||
		transaction == nil || audit == nil || tickets == nil || newID == nil || now == nil {
		return nil, ErrTerminalUnavailable
	}
	return &UseCase{
		policies: policies, sessions: sessions, targets: targets,
		projectRoles: projectRoles, transaction: transaction, audit: audit,
		tickets: tickets, newID: newID, now: now,
	}, nil
}

func (u *UseCase) GetProjectPolicy(
	ctx context.Context, principal security.Principal, projectID string,
) (AccessPolicy, error) {
	if err := principal.Require(security.PermissionTerminalContainerOpen); err != nil {
		return AccessPolicy{}, err
	}
	projectID = strings.TrimSpace(projectID)
	if !validIdentifier(projectID) {
		return AccessPolicy{}, ErrTargetNotFound
	}
	exists, err := u.targets.ProjectExists(ctx, principal.OrganizationID, projectID)
	if err != nil {
		return AccessPolicy{}, err
	}
	if !exists {
		return AccessPolicy{}, ErrTargetNotFound
	}
	policy, err := u.policies.GetProjectPolicy(ctx, principal.OrganizationID, projectID)
	if errors.Is(err, ErrPolicyNotFound) {
		return DefaultProjectPolicy(principal.OrganizationID, projectID), nil
	}
	return policy, err
}

func (u *UseCase) GetOrganizationPolicy(
	ctx context.Context, principal security.Principal,
) (AccessPolicy, error) {
	if principal.Role != security.RoleOwner {
		return AccessPolicy{}, security.ErrForbidden
	}
	policy, err := u.policies.GetOrganizationPolicy(ctx, principal.OrganizationID)
	if errors.Is(err, ErrPolicyNotFound) {
		return DefaultOrganizationPolicy(principal.OrganizationID), nil
	}
	return policy, err
}

func (u *UseCase) SaveProjectPolicy(
	ctx context.Context,
	principal security.Principal,
	projectID string,
	input PolicyInput,
	expectedVersion uint64,
	requestID string,
) (AccessPolicy, error) {
	if err := principal.Require(security.PermissionTerminalPolicyManage); err != nil {
		return AccessPolicy{}, err
	}
	projectID = strings.TrimSpace(projectID)
	exists, err := u.targets.ProjectExists(ctx, principal.OrganizationID, projectID)
	if err != nil {
		return AccessPolicy{}, err
	}
	if !exists {
		return AccessPolicy{}, ErrTargetNotFound
	}
	return u.savePolicy(ctx, principal, PolicyScopeProject, projectID, input, expectedVersion, requestID)
}

func (u *UseCase) SaveOrganizationPolicy(
	ctx context.Context,
	principal security.Principal,
	input PolicyInput,
	expectedVersion uint64,
	requestID string,
) (AccessPolicy, error) {
	if principal.Role != security.RoleOwner {
		return AccessPolicy{}, security.ErrForbidden
	}
	return u.savePolicy(ctx, principal, PolicyScopeOrganization, "", input, expectedVersion, requestID)
}

func (u *UseCase) savePolicy(
	ctx context.Context,
	principal security.Principal,
	scope PolicyScope,
	projectID string,
	input PolicyInput,
	expectedVersion uint64,
	requestID string,
) (AccessPolicy, error) {
	now := u.now().UTC()
	current, err := u.loadPolicy(ctx, principal.OrganizationID, projectID, scope)
	if err != nil && !errors.Is(err, ErrPolicyNotFound) {
		return AccessPolicy{}, err
	}
	var policy AccessPolicy
	if errors.Is(err, ErrPolicyNotFound) {
		if expectedVersion != 0 {
			return AccessPolicy{}, ErrPolicyConflict
		}
		policyID, idErr := u.newID()
		if idErr != nil {
			return AccessPolicy{}, idErr
		}
		if scope == PolicyScopeProject {
			policy, err = NewProjectPolicy(
				policyID, principal.OrganizationID, projectID, principal.UserID, input, now,
			)
		} else {
			policy, err = NewOrganizationPolicy(
				policyID, principal.OrganizationID, principal.UserID, input, now,
			)
		}
	} else {
		if current.Version != expectedVersion {
			return AccessPolicy{}, ErrPolicyConflict
		}
		policy, err = current.Change(input, principal.UserID, now)
	}
	if err != nil {
		return AccessPolicy{}, err
	}
	auditID, err := u.newID()
	if err != nil {
		return AccessPolicy{}, err
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		saved, saveErr := u.policies.SavePolicy(transactionContext, policy, expectedVersion)
		if saveErr != nil {
			return saveErr
		}
		policy = saved
		return u.audit.Record(transactionContext, sharedaudit.Event{
			ID: auditID, OrganizationID: principal.OrganizationID,
			ProjectID: projectID, ActorID: principal.UserID,
			Action: "terminal_policy.update", ResourceType: "terminal_policy",
			ResourceID: policy.ID, RequestID: requestID, CreatedAt: now,
		})
	})
	return policy, err
}

func (u *UseCase) CreateContainerSession(
	ctx context.Context,
	principal security.Principal,
	projectID, deploymentID, clientIP, userAgent, requestID string,
) (Credential, error) {
	if err := principal.Require(security.PermissionTerminalContainerOpen); err != nil {
		return Credential{}, err
	}
	target, err := u.targets.ResolveContainer(
		ctx, principal.OrganizationID, strings.TrimSpace(projectID), strings.TrimSpace(deploymentID),
	)
	if err != nil {
		return Credential{}, err
	}
	if target.Kind != KindContainer || target.OrganizationID != principal.OrganizationID ||
		target.ProjectID != strings.TrimSpace(projectID) {
		return Credential{}, ErrTargetNotFound
	}
	policy, err := u.effectiveProjectPolicy(ctx, target.OrganizationID, target.ProjectID)
	if err != nil {
		return Credential{}, err
	}
	if !policy.AllowsContainer(principal.Role, target.EnvironmentStage, target.RuntimeTargetID) {
		return Credential{}, ErrAccessDenied
	}
	return u.createSession(ctx, principal, target, policy, clientIP, userAgent, requestID)
}

func (u *UseCase) CreateHostSession(
	ctx context.Context,
	principal security.Principal,
	managedHostID, clientIP, userAgent, requestID string,
) (Credential, error) {
	if err := principal.Require(security.PermissionTerminalHostOpen); err != nil {
		return Credential{}, err
	}
	target, err := u.targets.ResolveHost(
		ctx, principal.OrganizationID, strings.TrimSpace(managedHostID),
	)
	if err != nil {
		return Credential{}, err
	}
	if target.Kind != KindHost || target.OrganizationID != principal.OrganizationID {
		return Credential{}, ErrTargetNotFound
	}
	policy, err := u.effectiveOrganizationPolicy(ctx, target.OrganizationID)
	if err != nil {
		return Credential{}, err
	}
	if !policy.AllowsHost(principal.Role, target.ManagedHostID) {
		return Credential{}, ErrAccessDenied
	}
	return u.createSession(ctx, principal, target, policy, clientIP, userAgent, requestID)
}

func (u *UseCase) createSession(
	ctx context.Context,
	principal security.Principal,
	target Target,
	policy AccessPolicy,
	clientIP, userAgent, requestID string,
) (Credential, error) {
	sessionID, err := u.newID()
	if err != nil {
		return Credential{}, err
	}
	auditID, err := u.newID()
	if err != nil {
		return Credential{}, err
	}
	rawTicket, ticketHash, err := u.tickets.New()
	if err != nil {
		return Credential{}, err
	}
	now := u.now().UTC()
	session, err := NewTerminalSession(
		sessionID, principal.UserID, principal.SessionID, ticketHash, clientIP, userAgent, requestID,
		target, policy, now,
	)
	if err != nil {
		return Credential{}, err
	}
	for userSlot := 1; userSlot <= policy.MaximumPerUser; userSlot++ {
		for targetSlot := 1; targetSlot <= policy.MaximumPerTarget; targetSlot++ {
			candidate := session
			candidate.UserConcurrencySlot = userSlot
			candidate.TargetConcurrencySlot = targetSlot
			err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
				created, createErr := u.sessions.CreateSession(transactionContext, candidate)
				if createErr != nil {
					return createErr
				}
				candidate = created
				return u.audit.Record(transactionContext, sharedaudit.Event{
					ID: auditID, OrganizationID: principal.OrganizationID,
					ProjectID: target.ProjectID, ActorID: principal.UserID,
					Action: "terminal_session.create", ResourceType: "terminal_session",
					ResourceID: candidate.ID, RequestID: requestID, CreatedAt: now,
				})
			})
			if errors.Is(err, ErrSessionSlotConflict) {
				continue
			}
			if err != nil {
				return Credential{}, err
			}
			return Credential{
				Session: candidate.Redacted(), Ticket: rawTicket,
				ExpiresAt: candidate.TicketExpiresAt,
			}, nil
		}
	}
	return Credential{}, ErrSessionLimit
}

func (u *UseCase) GetSession(
	ctx context.Context,
	principal security.Principal,
	sessionID string,
) (TerminalSession, error) {
	session, err := u.sessions.GetSession(ctx, principal.OrganizationID, strings.TrimSpace(sessionID))
	if err != nil {
		return TerminalSession{}, err
	}
	if err := u.authorizeRead(ctx, principal, session); err != nil {
		return TerminalSession{}, err
	}
	return session.Redacted(), nil
}

func (u *UseCase) TerminateSession(
	ctx context.Context,
	principal security.Principal,
	sessionID, requestID string,
) (TerminalSession, error) {
	session, err := u.sessions.GetSession(ctx, principal.OrganizationID, strings.TrimSpace(sessionID))
	if err != nil {
		return TerminalSession{}, err
	}
	reason := CloseReasonAdministratorTerminated
	if session.ActorID == principal.UserID {
		reason = CloseReasonUserRequested
	} else if err := u.authorizeTerminateOther(ctx, principal, session); err != nil {
		return TerminalSession{}, err
	}
	now := u.now().UTC()
	updated, err := session.RequestTermination(reason, now)
	if err != nil {
		return TerminalSession{}, err
	}
	if updated.Version == session.Version {
		return updated.Redacted(), nil
	}
	auditID, err := u.newID()
	if err != nil {
		return TerminalSession{}, err
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		saved, saveErr := u.sessions.SaveSession(transactionContext, updated, session.Version)
		if saveErr != nil {
			return saveErr
		}
		updated = saved
		return u.audit.Record(transactionContext, sharedaudit.Event{
			ID: auditID, OrganizationID: principal.OrganizationID,
			ProjectID: session.ProjectID, ActorID: principal.UserID,
			Action: "terminal_session.terminate", ResourceType: "terminal_session",
			ResourceID: session.ID, RequestID: requestID, CreatedAt: now,
		})
	})
	return updated.Redacted(), err
}

func (u *UseCase) authorizeRead(
	ctx context.Context, principal security.Principal, session TerminalSession,
) error {
	if principal.OrganizationID != session.OrganizationID {
		return ErrSessionNotFound
	}
	if principal.Role == security.RoleOwner {
		return nil
	}
	role, err := u.sessionRole(ctx, principal, session)
	if err != nil {
		return err
	}
	if session.ActorID != principal.UserID && role != security.RoleMaintainer {
		return security.ErrForbidden
	}
	principal.Role = role
	return principal.Require(security.PermissionTerminalSessionRead)
}

func (u *UseCase) authorizeTerminateOther(
	ctx context.Context, principal security.Principal, session TerminalSession,
) error {
	if principal.OrganizationID != session.OrganizationID {
		return ErrSessionNotFound
	}
	if principal.Role == security.RoleOwner {
		return nil
	}
	role, err := u.sessionRole(ctx, principal, session)
	if err != nil {
		return err
	}
	if role != security.RoleMaintainer {
		return security.ErrForbidden
	}
	principal.Role = role
	return principal.Require(security.PermissionTerminalSessionTerminate)
}

func (u *UseCase) sessionRole(
	ctx context.Context, principal security.Principal, session TerminalSession,
) (security.Role, error) {
	if session.ProjectID == "" {
		return principal.Role, nil
	}
	role, err := u.projectRoles.ResolveTerminalProjectRole(
		ctx, principal.OrganizationID, session.ProjectID, principal.UserID,
	)
	if errors.Is(err, ErrTargetNotFound) {
		return "", ErrSessionNotFound
	}
	return role, err
}

func (u *UseCase) loadPolicy(
	ctx context.Context, organizationID, projectID string, scope PolicyScope,
) (AccessPolicy, error) {
	if scope == PolicyScopeProject {
		return u.policies.GetProjectPolicy(ctx, organizationID, projectID)
	}
	return u.policies.GetOrganizationPolicy(ctx, organizationID)
}

func (u *UseCase) effectiveProjectPolicy(
	ctx context.Context, organizationID, projectID string,
) (AccessPolicy, error) {
	policy, err := u.policies.GetProjectPolicy(ctx, organizationID, projectID)
	if errors.Is(err, ErrPolicyNotFound) {
		return DefaultProjectPolicy(organizationID, projectID), nil
	}
	return policy, err
}

func (u *UseCase) effectiveOrganizationPolicy(
	ctx context.Context, organizationID string,
) (AccessPolicy, error) {
	policy, err := u.policies.GetOrganizationPolicy(ctx, organizationID)
	if errors.Is(err, ErrPolicyNotFound) {
		return DefaultOrganizationPolicy(organizationID), nil
	}
	return policy, err
}
