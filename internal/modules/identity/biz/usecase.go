package biz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/security"
	"github.com/owndock/owndock/internal/shared/transaction"
)

type IDGenerator func() (string, error)
type Clock func() time.Time

type Credentials struct {
	AccessToken  string
	ExpiresAt    time.Time
	User         User
	Organization Organization
}

type UseCase struct {
	repository    Repository
	transaction   transaction.Manager
	audit         sharedaudit.Recorder
	passwords     PasswordHasher
	tokens        SessionTokens
	newID         IDGenerator
	now           Clock
	sessionTTL    time.Duration
	loginGuard    LoginGuard
	loginLimit    int
	loginWindow   time.Duration
	maxSessions   int
	invitationTTL time.Duration
	invitations   UserInvitationRepository
	adminSessions AdministrativeSessionRepository
}

func (u *UseCase) WithAdministrativeSessions(repository AdministrativeSessionRepository) *UseCase {
	u.adminSessions = repository
	return u
}

func NewUseCase(
	repository Repository,
	transaction transaction.Manager,
	auditRecorder sharedaudit.Recorder,
	passwords PasswordHasher,
	tokens SessionTokens,
	newID IDGenerator,
	now Clock,
	sessionTTL time.Duration,
) *UseCase {
	return &UseCase{
		repository: repository, transaction: transaction, audit: auditRecorder,
		passwords: passwords, tokens: tokens, newID: newID, now: now, sessionTTL: sessionTTL,
	}
}

func (u *UseCase) WithLoginProtection(
	guard LoginGuard,
	limit int,
	window time.Duration,
) *UseCase {
	u.loginGuard = guard
	u.loginLimit = limit
	u.loginWindow = window
	return u
}

func (u *UseCase) WithSessionPolicy(maximumActive int) *UseCase {
	u.maxSessions = maximumActive
	return u
}

func (u *UseCase) WithInvitationPolicy(repository UserInvitationRepository, ttl time.Duration) *UseCase {
	u.invitations, u.invitationTTL = repository, ttl
	return u
}

func (u *UseCase) ListUsers(ctx context.Context, principal security.Principal) ([]User, error) {
	if err := principal.Require(security.PermissionOrganizationManage); err != nil {
		return nil, err
	}
	if u.invitations == nil {
		return nil, ErrInvalidInvitation
	}
	items, err := u.invitations.ListUsers(ctx, principal.OrganizationID)
	for index := range items {
		items[index].PasswordHash = ""
	}
	return items, err
}

func (u *UseCase) CreateInvitation(ctx context.Context, principal security.Principal,
	email, requestID string) (InvitationCredential, error) {
	if err := principal.Require(security.PermissionOrganizationManage); err != nil {
		return InvitationCredential{}, err
	}
	if u.invitationTTL < time.Minute || u.invitationTTL > 7*24*time.Hour {
		return InvitationCredential{}, ErrInvalidInvitation
	}
	if u.invitations == nil {
		return InvitationCredential{}, ErrInvalidInvitation
	}
	normalized, err := normalizeEmail(email)
	if err != nil {
		return InvitationCredential{}, err
	}
	if _, err := u.repository.FindUserByEmail(ctx, normalized); err == nil {
		return InvitationCredential{}, ErrUserAlreadyExists
	} else if !errors.Is(err, ErrNotFound) {
		return InvitationCredential{}, err
	}
	raw, tokenHash, err := u.tokens.New()
	if err != nil {
		return InvitationCredential{}, err
	}
	id, err := u.newID()
	if err != nil {
		return InvitationCredential{}, err
	}
	auditID, err := u.newID()
	if err != nil {
		return InvitationCredential{}, err
	}
	now := u.now().UTC()
	item, err := NewInvitation(id, principal.OrganizationID, normalized, tokenHash,
		principal.UserID, now, u.invitationTTL)
	if err != nil {
		return InvitationCredential{}, err
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		created, createErr := u.invitations.CreateInvitation(transactionContext, item)
		if createErr != nil {
			return createErr
		}
		item = created
		return u.audit.Record(transactionContext, sharedaudit.Event{
			ID: auditID, OrganizationID: principal.OrganizationID, ActorID: principal.UserID,
			Action: "identity.invitation_create", ResourceType: "user_invitation", ResourceID: item.ID,
			RequestID: requestID, CreatedAt: now,
		})
	})
	if err != nil {
		return InvitationCredential{}, err
	}
	return InvitationCredential{Invitation: item.Safe(), Token: raw}, nil
}

func (u *UseCase) ListInvitations(ctx context.Context, principal security.Principal) ([]Invitation, error) {
	if err := principal.Require(security.PermissionOrganizationManage); err != nil {
		return nil, err
	}
	if u.invitations == nil {
		return nil, ErrInvalidInvitation
	}
	items, err := u.invitations.ListInvitations(ctx, principal.OrganizationID)
	for index := range items {
		items[index] = items[index].Safe()
	}
	return items, err
}

func (u *UseCase) RevokeInvitation(ctx context.Context, principal security.Principal,
	invitationID, requestID string) (Invitation, error) {
	if err := principal.Require(security.PermissionOrganizationManage); err != nil {
		return Invitation{}, err
	}
	if u.invitations == nil {
		return Invitation{}, ErrInvalidInvitation
	}
	item, err := u.invitations.GetInvitation(ctx, principal.OrganizationID, strings.TrimSpace(invitationID))
	if err != nil {
		return Invitation{}, err
	}
	if item.Status == InvitationStatusRevoked {
		return item.Safe(), nil
	}
	now := u.now().UTC()
	updated, err := item.Revoke(principal.UserID, now)
	if err != nil {
		return Invitation{}, err
	}
	auditID, err := u.newID()
	if err != nil {
		return Invitation{}, err
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		var updateErr error
		updated, updateErr = u.invitations.RevokeInvitation(transactionContext, updated, item.Version)
		if updateErr != nil {
			return updateErr
		}
		return u.audit.Record(transactionContext, sharedaudit.Event{
			ID: auditID, OrganizationID: principal.OrganizationID, ActorID: principal.UserID,
			Action: "identity.invitation_revoke", ResourceType: "user_invitation", ResourceID: item.ID,
			RequestID: requestID, CreatedAt: now,
		})
	})
	return updated.Safe(), err
}

func (u *UseCase) AcceptInvitation(ctx context.Context, rawToken, password,
	requestID string) (Credentials, error) {
	rawToken = strings.TrimSpace(rawToken)
	if len(rawToken) < 32 || len(rawToken) > 256 || u.maxSessions < 1 || u.invitations == nil {
		return Credentials{}, ErrInvalidInvitation
	}
	if err := ValidatePassword(password); err != nil {
		return Credentials{}, err
	}
	now := u.now().UTC()
	invitation, err := u.invitations.FindInvitationByTokenHash(ctx, u.tokens.Hash(rawToken), now)
	if err != nil {
		if errors.Is(err, ErrInvalidInvitation) || errors.Is(err, ErrNotFound) {
			return Credentials{}, ErrInvalidInvitation
		}
		return Credentials{}, err
	}
	passwordHash, err := u.passwords.Hash(password)
	if err != nil {
		return Credentials{}, err
	}
	userID, err := u.newID()
	if err != nil {
		return Credentials{}, err
	}
	sessionID, err := u.newID()
	if err != nil {
		return Credentials{}, err
	}
	auditID, err := u.newID()
	if err != nil {
		return Credentials{}, err
	}
	user, err := NewInvitedUser(userID, invitation.OrganizationID, invitation.Email,
		passwordHash, now)
	if err != nil {
		return Credentials{}, ErrInvalidInvitation
	}
	rawSession, sessionHash, err := u.tokens.New()
	if err != nil {
		return Credentials{}, err
	}
	session := Session{ID: sessionID, UserID: user.ID, TokenHash: sessionHash,
		CreatedAt: now, ExpiresAt: now.Add(u.sessionTTL)}
	accepted, err := invitation.Accept(user.ID, now)
	if err != nil {
		return Credentials{}, ErrInvalidInvitation
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		if acceptErr := u.invitations.AcceptInvitation(transactionContext, accepted,
			invitation.Version, user, session); acceptErr != nil {
			return acceptErr
		}
		return u.audit.Record(transactionContext, sharedaudit.Event{
			ID: auditID, OrganizationID: invitation.OrganizationID, ActorID: user.ID,
			Action: "identity.invitation_accept", ResourceType: "user", ResourceID: user.ID,
			RequestID: requestID, CreatedAt: now,
		})
	})
	if err != nil {
		if errors.Is(err, ErrInvalidInvitation) || errors.Is(err, ErrUserAlreadyExists) {
			return Credentials{}, ErrInvalidInvitation
		}
		return Credentials{}, err
	}
	user.PasswordHash = ""
	return Credentials{AccessToken: rawSession, ExpiresAt: session.ExpiresAt, User: user}, nil
}

func (u *UseCase) Bootstrap(ctx context.Context, organizationName, email, password, requestID string) (Credentials, error) {
	if err := ValidatePassword(password); err != nil {
		return Credentials{}, err
	}
	passwordHash, err := u.passwords.Hash(password)
	if err != nil {
		return Credentials{}, err
	}
	now := u.now().UTC()
	organizationID, err := u.newID()
	if err != nil {
		return Credentials{}, err
	}
	userID, err := u.newID()
	if err != nil {
		return Credentials{}, err
	}
	sessionID, err := u.newID()
	if err != nil {
		return Credentials{}, err
	}
	auditID, err := u.newID()
	if err != nil {
		return Credentials{}, err
	}
	organization, err := NewOrganization(organizationID, organizationName, now)
	if err != nil {
		return Credentials{}, err
	}
	user, err := NewOwner(userID, organization.ID, email, passwordHash, now)
	if err != nil {
		return Credentials{}, err
	}
	rawToken, tokenHash, err := u.tokens.New()
	if err != nil {
		return Credentials{}, err
	}
	session := Session{
		ID: sessionID, UserID: user.ID, TokenHash: tokenHash,
		CreatedAt: now, ExpiresAt: now.Add(u.sessionTTL),
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		hasUsers, err := u.repository.HasUsers(transactionContext)
		if err != nil {
			return err
		}
		if hasUsers {
			return ErrAlreadyBootstrapped
		}
		if err := u.repository.CreateBootstrap(transactionContext, organization, user, session); err != nil {
			return err
		}
		return u.audit.Record(transactionContext, sharedaudit.Event{
			ID: auditID, OrganizationID: organization.ID, ActorID: user.ID,
			Action: "identity.bootstrap", ResourceType: "organization", ResourceID: organization.ID,
			RequestID: requestID, CreatedAt: now,
		})
	})
	if err != nil {
		return Credentials{}, err
	}
	return Credentials{AccessToken: rawToken, ExpiresAt: session.ExpiresAt, User: user, Organization: organization}, nil
}

func (u *UseCase) Login(ctx context.Context, email, password, requestID string) (Credentials, error) {
	normalized, err := normalizeEmail(email)
	if err != nil {
		_ = u.passwords.Verify(password, u.passwords.DummyHash())
		return Credentials{}, ErrInvalidCredentials
	}
	if u.loginGuard == nil || u.loginLimit < 1 ||
		u.loginWindow <= 0 || u.maxSessions < 1 {
		return Credentials{}, ErrLoginGuardMissing
	}
	now := u.now().UTC()
	loginKey := loginAttemptKey(normalized)
	allowed, retryAt, err := u.loginGuard.ReserveLoginAttempt(
		ctx,
		loginKey,
		now,
		u.loginLimit,
		u.loginWindow,
	)
	if err != nil {
		return Credentials{}, err
	}
	if !allowed {
		_ = u.passwords.Verify(password, u.passwords.DummyHash())
		retryAfter := retryAt.Sub(now)
		if retryAfter < time.Second {
			retryAfter = time.Second
		}
		return Credentials{}, &LoginRateLimitError{
			RetryAfter: retryAfter,
		}
	}
	user, err := u.repository.FindUserByEmail(ctx, normalized)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			_ = u.passwords.Verify(password, u.passwords.DummyHash())
			return Credentials{}, ErrInvalidCredentials
		}
		return Credentials{}, err
	}
	if !u.passwords.Verify(password, user.PasswordHash) {
		return Credentials{}, ErrInvalidCredentials
	}
	if err := u.loginGuard.ResetLoginAttempts(ctx, loginKey); err != nil {
		return Credentials{}, err
	}
	sessionID, err := u.newID()
	if err != nil {
		return Credentials{}, err
	}
	auditID, err := u.newID()
	if err != nil {
		return Credentials{}, err
	}
	rawToken, tokenHash, err := u.tokens.New()
	if err != nil {
		return Credentials{}, err
	}
	session := Session{
		ID: sessionID, UserID: user.ID, TokenHash: tokenHash,
		CreatedAt: now, ExpiresAt: now.Add(u.sessionTTL),
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		if err := u.repository.CreateSession(
			transactionContext,
			session,
			now,
			u.maxSessions,
		); err != nil {
			return err
		}
		return u.audit.Record(transactionContext, sharedaudit.Event{
			ID: auditID, OrganizationID: user.OrganizationID, ActorID: user.ID,
			Action: "identity.login", ResourceType: "session", ResourceID: session.ID,
			RequestID: requestID, CreatedAt: now,
		})
	})
	if err != nil {
		return Credentials{}, err
	}
	return Credentials{AccessToken: rawToken, ExpiresAt: session.ExpiresAt, User: user}, nil
}

func (u *UseCase) ListSessions(
	ctx context.Context,
	principal security.Principal,
) ([]Session, error) {
	if !principal.Valid() {
		return nil, security.ErrUnauthenticated
	}
	items, err := u.repository.ListSessions(
		ctx,
		principal.UserID,
		u.now().UTC(),
	)
	for index := range items {
		items[index].TokenHash = ""
	}
	return items, err
}

func (u *UseCase) ListUserSessions(
	ctx context.Context, principal security.Principal, userID string,
) ([]Session, error) {
	if err := principal.Require(security.PermissionOrganizationManage); err != nil {
		return nil, err
	}
	userID = strings.TrimSpace(userID)
	if userID == "" || len(userID) > 128 || u.adminSessions == nil {
		return nil, ErrNotFound
	}
	if _, err := u.adminSessions.GetOrganizationUser(
		ctx, principal.OrganizationID, userID,
	); err != nil {
		return nil, err
	}
	items, err := u.adminSessions.ListSessions(ctx, userID, u.now().UTC())
	for index := range items {
		items[index].TokenHash = ""
	}
	return items, err
}

func (u *UseCase) RevokeUserSession(
	ctx context.Context, principal security.Principal, userID, sessionID, requestID string,
) error {
	if err := principal.Require(security.PermissionOrganizationManage); err != nil {
		return err
	}
	userID, sessionID = strings.TrimSpace(userID), strings.TrimSpace(sessionID)
	if userID == "" || sessionID == "" || len(userID) > 128 || len(sessionID) > 128 ||
		u.adminSessions == nil {
		return ErrNotFound
	}
	if userID == principal.UserID && sessionID == principal.SessionID {
		return ErrCannotRevokeCurrent
	}
	if _, err := u.adminSessions.GetOrganizationUser(
		ctx, principal.OrganizationID, userID,
	); err != nil {
		return err
	}
	auditID, err := u.newID()
	if err != nil {
		return err
	}
	now := u.now().UTC()
	return u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		if deleteErr := u.adminSessions.DeleteSession(transactionContext, sessionID, userID); deleteErr != nil {
			return deleteErr
		}
		return u.audit.Record(transactionContext, sharedaudit.Event{
			ID: auditID, OrganizationID: principal.OrganizationID, ActorID: principal.UserID,
			Action: "identity.session_revoke_admin", ResourceType: "session", ResourceID: sessionID,
			RequestID: requestID, CreatedAt: now,
		})
	})
}

func (u *UseCase) RevokeAllUserSessions(
	ctx context.Context, principal security.Principal, userID, requestID string,
) (int64, error) {
	if err := principal.Require(security.PermissionOrganizationManage); err != nil {
		return 0, err
	}
	userID = strings.TrimSpace(userID)
	if userID == "" || len(userID) > 128 || u.adminSessions == nil {
		return 0, ErrNotFound
	}
	if userID == principal.UserID {
		return 0, ErrCannotRevokeCurrent
	}
	if _, err := u.adminSessions.GetOrganizationUser(
		ctx, principal.OrganizationID, userID,
	); err != nil {
		return 0, err
	}
	auditID, err := u.newID()
	if err != nil {
		return 0, err
	}
	now := u.now().UTC()
	var revoked int64
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		var deleteErr error
		revoked, deleteErr = u.adminSessions.DeleteUserSessions(transactionContext, userID)
		if deleteErr != nil {
			return deleteErr
		}
		return u.audit.Record(transactionContext, sharedaudit.Event{
			ID: auditID, OrganizationID: principal.OrganizationID, ActorID: principal.UserID,
			Action: "identity.session_revoke_all_admin", ResourceType: "user", ResourceID: userID,
			RequestID: requestID, CreatedAt: now,
		})
	})
	return revoked, err
}

func (u *UseCase) RevokeSession(
	ctx context.Context,
	principal security.Principal,
	sessionID, requestID string,
) error {
	if !principal.Valid() {
		return security.ErrUnauthenticated
	}
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" || len(sessionID) > 128 {
		return ErrNotFound
	}
	auditID, err := u.newID()
	if err != nil {
		return err
	}
	now := u.now().UTC()
	return u.transaction.WithinTransaction(
		ctx,
		func(transactionContext context.Context) error {
			if err := u.repository.DeleteSession(
				transactionContext,
				sessionID,
				principal.UserID,
			); err != nil {
				return err
			}
			return u.audit.Record(
				transactionContext,
				sharedaudit.Event{
					ID:             auditID,
					OrganizationID: principal.OrganizationID,
					ActorID:        principal.UserID,
					Action:         "identity.session.revoke",
					ResourceType:   "session",
					ResourceID:     sessionID,
					RequestID:      requestID,
					CreatedAt:      now,
				},
			)
		},
	)
}

func loginAttemptKey(normalizedEmail string) string {
	sum := sha256.Sum256([]byte(normalizedEmail))
	return hex.EncodeToString(sum[:])
}

func (u *UseCase) Authenticate(ctx context.Context, rawToken string) (security.Principal, error) {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return security.Principal{}, security.ErrUnauthenticated
	}
	session, user, err := u.repository.FindSession(ctx, u.tokens.Hash(rawToken), u.now().UTC())
	if err != nil {
		return security.Principal{}, security.ErrUnauthenticated
	}
	principal := security.Principal{
		UserID: user.ID, OrganizationID: user.OrganizationID, Email: user.Email,
		Role: user.Role, SessionID: session.ID,
	}
	if !principal.Valid() {
		return security.Principal{}, security.ErrUnauthenticated
	}
	return principal, nil
}

func (u *UseCase) Logout(ctx context.Context, principal security.Principal, requestID string) error {
	if !principal.Valid() {
		return security.ErrUnauthenticated
	}
	auditID, err := u.newID()
	if err != nil {
		return err
	}
	now := u.now().UTC()
	return u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		if err := u.repository.DeleteSession(transactionContext, principal.SessionID, principal.UserID); err != nil &&
			!errors.Is(err, ErrNotFound) {
			return err
		}
		return u.audit.Record(transactionContext, sharedaudit.Event{
			ID: auditID, OrganizationID: principal.OrganizationID, ActorID: principal.UserID,
			Action: "identity.logout", ResourceType: "session", ResourceID: principal.SessionID,
			RequestID: requestID, CreatedAt: now,
		})
	})
}
