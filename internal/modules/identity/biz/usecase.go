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
	repository  Repository
	transaction transaction.Manager
	audit       sharedaudit.Recorder
	passwords   PasswordHasher
	tokens      SessionTokens
	newID       IDGenerator
	now         Clock
	sessionTTL  time.Duration
	loginGuard  LoginGuard
	loginLimit  int
	loginWindow time.Duration
	maxSessions int
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
	return u.repository.ListSessions(
		ctx,
		principal.UserID,
		u.now().UTC(),
	)
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
