package biz

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/security"
	"github.com/owndock/owndock/internal/shared/transaction"
)

func TestBootstrapLoginAuthenticateAndLogout(t *testing.T) {
	repository := &fakeRepository{}
	audits := &fakeAudit{}
	ids := 0
	useCase := NewUseCase(
		repository,
		transaction.Passthrough{},
		audits,
		fakePasswords{},
		fakeTokens{},
		func() (string, error) {
			ids++
			return fmt.Sprintf("id-%d", ids), nil
		},
		func() time.Time { return time.Unix(100, 0) },
		time.Hour,
	).WithLoginProtection(
		&fakeLoginGuard{allowed: true},
		5,
		time.Minute,
	).WithSessionPolicy(10)

	credentials, err := useCase.Bootstrap(context.Background(), "Example Company", "OWNER@example.com", "long-enough-password", "request-1")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	if credentials.User.Role != "owner" || credentials.User.Email != "owner@example.com" {
		t.Fatalf("credentials = %+v", credentials)
	}
	principal, err := useCase.Authenticate(context.Background(), credentials.AccessToken)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if principal.UserID != credentials.User.ID || principal.OrganizationID != credentials.Organization.ID {
		t.Fatalf("principal = %+v", principal)
	}
	if _, err := useCase.Bootstrap(context.Background(), "Other", "other@example.com", "long-enough-password", "request-2"); !errors.Is(err, ErrAlreadyBootstrapped) {
		t.Fatalf("second Bootstrap() error = %v", err)
	}
	if _, err := useCase.Login(context.Background(), "owner@example.com", "wrong-password", "request-3"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login() error = %v", err)
	}
	login, err := useCase.Login(context.Background(), "owner@example.com", "long-enough-password", "request-4")
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	loginPrincipal, err := useCase.Authenticate(context.Background(), login.AccessToken)
	if err != nil {
		t.Fatalf("Authenticate(login token) error = %v", err)
	}
	if err := useCase.Logout(context.Background(), loginPrincipal, "request-5"); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}
	if _, err := useCase.Authenticate(context.Background(), login.AccessToken); err == nil {
		t.Fatal("logged-out token was accepted")
	}
	if len(audits.events) != 3 {
		t.Fatalf("audit event count = %d, want 3", len(audits.events))
	}
}

func TestLoginProtectionUsesHashedKeyAndResetsAfterSuccess(
	t *testing.T,
) {
	repository := &fakeRepository{
		user: User{
			ID:              "user-1",
			OrganizationID:  "organization-1",
			Email:           "owner@example.com",
			EmailNormalized: "owner@example.com",
			PasswordHash:    "hash:correct-password",
			Role:            "owner",
		},
		sessions: make(map[string]Session),
	}
	guard := &fakeLoginGuard{
		allowed: false,
		retryAt: time.Unix(160, 0),
	}
	useCase := NewUseCase(
		repository,
		transaction.Passthrough{},
		&fakeAudit{},
		fakePasswords{},
		fakeTokens{},
		func() (string, error) { return "session-1", nil },
		func() time.Time { return time.Unix(100, 0) },
		time.Hour,
	).WithLoginProtection(guard, 5, time.Minute).
		WithSessionPolicy(10)

	_, loginError := useCase.Login(
		context.Background(),
		"OWNER@example.com",
		"correct-password",
		"request-1",
	)
	if !errors.Is(loginError, ErrLoginRateLimited) {
		t.Fatalf("rate-limited Login() error = %v", loginError)
	}
	var rateLimit *LoginRateLimitError
	if !errors.As(loginError, &rateLimit) ||
		rateLimit.RetryAfter != time.Minute {
		t.Fatalf("rate limit detail = %+v", rateLimit)
	}
	if guard.key == "owner@example.com" || len(guard.key) != 64 {
		t.Fatalf("login guard key = %q", guard.key)
	}

	guard.allowed = true
	if _, err := useCase.Login(
		context.Background(),
		"owner@example.com",
		"correct-password",
		"request-2",
	); err != nil {
		t.Fatalf("successful Login() error = %v", err)
	}
	if guard.resetKey != guard.key {
		t.Fatalf(
			"reset key = %q, reserve key = %q",
			guard.resetKey,
			guard.key,
		)
	}
}

func TestLoginFailsClosedWithoutProtection(t *testing.T) {
	repository := &fakeRepository{
		user: User{
			ID:              "user-1",
			OrganizationID:  "organization-1",
			Email:           "owner@example.com",
			EmailNormalized: "owner@example.com",
			PasswordHash:    "hash:correct-password",
			Role:            "owner",
		},
		sessions: make(map[string]Session),
	}
	useCase := NewUseCase(
		repository,
		transaction.Passthrough{},
		&fakeAudit{},
		fakePasswords{},
		fakeTokens{},
		func() (string, error) { return "session-1", nil },
		func() time.Time { return time.Unix(100, 0) },
		time.Hour,
	)
	if _, err := useCase.Login(
		context.Background(),
		"owner@example.com",
		"correct-password",
		"request",
	); !errors.Is(err, ErrLoginGuardMissing) {
		t.Fatalf("Login() without protection error = %v", err)
	}
}

func TestSessionGovernanceListsAndRevokesOnlyOwnedSession(t *testing.T) {
	now := time.Unix(100, 0)
	repository := &fakeRepository{
		user: User{
			ID:             "user-1",
			OrganizationID: "organization-1",
			Role:           "owner",
		},
		sessions: map[string]Session{
			"hash-current": {
				ID:        "session-current",
				UserID:    "user-1",
				TokenHash: "hash-current",
				CreatedAt: now,
				ExpiresAt: now.Add(time.Hour),
			},
			"hash-other": {
				ID:        "session-other",
				UserID:    "other-user",
				TokenHash: "hash-other",
				CreatedAt: now,
				ExpiresAt: now.Add(time.Hour),
			},
		},
	}
	audits := &fakeAudit{}
	useCase := NewUseCase(
		repository,
		transaction.Passthrough{},
		audits,
		fakePasswords{},
		fakeTokens{},
		func() (string, error) { return "audit-1", nil },
		func() time.Time { return now },
		time.Hour,
	)
	principal := security.Principal{
		UserID:         "user-1",
		OrganizationID: "organization-1",
		Role:           security.RoleOwner,
		SessionID:      "session-current",
	}
	sessions, err := useCase.ListSessions(
		context.Background(),
		principal,
	)
	if err != nil || len(sessions) != 1 ||
		sessions[0].ID != "session-current" {
		t.Fatalf("ListSessions() = %+v, %v", sessions, err)
	}
	if err := useCase.RevokeSession(
		context.Background(),
		principal,
		"session-other",
		"request-1",
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoke another user's session error = %v", err)
	}
	if err := useCase.RevokeSession(
		context.Background(),
		principal,
		"session-current",
		"request-2",
	); err != nil {
		t.Fatalf("revoke own session error = %v", err)
	}
	if len(audits.events) != 1 ||
		audits.events[0].Action != "identity.session.revoke" {
		t.Fatalf("session revoke audits = %+v", audits.events)
	}
}

type fakeRepository struct {
	organization Organization
	user         User
	sessions     map[string]Session
}

func (r *fakeRepository) HasUsers(context.Context) (bool, error) {
	return r.user.ID != "", nil
}

func (r *fakeRepository) CreateBootstrap(_ context.Context, organization Organization, user User, session Session) error {
	r.organization = organization
	r.user = user
	r.sessions = map[string]Session{session.TokenHash: session}
	return nil
}

func (r *fakeRepository) FindUserByEmail(_ context.Context, email string) (User, error) {
	if r.user.EmailNormalized != email {
		return User{}, ErrNotFound
	}
	return r.user, nil
}

func (r *fakeRepository) CreateSession(
	_ context.Context,
	session Session,
	_ time.Time,
	_ int,
) error {
	r.sessions[session.TokenHash] = session
	return nil
}

func (r *fakeRepository) FindSession(_ context.Context, tokenHash string, now time.Time) (Session, User, error) {
	session, ok := r.sessions[tokenHash]
	if !ok || !session.ExpiresAt.After(now) {
		return Session{}, User{}, ErrNotFound
	}
	return session, r.user, nil
}

func (r *fakeRepository) ListSessions(
	_ context.Context,
	userID string,
	now time.Time,
) ([]Session, error) {
	var result []Session
	for _, session := range r.sessions {
		if session.UserID == userID && session.ExpiresAt.After(now) {
			result = append(result, session)
		}
	}
	return result, nil
}

func (r *fakeRepository) DeleteSession(_ context.Context, sessionID, userID string) error {
	for hash, session := range r.sessions {
		if session.ID == sessionID && session.UserID == userID {
			delete(r.sessions, hash)
			return nil
		}
	}
	return ErrNotFound
}

type fakePasswords struct{}

func (fakePasswords) Hash(value string) (string, error) { return "hash:" + value, nil }
func (fakePasswords) Verify(value, encoded string) bool { return encoded == "hash:"+value }
func (fakePasswords) DummyHash() string                 { return "hash:dummy-password" }

type fakeTokens struct{}

func (fakeTokens) New() (string, string, error) { return "raw-token", "hash:raw-token", nil }
func (fakeTokens) Hash(value string) string     { return "hash:" + value }

type fakeAudit struct {
	events []sharedaudit.Event
}

type fakeLoginGuard struct {
	allowed  bool
	retryAt  time.Time
	key      string
	resetKey string
}

func (g *fakeLoginGuard) ReserveLoginAttempt(
	_ context.Context,
	key string,
	_ time.Time,
	_ int,
	_ time.Duration,
) (bool, time.Time, error) {
	g.key = key
	return g.allowed, g.retryAt, nil
}

func (g *fakeLoginGuard) ResetLoginAttempts(
	_ context.Context,
	key string,
) error {
	g.resetKey = key
	return nil
}

func (a *fakeAudit) Record(_ context.Context, event sharedaudit.Event) error {
	a.events = append(a.events, event)
	return nil
}
