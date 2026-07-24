package biz

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
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
	)

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

func (r *fakeRepository) CreateSession(_ context.Context, session Session) error {
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

func (a *fakeAudit) Record(_ context.Context, event sharedaudit.Event) error {
	a.events = append(a.events, event)
	return nil
}
