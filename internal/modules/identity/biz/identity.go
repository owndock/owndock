package biz

import (
	"context"
	"errors"
	"net/mail"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/shared/security"
)

var (
	ErrAlreadyBootstrapped = errors.New("identity has already been bootstrapped")
	ErrInvalidCredentials  = errors.New("email or password is invalid")
	ErrInvalidEmail        = errors.New("email is invalid")
	ErrInvalidName         = errors.New("organization name is invalid")
	ErrInvalidPassword     = errors.New("password must contain between 12 and 128 characters")
	ErrLoginGuardMissing   = errors.New("login protection is unavailable")
	ErrLoginRateLimited    = errors.New("login attempt rate limit exceeded")
	ErrNotFound            = errors.New("identity was not found")
)

type Organization struct {
	ID        string
	Name      string
	CreatedAt time.Time
}

type User struct {
	ID              string
	OrganizationID  string
	Email           string
	EmailNormalized string
	PasswordHash    string
	Role            security.Role
	CreatedAt       time.Time
}

type Session struct {
	ID        string
	UserID    string
	TokenHash string
	CreatedAt time.Time
	ExpiresAt time.Time
}

type Repository interface {
	HasUsers(context.Context) (bool, error)
	CreateBootstrap(context.Context, Organization, User, Session) error
	FindUserByEmail(context.Context, string) (User, error)
	CreateSession(context.Context, Session, time.Time, int) error
	FindSession(context.Context, string, time.Time) (Session, User, error)
	ListSessions(context.Context, string, time.Time) ([]Session, error)
	DeleteSession(context.Context, string, string) error
}

// LoginGuard persists failed-login admission state independently from
// application process memory so multiple Server instances enforce one limit.
// The key is a one-way hash of the normalized email address.
type LoginGuard interface {
	ReserveLoginAttempt(
		context.Context,
		string,
		time.Time,
		int,
		time.Duration,
	) (allowed bool, retryAt time.Time, err error)
	ResetLoginAttempts(context.Context, string) error
}

type LoginRateLimitError struct {
	RetryAfter time.Duration
}

func (e *LoginRateLimitError) Error() string {
	return ErrLoginRateLimited.Error()
}

func (e *LoginRateLimitError) Is(target error) bool {
	return target == ErrLoginRateLimited
}

type PasswordHasher interface {
	Hash(string) (string, error)
	Verify(string, string) bool
	DummyHash() string
}

type SessionTokens interface {
	New() (string, string, error)
	Hash(string) string
}

func NewOrganization(id, name string, now time.Time) (Organization, error) {
	name = strings.TrimSpace(name)
	if len(name) < 2 || len(name) > 80 {
		return Organization{}, ErrInvalidName
	}
	return Organization{ID: id, Name: name, CreatedAt: now.UTC()}, nil
}

func NewOwner(id, organizationID, email, passwordHash string, now time.Time) (User, error) {
	normalized, err := normalizeEmail(email)
	if err != nil {
		return User{}, err
	}
	return User{
		ID: id, OrganizationID: organizationID,
		Email: normalized, EmailNormalized: normalized,
		PasswordHash: passwordHash, Role: security.RoleOwner, CreatedAt: now.UTC(),
	}, nil
}

func ValidatePassword(password string) error {
	if len(password) < 12 || len(password) > 128 {
		return ErrInvalidPassword
	}
	return nil
}

func normalizeEmail(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	address, err := mail.ParseAddress(value)
	if err != nil || address.Address != value || len(value) > 254 {
		return "", ErrInvalidEmail
	}
	return value, nil
}
