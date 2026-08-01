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
	ErrInvalidInvitation   = errors.New("invitation is invalid or expired")
	ErrInvalidEmail        = errors.New("email is invalid")
	ErrInvalidName         = errors.New("organization name is invalid")
	ErrInvalidPassword     = errors.New("password must contain between 12 and 128 characters")
	ErrLoginGuardMissing   = errors.New("login protection is unavailable")
	ErrLoginRateLimited    = errors.New("login attempt rate limit exceeded")
	ErrNotFound            = errors.New("identity was not found")
	ErrUserAlreadyExists   = errors.New("user already exists")
	ErrCannotRevokeCurrent = errors.New("current session cannot be revoked through administration")
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

type InvitationStatus string

const (
	InvitationStatusActive   InvitationStatus = "active"
	InvitationStatusAccepted InvitationStatus = "accepted"
	InvitationStatusRevoked  InvitationStatus = "revoked"
)

type Invitation struct {
	ID              string
	OrganizationID  string
	Email           string
	EmailNormalized string
	TokenHash       string
	Status          InvitationStatus
	Version         uint64
	InvitedBy       string
	CreatedAt       time.Time
	ExpiresAt       time.Time
	AcceptedBy      string
	AcceptedAt      time.Time
	RevokedBy       string
	RevokedAt       time.Time
}

type InvitationCredential struct {
	Invitation Invitation
	Token      string
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

type UserInvitationRepository interface {
	ListUsers(context.Context, string) ([]User, error)
	CreateInvitation(context.Context, Invitation) (Invitation, error)
	ListInvitations(context.Context, string) ([]Invitation, error)
	GetInvitation(context.Context, string, string) (Invitation, error)
	FindInvitationByTokenHash(context.Context, string, time.Time) (Invitation, error)
	AcceptInvitation(context.Context, Invitation, uint64, User, Session) error
	RevokeInvitation(context.Context, Invitation, uint64) (Invitation, error)
}

type AdministrativeSessionRepository interface {
	GetOrganizationUser(context.Context, string, string) (User, error)
	ListSessions(context.Context, string, time.Time) ([]Session, error)
	DeleteSession(context.Context, string, string) error
	DeleteUserSessions(context.Context, string) (int64, error)
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

func NewInvitedUser(id, organizationID, email, passwordHash string, now time.Time) (User, error) {
	normalized, err := normalizeEmail(email)
	if err != nil || strings.TrimSpace(id) == "" || strings.TrimSpace(organizationID) == "" ||
		strings.TrimSpace(passwordHash) == "" || now.IsZero() {
		return User{}, ErrInvalidInvitation
	}
	return User{
		ID: strings.TrimSpace(id), OrganizationID: strings.TrimSpace(organizationID),
		Email: normalized, EmailNormalized: normalized,
		PasswordHash: passwordHash, Role: security.RoleViewer, CreatedAt: now.UTC(),
	}, nil
}

func NewInvitation(id, organizationID, email, tokenHash, invitedBy string,
	now time.Time, ttl time.Duration) (Invitation, error) {
	normalized, err := normalizeEmail(email)
	if err != nil || strings.TrimSpace(id) == "" || strings.TrimSpace(organizationID) == "" ||
		strings.TrimSpace(tokenHash) == "" || strings.TrimSpace(invitedBy) == "" ||
		now.IsZero() || ttl < time.Minute || ttl > 7*24*time.Hour {
		return Invitation{}, ErrInvalidInvitation
	}
	return Invitation{
		ID: strings.TrimSpace(id), OrganizationID: strings.TrimSpace(organizationID),
		Email: normalized, EmailNormalized: normalized, TokenHash: strings.TrimSpace(tokenHash),
		Status: InvitationStatusActive, Version: 1, InvitedBy: strings.TrimSpace(invitedBy),
		CreatedAt: now.UTC(), ExpiresAt: now.UTC().Add(ttl),
	}, nil
}

func (i Invitation) Safe() Invitation {
	i.TokenHash = ""
	return i
}

func (i Invitation) Accept(userID string, now time.Time) (Invitation, error) {
	if i.Status != InvitationStatusActive || !i.ExpiresAt.After(now) ||
		strings.TrimSpace(userID) == "" || now.IsZero() {
		return Invitation{}, ErrInvalidInvitation
	}
	i.Status, i.Version = InvitationStatusAccepted, i.Version+1
	i.AcceptedBy, i.AcceptedAt = strings.TrimSpace(userID), now.UTC()
	i.TokenHash = ""
	return i, nil
}

func (i Invitation) Revoke(userID string, now time.Time) (Invitation, error) {
	if i.Status != InvitationStatusActive || strings.TrimSpace(userID) == "" || now.IsZero() {
		return Invitation{}, ErrInvalidInvitation
	}
	i.Status, i.Version = InvitationStatusRevoked, i.Version+1
	i.RevokedBy, i.RevokedAt = strings.TrimSpace(userID), now.UTC()
	i.TokenHash = ""
	return i, nil
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
