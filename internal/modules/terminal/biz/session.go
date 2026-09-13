package biz

import (
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/owndock/owndock/internal/shared/runtimeaccess"
)

const DefaultTicketTTL = time.Minute

var (
	ErrInvalidSession      = errors.New("terminal session is invalid")
	ErrSessionConflict     = errors.New("terminal session has changed")
	ErrSessionNotFound     = errors.New("terminal session was not found")
	ErrSessionSlotConflict = errors.New("terminal session concurrency slot is occupied")
	ErrSessionLimit        = errors.New("terminal session concurrency limit reached")
	ErrInvalidTicket       = errors.New("terminal session ticket is invalid or expired")
	ErrTargetNotFound      = errors.New("terminal target was not found")
	ErrTargetUnavailable   = errors.New("terminal target is unavailable")
	ErrAccessDenied        = errors.New("terminal access policy denied the request")
)

type Kind string
type SessionStatus string
type CloseReason string

const (
	KindContainer Kind = "container"
	KindHost      Kind = "host"

	StatusPending SessionStatus = "pending"
	StatusOpen    SessionStatus = "open"
	StatusClosing SessionStatus = "closing"
	StatusClosed  SessionStatus = "closed"
	StatusFailed  SessionStatus = "failed"
	StatusExpired SessionStatus = "expired"

	CloseReasonUserRequested           CloseReason = "user_requested"
	CloseReasonAdministratorTerminated CloseReason = "administrator_terminated"
	CloseReasonPermissionRevoked       CloseReason = "permission_revoked"
	CloseReasonIdleTimeout             CloseReason = "idle_timeout"
	CloseReasonMaximumDuration         CloseReason = "maximum_duration"
	CloseReasonTargetUnavailable       CloseReason = "target_unavailable"
	CloseReasonConnectionFailed        CloseReason = "connection_failed"
	CloseReasonServerShutdown          CloseReason = "server_shutdown"
)

type Target struct {
	Kind               Kind
	OrganizationID     string
	ProjectID          string
	ApplicationID      string
	EnvironmentID      string
	ManagedHostID      string
	RuntimeTargetID    string
	DeploymentID       string
	RunningInstanceID  string
	InstanceGeneration uint64
	ContainerName      string
	EnvironmentStage   string
	ConnectionMode     runtimeaccess.Mode
	Connection         runtimeaccess.Connection
	SSHAddress         string
	SSHUser            string
	SSHHostKeySHA256   string
	SSHCredentialRef   string
}

type TerminalSession struct {
	ID                      string
	OrganizationID          string
	ProjectID               string
	Kind                    Kind
	ActorID                 string
	AuthenticationSessionID string
	ManagedHostID           string
	RuntimeTargetID         string
	DeploymentID            string
	ApplicationID           string
	EnvironmentID           string
	RunningInstanceID       string
	InstanceGeneration      uint64
	Status                  SessionStatus
	ConnectionMode          runtimeaccess.Mode
	CreatedAt               time.Time
	ConnectedAt             time.Time
	LastActivityAt          time.Time
	EndedAt                 time.Time
	IdleDeadline            time.Time
	MaximumDeadline         time.Time
	TicketHash              string
	TicketExpiresAt         time.Time
	TicketConsumedAt        time.Time
	ClientIP                string
	UserAgent               string
	RequestID               string
	CloseReason             CloseReason
	SafeErrorCode           string
	UserConcurrencySlot     int
	TargetConcurrencySlot   int
	Active                  bool
	Version                 uint64
}

type Credential struct {
	Session   TerminalSession
	Ticket    string
	ExpiresAt time.Time
}

func NewTerminalSession(
	id, actorID, authenticationSessionID, ticketHash, clientIP, userAgent, requestID string,
	target Target,
	policy AccessPolicy,
	now time.Time,
) (TerminalSession, error) {
	now = now.UTC()
	ticketExpiresAt := now.Add(DefaultTicketTTL)
	if maximum := now.Add(policy.MaximumDuration); maximum.Before(ticketExpiresAt) {
		ticketExpiresAt = maximum
	}
	session := TerminalSession{
		ID: strings.TrimSpace(id), OrganizationID: strings.TrimSpace(target.OrganizationID),
		ProjectID: strings.TrimSpace(target.ProjectID), Kind: target.Kind,
		ActorID: strings.TrimSpace(actorID), ManagedHostID: strings.TrimSpace(target.ManagedHostID),
		AuthenticationSessionID: strings.TrimSpace(authenticationSessionID),
		RuntimeTargetID:         strings.TrimSpace(target.RuntimeTargetID),
		DeploymentID:            strings.TrimSpace(target.DeploymentID),
		ApplicationID:           strings.TrimSpace(target.ApplicationID),
		EnvironmentID:           strings.TrimSpace(target.EnvironmentID),
		RunningInstanceID:       strings.TrimSpace(target.RunningInstanceID),
		InstanceGeneration:      target.InstanceGeneration,
		Status:                  StatusPending, ConnectionMode: target.ConnectionMode,
		CreatedAt: now, LastActivityAt: now,
		IdleDeadline: now.Add(policy.IdleTimeout), MaximumDeadline: now.Add(policy.MaximumDuration),
		TicketHash: strings.TrimSpace(ticketHash), TicketExpiresAt: ticketExpiresAt,
		ClientIP: strings.TrimSpace(clientIP), UserAgent: strings.TrimSpace(userAgent),
		RequestID: strings.TrimSpace(requestID), Active: true, Version: 1,
	}
	if err := session.Validate(); err != nil {
		return TerminalSession{}, err
	}
	return session, nil
}

func (s TerminalSession) Validate() error {
	if !validIdentifier(s.ID) || !validIdentifier(s.OrganizationID) ||
		!validIdentifier(s.ActorID) || !validIdentifier(s.AuthenticationSessionID) ||
		!validIdentifier(s.ManagedHostID) ||
		!s.Kind.Valid() || !s.Status.Valid() || !s.ConnectionMode.Valid() ||
		s.CreatedAt.IsZero() || s.LastActivityAt.IsZero() ||
		!s.IdleDeadline.After(s.CreatedAt) || !s.MaximumDeadline.After(s.IdleDeadline) ||
		!validTicketHash(s.TicketHash) || s.TicketExpiresAt.IsZero() ||
		!s.TicketExpiresAt.After(s.CreatedAt) || !validClientIP(s.ClientIP) ||
		!validUserAgent(s.UserAgent) || !validRequestMetadata(s.RequestID) || s.Version == 0 {
		return ErrInvalidSession
	}
	if s.Kind == KindContainer {
		if !validIdentifier(s.ProjectID) || !validIdentifier(s.RuntimeTargetID) ||
			!validIdentifier(s.DeploymentID) || !validIdentifier(s.RunningInstanceID) ||
			s.InstanceGeneration == 0 {
			return ErrInvalidSession
		}
	} else if s.ProjectID != "" || s.RuntimeTargetID != "" || s.DeploymentID != "" ||
		s.ApplicationID != "" || s.EnvironmentID != "" ||
		s.RunningInstanceID != "" || s.InstanceGeneration != 0 {
		return ErrInvalidSession
	}
	if s.Active != s.Status.Active() || s.UserConcurrencySlot < 0 ||
		s.TargetConcurrencySlot < 0 || s.UserConcurrencySlot > 10 ||
		s.TargetConcurrencySlot > 50 {
		return ErrInvalidSession
	}
	return nil
}

func validTicketHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && strings.ToLower(value) == value
}

func (s TerminalSession) Redacted() TerminalSession {
	s.TicketHash = ""
	s.AuthenticationSessionID = ""
	return s
}

func (s TerminalSession) TargetScope() string {
	if s.Kind == KindContainer {
		return "runtime_target:" + s.RuntimeTargetID
	}
	return "managed_host:" + s.ManagedHostID
}

func (s TerminalSession) RequestTermination(reason CloseReason, now time.Time) (TerminalSession, error) {
	if !reason.Valid() || now.IsZero() {
		return TerminalSession{}, ErrInvalidSession
	}
	switch s.Status {
	case StatusPending:
		s.Status, s.Active, s.CloseReason = StatusClosed, false, reason
		s.EndedAt, s.TicketHash = now.UTC(), ""
	case StatusOpen:
		s.Status, s.CloseReason = StatusClosing, reason
	case StatusClosing, StatusClosed, StatusFailed, StatusExpired:
		return s, nil
	default:
		return TerminalSession{}, ErrSessionConflict
	}
	s.Version++
	return s, s.validateWithoutTicket()
}

func (s TerminalSession) MarkOpen(now time.Time) (TerminalSession, error) {
	if s.Status != StatusPending || now.IsZero() || !now.Before(s.TicketExpiresAt) ||
		!now.Before(s.MaximumDeadline) {
		return TerminalSession{}, ErrSessionConflict
	}
	s.Status, s.ConnectedAt, s.LastActivityAt = StatusOpen, now.UTC(), now.UTC()
	s.TicketConsumedAt, s.TicketHash = now.UTC(), ""
	s.Version++
	return s, s.validateWithoutTicket()
}

func (s TerminalSession) Close(reason CloseReason, safeErrorCode string, now time.Time) (TerminalSession, error) {
	if !reason.Valid() || now.IsZero() || !validSafeErrorCode(safeErrorCode) {
		return TerminalSession{}, ErrInvalidSession
	}
	if s.Status == StatusClosed || s.Status == StatusFailed || s.Status == StatusExpired {
		return s, nil
	}
	if s.Status != StatusPending && s.Status != StatusOpen && s.Status != StatusClosing {
		return TerminalSession{}, ErrSessionConflict
	}
	if safeErrorCode == "" {
		s.Status = StatusClosed
	} else {
		s.Status = StatusFailed
	}
	s.Active, s.EndedAt, s.CloseReason = false, now.UTC(), reason
	s.SafeErrorCode, s.TicketHash = safeErrorCode, ""
	s.Version++
	return s, s.validateWithoutTicket()
}

func (k Kind) Valid() bool { return k == KindContainer || k == KindHost }

func (s SessionStatus) Valid() bool {
	switch s {
	case StatusPending, StatusOpen, StatusClosing, StatusClosed, StatusFailed, StatusExpired:
		return true
	default:
		return false
	}
}

func (s SessionStatus) Active() bool {
	return s == StatusPending || s == StatusOpen || s == StatusClosing
}

func (r CloseReason) Valid() bool {
	switch r {
	case CloseReasonUserRequested, CloseReasonAdministratorTerminated,
		CloseReasonPermissionRevoked, CloseReasonIdleTimeout,
		CloseReasonMaximumDuration, CloseReasonTargetUnavailable,
		CloseReasonConnectionFailed, CloseReasonServerShutdown:
		return true
	default:
		return false
	}
}

func (s TerminalSession) validateWithoutTicket() error {
	ticketHash := s.TicketHash
	if ticketHash == "" {
		s.TicketHash = strings.Repeat("0", 64)
	}
	err := s.Validate()
	s.TicketHash = ticketHash
	return err
}

func validClientIP(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.IsValid() && !address.IsUnspecified()
}

func validUserAgent(value string) bool {
	if value == "" || len(value) > 512 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validRequestMetadata(value string) bool {
	return value != "" && len(value) <= 128 && strings.TrimSpace(value) == value
}

func validSafeErrorCode(value string) bool {
	if value == "" {
		return true
	}
	return len(value) <= 64 && validIdentifier(value)
}
