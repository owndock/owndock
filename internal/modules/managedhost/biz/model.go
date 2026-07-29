package biz

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/secretref"
)

var (
	ErrDuplicateName            = errors.New("managed host name already exists")
	ErrEnrollmentNotAllowed     = errors.New("agent enrollment is not allowed for this host")
	ErrEnrollmentUnavailable    = errors.New("agent enrollment is unavailable")
	ErrAgentControlUnavailable  = errors.New("agent control is unavailable")
	ErrAgentProtocolUnsupported = errors.New("agent protocol version is unsupported")
	ErrAgentSessionInvalid      = errors.New("agent session is invalid")
	ErrInvalidAgentIdentity     = errors.New("agent identity is invalid")
	ErrInvalidEnrollment        = errors.New("agent enrollment is invalid")
	ErrInvalidHost              = errors.New("managed host is invalid")
	ErrNotFound                 = errors.New("managed host was not found")
)

type Status string

const (
	StatusEnrolling Status = "enrolling"
	StatusOnline    Status = "online"
	StatusOffline   Status = "offline"
	StatusDisabled  Status = "disabled"
)

func (s Status) Valid() bool {
	switch s {
	case StatusEnrolling, StatusOnline, StatusOffline, StatusDisabled:
		return true
	default:
		return false
	}
}

// ManagedHost is an Organization-owned Linux host. Project access is granted
// separately by Runtime Target; it never grants host-shell access implicitly.
type ManagedHost struct {
	ID                        string
	OrganizationID            string
	Name                      string
	Status                    Status
	ConnectionMode            runtimeaccess.Mode
	AgentIdentityID           string
	AgentInstanceID           string
	AgentCertificateExpiresAt time.Time
	AgentBootID               string
	AgentSessionID            string
	DirectSSHRef              string
	LastSeenAt                time.Time
	AgentVersion              string
	ProtocolVersion           string
	Capabilities              []string
	CreatedBy                 string
	CreatedAt                 time.Time
	UpdatedAt                 time.Time
}

type Repository interface {
	List(context.Context, string) ([]ManagedHost, error)
	Get(context.Context, string, string) (ManagedHost, error)
	Create(context.Context, ManagedHost) (ManagedHost, error)
	Disable(context.Context, string, string, time.Time) (ManagedHost, error)
	ConnectionMode(context.Context, string, string) (runtimeaccess.Mode, bool, error)
}

type Enrollment struct {
	ID             string
	OrganizationID string
	ManagedHostID  string
	TokenHash      string
	ExpiresAt      time.Time
	ConsumedAt     time.Time
	CreatedBy      string
	CreatedAt      time.Time
}

type AgentIdentity struct {
	ID                 string
	OrganizationID     string
	ManagedHostID      string
	InstanceID         string
	CertificateSerial  string
	CertificateSHA256  string
	CertificateExpires time.Time
	AgentVersion       string
	ProtocolVersion    string
	Capabilities       []string
	IssuedAt           time.Time
	RevokedAt          time.Time
}

type EnrollmentRepository interface {
	CreateEnrollment(context.Context, Enrollment) error
	FindAvailableEnrollment(context.Context, string, time.Time) (Enrollment, error)
	ActivateAgent(
		context.Context,
		string,
		string,
		time.Time,
		AgentIdentity,
	) error
}

type AgentCertificateIdentity struct {
	OrganizationID    string
	ManagedHostID     string
	IdentityID        string
	InstanceID        string
	CertificateSerial string
	CertificateSHA256 string
}

type AgentHello struct {
	OrganizationID  string
	ManagedHostID   string
	IdentityID      string
	InstanceID      string
	BootID          string
	AgentVersion    string
	ProtocolVersion string
	Capabilities    []string
}

type AgentSession struct {
	ID              string
	OrganizationID  string
	ManagedHostID   string
	IdentityID      string
	InstanceID      string
	BootID          string
	AgentVersion    string
	ProtocolVersion string
	Capabilities    []string
	ConnectedAt     time.Time
}

type AgentConnectionRepository interface {
	AuthenticateAgent(
		context.Context,
		AgentCertificateIdentity,
		time.Time,
	) (AgentIdentity, error)
	ConnectAgent(context.Context, AgentSession, time.Time) error
	HeartbeatAgent(context.Context, AgentSession, time.Time) error
	DisconnectAgent(context.Context, AgentSession, time.Time) (bool, error)
}

type AgentConnectionCloser interface {
	DisconnectHost(string)
}

type AgentConnectionRegistry interface {
	AgentConnectionCloser
	Register(string, string, context.CancelFunc) <-chan AgentCommand
	Unregister(string, string)
	Complete(string, string, AgentCommandResult) error
}

type AgentCommandDispatcher interface {
	Dispatch(context.Context, string, AgentCommand) (AgentCommandResult, error)
}

type EnrollmentTokens interface {
	New() (string, string, error)
	Hash(string) string
}

type AgentCertificateClaim struct {
	OrganizationID string
	ManagedHostID  string
	IdentityID     string
	InstanceID     string
}

type IssuedCertificate struct {
	CertificatePEM   []byte
	CACertificatePEM []byte
	Serial           string
	SHA256           string
	ExpiresAt        time.Time
}

type CertificateIssuer interface {
	Issue(
		context.Context,
		AgentCertificateClaim,
		[]byte,
		time.Time,
	) (IssuedCertificate, error)
}

type EnrollmentCredential struct {
	EnrollmentID  string
	ManagedHostID string
	Token         string
	ExpiresAt     time.Time
}

type AgentCredentials struct {
	Identity         AgentIdentity
	CertificatePEM   []byte
	CACertificatePEM []byte
}

func NewManagedHost(
	id, organizationID, name string,
	connectionMode runtimeaccess.Mode,
	directSSHRef, createdBy string,
	now time.Time,
) (ManagedHost, error) {
	id = strings.TrimSpace(id)
	organizationID = strings.TrimSpace(organizationID)
	name = strings.TrimSpace(name)
	createdBy = strings.TrimSpace(createdBy)
	directSSHRef = strings.TrimSpace(directSSHRef)
	if id == "" || organizationID == "" || createdBy == "" ||
		len(name) < 2 || len(name) > 80 || !connectionMode.Valid() {
		return ManagedHost{}, ErrInvalidHost
	}
	status := StatusOffline
	switch connectionMode {
	case runtimeaccess.ModeAgent:
		if directSSHRef != "" {
			return ManagedHost{}, ErrInvalidHost
		}
		status = StatusEnrolling
	case runtimeaccess.ModeDirectDocker:
		if directSSHRef != "" {
			if _, err := secretref.Alias(directSSHRef); err != nil {
				return ManagedHost{}, ErrInvalidHost
			}
		}
	}
	now = now.UTC()
	return ManagedHost{
		ID: id, OrganizationID: organizationID, Name: name,
		Status: status, ConnectionMode: connectionMode,
		DirectSSHRef: directSSHRef, Capabilities: []string{},
		CreatedBy: createdBy, CreatedAt: now, UpdatedAt: now,
	}, nil
}

func NewEnrollment(
	id string,
	host ManagedHost,
	tokenHash, createdBy string,
	now time.Time,
	ttl time.Duration,
) (Enrollment, error) {
	id = strings.TrimSpace(id)
	tokenHash = strings.TrimSpace(tokenHash)
	createdBy = strings.TrimSpace(createdBy)
	if id == "" || host.ID == "" || host.OrganizationID == "" ||
		host.ConnectionMode != runtimeaccess.ModeAgent ||
		host.Status == StatusDisabled ||
		host.AgentIdentityID != "" ||
		tokenHash == "" || createdBy == "" || ttl <= 0 {
		return Enrollment{}, ErrEnrollmentNotAllowed
	}
	now = now.UTC()
	return Enrollment{
		ID: id, OrganizationID: host.OrganizationID, ManagedHostID: host.ID,
		TokenHash: tokenHash, ExpiresAt: now.Add(ttl),
		CreatedBy: createdBy, CreatedAt: now,
	}, nil
}

func NewAgentIdentity(
	id string,
	enrollment Enrollment,
	instanceID, agentVersion, protocolVersion string,
	capabilities []string,
	certificate IssuedCertificate,
	now time.Time,
) (AgentIdentity, error) {
	id = strings.TrimSpace(id)
	instanceID, agentVersion, protocolVersion, capabilities, err := validateAgentMetadata(
		instanceID, agentVersion, protocolVersion, capabilities,
	)
	if err != nil || id == "" || enrollment.ID == "" ||
		enrollment.OrganizationID == "" || enrollment.ManagedHostID == "" ||
		certificate.Serial == "" || certificate.SHA256 == "" ||
		!certificate.ExpiresAt.After(now) {
		return AgentIdentity{}, ErrInvalidAgentIdentity
	}
	return AgentIdentity{
		ID: id, OrganizationID: enrollment.OrganizationID,
		ManagedHostID: enrollment.ManagedHostID, InstanceID: instanceID,
		CertificateSerial:  certificate.Serial,
		CertificateSHA256:  certificate.SHA256,
		CertificateExpires: certificate.ExpiresAt.UTC(),
		AgentVersion:       agentVersion, ProtocolVersion: protocolVersion,
		Capabilities: capabilities, IssuedAt: now.UTC(),
	}, nil
}

func validateAgentMetadata(
	instanceID, agentVersion, protocolVersion string,
	capabilities []string,
) (string, string, string, []string, error) {
	instanceID = strings.TrimSpace(instanceID)
	agentVersion = strings.TrimSpace(agentVersion)
	protocolVersion = strings.TrimSpace(protocolVersion)
	if !validIdentitySegment(instanceID) ||
		agentVersion == "" || len(agentVersion) > 64 ||
		protocolVersion == "" || len(protocolVersion) > 64 {
		return "", "", "", nil, ErrInvalidAgentIdentity
	}
	capabilities, err := normalizeCapabilities(capabilities)
	if err != nil {
		return "", "", "", nil, err
	}
	return instanceID, agentVersion, protocolVersion, capabilities, nil
}

func validIdentitySegment(value string) bool {
	if value == "" || len(value) > 128 || value == "." || value == ".." {
		return false
	}
	if value[0] == '.' {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func normalizeCapabilities(values []string) ([]string, error) {
	const maximumCapabilities = 16
	if len(values) > maximumCapabilities {
		return nil, ErrInvalidAgentIdentity
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || len(value) > 64 {
			return nil, ErrInvalidAgentIdentity
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result, nil
}
