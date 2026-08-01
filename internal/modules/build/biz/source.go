package biz

import (
	"errors"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/owndock/owndock/internal/shared/secretref"
)

var (
	ErrDuplicateName              = errors.New("build resource name already exists")
	ErrNotFound                   = errors.New("build resource was not found")
	ErrInvalidCredential          = errors.New("repository credential is invalid")
	ErrInvalidSourceRepository    = errors.New("source repository is invalid")
	ErrCredentialProtocolMismatch = errors.New("repository credential does not match repository protocol")
)

type CredentialType string

const (
	CredentialTypeSSHDeployKey     CredentialType = "ssh_deploy_key"
	CredentialTypeHTTPSAccessToken CredentialType = "https_access_token"
)

func (t CredentialType) Valid() bool {
	return t == CredentialTypeSSHDeployKey || t == CredentialTypeHTTPSAccessToken
}

type RepositoryProtocol string

const (
	RepositoryProtocolHTTPS RepositoryProtocol = "https"
	RepositoryProtocolSSH   RepositoryProtocol = "ssh"
)

type RepositoryCredential struct {
	ID                   string
	ProjectID            string
	Name                 string
	Type                 CredentialType
	Username             string
	SecretRef            string
	PublicKeyFingerprint string
	Version              uint64
	CreatedBy            string
	CreatedAt            time.Time
}

// CredentialSummary is safe to return through the API. SecretRef is
// deliberately represented only as a boolean.
type CredentialSummary struct {
	ID                   string
	ProjectID            string
	Name                 string
	Type                 CredentialType
	Username             string
	SecretConfigured     bool
	PublicKeyFingerprint string
	Version              uint64
	CreatedBy            string
	CreatedAt            time.Time
}

func (c RepositoryCredential) Summary() CredentialSummary {
	return CredentialSummary{
		ID: c.ID, ProjectID: c.ProjectID, Name: c.Name, Type: c.Type,
		Username: c.Username, SecretConfigured: c.SecretRef != "",
		PublicKeyFingerprint: c.PublicKeyFingerprint, Version: c.Version,
		CreatedBy: c.CreatedBy, CreatedAt: c.CreatedAt,
	}
}

type SourceRepositoryStatus string

const (
	SourceRepositoryStatusPending             SourceRepositoryStatus = "pending"
	SourceRepositoryStatusReady               SourceRepositoryStatus = "ready"
	SourceRepositoryStatusUnreachable         SourceRepositoryStatus = "unreachable"
	SourceRepositoryStatusAuthenticationError SourceRepositoryStatus = "authentication_error"
	SourceRepositoryStatusHostKeyMismatch     SourceRepositoryStatus = "host_key_mismatch"
	SourceRepositoryStatusReferenceNotFound   SourceRepositoryStatus = "reference_not_found"
)

func (s SourceRepositoryStatus) ValidProbeResult() bool {
	return s == SourceRepositoryStatusReady ||
		s == SourceRepositoryStatusUnreachable ||
		s == SourceRepositoryStatusAuthenticationError ||
		s == SourceRepositoryStatusHostKeyMismatch ||
		s == SourceRepositoryStatusReferenceNotFound
}

type SourceRepository struct {
	ID                    string
	ProjectID             string
	Name                  string
	RepositoryURL         string
	Protocol              RepositoryProtocol
	DefaultBranch         string
	CredentialID          string
	SSHHostKeyFingerprint string
	Status                SourceRepositoryStatus
	LastProbedAt          time.Time
	CreatedBy             string
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

func NewRepositoryCredential(
	id, projectID, name string,
	credentialType CredentialType,
	username, secretReference, publicKeyFingerprint, createdBy string,
	now time.Time,
) (RepositoryCredential, error) {
	id, projectID, createdBy = strings.TrimSpace(id), strings.TrimSpace(projectID), strings.TrimSpace(createdBy)
	name = strings.TrimSpace(name)
	username = strings.TrimSpace(username)
	secretReference = strings.TrimSpace(secretReference)
	publicKeyFingerprint = strings.TrimSpace(publicKeyFingerprint)
	if !validIdentifier(id) || !validIdentifier(projectID) || !validIdentifier(createdBy) ||
		!validName(name) || !credentialType.Valid() || now.IsZero() {
		return RepositoryCredential{}, ErrInvalidCredential
	}
	if _, err := secretref.Alias(secretReference); err != nil {
		return RepositoryCredential{}, ErrInvalidCredential
	}
	switch credentialType {
	case CredentialTypeSSHDeployKey:
		if username != "" || !validSSHFingerprint(publicKeyFingerprint) {
			return RepositoryCredential{}, ErrInvalidCredential
		}
	case CredentialTypeHTTPSAccessToken:
		if publicKeyFingerprint != "" || len(username) > 128 || hasUnsafeText(username) {
			return RepositoryCredential{}, ErrInvalidCredential
		}
	}
	return RepositoryCredential{
		ID: id, ProjectID: projectID, Name: name, Type: credentialType,
		Username: username, SecretRef: secretReference,
		PublicKeyFingerprint: publicKeyFingerprint, Version: 1,
		CreatedBy: createdBy, CreatedAt: now.UTC(),
	}, nil
}

func NewSourceRepository(
	id, projectID, name, repositoryURL, defaultBranch, credentialID,
	sshHostKeyFingerprint, createdBy string,
	now time.Time,
) (SourceRepository, error) {
	id, projectID, createdBy = strings.TrimSpace(id), strings.TrimSpace(projectID), strings.TrimSpace(createdBy)
	name = strings.TrimSpace(name)
	repositoryURL = strings.TrimSpace(repositoryURL)
	defaultBranch = strings.TrimSpace(defaultBranch)
	credentialID = strings.TrimSpace(credentialID)
	sshHostKeyFingerprint = strings.TrimSpace(sshHostKeyFingerprint)
	protocol, err := validateRepositoryURL(repositoryURL)
	if err != nil || !validIdentifier(id) || !validIdentifier(projectID) ||
		!validIdentifier(createdBy) || !validName(name) ||
		!validGitBranch(defaultBranch) || now.IsZero() ||
		(credentialID != "" && !validIdentifier(credentialID)) {
		return SourceRepository{}, ErrInvalidSourceRepository
	}
	switch protocol {
	case RepositoryProtocolSSH:
		if !validSSHFingerprint(sshHostKeyFingerprint) {
			return SourceRepository{}, ErrInvalidSourceRepository
		}
	case RepositoryProtocolHTTPS:
		if sshHostKeyFingerprint != "" {
			return SourceRepository{}, ErrInvalidSourceRepository
		}
	}
	return SourceRepository{
		ID: id, ProjectID: projectID, Name: name,
		RepositoryURL: repositoryURL, Protocol: protocol,
		DefaultBranch: defaultBranch, CredentialID: credentialID,
		SSHHostKeyFingerprint: sshHostKeyFingerprint,
		Status:                SourceRepositoryStatusPending,
		CreatedBy:             createdBy, CreatedAt: now.UTC(), UpdatedAt: now.UTC(),
	}, nil
}

func CredentialSupportsProtocol(credential RepositoryCredential, protocol RepositoryProtocol) bool {
	return credential.Type == CredentialTypeSSHDeployKey && protocol == RepositoryProtocolSSH ||
		credential.Type == CredentialTypeHTTPSAccessToken && protocol == RepositoryProtocolHTTPS
}

var (
	identifierPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	sshFingerprintPattern = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)
	scpRepositoryPattern  = regexp.MustCompile(`^([A-Za-z0-9._-]+)@([A-Za-z0-9.-]+):(.+)$`)
)

func validIdentifier(value string) bool {
	return identifierPattern.MatchString(value)
}

func validName(value string) bool {
	return value != "" && len(value) <= 100 && !hasUnsafeText(value)
}

func hasUnsafeText(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}
	return false
}

func validSSHFingerprint(value string) bool {
	return sshFingerprintPattern.MatchString(value)
}

func validGitBranch(value string) bool {
	if value == "" || len(value) > 255 || value == "@" ||
		strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") ||
		strings.HasPrefix(value, "refs/") ||
		strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") ||
		strings.HasSuffix(value, ".lock") || strings.Contains(value, "..") ||
		strings.Contains(value, "@{") || strings.Contains(value, "//") {
		return false
	}
	for _, character := range value {
		if unicode.IsSpace(character) || unicode.IsControl(character) ||
			strings.ContainsRune(`~^:?*[\\`, character) {
			return false
		}
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || strings.HasPrefix(component, ".") ||
			strings.HasSuffix(component, ".lock") {
			return false
		}
	}
	return true
}

func validateRepositoryURL(value string) (RepositoryProtocol, error) {
	if value == "" || len(value) > 2048 || hasUnsafeText(value) || strings.ContainsAny(value, " \t\r\n\\") {
		return "", ErrInvalidSourceRepository
	}
	if match := scpRepositoryPattern.FindStringSubmatch(value); match != nil {
		if match[2] == "" || !validRepositoryPath(match[3]) {
			return "", ErrInvalidSourceRepository
		}
		return RepositoryProtocolSSH, nil
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Host == "" || parsed.Hostname() == "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" || !validRepositoryPath(parsed.Path) {
		return "", ErrInvalidSourceRepository
	}
	if port := parsed.Port(); port != "" {
		number, portErr := strconv.Atoi(port)
		if portErr != nil || number < 1 || number > 65535 {
			return "", ErrInvalidSourceRepository
		}
	}
	if ip := net.ParseIP(parsed.Hostname()); ip == nil && strings.Contains(parsed.Hostname(), "_") {
		return "", ErrInvalidSourceRepository
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
		if parsed.Scheme != "https" || parsed.User != nil {
			return "", ErrInvalidSourceRepository
		}
		return RepositoryProtocolHTTPS, nil
	case "ssh":
		if parsed.Scheme != "ssh" || parsed.User == nil || parsed.User.Username() == "" {
			return "", ErrInvalidSourceRepository
		}
		if _, passwordSet := parsed.User.Password(); passwordSet {
			return "", ErrInvalidSourceRepository
		}
		return RepositoryProtocolSSH, nil
	default:
		return "", ErrInvalidSourceRepository
	}
}

func validRepositoryPath(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && value != "/" && !strings.HasPrefix(value, "-") &&
		!strings.Contains(value, "..") && !strings.ContainsAny(value, "\x00\r\n")
}
