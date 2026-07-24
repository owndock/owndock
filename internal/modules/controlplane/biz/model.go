package biz

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
)

var (
	ErrDuplicateName        = errors.New("resource name already exists")
	ErrDuplicateRelease     = errors.New("release already exists")
	ErrInvalidImage         = errors.New("image must be pinned by a sha256 digest")
	ErrInvalidName          = errors.New("resource name is invalid")
	ErrInvalidRuntimeTarget = errors.New("runtime target is invalid")
	ErrNotFound             = errors.New("resource was not found")
)

type Project struct {
	ID             string
	OrganizationID string
	Name           string
	CreatedBy      string
	CreatedAt      time.Time
}

type Application struct {
	ID        string
	ProjectID string
	Name      string
	CreatedBy string
	CreatedAt time.Time
}

type Release struct {
	ID            string
	ProjectID     string
	ApplicationID string
	ImageDigest   string
	CreatedBy     string
	CreatedAt     time.Time
}

type RuntimeTargetStatus string

const RuntimeTargetStatusPending RuntimeTargetStatus = "pending"

type RuntimeTarget struct {
	ID            string
	ProjectID     string
	Name          string
	Endpoint      string
	TLSServerName string
	CredentialRef string
	Status        RuntimeTargetStatus
	CreatedBy     string
	CreatedAt     time.Time
}

type ProjectRepository interface {
	ListProjects(context.Context, string) ([]Project, error)
	CreateProject(context.Context, Project) (Project, error)
	ProjectExists(context.Context, string, string) (bool, error)
}

type ApplicationRepository interface {
	ListApplications(context.Context, string) ([]Application, error)
	CreateApplication(context.Context, Application) (Application, error)
	ApplicationExists(context.Context, string, string) (bool, error)
}

type ReleaseRepository interface {
	ListReleases(context.Context, string, string) ([]Release, error)
	CreateRelease(context.Context, Release) (Release, error)
}

type RuntimeTargetRepository interface {
	ListRuntimeTargets(context.Context, string) ([]RuntimeTarget, error)
	CreateRuntimeTarget(context.Context, RuntimeTarget) (RuntimeTarget, error)
}

func NewProject(id, organizationID, name, createdBy string, now time.Time) (Project, error) {
	name, err := validName(name)
	if err != nil {
		return Project{}, err
	}
	return Project{
		ID: id, OrganizationID: organizationID, Name: name,
		CreatedBy: createdBy, CreatedAt: now.UTC(),
	}, nil
}

func NewApplication(id, projectID, name, createdBy string, now time.Time) (Application, error) {
	name, err := validName(name)
	if err != nil {
		return Application{}, err
	}
	return Application{
		ID: id, ProjectID: projectID, Name: name,
		CreatedBy: createdBy, CreatedAt: now.UTC(),
	}, nil
}

func NewRelease(id, projectID, applicationID, image, createdBy string, now time.Time) (Release, error) {
	image, err := canonicalDigestReference(image)
	if err != nil {
		return Release{}, err
	}
	return Release{
		ID: id, ProjectID: projectID, ApplicationID: applicationID,
		ImageDigest: image, CreatedBy: createdBy, CreatedAt: now.UTC(),
	}, nil
}

func NewRuntimeTarget(
	id, projectID, name, endpoint, tlsServerName, credentialRef, createdBy string,
	now time.Time,
) (RuntimeTarget, error) {
	name, err := validName(name)
	if err != nil {
		return RuntimeTarget{}, err
	}
	endpoint, tlsServerName, credentialRef, err = validRuntimeTarget(endpoint, tlsServerName, credentialRef)
	if err != nil {
		return RuntimeTarget{}, err
	}
	return RuntimeTarget{
		ID: id, ProjectID: projectID, Name: name, Endpoint: endpoint,
		TLSServerName: tlsServerName, CredentialRef: credentialRef,
		Status: RuntimeTargetStatusPending, CreatedBy: createdBy, CreatedAt: now.UTC(),
	}, nil
}

func validName(value string) (string, error) {
	value = strings.TrimSpace(value)
	if len(value) < 2 || len(value) > 80 {
		return "", ErrInvalidName
	}
	return value, nil
}

func canonicalDigestReference(value string) (string, error) {
	named, err := reference.ParseNormalizedNamed(strings.TrimSpace(value))
	if err != nil {
		return "", ErrInvalidImage
	}
	digested, ok := named.(reference.Digested)
	if !ok || digested.Digest().Algorithm() != digest.SHA256 || digested.Digest().Validate() != nil {
		return "", ErrInvalidImage
	}
	return reference.FamiliarString(named), nil
}

func validRuntimeTarget(endpoint, tlsServerName, credentialRef string) (string, string, string, error) {
	endpoint = strings.TrimSpace(endpoint)
	tlsServerName = strings.TrimSpace(tlsServerName)
	credentialRef = strings.TrimSpace(credentialRef)
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "tcp" || parsed.Host == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Path != "" && parsed.Path != "/") ||
		tlsServerName == "" || credentialRef == "" {
		return "", "", "", ErrInvalidRuntimeTarget
	}
	host, port, err := net.SplitHostPort(parsed.Host)
	if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
		return "", "", "", ErrInvalidRuntimeTarget
	}
	return "tcp://" + net.JoinHostPort(host, port), tlsServerName, credentialRef, nil
}
