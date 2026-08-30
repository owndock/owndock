package biz

import (
	"context"
	"errors"
	"net"
	"net/mail"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
	"github.com/owndock/owndock/internal/shared/registryauth"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/runtimespec"
	"github.com/owndock/owndock/internal/shared/secretref"
	"github.com/owndock/owndock/internal/shared/security"
)

var (
	ErrDuplicateName                 = errors.New("resource name already exists")
	ErrDuplicateRelease              = errors.New("release already exists")
	ErrInvalidImage                  = errors.New("image must be pinned by a sha256 digest")
	ErrInvalidName                   = errors.New("resource name is invalid")
	ErrInvalidRegistry               = errors.New("registry credential is invalid")
	ErrInvalidRuntimeSpec            = errors.New("release runtime specification is invalid")
	ErrInvalidRuntimeTarget          = errors.New("runtime target is invalid")
	ErrManagedHostNotFound           = errors.New("managed host was not found")
	ErrInvalidProjectMember          = errors.New("project member is invalid")
	ErrProjectMemberConflict         = errors.New("project member already exists or has changed")
	ErrCannotModifySelf              = errors.New("project member cannot modify their own membership")
	ErrRuntimeTargetHostMismatch     = errors.New("runtime target connection mode does not match managed host")
	ErrRuntimeTargetProbeUnavailable = errors.New("runtime target probe is unavailable")
	ErrNotFound                      = errors.New("resource was not found")
	ErrInvalidTemplate               = errors.New("template is invalid")
)

type Project struct {
	ID             string
	OrganizationID string
	Name           string
	CreatedBy      string
	CreatedAt      time.Time
}

// ProjectMember grants a local Organization user access to one Project. Owner
// access is implicit and is deliberately never persisted as a membership row.
type ProjectMember struct {
	OrganizationID string
	ProjectID      string
	UserID         string
	Email          string
	Role           security.Role
	Version        uint64
	CreatedBy      string
	CreatedAt      time.Time
	UpdatedBy      string
	UpdatedAt      time.Time
}

type OrganizationUser struct {
	ID             string
	OrganizationID string
	Email          string
	Role           security.Role
}

type Application struct {
	ID               string
	ProjectID        string
	Name             string
	TemplateSnapshot *ApplicationTemplateSnapshot
	CreatedBy        string
	CreatedAt        time.Time
}

// LocalizedText keeps the built-in catalog useful to both supported product
// locales without making the selected request language part of a persisted
// Application snapshot.
type LocalizedText struct {
	English           string
	SimplifiedChinese string
}

// TemplatePreset contains safe defaults only. It deliberately does not carry
// credentials, repository IDs, registry IDs, Environment values, commands or
// deployment targets.
type TemplatePreset struct {
	DockerfilePath string
	ContextPath    string
	RuntimeSpec    runtimespec.Spec
}

type Template struct {
	ID          string
	Version     uint64
	Name        LocalizedText
	Description LocalizedText
	Preset      TemplatePreset
}

// ApplicationTemplateSnapshot is copied at Application creation. Later
// catalog revisions cannot mutate an existing Application implicitly.
type ApplicationTemplateSnapshot struct {
	TemplateID      string
	TemplateVersion uint64
	DockerfilePath  string
	ContextPath     string
	RuntimeSpec     runtimespec.Spec
}

type TemplateCatalog interface {
	ListTemplates(context.Context) ([]Template, error)
	GetTemplate(context.Context, string) (Template, error)
}

type Release struct {
	ID                   string
	ProjectID            string
	ApplicationID        string
	ImageDigest          string
	RegistryCredentialID string
	SourceArtifactID     string
	RuntimeSpec          runtimespec.Spec
	CreatedBy            string
	CreatedAt            time.Time
}

// RegistryCredential stores only registry metadata and an external secret
// reference. Password material never crosses the control-plane repository.
type RegistryCredential struct {
	ID                 string
	ProjectID          string
	Name               string
	Server             string
	AuthenticationMode registryauth.Mode
	Username           string
	PasswordRef        string
	CreatedBy          string
	CreatedAt          time.Time
}

type RuntimeTargetStatus string

const (
	RuntimeTargetStatusPending         RuntimeTargetStatus = "pending"
	RuntimeTargetStatusReady           RuntimeTargetStatus = "ready"
	RuntimeTargetStatusUnreachable     RuntimeTargetStatus = "unreachable"
	RuntimeTargetStatusCredentialError RuntimeTargetStatus = "credential_error"
)

type RuntimeTarget struct {
	ID             string
	ProjectID      string
	Name           string
	ManagedHostID  string
	ConnectionMode runtimeaccess.Mode
	Endpoint       string
	TLSServerName  string
	CredentialRef  string
	Status         RuntimeTargetStatus
	LastProbedAt   time.Time
	CreatedBy      string
	CreatedAt      time.Time
}

type Environment struct {
	ID        string
	ProjectID string
	Name      string
	Stage     string
	Variables map[string]string
	CreatedBy string
	CreatedAt time.Time
}

type EnvironmentStage string

const (
	EnvironmentStageDevelopment EnvironmentStage = "development"
	EnvironmentStageStaging     EnvironmentStage = "staging"
	EnvironmentStageProduction  EnvironmentStage = "production"
)

type ProjectRepository interface {
	ListProjects(context.Context, string) ([]Project, error)
	CreateProject(context.Context, Project) (Project, error)
	ProjectExists(context.Context, string, string) (bool, error)
}

type ProjectMemberRepository interface {
	ListProjectIDsForUser(context.Context, string, string) ([]string, error)
	ResolveProjectRole(context.Context, string, string, string) (security.Role, error)
	FindOrganizationUserByEmail(context.Context, string, string) (OrganizationUser, error)
	ListProjectMembers(context.Context, string) ([]ProjectMember, error)
	GetProjectMember(context.Context, string, string) (ProjectMember, error)
	CreateProjectMember(context.Context, ProjectMember) (ProjectMember, error)
	UpdateProjectMember(context.Context, ProjectMember, uint64) (ProjectMember, error)
	DeleteProjectMember(context.Context, string, string, uint64) error
}

func NewProjectMember(
	projectID string, user OrganizationUser, role security.Role, createdBy string, now time.Time,
) (ProjectMember, error) {
	projectID, createdBy = strings.TrimSpace(projectID), strings.TrimSpace(createdBy)
	if projectID == "" || user.ID == "" || user.OrganizationID == "" || user.Email == "" || createdBy == "" || now.IsZero() ||
		user.Role == security.RoleOwner || !validProjectMemberRole(role) {
		return ProjectMember{}, ErrInvalidProjectMember
	}
	return ProjectMember{
		OrganizationID: user.OrganizationID, ProjectID: projectID, UserID: user.ID, Email: user.Email, Role: role,
		Version: 1, CreatedBy: createdBy, CreatedAt: now.UTC(),
		UpdatedBy: createdBy, UpdatedAt: now.UTC(),
	}, nil
}

func (m ProjectMember) ChangeRole(role security.Role, updatedBy string, now time.Time) (ProjectMember, error) {
	updatedBy = strings.TrimSpace(updatedBy)
	if !validProjectMemberRole(role) || updatedBy == "" || now.IsZero() || m.Version == 0 {
		return ProjectMember{}, ErrInvalidProjectMember
	}
	m.Role, m.Version, m.UpdatedBy, m.UpdatedAt = role, m.Version+1, updatedBy, now.UTC()
	return m, nil
}

func validProjectMemberRole(role security.Role) bool {
	return role == security.RoleMaintainer || role == security.RoleDeveloper || role == security.RoleViewer
}

func normalizeProjectMemberEmail(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	address, err := mail.ParseAddress(value)
	if err != nil || address.Address != value || len(value) > 254 {
		return "", ErrInvalidProjectMember
	}
	return value, nil
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

type ArtifactReleaseRepository interface {
	GetReleaseByArtifact(context.Context, string, string) (Release, error)
}

type RuntimeTargetRepository interface {
	ListRuntimeTargets(context.Context, string) ([]RuntimeTarget, error)
	CreateRuntimeTarget(context.Context, RuntimeTarget) (RuntimeTarget, error)
}

type RuntimeTargetProbeRepository interface {
	GetRuntimeTarget(context.Context, string, string) (RuntimeTarget, error)
	UpdateRuntimeTargetProbe(
		context.Context,
		string,
		string,
		RuntimeTargetStatus,
		time.Time,
	) (RuntimeTarget, error)
}

type RuntimeTargetProber interface {
	ProbeRuntimeTarget(
		context.Context,
		RuntimeTarget,
	) (RuntimeTargetStatus, error)
}

type RegistryCredentialRepository interface {
	ListRegistryCredentials(context.Context, string) ([]RegistryCredential, error)
	CreateRegistryCredential(context.Context, RegistryCredential) (RegistryCredential, error)
	GetRegistryCredential(context.Context, string, string) (RegistryCredential, error)
}

type EnvironmentRepository interface {
	ListEnvironments(context.Context, string) ([]Environment, error)
	CreateEnvironment(context.Context, Environment) (Environment, error)
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
	return NewApplicationFromTemplate(
		id, projectID, name, createdBy, now, nil,
	)
}

func NewApplicationFromTemplate(
	id, projectID, name, createdBy string,
	now time.Time,
	template *Template,
) (Application, error) {
	name, err := validName(name)
	if err != nil {
		return Application{}, err
	}
	item := Application{
		ID: id, ProjectID: projectID, Name: name,
		CreatedBy: createdBy, CreatedAt: now.UTC(),
	}
	if template == nil {
		return item, nil
	}
	normalized, err := NormalizeTemplate(*template)
	if err != nil {
		return Application{}, err
	}
	item.TemplateSnapshot, err = NormalizeApplicationTemplateSnapshot(
		&ApplicationTemplateSnapshot{
			TemplateID: normalized.ID, TemplateVersion: normalized.Version,
			DockerfilePath: normalized.Preset.DockerfilePath,
			ContextPath:    normalized.Preset.ContextPath,
			RuntimeSpec:    cloneRuntimeSpec(normalized.Preset.RuntimeSpec),
		},
	)
	if err != nil {
		return Application{}, err
	}
	return item, nil
}

func NormalizeApplicationTemplateSnapshot(
	item *ApplicationTemplateSnapshot,
) (*ApplicationTemplateSnapshot, error) {
	if item == nil {
		return nil, nil
	}
	template, err := NormalizeTemplate(Template{
		ID: item.TemplateID, Version: item.TemplateVersion,
		Name: LocalizedText{English: "snapshot", SimplifiedChinese: "快照"},
		Description: LocalizedText{
			English: "snapshot", SimplifiedChinese: "快照",
		},
		Preset: TemplatePreset{
			DockerfilePath: item.DockerfilePath,
			ContextPath:    item.ContextPath,
			RuntimeSpec:    cloneRuntimeSpec(item.RuntimeSpec),
		},
	})
	if err != nil {
		return nil, err
	}
	return &ApplicationTemplateSnapshot{
		TemplateID: template.ID, TemplateVersion: template.Version,
		DockerfilePath: template.Preset.DockerfilePath,
		ContextPath:    template.Preset.ContextPath,
		RuntimeSpec:    cloneRuntimeSpec(template.Preset.RuntimeSpec),
	}, nil
}

func NormalizeTemplate(item Template) (Template, error) {
	item.ID = strings.TrimSpace(item.ID)
	item.Name.English = strings.TrimSpace(item.Name.English)
	item.Name.SimplifiedChinese = strings.TrimSpace(item.Name.SimplifiedChinese)
	item.Description.English = strings.TrimSpace(item.Description.English)
	item.Description.SimplifiedChinese = strings.TrimSpace(
		item.Description.SimplifiedChinese,
	)
	item.Preset.DockerfilePath = strings.TrimSpace(item.Preset.DockerfilePath)
	item.Preset.ContextPath = strings.TrimSpace(item.Preset.ContextPath)
	contextPath, contextOK := safeTemplatePath(item.Preset.ContextPath, true)
	dockerfilePath, dockerfileOK := safeTemplatePath(
		item.Preset.DockerfilePath,
		false,
	)
	if !validTemplateID(item.ID) || item.Version == 0 ||
		len(item.Name.English) > 80 || len(item.Name.SimplifiedChinese) > 80 ||
		item.Name.English == "" || item.Name.SimplifiedChinese == "" ||
		len(item.Description.English) > 240 ||
		len(item.Description.SimplifiedChinese) > 240 ||
		item.Description.English == "" ||
		item.Description.SimplifiedChinese == "" ||
		!contextOK || !dockerfileOK ||
		(contextPath != "." && dockerfilePath != contextPath &&
			!strings.HasPrefix(dockerfilePath, contextPath+"/")) {
		return Template{}, ErrInvalidTemplate
	}
	item.Preset.ContextPath = contextPath
	item.Preset.DockerfilePath = dockerfilePath
	runtimeSpec, err := runtimespec.Normalize(
		cloneRuntimeSpec(item.Preset.RuntimeSpec),
	)
	if err != nil {
		return Template{}, ErrInvalidTemplate
	}
	item.Preset.RuntimeSpec = runtimeSpec
	return item, nil
}

func validTemplateID(value string) bool {
	if len(value) < 2 || len(value) > 80 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func safeTemplatePath(value string, allowRoot bool) (string, bool) {
	if value == "" || len(value) > 255 || strings.Contains(value, "\\") ||
		strings.ContainsRune(value, 0) || path.IsAbs(value) {
		return "", false
	}
	cleaned := path.Clean(value)
	if cleaned != value || cleaned == ".." || strings.HasPrefix(cleaned, "../") ||
		(!allowRoot && cleaned == ".") {
		return "", false
	}
	return cleaned, true
}

func cloneRuntimeSpec(value runtimespec.Spec) runtimespec.Spec {
	value.Ports = append([]runtimespec.Port(nil), value.Ports...)
	value.EnvironmentKeys = append([]string(nil), value.EnvironmentKeys...)
	if value.HealthCheck != nil {
		health := *value.HealthCheck
		health.Command = append([]string(nil), value.HealthCheck.Command...)
		value.HealthCheck = &health
	}
	return value
}

func NewRelease(id, projectID, applicationID, image, createdBy string, now time.Time) (Release, error) {
	return NewReleaseWithRegistry(id, projectID, applicationID, image, "", createdBy, now)
}

func NewReleaseWithRegistry(
	id, projectID, applicationID, image, registryCredentialID, createdBy string,
	now time.Time,
) (Release, error) {
	return NewReleaseWithRuntimeSpec(
		id, projectID, applicationID, image, registryCredentialID,
		runtimespec.Spec{}, createdBy, now,
	)
}

func NewReleaseWithRuntimeSpec(
	id, projectID, applicationID, image, registryCredentialID string,
	runtimeSpec runtimespec.Spec,
	createdBy string,
	now time.Time,
) (Release, error) {
	image, err := canonicalDigestReference(image)
	if err != nil {
		return Release{}, err
	}
	runtimeSpec, err = runtimespec.Normalize(runtimeSpec)
	if err != nil {
		return Release{}, ErrInvalidRuntimeSpec
	}
	return Release{
		ID: id, ProjectID: projectID, ApplicationID: applicationID,
		ImageDigest: image, RegistryCredentialID: strings.TrimSpace(registryCredentialID),
		RuntimeSpec: runtimeSpec,
		CreatedBy:   createdBy, CreatedAt: now.UTC(),
	}, nil
}

func NewReleaseFromArtifact(
	id, projectID, applicationID, image, registryCredentialID, artifactID string,
	runtimeSpec runtimespec.Spec,
	createdBy string,
	now time.Time,
) (Release, error) {
	artifactID = strings.TrimSpace(artifactID)
	if artifactID == "" {
		return Release{}, ErrInvalidImage
	}
	item, err := NewReleaseWithRuntimeSpec(
		id, projectID, applicationID, image, registryCredentialID,
		runtimeSpec, createdBy, now,
	)
	if err != nil {
		return Release{}, err
	}
	item.SourceArtifactID = artifactID
	return item, nil
}

func NewRegistryCredential(
	id, projectID, name, server string, authenticationMode registryauth.Mode,
	username, passwordRef, createdBy string,
	now time.Time,
) (RegistryCredential, error) {
	name, err := validName(name)
	if err != nil {
		return RegistryCredential{}, err
	}
	server, username, passwordRef, err = validRegistryCredential(
		server, authenticationMode, username, passwordRef,
	)
	if err != nil {
		return RegistryCredential{}, err
	}
	return RegistryCredential{
		ID: id, ProjectID: projectID, Name: name, Server: server,
		AuthenticationMode: authenticationMode, Username: username, PasswordRef: passwordRef,
		CreatedBy: createdBy, CreatedAt: now.UTC(),
	}, nil
}

func NewRuntimeTarget(
	id, projectID, name, managedHostID string,
	connectionMode runtimeaccess.Mode,
	endpoint, tlsServerName, credentialRef, createdBy string,
	now time.Time,
) (RuntimeTarget, error) {
	name, err := validName(name)
	if err != nil {
		return RuntimeTarget{}, err
	}
	managedHostID = strings.TrimSpace(managedHostID)
	if managedHostID == "" {
		return RuntimeTarget{}, ErrInvalidRuntimeTarget
	}
	switch connectionMode {
	case runtimeaccess.ModeDirectDocker:
		endpoint, tlsServerName, credentialRef, err = validRuntimeTarget(
			endpoint, tlsServerName, credentialRef,
		)
		if err != nil {
			return RuntimeTarget{}, err
		}
		if _, err := runtimeaccess.NewDirectDocker(
			managedHostID, endpoint, tlsServerName, credentialRef,
		); err != nil {
			return RuntimeTarget{}, ErrInvalidRuntimeTarget
		}
	case runtimeaccess.ModeAgent:
		if strings.TrimSpace(endpoint) != "" ||
			strings.TrimSpace(tlsServerName) != "" ||
			strings.TrimSpace(credentialRef) != "" {
			return RuntimeTarget{}, ErrInvalidRuntimeTarget
		}
		if _, err := runtimeaccess.NewAgent(managedHostID); err != nil {
			return RuntimeTarget{}, ErrInvalidRuntimeTarget
		}
	default:
		return RuntimeTarget{}, ErrInvalidRuntimeTarget
	}
	return RuntimeTarget{
		ID: id, ProjectID: projectID, Name: name,
		ManagedHostID: managedHostID, ConnectionMode: connectionMode,
		Endpoint:      endpoint,
		TLSServerName: tlsServerName, CredentialRef: credentialRef,
		Status: RuntimeTargetStatusPending, CreatedBy: createdBy, CreatedAt: now.UTC(),
	}, nil
}

func NewEnvironment(id, projectID, name, stage, createdBy string, now time.Time) (Environment, error) {
	return NewEnvironmentWithVariables(id, projectID, name, stage, nil, createdBy, now)
}

func NewEnvironmentWithVariables(
	id, projectID, name, stage string,
	variables map[string]string,
	createdBy string,
	now time.Time,
) (Environment, error) {
	name, err := validName(name)
	if err != nil {
		return Environment{}, err
	}
	stage = strings.TrimSpace(stage)
	if stage != string(EnvironmentStageDevelopment) && stage != string(EnvironmentStageStaging) && stage != string(EnvironmentStageProduction) {
		return Environment{}, ErrInvalidName
	}
	if projectID == "" || createdBy == "" {
		return Environment{}, ErrInvalidName
	}
	variables, err = runtimespec.NormalizeVariables(variables)
	if err != nil {
		return Environment{}, ErrInvalidRuntimeSpec
	}
	return Environment{
		ID: id, ProjectID: projectID, Name: name, Stage: stage, Variables: variables,
		CreatedBy: createdBy, CreatedAt: now.UTC(),
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

func validRegistryCredential(server string, authenticationMode registryauth.Mode,
	username, passwordRef string,
) (string, string, string, error) {
	server = strings.ToLower(strings.TrimSpace(server))
	username = strings.TrimSpace(username)
	passwordRef = strings.TrimSpace(passwordRef)
	if server == "" || !authenticationMode.Valid() {
		return "", "", "", ErrInvalidRegistry
	}
	parsed, err := url.Parse("https://" + server)
	if err != nil || parsed.Host != server || parsed.Hostname() == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Path != "" && parsed.Path != "/") {
		return "", "", "", ErrInvalidRegistry
	}
	switch authenticationMode {
	case registryauth.ModeAnonymous:
		if username != "" || passwordRef != "" {
			return "", "", "", ErrInvalidRegistry
		}
	case registryauth.ModeBasic:
		if username == "" || len(username) > 255 || strings.ContainsAny(username, ":\r\n\x00") || passwordRef == "" {
			return "", "", "", ErrInvalidRegistry
		}
		if _, err := secretref.Alias(passwordRef); err != nil {
			return "", "", "", ErrInvalidRegistry
		}
	default:
		return "", "", "", ErrInvalidRegistry
	}
	return server, username, passwordRef, nil
}

func ImageRegistry(value string) (string, error) {
	named, err := reference.ParseNormalizedNamed(strings.TrimSpace(value))
	if err != nil {
		return "", ErrInvalidImage
	}
	return strings.ToLower(reference.Domain(named)), nil
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
	if _, err := secretref.Alias(credentialRef); err != nil {
		return "", "", "", ErrInvalidRuntimeTarget
	}
	host, port, err := net.SplitHostPort(parsed.Host)
	if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
		return "", "", "", ErrInvalidRuntimeTarget
	}
	return "tcp://" + net.JoinHostPort(host, port), tlsServerName, credentialRef, nil
}
