package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-kratos/kratos/v2/log"

	applicationbiz "github.com/owndock/owndock/internal/modules/application/biz"
	applicationdata "github.com/owndock/owndock/internal/modules/application/data"
	applicationservice "github.com/owndock/owndock/internal/modules/application/service"
	controlplanebiz "github.com/owndock/owndock/internal/modules/controlplane/biz"
	controlplaneservice "github.com/owndock/owndock/internal/modules/controlplane/service"
	deploymentbiz "github.com/owndock/owndock/internal/modules/deployment/biz"
	deploymentdata "github.com/owndock/owndock/internal/modules/deployment/data"
	deploymentservice "github.com/owndock/owndock/internal/modules/deployment/service"
	environmentbiz "github.com/owndock/owndock/internal/modules/environment/biz"
	environmentdata "github.com/owndock/owndock/internal/modules/environment/data"
	environmentservice "github.com/owndock/owndock/internal/modules/environment/service"
	identitybiz "github.com/owndock/owndock/internal/modules/identity/biz"
	identityservice "github.com/owndock/owndock/internal/modules/identity/service"
	managedhostbiz "github.com/owndock/owndock/internal/modules/managedhost/biz"
	managedhostservice "github.com/owndock/owndock/internal/modules/managedhost/service"
	"github.com/owndock/owndock/internal/modules/meta"
	platformconfig "github.com/owndock/owndock/internal/platform/config"
	"github.com/owndock/owndock/internal/platform/health"
	"github.com/owndock/owndock/internal/platform/observability"
	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/transaction"
)

const contractAccessToken = "test-token-0123456789012345678901234567890123456789"

type contractLoginGuard struct{}

func (contractLoginGuard) ReserveLoginAttempt(
	context.Context,
	string,
	time.Time,
	int,
	time.Duration,
) (bool, time.Time, error) {
	return true, time.Time{}, nil
}

func (contractLoginGuard) ResetLoginAttempts(
	context.Context,
	string,
) error {
	return nil
}

func newProductContractHTTPHandler(t *testing.T) http.Handler {
	t.Helper()
	now := func() time.Time { return time.Unix(100, 0).UTC() }
	newID := func() (string, error) { return "test-id", nil }
	audits := &contractAudit{}

	identityUseCase := identitybiz.NewUseCase(
		&contractIdentityRepository{},
		transaction.Passthrough{},
		audits,
		contractPasswords{},
		contractTokens{},
		newID,
		now,
		time.Hour,
	).WithLoginProtection(
		contractLoginGuard{},
		5,
		15*time.Minute,
	).WithSessionPolicy(10)
	identityHTTP := identityservice.NewHTTP(identityUseCase, func() (string, error) {
		return "bootstrap-secret", nil
	})
	controlStore := &contractControlStore{}
	managedHostStore := &contractManagedHostStore{}
	controlUseCase := controlplanebiz.NewUseCaseWithResources(
		controlStore, controlStore, controlStore, controlStore, controlStore, controlStore,
		transaction.Passthrough{}, audits, audits, newID, now,
	).WithManagedHosts(managedHostStore).
		WithRuntimeTargetProbe(controlStore, contractRuntimeTargetProber{})
	controlHTTP := controlplaneservice.NewHTTP(controlUseCase)
	managedHostHTTP := managedhostservice.NewHTTP(managedhostbiz.NewUseCase(
		managedHostStore, transaction.Passthrough{}, audits, newID, now,
	))
	formalDeploymentHTTP := deploymentservice.NewHTTP(
		deploymentbiz.NewUseCase(deploymentdata.NewMemoryRepository(), nil, nil, newID, now).
			WithFormalReferences(deploymentdata.NewFormalReferenceLookup(controlStore)).
			WithFormalSecurity(transaction.Passthrough{}, audits),
	)
	productAPI, err := NewProductAPIWithDeploymentAndManagedHost(
		identityHTTP, controlHTTP, http.HandlerFunc(formalDeploymentHTTP.HandleFormal),
		managedHostHTTP, identityHTTP.Authenticate,
	)
	if err != nil {
		t.Fatalf("NewProductAPI() error = %v", err)
	}

	applications := applicationdata.NewMemoryRepository()
	environments := environmentdata.NewMemoryRepository()
	samples := &EngineeringSamples{
		Application: applicationservice.NewHTTP(applicationbiz.NewUseCase(applications, newID, now)),
		Environment: environmentservice.NewHTTP(environmentbiz.NewUseCase(environments, newID, now)),
		Deployment: deploymentservice.NewHTTP(deploymentbiz.NewUseCase(
			deploymentdata.NewMemoryRepository(),
			deploymentdata.NewApplicationLookup(applications),
			deploymentdata.NewEnvironmentLookup(environments),
			newID,
			now,
		)),
	}
	checker := health.NewChecker()
	checker.SetReady(true)
	tracing, err := observability.NewTracing(context.Background(), platformconfig.Tracing{}, "owndock", "test", "test-instance")
	if err != nil {
		t.Fatalf("NewTracing() error = %v", err)
	}
	srv, err := NewHTTPServer(
		platformconfig.HTTP{Address: "127.0.0.1:0", Timeout: "1s"},
		checker,
		meta.NewService(meta.BuildInfo{Service: "owndock", Version: "test"}),
		samples,
		productAPI,
		observability.NewMetrics(),
		tracing,
		log.NewStdLogger(httptest.NewRecorder()),
	)
	if err != nil {
		t.Fatalf("NewHTTPServer() error = %v", err)
	}
	return srv
}

type contractIdentityRepository struct {
	user     identitybiz.User
	sessions map[string]identitybiz.Session
}

func (r *contractIdentityRepository) HasUsers(context.Context) (bool, error) {
	return r.user.ID != "", nil
}

func (r *contractIdentityRepository) CreateBootstrap(
	_ context.Context,
	_ identitybiz.Organization,
	user identitybiz.User,
	session identitybiz.Session,
) error {
	r.user = user
	r.sessions = map[string]identitybiz.Session{session.TokenHash: session}
	return nil
}

func (r *contractIdentityRepository) FindUserByEmail(_ context.Context, email string) (identitybiz.User, error) {
	if r.user.EmailNormalized != email {
		return identitybiz.User{}, identitybiz.ErrNotFound
	}
	return r.user, nil
}

func (r *contractIdentityRepository) CreateSession(
	_ context.Context,
	session identitybiz.Session,
	_ time.Time,
	_ int,
) error {
	r.sessions[session.TokenHash] = session
	return nil
}

func (r *contractIdentityRepository) FindSession(
	_ context.Context,
	tokenHash string,
	now time.Time,
) (identitybiz.Session, identitybiz.User, error) {
	session, ok := r.sessions[tokenHash]
	if !ok || !session.ExpiresAt.After(now) {
		return identitybiz.Session{}, identitybiz.User{}, identitybiz.ErrNotFound
	}
	return session, r.user, nil
}

func (r *contractIdentityRepository) ListSessions(
	_ context.Context,
	userID string,
	now time.Time,
) ([]identitybiz.Session, error) {
	var result []identitybiz.Session
	for _, session := range r.sessions {
		if session.UserID == userID && session.ExpiresAt.After(now) {
			result = append(result, session)
		}
	}
	return result, nil
}

func (r *contractIdentityRepository) DeleteSession(_ context.Context, sessionID, userID string) error {
	for hash, session := range r.sessions {
		if session.ID == sessionID && session.UserID == userID {
			delete(r.sessions, hash)
			return nil
		}
	}
	return identitybiz.ErrNotFound
}

type contractPasswords struct{}

func (contractPasswords) Hash(value string) (string, error) { return "hash:" + value, nil }
func (contractPasswords) Verify(value, encoded string) bool { return encoded == "hash:"+value }
func (contractPasswords) DummyHash() string                 { return "hash:dummy" }

type contractTokens struct{}

func (contractTokens) New() (string, string, error) {
	return contractAccessToken, "hash:" + contractAccessToken, nil
}
func (contractTokens) Hash(value string) string { return "hash:" + value }

type contractAudit struct {
	events []sharedaudit.Event
}

func (a *contractAudit) Record(_ context.Context, event sharedaudit.Event) error {
	a.events = append(a.events, event)
	return nil
}

func (a *contractAudit) List(_ context.Context, organizationID, projectID string, limit int64) ([]sharedaudit.Event, error) {
	var result []sharedaudit.Event
	for _, event := range a.events {
		if event.OrganizationID == organizationID && (projectID == "" || event.ProjectID == projectID) {
			result = append(result, event)
		}
	}
	if int64(len(result)) > limit {
		result = result[:limit]
	}
	return result, nil
}

type contractControlStore struct {
	projects     []controlplanebiz.Project
	applications []controlplanebiz.Application
	releases     []controlplanebiz.Release
	targets      []controlplanebiz.RuntimeTarget
	registries   []controlplanebiz.RegistryCredential
	environments []controlplanebiz.Environment
}

type contractRuntimeTargetProber struct{}

type contractManagedHostStore struct {
	items []managedhostbiz.ManagedHost
}

func (s *contractManagedHostStore) List(
	_ context.Context,
	organizationID string,
) ([]managedhostbiz.ManagedHost, error) {
	var result []managedhostbiz.ManagedHost
	for _, item := range s.items {
		if item.OrganizationID == organizationID {
			result = append(result, item)
		}
	}
	return result, nil
}

func (s *contractManagedHostStore) Get(
	_ context.Context,
	organizationID, hostID string,
) (managedhostbiz.ManagedHost, error) {
	for _, item := range s.items {
		if item.OrganizationID == organizationID && item.ID == hostID {
			return item, nil
		}
	}
	return managedhostbiz.ManagedHost{}, managedhostbiz.ErrNotFound
}

func (s *contractManagedHostStore) Create(
	_ context.Context,
	item managedhostbiz.ManagedHost,
) (managedhostbiz.ManagedHost, error) {
	s.items = append(s.items, item)
	return item, nil
}

func (s *contractManagedHostStore) Disable(
	_ context.Context,
	organizationID, hostID string,
	now time.Time,
) (managedhostbiz.ManagedHost, error) {
	for index := range s.items {
		if s.items[index].OrganizationID == organizationID &&
			s.items[index].ID == hostID {
			s.items[index].Status = managedhostbiz.StatusDisabled
			s.items[index].AgentBootID = ""
			s.items[index].AgentSessionID = ""
			s.items[index].UpdatedAt = now
			return s.items[index], nil
		}
	}
	return managedhostbiz.ManagedHost{}, managedhostbiz.ErrNotFound
}

func (s *contractManagedHostStore) ConnectionMode(
	ctx context.Context,
	organizationID, hostID string,
) (runtimeaccess.Mode, bool, error) {
	item, err := s.Get(ctx, organizationID, hostID)
	if err == managedhostbiz.ErrNotFound {
		return "", false, nil
	}
	return item.ConnectionMode, err == nil, err
}

func (contractRuntimeTargetProber) ProbeRuntimeTarget(
	context.Context,
	controlplanebiz.RuntimeTarget,
) (controlplanebiz.RuntimeTargetStatus, error) {
	return controlplanebiz.RuntimeTargetStatusReady, nil
}

func (s *contractControlStore) ListProjects(_ context.Context, organizationID string) ([]controlplanebiz.Project, error) {
	var result []controlplanebiz.Project
	for _, item := range s.projects {
		if item.OrganizationID == organizationID {
			result = append(result, item)
		}
	}
	return result, nil
}

func (s *contractControlStore) CreateProject(_ context.Context, item controlplanebiz.Project) (controlplanebiz.Project, error) {
	s.projects = append(s.projects, item)
	return item, nil
}

func (s *contractControlStore) ProjectExists(_ context.Context, organizationID, projectID string) (bool, error) {
	for _, item := range s.projects {
		if item.ID == projectID && item.OrganizationID == organizationID {
			return true, nil
		}
	}
	return false, nil
}

func (s *contractControlStore) ListApplications(_ context.Context, projectID string) ([]controlplanebiz.Application, error) {
	var result []controlplanebiz.Application
	for _, item := range s.applications {
		if item.ProjectID == projectID {
			result = append(result, item)
		}
	}
	return result, nil
}

func (s *contractControlStore) CreateApplication(_ context.Context, item controlplanebiz.Application) (controlplanebiz.Application, error) {
	s.applications = append(s.applications, item)
	return item, nil
}

func (s *contractControlStore) ApplicationExists(_ context.Context, projectID, applicationID string) (bool, error) {
	for _, item := range s.applications {
		if item.ProjectID == projectID && item.ID == applicationID {
			return true, nil
		}
	}
	return false, nil
}

func (s *contractControlStore) ListReleases(_ context.Context, projectID, applicationID string) ([]controlplanebiz.Release, error) {
	var result []controlplanebiz.Release
	for _, item := range s.releases {
		if item.ProjectID == projectID && item.ApplicationID == applicationID {
			result = append(result, item)
		}
	}
	return result, nil
}

func (s *contractControlStore) CreateRelease(_ context.Context, item controlplanebiz.Release) (controlplanebiz.Release, error) {
	s.releases = append(s.releases, item)
	return item, nil
}

func (s *contractControlStore) ReleaseExists(_ context.Context, projectID, applicationID, releaseID string) (bool, error) {
	for _, item := range s.releases {
		if item.ID == releaseID && item.ProjectID == projectID && item.ApplicationID == applicationID {
			return true, nil
		}
	}
	return false, nil
}

func (s *contractControlStore) ListRuntimeTargets(_ context.Context, projectID string) ([]controlplanebiz.RuntimeTarget, error) {
	var result []controlplanebiz.RuntimeTarget
	for _, item := range s.targets {
		if item.ProjectID == projectID {
			result = append(result, item)
		}
	}
	return result, nil
}

func (s *contractControlStore) CreateRuntimeTarget(
	_ context.Context,
	item controlplanebiz.RuntimeTarget,
) (controlplanebiz.RuntimeTarget, error) {
	s.targets = append(s.targets, item)
	return item, nil
}

func (s *contractControlStore) RuntimeTargetExists(_ context.Context, projectID, targetID string) (bool, error) {
	for _, item := range s.targets {
		if item.ID == targetID && item.ProjectID == projectID {
			return true, nil
		}
	}
	return false, nil
}

func (s *contractControlStore) RuntimeTargetReady(_ context.Context, projectID, targetID string) (bool, error) {
	for _, item := range s.targets {
		if item.ID == targetID && item.ProjectID == projectID {
			return item.Status == controlplanebiz.RuntimeTargetStatusReady, nil
		}
	}
	return false, nil
}

func (s *contractControlStore) GetRuntimeTarget(
	_ context.Context,
	projectID, targetID string,
) (controlplanebiz.RuntimeTarget, error) {
	for _, item := range s.targets {
		if item.ID == targetID && item.ProjectID == projectID {
			return item, nil
		}
	}
	return controlplanebiz.RuntimeTarget{}, controlplanebiz.ErrNotFound
}

func (s *contractControlStore) UpdateRuntimeTargetProbe(
	_ context.Context,
	projectID, targetID string,
	status controlplanebiz.RuntimeTargetStatus,
	probedAt time.Time,
) (controlplanebiz.RuntimeTarget, error) {
	for i := range s.targets {
		if s.targets[i].ID == targetID && s.targets[i].ProjectID == projectID {
			s.targets[i].Status = status
			s.targets[i].LastProbedAt = probedAt
			return s.targets[i], nil
		}
	}
	return controlplanebiz.RuntimeTarget{}, controlplanebiz.ErrNotFound
}

func (s *contractControlStore) ListRegistryCredentials(
	_ context.Context,
	projectID string,
) ([]controlplanebiz.RegistryCredential, error) {
	var result []controlplanebiz.RegistryCredential
	for _, item := range s.registries {
		if item.ProjectID == projectID {
			result = append(result, item)
		}
	}
	return result, nil
}

func (s *contractControlStore) CreateRegistryCredential(
	_ context.Context,
	item controlplanebiz.RegistryCredential,
) (controlplanebiz.RegistryCredential, error) {
	s.registries = append(s.registries, item)
	return item, nil
}

func (s *contractControlStore) GetRegistryCredential(
	_ context.Context,
	projectID, credentialID string,
) (controlplanebiz.RegistryCredential, error) {
	for _, item := range s.registries {
		if item.ID == credentialID && item.ProjectID == projectID {
			return item, nil
		}
	}
	return controlplanebiz.RegistryCredential{}, controlplanebiz.ErrNotFound
}

func (s *contractControlStore) ListEnvironments(_ context.Context, projectID string) ([]controlplanebiz.Environment, error) {
	var result []controlplanebiz.Environment
	for _, item := range s.environments {
		if item.ProjectID == projectID {
			result = append(result, item)
		}
	}
	return result, nil
}

func (s *contractControlStore) CreateEnvironment(_ context.Context, item controlplanebiz.Environment) (controlplanebiz.Environment, error) {
	s.environments = append(s.environments, item)
	return item, nil
}

func (s *contractControlStore) EnvironmentExists(_ context.Context, projectID, environmentID string) (bool, error) {
	for _, item := range s.environments {
		if item.ID == environmentID && item.ProjectID == projectID {
			return true, nil
		}
	}
	return false, nil
}
