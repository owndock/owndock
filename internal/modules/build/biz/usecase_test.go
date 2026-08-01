package biz

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/runtimespec"
	"github.com/owndock/owndock/internal/shared/security"
	"github.com/owndock/owndock/internal/shared/transaction"
)

type projectLookupStub struct {
	exists bool
}

type configurationReferencesStub struct {
	applicationExists bool
	registryServer    string
	err               error
}

type automaticDeploymentReferencesStub struct{ err error }

func (s automaticDeploymentReferencesStub) ValidateAutomaticDeployment(
	context.Context, string, string, string,
) error {
	return s.err
}

func (s configurationReferencesStub) ApplicationExists(
	context.Context,
	string,
	string,
) (bool, error) {
	return s.applicationExists, s.err
}

func (s configurationReferencesStub) RegistryServer(
	context.Context,
	string,
	string,
) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	if s.registryServer == "" {
		return "", ErrNotFound
	}
	return s.registryServer, nil
}

func (s projectLookupStub) ProjectExists(
	context.Context,
	string,
	string,
) (bool, error) {
	return s.exists, nil
}

type repositoryStub struct {
	credentials    map[string]RepositoryCredential
	sources        map[string]SourceRepository
	configurations map[string]BuildConfiguration
	builds         map[string]Build
	triggers       map[string]BuildTrigger
	hooks          map[string]BuildHook
	deliveries     map[string]WebhookDelivery
	logs           map[string][]BuildLogEntry
}

func newRepositoryStub() *repositoryStub {
	return &repositoryStub{
		credentials:    make(map[string]RepositoryCredential),
		sources:        make(map[string]SourceRepository),
		configurations: make(map[string]BuildConfiguration),
		builds:         make(map[string]Build),
		triggers:       make(map[string]BuildTrigger),
		hooks:          make(map[string]BuildHook),
		deliveries:     make(map[string]WebhookDelivery),
		logs:           make(map[string][]BuildLogEntry),
	}
}

func (s *repositoryStub) AppendBuildLog(_ context.Context, item BuildLogAppend) error {
	entries := s.logs[item.BuildID]
	s.logs[item.BuildID] = append(entries, BuildLogEntry{
		Sequence: uint64(len(entries) + 1), Stage: item.Stage,
		Message: item.Message, CreatedAt: item.CreatedAt,
	})
	return nil
}

func (s *repositoryStub) ReadBuildLogs(_ context.Context, projectID, buildID string,
	query BuildLogQuery) (BuildLogPage, error) {
	build, ok := s.builds[buildID]
	if !ok || build.ProjectID != projectID {
		return BuildLogPage{}, ErrNotFound
	}
	query, err := query.Normalize()
	if err != nil {
		return BuildLogPage{}, err
	}
	entries := make([]BuildLogEntry, 0, query.Limit)
	for _, entry := range s.logs[buildID] {
		if entry.Sequence > query.AfterSequence && len(entries) < query.Limit {
			entries = append(entries, entry)
		}
	}
	next := query.AfterSequence
	if len(entries) > 0 {
		next = entries[len(entries)-1].Sequence
	}
	return BuildLogPage{
		Entries: entries, NextSequence: next,
		ExpiresAt: time.Unix(100, 0).Add(DefaultBuildLogRetention),
	}, nil
}

func (s *repositoryStub) ListBuildHooks(_ context.Context, projectID, applicationID, configurationID string) ([]BuildHookSummary, error) {
	items := make([]BuildHookSummary, 0)
	for _, item := range s.hooks {
		if item.ProjectID == projectID && item.ApplicationID == applicationID && item.BuildConfigurationID == configurationID {
			items = append(items, item.Summary())
		}
	}
	return items, nil
}

func (s *repositoryStub) CreateBuildHook(_ context.Context, item BuildHook) (BuildHookSummary, error) {
	s.hooks[item.ID] = item
	return item.Summary(), nil
}

func (s *repositoryStub) GetBuildHook(_ context.Context, id string) (BuildHook, error) {
	item, ok := s.hooks[id]
	if !ok {
		return BuildHook{}, ErrNotFound
	}
	return item, nil
}

func (s *repositoryStub) RevokeBuildHook(_ context.Context, item BuildHook, expected uint64) (BuildHookSummary, error) {
	current, ok := s.hooks[item.ID]
	if !ok {
		return BuildHookSummary{}, ErrNotFound
	}
	if current.Version != expected {
		return BuildHookSummary{}, ErrVersionConflict
	}
	s.hooks[item.ID] = item
	return item.Summary(), nil
}

func (s *repositoryStub) CreateWebhookDelivery(_ context.Context, item WebhookDelivery) error {
	key := string(item.Provider) + ":" + item.HookID + ":" + item.DeliveryID
	if _, ok := s.deliveries[key]; ok {
		return ErrDuplicateWebhookDelivery
	}
	s.deliveries[key] = item
	return nil
}

func (s *repositoryStub) GetWebhookDelivery(_ context.Context, hookID string, provider WebhookProvider, deliveryID string) (WebhookDelivery, error) {
	item, ok := s.deliveries[string(provider)+":"+hookID+":"+deliveryID]
	if !ok {
		return WebhookDelivery{}, ErrNotFound
	}
	return item, nil
}

func (s *repositoryStub) ListBuildTriggers(_ context.Context, projectID, applicationID, configurationID string) ([]BuildTrigger, error) {
	var items []BuildTrigger
	for _, item := range s.triggers {
		if item.ProjectID == projectID && item.ApplicationID == applicationID && item.BuildConfigurationID == configurationID {
			items = append(items, item)
		}
	}
	return items, nil
}
func (s *repositoryStub) CreateBuildTrigger(_ context.Context, item BuildTrigger) (BuildTrigger, error) {
	s.triggers[item.ID] = item
	return item, nil
}
func (s *repositoryStub) GetBuildTrigger(_ context.Context, id string) (BuildTrigger, error) {
	item, ok := s.triggers[id]
	if !ok {
		return BuildTrigger{}, ErrNotFound
	}
	return item, nil
}
func (s *repositoryStub) RevokeBuildTrigger(_ context.Context, item BuildTrigger, expected uint64) (BuildTrigger, error) {
	current, ok := s.triggers[item.ID]
	if !ok {
		return BuildTrigger{}, ErrNotFound
	}
	if current.Version != expected {
		return BuildTrigger{}, ErrVersionConflict
	}
	s.triggers[item.ID] = item
	return item, nil
}

func (s *repositoryStub) ListBuilds(_ context.Context, projectID string) ([]Build, error) {
	var items []Build
	for _, item := range s.builds {
		if item.ProjectID == projectID {
			items = append(items, item)
		}
	}
	return items, nil
}

func (s *repositoryStub) CreateBuild(_ context.Context, item Build) (Build, error) {
	for _, existing := range s.builds {
		if existing.ProjectID == item.ProjectID && existing.IdempotencyKey == item.IdempotencyKey {
			return Build{}, ErrDuplicateIdempotency
		}
	}
	s.builds[item.ID] = item
	return item, nil
}

func (s *repositoryStub) SaveBuild(_ context.Context, item Build, expected uint64) (Build, error) {
	current, found := s.builds[item.ID]
	if !found || current.ProjectID != item.ProjectID {
		return Build{}, ErrNotFound
	}
	if current.Version != expected {
		return Build{}, ErrVersionConflict
	}
	item.Version = expected + 1
	s.builds[item.ID] = item
	return item, nil
}

func (s *repositoryStub) GetBuild(_ context.Context, projectID, buildID string) (Build, error) {
	item, found := s.builds[buildID]
	if !found || item.ProjectID != projectID {
		return Build{}, ErrNotFound
	}
	return item, nil
}

func (s *repositoryStub) GetBuildByIdempotency(
	_ context.Context,
	projectID, idempotencyKey string,
) (Build, error) {
	for _, item := range s.builds {
		if item.ProjectID == projectID && item.IdempotencyKey == idempotencyKey {
			return item, nil
		}
	}
	return Build{}, ErrNotFound
}

func (s *repositoryStub) ListBuildConfigurations(
	_ context.Context,
	projectID, applicationID string,
) ([]BuildConfiguration, error) {
	var items []BuildConfiguration
	for _, item := range s.configurations {
		if item.ProjectID == projectID && item.ApplicationID == applicationID {
			items = append(items, item)
		}
	}
	return items, nil
}

func (s *repositoryStub) CreateBuildConfiguration(
	_ context.Context,
	item BuildConfiguration,
) (BuildConfiguration, error) {
	s.configurations[item.ID] = item
	return item, nil
}

func (s *repositoryStub) GetBuildConfiguration(
	_ context.Context,
	projectID, applicationID, configurationID string,
) (BuildConfiguration, error) {
	item, found := s.configurations[configurationID]
	if !found || item.ProjectID != projectID || item.ApplicationID != applicationID {
		return BuildConfiguration{}, ErrNotFound
	}
	return item, nil
}

func (s *repositoryStub) UpdateBuildConfiguration(
	_ context.Context,
	item BuildConfiguration,
	expectedVersion uint64,
) (BuildConfiguration, error) {
	current, found := s.configurations[item.ID]
	if !found {
		return BuildConfiguration{}, ErrNotFound
	}
	if current.Version != expectedVersion {
		return BuildConfiguration{}, ErrVersionConflict
	}
	s.configurations[item.ID] = item
	return item, nil
}

func (s *repositoryStub) ListCredentials(
	context.Context,
	string,
) ([]CredentialSummary, error) {
	result := make([]CredentialSummary, 0, len(s.credentials))
	for _, item := range s.credentials {
		result = append(result, item.Summary())
	}
	return result, nil
}

func (s *repositoryStub) CreateCredential(
	_ context.Context,
	item RepositoryCredential,
) (CredentialSummary, error) {
	s.credentials[item.ID] = item
	return item.Summary(), nil
}

func (s *repositoryStub) GetCredential(
	_ context.Context,
	projectID, credentialID string,
) (RepositoryCredential, error) {
	item, found := s.credentials[credentialID]
	if !found || item.ProjectID != projectID {
		return RepositoryCredential{}, ErrNotFound
	}
	return item, nil
}

func (s *repositoryStub) ListSources(
	context.Context,
	string,
) ([]SourceRepository, error) {
	result := make([]SourceRepository, 0, len(s.sources))
	for _, item := range s.sources {
		result = append(result, item)
	}
	return result, nil
}

func (s *repositoryStub) CreateSource(
	_ context.Context,
	item SourceRepository,
) (SourceRepository, error) {
	s.sources[item.ID] = item
	return item, nil
}

func (s *repositoryStub) GetSource(
	_ context.Context,
	projectID, sourceID string,
) (SourceRepository, error) {
	item, found := s.sources[sourceID]
	if !found || item.ProjectID != projectID {
		return SourceRepository{}, ErrNotFound
	}
	return item, nil
}

func (s *repositoryStub) UpdateSourceProbe(
	_ context.Context,
	projectID, sourceID string,
	status SourceRepositoryStatus,
	probedAt time.Time,
) (SourceRepository, error) {
	item, found := s.sources[sourceID]
	if !found || item.ProjectID != projectID {
		return SourceRepository{}, ErrNotFound
	}
	item.Status = status
	item.LastProbedAt = probedAt
	item.UpdatedAt = probedAt
	s.sources[sourceID] = item
	return item, nil
}

type sourceProberStub struct {
	status     SourceRepositoryStatus
	err        error
	called     int
	source     SourceRepository
	credential *RepositoryCredential
}

type sourceRevisionResolverStub struct {
	revision SourceRevision
	err      error
	called   int
	ref      string
	expected string
}

type buildTriggerTokensStub struct{}

func (buildTriggerTokensStub) New() (string, string, error) {
	return "plain-trigger-token", strings.Repeat("a", 64), nil
}
func (buildTriggerTokensStub) Hash(raw string) string {
	if raw == "plain-trigger-token" {
		return strings.Repeat("a", 64)
	}
	return strings.Repeat("b", 64)
}

type buildTriggerGuardStub struct {
	allowed bool
	retryAt time.Time
	calls   int
}

type webhookRateGuardStub struct {
	allowed bool
	retryAt time.Time
	calls   int
}

type webhookVerifierStub struct {
	event  WebhookEvent
	err    error
	calls  int
	hook   BuildHook
	lastID string
}

func (s *webhookVerifierStub) VerifyAndParse(_ context.Context, hook BuildHook, envelope WebhookEnvelope) (WebhookEvent, error) {
	s.calls++
	s.hook, s.lastID = hook, envelope.DeliveryID
	return s.event, s.err
}

func (g *buildTriggerGuardStub) ReserveBuildTrigger(_ context.Context, _ string, _ time.Time, _ int, _ time.Duration) (bool, time.Time, error) {
	g.calls++
	return g.allowed, g.retryAt, nil
}

func (g *webhookRateGuardStub) ReserveBuildWebhook(_ context.Context, _ string, _ time.Time, _ int, _ time.Duration) (bool, time.Time, error) {
	g.calls++
	return g.allowed, g.retryAt, nil
}

func (s *sourceRevisionResolverStub) ResolveSourceRevision(
	_ context.Context,
	_ SourceRepository,
	_ *RepositoryCredential,
	ref, expectedCommitSHA string,
) (SourceRevision, error) {
	s.called++
	s.ref = ref
	s.expected = expectedCommitSHA
	return s.revision, s.err
}

func (s *sourceProberStub) ProbeSource(
	_ context.Context,
	source SourceRepository,
	credential *RepositoryCredential,
) (SourceRepositoryStatus, error) {
	s.called++
	s.source = source
	s.credential = credential
	return s.status, s.err
}

type auditStub struct {
	events []sharedaudit.Event
	err    error
}

func (s *auditStub) Record(_ context.Context, event sharedaudit.Event) error {
	if s.err != nil {
		return s.err
	}
	s.events = append(s.events, event)
	return nil
}

func TestUseCaseCreatesCredentialAndCompatibleSource(t *testing.T) {
	repository := newRepositoryStub()
	audit := &auditStub{}
	sequence := 0
	useCase := NewUseCase(
		projectLookupStub{exists: true}, repository, transaction.Passthrough{}, audit,
		func() (string, error) {
			sequence++
			return fmt.Sprintf("id-%d", sequence), nil
		},
		func() time.Time { return time.Unix(100, 0) },
	)
	maintainer := testPrincipal(security.RoleMaintainer)
	credential, err := useCase.CreateCredential(
		context.Background(), maintainer, "project-1", "Git token",
		CredentialTypeHTTPSAccessToken, "build-user", "secret://git-token", "",
		"request-1",
	)
	if err != nil || credential.ID == "" || !credential.SecretConfigured {
		t.Fatalf("CreateCredential() = %+v, %v", credential, err)
	}
	source, err := useCase.CreateSource(
		context.Background(), maintainer, "project-1", "API",
		"https://git.example.com/team/api.git", "main", credential.ID, "",
		"request-2",
	)
	if err != nil || source.CredentialID != credential.ID || source.Protocol != RepositoryProtocolHTTPS {
		t.Fatalf("CreateSource() = %+v, %v", source, err)
	}
	if len(audit.events) != 2 ||
		audit.events[0].Action != "repository_credential.create" ||
		audit.events[1].Action != "source_repository.create" ||
		audit.events[1].ProjectID != "project-1" ||
		audit.events[1].RequestID != "request-2" {
		t.Fatalf("audit events = %+v", audit.events)
	}
	listed, err := useCase.ListCredentials(
		context.Background(), testPrincipal(security.RoleViewer), "project-1",
	)
	if err != nil || len(listed) != 1 || !listed[0].SecretConfigured {
		t.Fatalf("ListCredentials() = %+v, %v", listed, err)
	}
}

func TestUseCaseRejectsProtocolMismatchAndInsufficientRole(t *testing.T) {
	repository := newRepositoryStub()
	credential, err := NewRepositoryCredential(
		"credential-1", "project-1", "Deploy key", CredentialTypeSSHDeployKey,
		"", "secret://deploy-key", testSSHFingerprint, "user-1", time.Unix(100, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	repository.credentials[credential.ID] = credential
	useCase := NewUseCase(
		projectLookupStub{exists: true}, repository, transaction.Passthrough{},
		&auditStub{}, func() (string, error) { return "new-id", nil }, time.Now,
	)
	if _, err := useCase.CreateSource(
		context.Background(), testPrincipal(security.RoleMaintainer), "project-1",
		"API", "https://git.example.com/team/api.git", "main", credential.ID, "",
		"request-1",
	); !errors.Is(err, ErrCredentialProtocolMismatch) {
		t.Fatalf("protocol mismatch error = %v", err)
	}
	if _, err := useCase.CreateCredential(
		context.Background(), testPrincipal(security.RoleDeveloper), "project-1",
		"Token", CredentialTypeHTTPSAccessToken, "", "secret://token", "", "request-2",
	); !errors.Is(err, security.ErrForbidden) {
		t.Fatalf("developer credential create error = %v", err)
	}
	if len(repository.sources) != 0 {
		t.Fatalf("unexpected sources = %+v", repository.sources)
	}
}

func TestUseCaseHidesCrossOrganizationProject(t *testing.T) {
	useCase := NewUseCase(
		projectLookupStub{exists: false}, newRepositoryStub(), transaction.Passthrough{},
		&auditStub{}, func() (string, error) { return "new-id", nil }, time.Now,
	)
	if _, err := useCase.ListSources(
		context.Background(), testPrincipal(security.RoleViewer), "other-project",
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-organization ListSources() error = %v", err)
	}
}

func TestUseCaseProbesSourceAndAuditsSafeResult(t *testing.T) {
	repository := newRepositoryStub()
	credential, err := NewRepositoryCredential(
		"credential-1", "project-1", "Git token", CredentialTypeHTTPSAccessToken,
		"builder", "secret://git-token", "", "user-1", time.Unix(90, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	source, err := NewSourceRepository(
		"source-1", "project-1", "API", "https://git.example.com/team/api.git",
		"main", credential.ID, "", "user-1", time.Unix(90, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	repository.credentials[credential.ID] = credential
	repository.sources[source.ID] = source
	audit := &auditStub{}
	prober := &sourceProberStub{status: SourceRepositoryStatusReady}
	useCase := NewUseCase(
		projectLookupStub{exists: true}, repository, transaction.Passthrough{}, audit,
		func() (string, error) { return "audit-1", nil },
		func() time.Time { return time.Unix(100, 0) },
	).WithSourceProber(prober)

	updated, err := useCase.ProbeSource(
		context.Background(), testPrincipal(security.RoleMaintainer),
		"project-1", source.ID, "request-1",
	)
	if err != nil || updated.Status != SourceRepositoryStatusReady ||
		!updated.LastProbedAt.Equal(time.Unix(100, 0)) {
		t.Fatalf("ProbeSource() = %+v, %v", updated, err)
	}
	if prober.called != 1 || prober.source.ID != source.ID ||
		prober.credential == nil || prober.credential.SecretRef != "secret://git-token" {
		t.Fatalf("prober call = %+v", prober)
	}
	if len(audit.events) != 1 || audit.events[0].Action != "source_repository.probe" ||
		audit.events[0].ResourceID != source.ID || audit.events[0].RequestID != "request-1" {
		t.Fatalf("audit events = %+v", audit.events)
	}
}

func TestUseCaseProbeRequiresMaintainerAndRegisteredProber(t *testing.T) {
	repository := newRepositoryStub()
	source, err := NewSourceRepository(
		"source-1", "project-1", "API", "https://git.example.com/team/api.git",
		"main", "", "", "user-1", time.Unix(90, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	repository.sources[source.ID] = source
	useCase := NewUseCase(
		projectLookupStub{exists: true}, repository, transaction.Passthrough{},
		&auditStub{}, func() (string, error) { return "audit-1", nil }, time.Now,
	)
	if _, err := useCase.ProbeSource(
		context.Background(), testPrincipal(security.RoleViewer),
		"project-1", source.ID, "request-1",
	); !errors.Is(err, security.ErrForbidden) {
		t.Fatalf("viewer ProbeSource() error = %v", err)
	}
	if _, err := useCase.ProbeSource(
		context.Background(), testPrincipal(security.RoleMaintainer),
		"project-1", source.ID, "request-2",
	); !errors.Is(err, ErrSourceProbeUnavailable) {
		t.Fatalf("unregistered ProbeSource() error = %v", err)
	}
}

func TestUseCaseCreatesAndUpdatesBuildConfiguration(t *testing.T) {
	repository := newRepositoryStub()
	source, err := NewSourceRepository(
		"source-1", "project-1", "API", "https://git.example.com/team/api.git",
		"main", "", "", "user-1", time.Unix(90, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	repository.sources[source.ID] = source
	audit := &auditStub{}
	sequence := 0
	references := configurationReferencesStub{
		applicationExists: true, registryServer: "registry.example.com",
	}
	useCase := NewUseCase(
		projectLookupStub{exists: true}, repository, transaction.Passthrough{}, audit,
		func() (string, error) {
			sequence++
			return fmt.Sprintf("id-%d", sequence), nil
		},
		func() time.Time { return time.Unix(int64(100+sequence), 0) },
	).WithConfigurationReferences(references, references)

	created, err := useCase.CreateBuildConfiguration(
		context.Background(), testPrincipal(security.RoleDeveloper),
		"project-1", "application-1", "API build", source.ID,
		"", "", nil, "registry-1", "registry.example.com/team/api", "",
		BuildResources{}, 0, 0, true, "request-create",
	)
	if err != nil || created.Version != 1 || created.DockerfilePath != "Dockerfile" ||
		!reflect.DeepEqual(created.AllowedRefs, []string{"refs/heads/main"}) {
		t.Fatalf("CreateBuildConfiguration() = %+v, %v", created, err)
	}
	name := "API production build"
	updated, err := useCase.UpdateBuildConfiguration(
		context.Background(), testPrincipal(security.RoleDeveloper),
		"project-1", "application-1", created.ID, 1,
		BuildConfigurationPatch{Name: &name}, "request-update",
	)
	if err != nil || updated.Version != 2 || updated.Name != name {
		t.Fatalf("UpdateBuildConfiguration() = %+v, %v", updated, err)
	}
	if len(audit.events) != 2 || audit.events[0].Action != "build_configuration.create" ||
		audit.events[1].Action != "build_configuration.update" {
		t.Fatalf("audit events = %+v", audit.events)
	}
	if _, err := useCase.GetBuildConfiguration(
		context.Background(), testPrincipal(security.RoleViewer),
		"project-1", "application-1", created.ID,
	); err != nil {
		t.Fatalf("viewer GetBuildConfiguration() error = %v", err)
	}
	if _, err := useCase.UpdateBuildConfiguration(
		context.Background(), testPrincipal(security.RoleDeveloper),
		"project-1", "application-1", created.ID, 1,
		BuildConfigurationPatch{Name: &name}, "request-stale",
	); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale update error = %v", err)
	}
}

func TestUseCaseRestrictsAutomaticDeploymentRulesToMaintainerAndDevelopment(t *testing.T) {
	repository := newRepositoryStub()
	source, err := NewSourceRepository(
		"source-1", "project-1", "API", "https://git.example.com/team/api.git",
		"main", "", "", "user-1", time.Unix(90, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	repository.sources[source.ID] = source
	references := configurationReferencesStub{
		applicationExists: true, registryServer: "registry.example.com",
	}
	sequence := 0
	newUseCase := func(automaticErr error) *UseCase {
		return NewUseCase(
			projectLookupStub{exists: true}, repository, transaction.Passthrough{},
			&auditStub{}, func() (string, error) {
				sequence++
				return fmt.Sprintf("auto-%d", sequence), nil
			}, func() time.Time { return time.Unix(100, 0) },
		).WithConfigurationReferences(references, references).
			WithAutomaticDeploymentReferences(automaticDeploymentReferencesStub{err: automaticErr})
	}
	rules := []AutomaticDeploymentRule{{EnvironmentID: "development-1", RuntimeTargetID: "target-1"}}
	create := func(useCase *UseCase, role security.Role) (BuildConfiguration, error) {
		return useCase.CreateBuildConfigurationWithDeliverySpec(
			context.Background(), testPrincipal(role), "project-1", "application-1",
			"API build", source.ID, "", "", nil, "registry-1",
			"registry.example.com/team/api", "", BuildResources{}, 0, 0, true,
			runtimespec.Spec{}, rules, "request-create",
		)
	}
	if _, err := create(newUseCase(nil), security.RoleDeveloper); !errors.Is(err, security.ErrForbidden) {
		t.Fatalf("Developer automatic deployment create error = %v", err)
	}
	if _, err := create(newUseCase(ErrAutomaticDeploymentDenied), security.RoleMaintainer); !errors.Is(err, ErrAutomaticDeploymentDenied) {
		t.Fatalf("staging automatic deployment create error = %v", err)
	}
	created, err := create(newUseCase(nil), security.RoleMaintainer)
	if err != nil || !reflect.DeepEqual(created.AutomaticDeployments, rules) {
		t.Fatalf("Maintainer automatic deployment create = %+v/%v", created, err)
	}
	emptyRules := []AutomaticDeploymentRule{}
	if _, err := newUseCase(nil).UpdateBuildConfiguration(
		context.Background(), testPrincipal(security.RoleDeveloper),
		"project-1", "application-1", created.ID, created.Version,
		BuildConfigurationPatch{AutomaticDeployments: &emptyRules}, "request-update",
	); !errors.Is(err, security.ErrForbidden) {
		t.Fatalf("Developer automatic deployment update error = %v", err)
	}
}

func TestUseCaseRejectsBuildConfigurationReferenceMismatch(t *testing.T) {
	repository := newRepositoryStub()
	source, err := NewSourceRepository(
		"source-1", "project-1", "API", "https://git.example.com/team/api.git",
		"main", "", "", "user-1", time.Unix(90, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	repository.sources[source.ID] = source
	references := configurationReferencesStub{
		applicationExists: true, registryServer: "registry.other.example",
	}
	useCase := NewUseCase(
		projectLookupStub{exists: true}, repository, transaction.Passthrough{},
		&auditStub{}, func() (string, error) { return "id-1", nil }, time.Now,
	).WithConfigurationReferences(references, references)
	if _, err := useCase.CreateBuildConfiguration(
		context.Background(), testPrincipal(security.RoleDeveloper),
		"project-1", "application-1", "API build", source.ID,
		"Dockerfile", ".", []string{"refs/heads/main"},
		"registry-1", "registry.example.com/team/api", BuildPlatformLinuxAMD64,
		BuildResources{}, 0, 0, false, "request-1",
	); !errors.Is(err, ErrRegistryMismatch) {
		t.Fatalf("registry mismatch error = %v", err)
	}
	if len(repository.configurations) != 0 {
		t.Fatalf("unexpected configurations = %+v", repository.configurations)
	}
}

func TestUseCaseTriggersIdempotentBuildWithImmutableSnapshot(t *testing.T) {
	repository := newRepositoryStub()
	source, err := NewSourceRepository(
		"source-1", "project-1", "API", "https://git.example.com/team/api.git",
		"main", "", "", "user-1", time.Unix(90, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := NewBuildConfiguration(
		"configuration-1", "project-1", "application-1", "API build", source.ID,
		"Dockerfile", ".", []string{"refs/heads/main"},
		"registry-1", "registry.example.com/team/api", BuildPlatformLinuxAMD64,
		BuildResources{}, 0, 0, true, "user-1", time.Unix(90, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	repository.sources[source.ID] = source
	repository.configurations[configuration.ID] = configuration
	resolver := &sourceRevisionResolverStub{revision: SourceRevision{
		SourceRepositoryID: source.ID,
		Ref:                "refs/heads/main",
		CommitSHA:          "a975c10d68a2d7461634f13b15c52a2efba72d16",
	}}
	audit := &auditStub{}
	sequence := 0
	references := configurationReferencesStub{
		applicationExists: true, registryServer: "registry.example.com",
	}
	useCase := NewUseCase(
		projectLookupStub{exists: true}, repository, transaction.Passthrough{}, audit,
		func() (string, error) {
			sequence++
			return fmt.Sprintf("id-%d", sequence), nil
		},
		func() time.Time { return time.Unix(100, 0) },
	).WithConfigurationReferences(references, references).
		WithSourceRevisionResolver(resolver)

	created, err := useCase.TriggerManualBuild(
		context.Background(), testPrincipal(security.RoleDeveloper),
		"project-1", "application-1", configuration.ID, "refs/heads/main", "",
		"trigger-1", "request-1",
	)
	if err != nil || created.Status != BuildStatusQueued ||
		created.Configuration.ConfigurationVersion != 1 ||
		created.Revision.CommitSHA != resolver.revision.CommitSHA {
		t.Fatalf("TriggerManualBuild() = %+v, %v", created, err)
	}
	name := "changed after trigger"
	updated, err := configuration.Apply(
		BuildConfigurationPatch{Name: &name}, "user-1", time.Unix(200, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	repository.configurations[configuration.ID] = updated
	replayed, err := useCase.TriggerManualBuild(
		context.Background(), testPrincipal(security.RoleDeveloper),
		"project-1", "application-1", configuration.ID, "refs/heads/main", "",
		"trigger-1", "request-replay",
	)
	if err != nil || replayed.ID != created.ID || resolver.called != 1 ||
		replayed.Configuration.ConfigurationVersion != 1 || len(audit.events) != 1 ||
		audit.events[0].Action != "build.trigger_manual" {
		t.Fatalf("replayed/audit = %+v / %+v, calls=%d, err=%v", replayed, audit.events, resolver.called, err)
	}
	if _, err := useCase.TriggerManualBuild(
		context.Background(), testPrincipal(security.RoleDeveloper),
		"project-1", "application-1", configuration.ID, "refs/tags/v1.0.0", "",
		"trigger-1", "request-mismatch",
	); !errors.Is(err, ErrIdempotencyMismatch) {
		t.Fatalf("idempotency mismatch error = %v", err)
	}
}

func TestUseCaseRejectsDisallowedBuildRefAndViewerTrigger(t *testing.T) {
	repository := newRepositoryStub()
	source, err := NewSourceRepository(
		"source-1", "project-1", "API", "https://git.example.com/team/api.git",
		"main", "", "", "user-1", time.Unix(90, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := NewBuildConfiguration(
		"configuration-1", "project-1", "application-1", "API build", source.ID,
		"Dockerfile", ".", []string{"refs/heads/main"},
		"registry-1", "registry.example.com/team/api", BuildPlatformLinuxAMD64,
		BuildResources{}, 0, 0, false, "user-1", time.Unix(90, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	repository.sources[source.ID] = source
	repository.configurations[configuration.ID] = configuration
	resolver := &sourceRevisionResolverStub{}
	references := configurationReferencesStub{
		applicationExists: true, registryServer: "registry.example.com",
	}
	useCase := NewUseCase(
		projectLookupStub{exists: true}, repository, transaction.Passthrough{},
		&auditStub{}, func() (string, error) { return "id-1", nil }, time.Now,
	).WithConfigurationReferences(references, references).
		WithSourceRevisionResolver(resolver)
	if _, err := useCase.TriggerManualBuild(
		context.Background(), testPrincipal(security.RoleDeveloper),
		"project-1", "application-1", configuration.ID, "refs/heads/develop", "",
		"trigger-1", "request-1",
	); !errors.Is(err, ErrRevisionNotFound) || resolver.called != 0 {
		t.Fatalf("disallowed ref error/calls = %v/%d", err, resolver.called)
	}
	if _, err := useCase.TriggerManualBuild(
		context.Background(), testPrincipal(security.RoleViewer),
		"project-1", "application-1", configuration.ID, "refs/heads/main", "",
		"trigger-2", "request-2",
	); !errors.Is(err, security.ErrForbidden) {
		t.Fatalf("viewer trigger error = %v", err)
	}
}

func testPrincipal(role security.Role) security.Principal {
	return security.Principal{
		UserID: "user-1", OrganizationID: "organization-1",
		SessionID: "session-1", Role: role,
	}
}

func TestUseCaseReadsProjectScopedBuildLogs(t *testing.T) {
	repository := newRepositoryStub()
	repository.builds["build-1"] = Build{
		ID: "build-1", ProjectID: "project-1", Status: BuildStatusSucceeded,
	}
	repository.logs["build-1"] = []BuildLogEntry{{
		Sequence: 1, Stage: BuildLogStageBuild,
		Message: "image built", CreatedAt: time.Unix(101, 0),
	}}
	useCase := NewUseCase(
		projectLookupStub{exists: true}, repository, transaction.Passthrough{},
		&auditStub{}, func() (string, error) { return "new-id", nil }, time.Now,
	).WithBuildLogs(repository)

	page, err := useCase.ReadBuildLogs(
		context.Background(), testPrincipal(security.RoleViewer),
		"project-1", "build-1", BuildLogQuery{},
	)
	if err != nil || len(page.Entries) != 1 || !page.Complete {
		t.Fatalf("ReadBuildLogs() = %+v, %v", page, err)
	}
	if _, err := useCase.ReadBuildLogs(
		context.Background(), security.Principal{}, "project-1", "build-1", BuildLogQuery{},
	); !errors.Is(err, security.ErrUnauthenticated) {
		t.Fatalf("anonymous ReadBuildLogs() error = %v", err)
	}
	hidden := NewUseCase(
		projectLookupStub{exists: false}, repository, transaction.Passthrough{},
		&auditStub{}, func() (string, error) { return "new-id", nil }, time.Now,
	).WithBuildLogs(repository)
	if _, err := hidden.ReadBuildLogs(
		context.Background(), testPrincipal(security.RoleViewer),
		"project-1", "build-1", BuildLogQuery{},
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-organization ReadBuildLogs() error = %v", err)
	}
}

func TestBuildTriggerLifecycleAndExternalBuild(t *testing.T) {
	repository := newRepositoryStub()
	source, err := NewSourceRepository(
		"source-1", "project-1", "API", "https://git.example.com/team/api.git",
		"main", "", "", "user-1", time.Unix(90, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := NewBuildConfiguration(
		"configuration-1", "project-1", "application-1", "API build", source.ID,
		"Dockerfile", ".", []string{"refs/heads/main", "refs/tags/v1.0.0"},
		"registry-1", "registry.example.com/team/api", BuildPlatformLinuxAMD64,
		BuildResources{}, 0, 0, false, "user-1", time.Unix(90, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	repository.sources[source.ID], repository.configurations[configuration.ID] = source, configuration
	resolver := &sourceRevisionResolverStub{revision: SourceRevision{
		SourceRepositoryID: source.ID, Ref: "refs/heads/main",
		CommitSHA: "a975c10d68a2d7461634f13b15c52a2efba72d16",
	}}
	guard := &buildTriggerGuardStub{allowed: true}
	audit := &auditStub{}
	sequence := 0
	references := configurationReferencesStub{applicationExists: true, registryServer: "registry.example.com"}
	useCase := NewUseCase(projectLookupStub{exists: true}, repository, transaction.Passthrough{}, audit,
		func() (string, error) { sequence++; return fmt.Sprintf("id-%d", sequence), nil },
		func() time.Time { return time.Unix(100, 0) },
	).WithConfigurationReferences(references, references).
		WithSourceRevisionResolver(resolver).
		WithBuildTriggerAutomation(buildTriggerTokensStub{}, guard, 60, time.Minute)

	if _, err := useCase.CreateBuildTrigger(context.Background(), testPrincipal(security.RoleDeveloper),
		"project-1", "application-1", configuration.ID, "Git automation",
		[]string{"refs/heads/main"}, "request-forbidden"); !errors.Is(err, security.ErrForbidden) {
		t.Fatalf("developer create trigger error = %v", err)
	}
	credential, err := useCase.CreateBuildTrigger(context.Background(), testPrincipal(security.RoleMaintainer),
		"project-1", "application-1", configuration.ID, "Git automation",
		[]string{"refs/heads/main"}, "request-create")
	if err != nil || credential.Token != "plain-trigger-token" ||
		credential.Trigger.Status != BuildTriggerStatusActive {
		t.Fatalf("CreateBuildTrigger() = %+v, %v", credential, err)
	}
	if _, err := useCase.CreateBuildTrigger(context.Background(), testPrincipal(security.RoleMaintainer),
		"project-1", "application-1", configuration.ID, "Invalid refs",
		[]string{"refs/heads/not-allowed"}, "request-invalid"); !errors.Is(err, ErrInvalidBuildTrigger) {
		t.Fatalf("invalid allowed refs error = %v", err)
	}
	build, err := useCase.TriggerExternalBuild(context.Background(), credential.Trigger.ID,
		credential.Token, "refs/heads/main", resolver.revision.CommitSHA,
		"external-1", "request-trigger")
	if err != nil || build.TriggerSource != BuildTriggerSourceTriggerAPI ||
		build.TriggerID != credential.Trigger.ID || build.TriggeredBy != credential.Trigger.ID ||
		resolver.expected != resolver.revision.CommitSHA || guard.calls != 1 {
		t.Fatalf("TriggerExternalBuild() = %+v, resolver=%+v guard=%+v err=%v", build, resolver, guard, err)
	}
	if _, err := useCase.TriggerExternalBuild(context.Background(), credential.Trigger.ID,
		"wrong-token", "refs/heads/main", resolver.revision.CommitSHA,
		"external-2", "request-token"); !errors.Is(err, ErrInvalidBuildTriggerToken) || guard.calls != 1 {
		t.Fatalf("invalid token error/guard calls = %v/%d", err, guard.calls)
	}
	revoked, err := useCase.RevokeBuildTrigger(context.Background(), testPrincipal(security.RoleMaintainer),
		"project-1", "application-1", configuration.ID, credential.Trigger.ID, "request-revoke")
	if err != nil || revoked.Status != BuildTriggerStatusRevoked || revoked.Version != 2 {
		t.Fatalf("RevokeBuildTrigger() = %+v, %v", revoked, err)
	}
	if _, err := useCase.TriggerExternalBuild(context.Background(), credential.Trigger.ID,
		credential.Token, "refs/heads/main", resolver.revision.CommitSHA,
		"external-3", "request-revoked"); !errors.Is(err, ErrBuildTriggerRevoked) {
		t.Fatalf("revoked token error = %v", err)
	}
	if len(audit.events) != 3 || audit.events[0].Action != "build_trigger.create" ||
		audit.events[1].Action != "build.trigger_api" || audit.events[2].Action != "build_trigger.revoke" {
		t.Fatalf("audit events = %+v", audit.events)
	}
}

func TestExternalBuildTriggerRateLimit(t *testing.T) {
	repository := newRepositoryStub()
	trigger, err := NewBuildTrigger("trigger-1", "organization-1", "project-1", "application-1",
		"configuration-1", "Automation", []string{"refs/heads/main"}, strings.Repeat("a", 64),
		"user-1", time.Unix(90, 0))
	if err != nil {
		t.Fatal(err)
	}
	repository.triggers[trigger.ID] = trigger
	guard := &buildTriggerGuardStub{allowed: false, retryAt: time.Unix(130, 0)}
	useCase := NewUseCase(projectLookupStub{exists: true}, repository, transaction.Passthrough{},
		&auditStub{}, func() (string, error) { return "id-1", nil }, func() time.Time { return time.Unix(100, 0) }).
		WithBuildTriggerAutomation(buildTriggerTokensStub{}, guard, 1, time.Minute)
	_, err = useCase.TriggerExternalBuild(context.Background(), trigger.ID, "plain-trigger-token",
		"refs/heads/main", "a975c10d68a2d7461634f13b15c52a2efba72d16", "external-1", "request-1")
	var rateLimit *BuildTriggerRateLimitError
	if !errors.As(err, &rateLimit) || rateLimit.RetryAfter != 30*time.Second {
		t.Fatalf("rate limit error = %#v", err)
	}
}

func TestBuildHookLifecycleWebhookAndReplay(t *testing.T) {
	repository := newRepositoryStub()
	source, err := NewSourceRepository("source-1", "project-1", "API", "https://git.example.com/team/api.git", "main", "", "", "user-1", time.Unix(90, 0))
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := NewBuildConfiguration(
		"configuration-1", "project-1", "application-1", "API build", source.ID,
		"Dockerfile", ".", []string{"refs/heads/main"}, "registry-1",
		"registry.example.com/team/api", BuildPlatformLinuxAMD64, BuildResources{},
		0, 0, false, "user-1", time.Unix(90, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	repository.sources[source.ID], repository.configurations[configuration.ID] = source, configuration
	commit := "a975c10d68a2d7461634f13b15c52a2efba72d16"
	verifier := &webhookVerifierStub{event: WebhookEvent{Supported: true, Ref: "refs/heads/main", CommitSHA: commit}}
	webhookGuard := &webhookRateGuardStub{allowed: true}
	resolver := &sourceRevisionResolverStub{revision: SourceRevision{SourceRepositoryID: source.ID, Ref: "refs/heads/main", CommitSHA: commit}}
	audit := &auditStub{}
	sequence := 0
	references := configurationReferencesStub{applicationExists: true, registryServer: "registry.example.com"}
	useCase := NewUseCase(projectLookupStub{exists: true}, repository, transaction.Passthrough{}, audit,
		func() (string, error) { sequence++; return fmt.Sprintf("id-%d", sequence), nil },
		func() time.Time { return time.Unix(100, 0) },
	).WithConfigurationReferences(references, references).
		WithSourceRevisionResolver(resolver).
		WithWebhookVerifier(verifier).
		WithWebhookAdmission(webhookGuard, 120, time.Minute)

	if _, err := useCase.CreateBuildHook(context.Background(), testPrincipal(security.RoleDeveloper),
		"project-1", "application-1", configuration.ID, "GitHub", WebhookProviderGitHub,
		[]string{"refs/heads/main"}, "secret://github-hook", "request-forbidden"); !errors.Is(err, security.ErrForbidden) {
		t.Fatalf("developer create hook error = %v", err)
	}
	hook, err := useCase.CreateBuildHook(context.Background(), testPrincipal(security.RoleMaintainer),
		"project-1", "application-1", configuration.ID, "GitHub", WebhookProviderGitHub,
		[]string{"refs/heads/main"}, "secret://github-hook", "request-create")
	if err != nil || !hook.SecretConfigured || hook.Provider != WebhookProviderGitHub {
		t.Fatalf("CreateBuildHook() = %+v, %v", hook, err)
	}

	envelope := WebhookEnvelope{DeliveryID: "delivery-1", Event: "push", Body: []byte("signed")}
	first, err := useCase.HandleWebhook(context.Background(), WebhookProviderGitHub, hook.ID, envelope, "request-webhook")
	if err != nil || first.Status != WebhookDeliveryStatusAccepted || first.BuildID == "" || resolver.expected != commit {
		t.Fatalf("HandleWebhook() = %+v, resolver=%+v, %v", first, resolver, err)
	}
	replay, err := useCase.HandleWebhook(context.Background(), WebhookProviderGitHub, hook.ID, envelope, "request-replay")
	if err != nil || replay != first || verifier.calls != 2 || webhookGuard.calls != 1 || resolver.called != 1 || len(repository.builds) != 1 {
		t.Fatalf("replay = %+v, verifier=%d admissions=%d resolver=%d builds=%d err=%v", replay, verifier.calls, webhookGuard.calls, resolver.called, len(repository.builds), err)
	}
	verifier.err = ErrInvalidWebhookSignature
	if _, err := useCase.HandleWebhook(context.Background(), WebhookProviderGitHub, hook.ID, envelope,
		"request-forged-replay"); !errors.Is(err, ErrInvalidWebhookSignature) {
		t.Fatalf("forged replay error = %v", err)
	}
	if resolver.called != 1 || len(repository.builds) != 1 {
		t.Fatalf("forged replay changed state: resolver=%d builds=%d", resolver.called, len(repository.builds))
	}
	verifier.err = nil

	verifier.event = WebhookEvent{Supported: false}
	ignored, err := useCase.HandleWebhook(context.Background(), WebhookProviderGitHub, hook.ID,
		WebhookEnvelope{DeliveryID: "delivery-2", Event: "issues", Body: []byte("signed")}, "request-ignored")
	if err != nil || ignored.Status != WebhookDeliveryStatusIgnored || ignored.BuildID != "" || len(repository.deliveries) != 2 {
		t.Fatalf("ignored = %+v deliveries=%d err=%v", ignored, len(repository.deliveries), err)
	}
	revoked, err := useCase.RevokeBuildHook(context.Background(), testPrincipal(security.RoleMaintainer),
		"project-1", "application-1", configuration.ID, hook.ID, "request-revoke")
	if err != nil || revoked.Status != BuildHookStatusRevoked || revoked.Version != 2 {
		t.Fatalf("RevokeBuildHook() = %+v, %v", revoked, err)
	}
	if _, err := useCase.HandleWebhook(context.Background(), WebhookProviderGitHub, hook.ID,
		WebhookEnvelope{DeliveryID: "delivery-3", Event: "push", Body: []byte("signed")}, "request-revoked"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked hook error = %v", err)
	}
}

func TestBuildWebhookSharedAdmissionRejectsUniqueFlood(t *testing.T) {
	repository := newRepositoryStub()
	hook := BuildHook{ID: "hook-1", OrganizationID: "organization-1", ProjectID: "project-1",
		ApplicationID: "application-1", BuildConfigurationID: "configuration-1",
		Provider: WebhookProviderGitHub, Status: BuildHookStatusActive}
	repository.hooks[hook.ID] = hook
	guard := &webhookRateGuardStub{allowed: false, retryAt: time.Unix(145, 0)}
	verifier := &webhookVerifierStub{event: WebhookEvent{Supported: false}}
	useCase := NewUseCase(projectLookupStub{exists: true}, repository, transaction.Passthrough{},
		&auditStub{}, func() (string, error) { return "id-1", nil }, func() time.Time { return time.Unix(100, 0) }).
		WithWebhookVerifier(verifier).
		WithWebhookAdmission(guard, 120, time.Minute)

	_, err := useCase.HandleWebhook(t.Context(), WebhookProviderGitHub, hook.ID,
		WebhookEnvelope{DeliveryID: "unique-delivery", Event: "push", Body: []byte("signed")}, "request-1")
	var rateLimit *WebhookRateLimitError
	if !errors.As(err, &rateLimit) || rateLimit.RetryAfter != 45*time.Second {
		t.Fatalf("rate limit error = %#v", err)
	}
	if verifier.calls != 1 || guard.calls != 1 || len(repository.deliveries) != 0 || len(repository.builds) != 0 {
		t.Fatalf("verifier=%d admissions=%d deliveries=%d builds=%d", verifier.calls, guard.calls, len(repository.deliveries), len(repository.builds))
	}
}

func TestBuildCancelAndRetryUseCases(t *testing.T) {
	repository := newRepositoryStub()
	now := time.Unix(100, 0)
	queued := Build{ID: "build-queued", OrganizationID: "organization-1", ProjectID: "project-1", ApplicationID: "application-1",
		BuildConfigurationID: "configuration-1", Status: BuildStatusQueued, Version: 1, CreatedAt: now, UpdatedAt: now}
	failed := queued
	failed.ID, failed.IdempotencyKey, failed.Status = "build-failed", "original-build", BuildStatusFailed
	failed.FailureCategory, failed.FinishedAt = BuildFailureBuild, now
	repository.builds[queued.ID], repository.builds[failed.ID] = queued, failed
	audit := &auditStub{}
	sequence := 0
	useCase := NewUseCase(projectLookupStub{exists: true}, repository, transaction.Passthrough{}, audit,
		func() (string, error) { sequence++; return fmt.Sprintf("id-%d", sequence), nil },
		func() time.Time { return time.Unix(200, 0) })

	canceled, err := useCase.CancelBuild(context.Background(), testPrincipal(security.RoleDeveloper), "project-1", queued.ID, "request-cancel")
	if err != nil || canceled.Status != BuildStatusCanceling || canceled.Version != 2 {
		t.Fatalf("CancelBuild() = %+v, %v", canceled, err)
	}
	replayedCancel, err := useCase.CancelBuild(context.Background(), testPrincipal(security.RoleDeveloper), "project-1", queued.ID, "request-cancel-replay")
	if err != nil || replayedCancel.ID != canceled.ID || len(audit.events) != 1 {
		t.Fatalf("cancel replay = %+v audit=%d err=%v", replayedCancel, len(audit.events), err)
	}

	retry, err := useCase.RetryBuild(context.Background(), testPrincipal(security.RoleDeveloper), "project-1", failed.ID, "retry-build-1", "request-retry")
	if err != nil || retry.Status != BuildStatusQueued || retry.SourceBuildID != failed.ID || retry.TriggerSource != BuildTriggerSourceRetry {
		t.Fatalf("RetryBuild() = %+v, %v", retry, err)
	}
	replayedRetry, err := useCase.RetryBuild(context.Background(), testPrincipal(security.RoleDeveloper), "project-1", failed.ID, "retry-build-1", "request-retry-replay")
	if err != nil || replayedRetry.ID != retry.ID || len(audit.events) != 2 {
		t.Fatalf("retry replay = %+v audit=%d err=%v", replayedRetry, len(audit.events), err)
	}
	if _, err := useCase.RetryBuild(context.Background(), testPrincipal(security.RoleDeveloper), "project-1", queued.ID, "retry-build-2", "request-invalid"); !errors.Is(err, ErrBuildRetryRequiresFailed) {
		t.Fatalf("retry queued error = %v", err)
	}
	if _, err := useCase.CancelBuild(context.Background(), testPrincipal(security.RoleViewer), "project-1", failed.ID, "request-forbidden"); !errors.Is(err, security.ErrForbidden) {
		t.Fatalf("viewer cancel error = %v", err)
	}
}
