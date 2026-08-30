package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/build/biz"
	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/runtimespec"
	"github.com/owndock/owndock/internal/shared/security"
	"github.com/owndock/owndock/internal/shared/transaction"
)

type serviceProjects struct{}

type serviceBuildTriggerTokens struct{}

func (serviceBuildTriggerTokens) New() (string, string, error) {
	return "plain-trigger-token", strings.Repeat("a", 64), nil
}
func (serviceBuildTriggerTokens) Hash(raw string) string {
	if raw == "plain-trigger-token" {
		return strings.Repeat("a", 64)
	}
	return strings.Repeat("b", 64)
}

type serviceBuildTriggerGuard struct{}

func (serviceBuildTriggerGuard) ReserveBuildTrigger(context.Context, string, time.Time, int, time.Duration) (bool, time.Time, error) {
	return true, time.Time{}, nil
}

type serviceWebhookVerifier struct{}

func (serviceWebhookVerifier) VerifyAndParse(_ context.Context, hook biz.BuildHook, envelope biz.WebhookEnvelope) (biz.WebhookEvent, error) {
	if hook.Provider != biz.WebhookProviderGitHub || envelope.DeliveryID == "" || envelope.Event != "push" || envelope.Signature == "" || string(envelope.Body) == "" {
		return biz.WebhookEvent{}, biz.ErrInvalidWebhook
	}
	return biz.WebhookEvent{Supported: true, Ref: "refs/heads/main", CommitSHA: "a975c10d68a2d7461634f13b15c52a2efba72d16"}, nil
}

type serviceWebhookRateGuard struct{}

func (serviceWebhookRateGuard) ReserveBuildWebhook(_ context.Context, _ string, now time.Time, _ int, _ time.Duration) (bool, time.Time, error) {
	return true, now, nil
}

func (serviceProjects) ProjectExists(context.Context, string, string) (bool, error) {
	return true, nil
}

func (serviceProjects) ApplicationExists(context.Context, string, string) (bool, error) {
	return true, nil
}

func (serviceProjects) RegistryServer(context.Context, string, string) (string, error) {
	return "registry.example.com", nil
}

func (serviceProjects) ValidateAutomaticDeployment(context.Context, string, string, string) error {
	return nil
}

type serviceRepository struct {
	credentials    map[string]biz.RepositoryCredential
	sources        map[string]biz.SourceRepository
	configurations map[string]biz.BuildConfiguration
	builds         map[string]biz.Build
	triggers       map[string]biz.BuildTrigger
	hooks          map[string]biz.BuildHook
	deliveries     map[string]biz.WebhookDelivery
	artifacts      map[string]biz.Artifact
	logs           map[string][]biz.BuildLogEntry
}

func newServiceRepository() *serviceRepository {
	return &serviceRepository{
		credentials:    make(map[string]biz.RepositoryCredential),
		sources:        make(map[string]biz.SourceRepository),
		configurations: make(map[string]biz.BuildConfiguration),
		builds:         make(map[string]biz.Build),
		triggers:       make(map[string]biz.BuildTrigger),
		hooks:          make(map[string]biz.BuildHook),
		deliveries:     make(map[string]biz.WebhookDelivery),
		artifacts:      make(map[string]biz.Artifact),
		logs:           make(map[string][]biz.BuildLogEntry),
	}
}

func (s *serviceRepository) AppendBuildLog(_ context.Context, item biz.BuildLogAppend) error {
	entries := s.logs[item.BuildID]
	s.logs[item.BuildID] = append(entries, biz.BuildLogEntry{
		Sequence: uint64(len(entries) + 1), Stage: item.Stage,
		Message: item.Message, CreatedAt: item.CreatedAt,
	})
	return nil
}

func (s *serviceRepository) ReadBuildLogs(_ context.Context, projectID, buildID string,
	query biz.BuildLogQuery) (biz.BuildLogPage, error) {
	if item, ok := s.builds[buildID]; !ok || item.ProjectID != projectID {
		return biz.BuildLogPage{}, biz.ErrNotFound
	}
	query, err := query.Normalize()
	if err != nil {
		return biz.BuildLogPage{}, err
	}
	entries := make([]biz.BuildLogEntry, 0, query.Limit)
	for _, entry := range s.logs[buildID] {
		if entry.Sequence > query.AfterSequence && len(entries) < query.Limit {
			entries = append(entries, entry)
		}
	}
	next := query.AfterSequence
	if len(entries) > 0 {
		next = entries[len(entries)-1].Sequence
	}
	return biz.BuildLogPage{Entries: entries, NextSequence: next,
		ExpiresAt: time.Unix(100, 0).Add(biz.DefaultBuildLogRetention)}, nil
}

func (s *serviceRepository) ListArtifacts(_ context.Context, projectID string) ([]biz.Artifact, error) {
	var result []biz.Artifact
	for _, item := range s.artifacts {
		if item.ProjectID == projectID {
			result = append(result, item)
		}
	}
	return result, nil
}
func (s *serviceRepository) GetArtifact(_ context.Context, projectID, artifactID string) (biz.Artifact, error) {
	item, ok := s.artifacts[artifactID]
	if !ok || item.ProjectID != projectID {
		return biz.Artifact{}, biz.ErrNotFound
	}
	return item, nil
}
func (s *serviceRepository) GetArtifactByBuild(_ context.Context, buildID string) (biz.Artifact, error) {
	for _, item := range s.artifacts {
		if item.BuildID == buildID {
			return item, nil
		}
	}
	return biz.Artifact{}, biz.ErrNotFound
}
func (s *serviceRepository) GetArtifactByRegistrationKey(_ context.Context,
	projectID, registrationKey string) (biz.Artifact, error) {
	for _, item := range s.artifacts {
		if item.ProjectID == projectID && item.RegistrationKey == registrationKey {
			return item, nil
		}
	}
	return biz.Artifact{}, biz.ErrNotFound
}
func (s *serviceRepository) CreateArtifact(_ context.Context, item biz.Artifact) (biz.Artifact, error) {
	s.artifacts[item.ID] = item
	return item, nil
}
func (s *serviceRepository) NextPendingArtifact(context.Context) (biz.Artifact, bool, error) {
	for _, item := range s.artifacts {
		if item.ReleaseStatus == biz.ArtifactReleasePending {
			return item, true, nil
		}
	}
	return biz.Artifact{}, false, nil
}
func (s *serviceRepository) SaveArtifactRelease(_ context.Context, item biz.Artifact, expected uint64) (biz.Artifact, error) {
	current, ok := s.artifacts[item.ID]
	if !ok || current.Version != expected {
		return biz.Artifact{}, biz.ErrVersionConflict
	}
	item.Version = expected + 1
	s.artifacts[item.ID] = item
	return item, nil
}

type serviceArtifactReleaseCreator struct{}

func (serviceArtifactReleaseCreator) CreateArtifactRelease(context.Context, biz.ArtifactReleaseRequest) (string, error) {
	return "release-1", nil
}

type serviceArtifactEvidenceScheduler struct{}

func (serviceArtifactEvidenceScheduler) EnsureArtifactEvidence(context.Context, biz.Artifact) error {
	return nil
}

type serviceArtifactProbe struct{}

func (serviceArtifactProbe) ProbeArtifact(context.Context, string, string, string, string) error {
	return nil
}

func (s *serviceRepository) ListBuildHooks(_ context.Context, projectID, applicationID, configurationID string) ([]biz.BuildHookSummary, error) {
	items := make([]biz.BuildHookSummary, 0)
	for _, item := range s.hooks {
		if item.ProjectID == projectID && item.ApplicationID == applicationID && item.BuildConfigurationID == configurationID {
			items = append(items, item.Summary())
		}
	}
	return items, nil
}
func (s *serviceRepository) CreateBuildHook(_ context.Context, item biz.BuildHook) (biz.BuildHookSummary, error) {
	s.hooks[item.ID] = item
	return item.Summary(), nil
}
func (s *serviceRepository) GetBuildHook(_ context.Context, id string) (biz.BuildHook, error) {
	item, ok := s.hooks[id]
	if !ok {
		return biz.BuildHook{}, biz.ErrNotFound
	}
	return item, nil
}
func (s *serviceRepository) RevokeBuildHook(_ context.Context, item biz.BuildHook, expected uint64) (biz.BuildHookSummary, error) {
	current, ok := s.hooks[item.ID]
	if !ok {
		return biz.BuildHookSummary{}, biz.ErrNotFound
	}
	if current.Version != expected {
		return biz.BuildHookSummary{}, biz.ErrVersionConflict
	}
	s.hooks[item.ID] = item
	return item.Summary(), nil
}
func (s *serviceRepository) CreateWebhookDelivery(_ context.Context, item biz.WebhookDelivery) error {
	key := string(item.Provider) + ":" + item.HookID + ":" + item.DeliveryID
	if _, ok := s.deliveries[key]; ok {
		return biz.ErrDuplicateWebhookDelivery
	}
	s.deliveries[key] = item
	return nil
}
func (s *serviceRepository) GetWebhookDelivery(_ context.Context, hookID string, provider biz.WebhookProvider, deliveryID string) (biz.WebhookDelivery, error) {
	item, ok := s.deliveries[string(provider)+":"+hookID+":"+deliveryID]
	if !ok {
		return biz.WebhookDelivery{}, biz.ErrNotFound
	}
	return item, nil
}

func (s *serviceRepository) ListBuildTriggers(_ context.Context, projectID, applicationID, configurationID string) ([]biz.BuildTrigger, error) {
	var items []biz.BuildTrigger
	for _, item := range s.triggers {
		if item.ProjectID == projectID && item.ApplicationID == applicationID && item.BuildConfigurationID == configurationID {
			items = append(items, item)
		}
	}
	return items, nil
}
func (s *serviceRepository) CreateBuildTrigger(_ context.Context, item biz.BuildTrigger) (biz.BuildTrigger, error) {
	s.triggers[item.ID] = item
	return item, nil
}
func (s *serviceRepository) GetBuildTrigger(_ context.Context, id string) (biz.BuildTrigger, error) {
	item, ok := s.triggers[id]
	if !ok {
		return biz.BuildTrigger{}, biz.ErrNotFound
	}
	return item, nil
}
func (s *serviceRepository) RevokeBuildTrigger(_ context.Context, item biz.BuildTrigger, expected uint64) (biz.BuildTrigger, error) {
	current, ok := s.triggers[item.ID]
	if !ok {
		return biz.BuildTrigger{}, biz.ErrNotFound
	}
	if current.Version != expected {
		return biz.BuildTrigger{}, biz.ErrVersionConflict
	}
	s.triggers[item.ID] = item
	return item, nil
}

func (s *serviceRepository) ListBuilds(_ context.Context, projectID string) ([]biz.Build, error) {
	var items []biz.Build
	for _, item := range s.builds {
		if item.ProjectID == projectID {
			items = append(items, item)
		}
	}
	return items, nil
}

func (s *serviceRepository) CreateBuild(_ context.Context, item biz.Build) (biz.Build, error) {
	for _, existing := range s.builds {
		if existing.ProjectID == item.ProjectID && existing.IdempotencyKey == item.IdempotencyKey {
			return biz.Build{}, biz.ErrDuplicateIdempotency
		}
	}
	s.builds[item.ID] = item
	return item, nil
}

func (s *serviceRepository) SaveBuild(_ context.Context, item biz.Build, expected uint64) (biz.Build, error) {
	current, found := s.builds[item.ID]
	if !found || current.ProjectID != item.ProjectID {
		return biz.Build{}, biz.ErrNotFound
	}
	if current.Version != expected {
		return biz.Build{}, biz.ErrVersionConflict
	}
	item.Version = expected + 1
	s.builds[item.ID] = item
	return item, nil
}

func (s *serviceRepository) GetBuild(_ context.Context, projectID, buildID string) (biz.Build, error) {
	item, found := s.builds[buildID]
	if !found || item.ProjectID != projectID {
		return biz.Build{}, biz.ErrNotFound
	}
	return item, nil
}

func (s *serviceRepository) GetBuildByIdempotency(
	_ context.Context,
	projectID, idempotencyKey string,
) (biz.Build, error) {
	for _, item := range s.builds {
		if item.ProjectID == projectID && item.IdempotencyKey == idempotencyKey {
			return item, nil
		}
	}
	return biz.Build{}, biz.ErrNotFound
}

func (s *serviceRepository) ListBuildConfigurations(
	_ context.Context,
	projectID, applicationID string,
) ([]biz.BuildConfiguration, error) {
	var items []biz.BuildConfiguration
	for _, item := range s.configurations {
		if item.ProjectID == projectID && item.ApplicationID == applicationID {
			items = append(items, item)
		}
	}
	return items, nil
}

func (s *serviceRepository) CreateBuildConfiguration(
	_ context.Context,
	item biz.BuildConfiguration,
) (biz.BuildConfiguration, error) {
	s.configurations[item.ID] = item
	return item, nil
}

func (s *serviceRepository) GetBuildConfiguration(
	_ context.Context,
	projectID, applicationID, configurationID string,
) (biz.BuildConfiguration, error) {
	item, found := s.configurations[configurationID]
	if !found || item.ProjectID != projectID || item.ApplicationID != applicationID {
		return biz.BuildConfiguration{}, biz.ErrNotFound
	}
	return item, nil
}

func (s *serviceRepository) UpdateBuildConfiguration(
	_ context.Context,
	item biz.BuildConfiguration,
	expectedVersion uint64,
) (biz.BuildConfiguration, error) {
	current, found := s.configurations[item.ID]
	if !found {
		return biz.BuildConfiguration{}, biz.ErrNotFound
	}
	if current.Version != expectedVersion {
		return biz.BuildConfiguration{}, biz.ErrVersionConflict
	}
	s.configurations[item.ID] = item
	return item, nil
}

func (s *serviceRepository) ListCredentials(context.Context, string) ([]biz.CredentialSummary, error) {
	items := make([]biz.CredentialSummary, 0, len(s.credentials))
	for _, item := range s.credentials {
		items = append(items, item.Summary())
	}
	return items, nil
}

func (s *serviceRepository) CreateCredential(_ context.Context, item biz.RepositoryCredential) (biz.CredentialSummary, error) {
	s.credentials[item.ID] = item
	return item.Summary(), nil
}

func (s *serviceRepository) GetCredential(_ context.Context, projectID, credentialID string) (biz.RepositoryCredential, error) {
	item, found := s.credentials[credentialID]
	if !found || item.ProjectID != projectID {
		return biz.RepositoryCredential{}, biz.ErrNotFound
	}
	return item, nil
}

func (s *serviceRepository) ListSources(context.Context, string) ([]biz.SourceRepository, error) {
	items := make([]biz.SourceRepository, 0, len(s.sources))
	for _, item := range s.sources {
		items = append(items, item)
	}
	return items, nil
}

func (s *serviceRepository) CreateSource(_ context.Context, item biz.SourceRepository) (biz.SourceRepository, error) {
	s.sources[item.ID] = item
	return item, nil
}

func (s *serviceRepository) GetSource(_ context.Context, projectID, sourceID string) (biz.SourceRepository, error) {
	item, found := s.sources[sourceID]
	if !found || item.ProjectID != projectID {
		return biz.SourceRepository{}, biz.ErrNotFound
	}
	return item, nil
}

func (s *serviceRepository) UpdateSourceProbe(
	_ context.Context,
	projectID, sourceID string,
	status biz.SourceRepositoryStatus,
	probedAt time.Time,
) (biz.SourceRepository, error) {
	item, found := s.sources[sourceID]
	if !found || item.ProjectID != projectID {
		return biz.SourceRepository{}, biz.ErrNotFound
	}
	item.Status = status
	item.LastProbedAt = probedAt
	item.UpdatedAt = probedAt
	s.sources[sourceID] = item
	return item, nil
}

type serviceProber struct{}

func (serviceProber) ProbeSource(
	context.Context,
	biz.SourceRepository,
	*biz.RepositoryCredential,
) (biz.SourceRepositoryStatus, error) {
	return biz.SourceRepositoryStatusReady, nil
}

func (serviceProber) ResolveSourceRevision(
	_ context.Context,
	source biz.SourceRepository,
	_ *biz.RepositoryCredential,
	ref, expectedCommitSHA string,
) (biz.SourceRevision, error) {
	commitSHA := "a975c10d68a2d7461634f13b15c52a2efba72d16"
	if expectedCommitSHA != "" && expectedCommitSHA != commitSHA {
		return biz.SourceRevision{}, biz.ErrRevisionMismatch
	}
	return biz.NewSourceRevision(source.ID, ref, commitSHA)
}

type serviceAudit struct{}

func (serviceAudit) Record(context.Context, sharedaudit.Event) error { return nil }

func TestHTTPCredentialNeverReturnsSecretReference(t *testing.T) {
	handler := newBuildHTTP(t)
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/projects/project-1/repository-credentials",
		strings.NewReader(`{"name":"Git token","type":"https_access_token","username":"builder","secret_ref":"secret://customer-git-token"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request = withBuildPrincipal(request, security.RoleMaintainer)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if strings.Contains(body, "secret_ref") || strings.Contains(body, "customer-git-token") ||
		!strings.Contains(body, `"secret_configured":true`) {
		t.Fatalf("credential response leaked or omitted secret state: %s", body)
	}

	list := httptest.NewRequest(http.MethodGet, "/api/v1/projects/project-1/repository-credentials", nil)
	list = withBuildPrincipal(list, security.RoleViewer)
	listRecorder := httptest.NewRecorder()
	handler.ServeHTTP(listRecorder, list)
	if listRecorder.Code != http.StatusOK || strings.Contains(listRecorder.Body.String(), "customer-git-token") {
		t.Fatalf("list status/body = %d/%s", listRecorder.Code, listRecorder.Body.String())
	}
}

func TestHTTPSourceRequiresPinnedSSHAndCompatibleCredential(t *testing.T) {
	handler := newBuildHTTP(t)
	credentialRequest := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/projects/project-1/repository-credentials",
		strings.NewReader(`{"name":"Deploy key","type":"ssh_deploy_key","secret_ref":"secret://deploy-key","public_key_fingerprint":"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`),
	)
	credentialRequest.Header.Set("Content-Type", "application/json")
	credentialRequest = withBuildPrincipal(credentialRequest, security.RoleMaintainer)
	credentialRecorder := httptest.NewRecorder()
	handler.ServeHTTP(credentialRecorder, credentialRequest)
	if credentialRecorder.Code != http.StatusCreated {
		t.Fatalf("credential status = %d, body = %s", credentialRecorder.Code, credentialRecorder.Body.String())
	}
	var credential credentialResponse
	if err := json.Unmarshal(credentialRecorder.Body.Bytes(), &credential); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name   string
		body   string
		status int
	}{
		{
			name:   "missing host key",
			body:   fmt.Sprintf(`{"name":"API","repository_url":"git@git.example.com:team/api.git","default_branch":"main","credential_id":%q}`, credential.ID),
			status: http.StatusUnprocessableEntity,
		},
		{
			name:   "pinned SSH",
			body:   fmt.Sprintf(`{"name":"API","repository_url":"git@git.example.com:team/api.git","default_branch":"main","credential_id":%q,"ssh_host_key_fingerprint":"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`, credential.ID),
			status: http.StatusCreated,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(
				http.MethodPost,
				"/api/v1/projects/project-1/source-repositories",
				strings.NewReader(test.body),
			)
			request.Header.Set("Content-Type", "application/json")
			request = withBuildPrincipal(request, security.RoleMaintainer)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != test.status {
				t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestHTTPDeveloperCannotManageSourceConnections(t *testing.T) {
	handler := newBuildHTTP(t)
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/projects/project-1/source-repositories",
		strings.NewReader(`{"name":"API","repository_url":"https://git.example.com/team/api.git","default_branch":"main"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request = withBuildPrincipal(request, security.RoleDeveloper)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
}

func TestHTTPProbesSourceWithoutReturningCredentialMaterial(t *testing.T) {
	handler := newBuildHTTP(t)
	create := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/projects/project-1/source-repositories",
		strings.NewReader(`{"name":"API","repository_url":"https://git.example.com/team/api.git","default_branch":"main"}`),
	)
	create.Header.Set("Content-Type", "application/json")
	create = withBuildPrincipal(create, security.RoleMaintainer)
	created := httptest.NewRecorder()
	handler.ServeHTTP(created, create)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", created.Code, created.Body.String())
	}
	var source sourceResponse
	if err := json.Unmarshal(created.Body.Bytes(), &source); err != nil {
		t.Fatal(err)
	}
	probe := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/projects/project-1/source-repositories/"+source.ID+"/probe",
		nil,
	)
	probe = withBuildPrincipal(probe, security.RoleMaintainer)
	probed := httptest.NewRecorder()
	handler.ServeHTTP(probed, probe)
	if probed.Code != http.StatusOK || !strings.Contains(probed.Body.String(), `"status":"ready"`) ||
		strings.Contains(probed.Body.String(), "secret_ref") {
		t.Fatalf("probe status/body = %d/%s", probed.Code, probed.Body.String())
	}
}

func TestHTTPBuildConfigurationCreateGetAndPatch(t *testing.T) {
	handler := newBuildHTTP(t)
	createSource := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/projects/project-1/source-repositories",
		strings.NewReader(`{"name":"API","repository_url":"https://git.example.com/team/api.git","default_branch":"main"}`),
	)
	createSource.Header.Set("Content-Type", "application/json")
	createSource = withBuildPrincipal(createSource, security.RoleMaintainer)
	sourceRecorder := httptest.NewRecorder()
	handler.ServeHTTP(sourceRecorder, createSource)
	if sourceRecorder.Code != http.StatusCreated {
		t.Fatalf("source status/body = %d/%s", sourceRecorder.Code, sourceRecorder.Body.String())
	}
	var source sourceResponse
	if err := json.Unmarshal(sourceRecorder.Body.Bytes(), &source); err != nil {
		t.Fatal(err)
	}

	createConfiguration := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/projects/project-1/applications/application-1/build-configurations",
		strings.NewReader(fmt.Sprintf(
			`{"name":"API build","source_repository_id":%q,"registry_credential_id":"registry-1","image_repository":"registry.example.com/team/api","release_runtime_spec":{"ports":[{"name":"http","container_port":8080}],"environment_keys":["DATABASE_URL"],"resources":{"cpu_milli":750,"memory_bytes":402653184}}}`,
			source.ID,
		)),
	)
	createConfiguration.Header.Set("Content-Type", "application/json")
	createConfiguration = withBuildPrincipal(createConfiguration, security.RoleDeveloper)
	configurationRecorder := httptest.NewRecorder()
	handler.ServeHTTP(configurationRecorder, createConfiguration)
	if configurationRecorder.Code != http.StatusCreated {
		t.Fatalf("configuration status/body = %d/%s", configurationRecorder.Code, configurationRecorder.Body.String())
	}
	var configuration buildConfigurationResponse
	if err := json.Unmarshal(configurationRecorder.Body.Bytes(), &configuration); err != nil {
		t.Fatal(err)
	}
	if configuration.Version != 1 || configuration.DockerfilePath != "Dockerfile" ||
		configuration.ContextPath != "." || len(configuration.AllowedRefs) != 1 ||
		configuration.AllowedRefs[0] != "refs/heads/main" || !configuration.AutoCreateRelease ||
		len(configuration.ReleaseRuntimeSpec.Ports) != 1 ||
		configuration.ReleaseRuntimeSpec.Ports[0].Protocol != "tcp" ||
		configuration.ReleaseRuntimeSpec.Resources.CPUMilli != 750 {
		t.Fatalf("configuration = %+v", configuration)
	}

	patch := httptest.NewRequest(
		http.MethodPatch,
		"/api/v1/projects/project-1/applications/application-1/build-configurations/"+configuration.ID,
		strings.NewReader(`{"expected_version":1,"timeout_seconds":900,"target_platform":"linux/arm64"}`),
	)
	patch.Header.Set("Content-Type", "application/json")
	patch = withBuildPrincipal(patch, security.RoleDeveloper)
	patchRecorder := httptest.NewRecorder()
	handler.ServeHTTP(patchRecorder, patch)
	if patchRecorder.Code != http.StatusOK ||
		!strings.Contains(patchRecorder.Body.String(), `"version":2`) ||
		!strings.Contains(patchRecorder.Body.String(), `"target_platform":"linux/arm64"`) {
		t.Fatalf("patch status/body = %d/%s", patchRecorder.Code, patchRecorder.Body.String())
	}
}

func TestHTTPAutomaticDeploymentRulesRequireMaintainerAndEnterResponse(t *testing.T) {
	handler := newBuildHTTP(t)
	createSource := httptest.NewRequest(
		http.MethodPost, "/api/v1/projects/project-1/source-repositories",
		strings.NewReader(`{"name":"API","repository_url":"https://git.example.com/team/api.git","default_branch":"main"}`),
	)
	createSource.Header.Set("Content-Type", "application/json")
	createSource = withBuildPrincipal(createSource, security.RoleMaintainer)
	sourceRecorder := httptest.NewRecorder()
	handler.ServeHTTP(sourceRecorder, createSource)
	if sourceRecorder.Code != http.StatusCreated {
		t.Fatalf("source status/body = %d/%s", sourceRecorder.Code, sourceRecorder.Body.String())
	}
	var source sourceResponse
	if err := json.Unmarshal(sourceRecorder.Body.Bytes(), &source); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(
		`{"name":"API auto","source_repository_id":%q,"registry_credential_id":"registry-1","image_repository":"registry.example.com/team/api","automatic_deployments":[{"environment_id":"development-1","runtime_target_id":"target-1"}]}`,
		source.ID,
	)
	developer := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/project-1/applications/application-1/build-configurations",
		strings.NewReader(body))
	developer.Header.Set("Content-Type", "application/json")
	developer = withBuildPrincipal(developer, security.RoleDeveloper)
	developerRecorder := httptest.NewRecorder()
	handler.ServeHTTP(developerRecorder, developer)
	if developerRecorder.Code != http.StatusForbidden {
		t.Fatalf("Developer status/body = %d/%s", developerRecorder.Code, developerRecorder.Body.String())
	}
	maintainer := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/project-1/applications/application-1/build-configurations",
		strings.NewReader(body))
	maintainer.Header.Set("Content-Type", "application/json")
	maintainer = withBuildPrincipal(maintainer, security.RoleMaintainer)
	maintainerRecorder := httptest.NewRecorder()
	handler.ServeHTTP(maintainerRecorder, maintainer)
	if maintainerRecorder.Code != http.StatusCreated ||
		!strings.Contains(maintainerRecorder.Body.String(), `"automatic_deployments":[{"environment_id":"development-1","runtime_target_id":"target-1"}]`) {
		t.Fatalf("Maintainer status/body = %d/%s", maintainerRecorder.Code, maintainerRecorder.Body.String())
	}
}

func TestHTTPTriggersAndReadsIdempotentBuildSnapshot(t *testing.T) {
	handler := newBuildHTTP(t)
	createSource := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/projects/project-1/source-repositories",
		strings.NewReader(`{"name":"API","repository_url":"https://git.example.com/team/api.git","default_branch":"main"}`),
	)
	createSource.Header.Set("Content-Type", "application/json")
	createSource = withBuildPrincipal(createSource, security.RoleMaintainer)
	sourceRecorder := httptest.NewRecorder()
	handler.ServeHTTP(sourceRecorder, createSource)
	if sourceRecorder.Code != http.StatusCreated {
		t.Fatalf("source status/body = %d/%s", sourceRecorder.Code, sourceRecorder.Body.String())
	}
	var source sourceResponse
	if err := json.Unmarshal(sourceRecorder.Body.Bytes(), &source); err != nil {
		t.Fatal(err)
	}
	createConfiguration := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/projects/project-1/applications/application-1/build-configurations",
		strings.NewReader(fmt.Sprintf(
			`{"name":"API build","source_repository_id":%q,"registry_credential_id":"registry-1","image_repository":"registry.example.com/team/api"}`,
			source.ID,
		)),
	)
	createConfiguration.Header.Set("Content-Type", "application/json")
	createConfiguration = withBuildPrincipal(createConfiguration, security.RoleDeveloper)
	configurationRecorder := httptest.NewRecorder()
	handler.ServeHTTP(configurationRecorder, createConfiguration)
	if configurationRecorder.Code != http.StatusCreated {
		t.Fatalf("configuration status/body = %d/%s", configurationRecorder.Code, configurationRecorder.Body.String())
	}
	var configuration buildConfigurationResponse
	if err := json.Unmarshal(configurationRecorder.Body.Bytes(), &configuration); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(
		`{"application_id":"application-1","build_configuration_id":%q,"ref":"refs/heads/main","expected_commit_sha":"a975c10d68a2d7461634f13b15c52a2efba72d16","idempotency_key":"manual-1"}`,
		configuration.ID,
	)
	trigger := func() *httptest.ResponseRecorder {
		request := httptest.NewRequest(
			http.MethodPost, "/api/v1/projects/project-1/builds", strings.NewReader(body),
		)
		request.Header.Set("Content-Type", "application/json")
		request = withBuildPrincipal(request, security.RoleDeveloper)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder
	}
	first := trigger()
	if first.Code != http.StatusAccepted {
		t.Fatalf("trigger status/body = %d/%s", first.Code, first.Body.String())
	}
	var created buildResponse
	if err := json.Unmarshal(first.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Status != biz.BuildStatusQueued ||
		created.Revision.CommitSHA != "a975c10d68a2d7461634f13b15c52a2efba72d16" ||
		created.Configuration.ConfigurationVersion != 1 {
		t.Fatalf("created build = %+v", created)
	}
	replayed := trigger()
	if replayed.Code != http.StatusAccepted || !strings.Contains(replayed.Body.String(), `"id":"`+created.ID+`"`) {
		t.Fatalf("replay status/body = %d/%s", replayed.Code, replayed.Body.String())
	}
	get := httptest.NewRequest(
		http.MethodGet, "/api/v1/projects/project-1/builds/"+created.ID, nil,
	)
	get = withBuildPrincipal(get, security.RoleViewer)
	getRecorder := httptest.NewRecorder()
	handler.ServeHTTP(getRecorder, get)
	if getRecorder.Code != http.StatusOK || !strings.Contains(getRecorder.Body.String(), `"status":"queued"`) {
		t.Fatalf("get status/body = %d/%s", getRecorder.Code, getRecorder.Body.String())
	}

	triggerPath := "/api/v1/projects/project-1/applications/application-1/build-configurations/" + configuration.ID + "/triggers"
	createTrigger := httptest.NewRequest(http.MethodPost, triggerPath,
		strings.NewReader(`{"name":"Git automation","allowed_refs":["refs/heads/main"]}`))
	createTrigger.Header.Set("Content-Type", "application/json")
	createTrigger = withBuildPrincipal(createTrigger, security.RoleMaintainer)
	triggerRecorder := httptest.NewRecorder()
	handler.ServeHTTP(triggerRecorder, createTrigger)
	if triggerRecorder.Code != http.StatusCreated || triggerRecorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("create trigger status/body = %d/%s", triggerRecorder.Code, triggerRecorder.Body.String())
	}
	var triggerCredential buildTriggerCredentialResponse
	if err := json.Unmarshal(triggerRecorder.Body.Bytes(), &triggerCredential); err != nil {
		t.Fatal(err)
	}
	if triggerCredential.Token != "plain-trigger-token" {
		t.Fatalf("trigger credential = %+v", triggerCredential)
	}

	listTrigger := httptest.NewRequest(http.MethodGet, triggerPath, nil)
	listTrigger = withBuildPrincipal(listTrigger, security.RoleMaintainer)
	listRecorder := httptest.NewRecorder()
	handler.ServeHTTP(listRecorder, listTrigger)
	if listRecorder.Code != http.StatusOK || strings.Contains(listRecorder.Body.String(), "plain-trigger-token") ||
		strings.Contains(listRecorder.Body.String(), "token_hash") {
		t.Fatalf("list trigger status/body = %d/%s", listRecorder.Code, listRecorder.Body.String())
	}

	externalBody := `{"commit_sha":"a975c10d68a2d7461634f13b15c52a2efba72d16","ref":"refs/heads/main"}`
	external := httptest.NewRequest(http.MethodPost, "/api/v1/build-triggers/"+triggerCredential.BuildTrigger.ID,
		strings.NewReader(externalBody))
	external.Header.Set("Content-Type", "application/json")
	external.Header.Set("Authorization", "Bearer "+triggerCredential.Token)
	external.Header.Set("Idempotency-Key", "external-1")
	externalRecorder := httptest.NewRecorder()
	handler.ServeHTTP(externalRecorder, external)
	if externalRecorder.Code != http.StatusAccepted || !strings.Contains(externalRecorder.Body.String(), `"trigger_source":"trigger_api"`) {
		t.Fatalf("external trigger status/body = %d/%s", externalRecorder.Code, externalRecorder.Body.String())
	}

	invalid := httptest.NewRequest(http.MethodPost, "/api/v1/build-triggers/"+triggerCredential.BuildTrigger.ID,
		strings.NewReader(externalBody))
	invalid.Header.Set("Content-Type", "application/json")
	invalid.Header.Set("Authorization", "Bearer wrong")
	invalid.Header.Set("Idempotency-Key", "external-2")
	invalidRecorder := httptest.NewRecorder()
	handler.ServeHTTP(invalidRecorder, invalid)
	if invalidRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("invalid token status/body = %d/%s", invalidRecorder.Code, invalidRecorder.Body.String())
	}

	hookPath := "/api/v1/projects/project-1/applications/application-1/build-configurations/" + configuration.ID + "/hooks"
	createHook := httptest.NewRequest(http.MethodPost, hookPath,
		strings.NewReader(`{"name":"GitHub webhook","provider":"github","allowed_refs":["refs/heads/main"],"secret_ref":"secret://github-hook"}`))
	createHook.Header.Set("Content-Type", "application/json")
	createHook = withBuildPrincipal(createHook, security.RoleMaintainer)
	hookRecorder := httptest.NewRecorder()
	handler.ServeHTTP(hookRecorder, createHook)
	if hookRecorder.Code != http.StatusCreated || strings.Contains(hookRecorder.Body.String(), "secret://") {
		t.Fatalf("create hook status/body = %d/%s", hookRecorder.Code, hookRecorder.Body.String())
	}
	var hook buildHookResponse
	if err := json.Unmarshal(hookRecorder.Body.Bytes(), &hook); err != nil {
		t.Fatal(err)
	}
	webhook := func() *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/build-hooks/github/"+hook.ID, strings.NewReader(`{"ref":"refs/heads/main"}`))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-GitHub-Delivery", "delivery-1")
		request.Header.Set("X-GitHub-Event", "push")
		request.Header.Set("X-Hub-Signature-256", "sha256=signed")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder
	}
	firstWebhook, replayedWebhook := webhook(), webhook()
	if firstWebhook.Code != http.StatusAccepted || replayedWebhook.Code != http.StatusAccepted ||
		!strings.Contains(firstWebhook.Body.String(), `"status":"accepted"`) {
		t.Fatalf("webhook statuses/bodies = %d/%s, %d/%s", firstWebhook.Code, firstWebhook.Body.String(), replayedWebhook.Code, replayedWebhook.Body.String())
	}
	tooLarge := httptest.NewRequest(http.MethodPost, "/api/v1/build-hooks/github/"+hook.ID, strings.NewReader(strings.Repeat("x", 1025)))
	tooLarge.Header.Set("Content-Type", "application/json")
	tooLargeRecorder := httptest.NewRecorder()
	handler.WithWebhookMaxBodyBytes(1024).ServeHTTP(tooLargeRecorder, tooLarge)
	if tooLargeRecorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized webhook status/body = %d/%s", tooLargeRecorder.Code, tooLargeRecorder.Body.String())
	}
}

func TestHTTPWebhookRateLimitIncludesRetryAfter(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/build-hooks/github/hook-1", nil)
	recorder := httptest.NewRecorder()
	if !writeError(recorder, request, &biz.WebhookRateLimitError{RetryAfter: 1500 * time.Millisecond}) {
		t.Fatal("webhook rate limit was not handled")
	}
	if recorder.Code != http.StatusTooManyRequests || recorder.Header().Get("Retry-After") != "2" ||
		!strings.Contains(recorder.Body.String(), `"code":"webhook_rate_limited"`) {
		t.Fatalf("status/header/body = %d/%q/%s", recorder.Code, recorder.Header().Get("Retry-After"), recorder.Body.String())
	}
}

func TestHTTPArtifactListGetAndCreateRelease(t *testing.T) {
	handler, repository := newBuildHTTPWithRepository(t)
	repository.artifacts["artifact-1"] = biz.Artifact{
		ID: "artifact-1", OrganizationID: "organization-1", ProjectID: "project-1",
		ApplicationID: "application-1", BuildID: "build-1",
		Origin: biz.ArtifactOriginOwnDockBuild, Producer: "owndock-build-worker",
		ProducerVerification: biz.ArtifactProducerVerified,
		BuildConfigurationID: "configuration-1", RegistryCredentialID: "registry-1",
		ImageRepository: "registry.example.com/team/api",
		ImageDigest:     "registry.example.com/team/api@sha256:" + strings.Repeat("a", 64),
		TargetPlatform:  biz.BuildPlatformLinuxAMD64,
		ReleaseRuntimeSpec: runtimespec.Spec{Resources: runtimespec.Resources{
			CPUMilli: 500, MemoryBytes: 256 * 1024 * 1024,
		}},
		ReleaseStatus: biz.ArtifactReleaseAvailable, Version: 1,
		CreatedAt: time.Unix(100, 0).UTC(),
	}
	list := withBuildPrincipal(httptest.NewRequest(http.MethodGet, "/api/v1/projects/project-1/artifacts", nil), security.RoleViewer)
	listRecorder := httptest.NewRecorder()
	handler.ServeHTTP(listRecorder, list)
	if listRecorder.Code != http.StatusOK || !strings.Contains(listRecorder.Body.String(), `"artifact-1"`) ||
		!strings.Contains(listRecorder.Body.String(), `"release_runtime_spec"`) {
		t.Fatalf("list status/body = %d/%s", listRecorder.Code, listRecorder.Body.String())
	}
	create := httptest.NewRequest(http.MethodPost, "/api/v1/projects/project-1/artifacts/artifact-1:create-release", strings.NewReader(`{"runtime_spec":{"ports":[],"environment_keys":[],"resources":{"cpu_milli":500,"memory_bytes":268435456}}}`))
	create.Header.Set("Content-Type", "application/json")
	create = withBuildPrincipal(create, security.RoleDeveloper)
	createRecorder := httptest.NewRecorder()
	handler.ServeHTTP(createRecorder, create)
	if createRecorder.Code != http.StatusCreated || !strings.Contains(createRecorder.Body.String(), `"release_status":"release_created"`) ||
		!strings.Contains(createRecorder.Body.String(), `"release_id":"release-1"`) {
		t.Fatalf("create status/body = %d/%s", createRecorder.Code, createRecorder.Body.String())
	}
	get := withBuildPrincipal(httptest.NewRequest(http.MethodGet, "/api/v1/projects/project-1/artifacts/artifact-1", nil), security.RoleViewer)
	getRecorder := httptest.NewRecorder()
	handler.ServeHTTP(getRecorder, get)
	if getRecorder.Code != http.StatusOK || !strings.Contains(getRecorder.Body.String(), `"release_id":"release-1"`) {
		t.Fatalf("get status/body = %d/%s", getRecorder.Code, getRecorder.Body.String())
	}
}

func TestHTTPRegistersExternalArtifactWithoutExposingIdempotencyKey(t *testing.T) {
	handler, _ := newBuildHTTPWithRepository(t)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/projects/project-1/artifacts",
		strings.NewReader(`{"application_id":"application-1","registry_credential_id":"registry-1","image_digest":"registry.example.com/team/api@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","target_platform":"linux/arm64","producer":"github-actions/team/api"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "delivery-secret-123")
	request = withBuildPrincipal(request, security.RoleDeveloper)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated ||
		!strings.Contains(recorder.Body.String(), `"origin":"external"`) ||
		!strings.Contains(recorder.Body.String(), `"producer":"github-actions/team/api"`) ||
		!strings.Contains(recorder.Body.String(), `"producer_verification":"declared"`) ||
		strings.Contains(recorder.Body.String(), "delivery-secret-123") ||
		strings.Contains(recorder.Body.String(), `"build_id"`) {
		t.Fatalf("register status/body = %d/%s", recorder.Code, recorder.Body.String())
	}
}

func TestHTTPExternalArtifactRegistryErrorsAreSafe(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/projects/project-1/artifacts", nil)
	for name, testCase := range map[string]struct {
		err    error
		status int
		code   string
	}{
		"authentication": {biz.ErrArtifactRegistryAuthentication, http.StatusUnprocessableEntity, "artifact_registry_authentication_failed"},
		"unavailable":    {biz.ErrArtifactRegistryUnavailable, http.StatusServiceUnavailable, "artifact_registry_unavailable"},
		"integrity":      {biz.ErrArtifactRegistryIntegrity, http.StatusBadGateway, "artifact_registry_integrity_failed"},
		"registration":   {biz.ErrArtifactRegistrationUnavailable, http.StatusServiceUnavailable, "external_artifact_registration_unavailable"},
	} {
		t.Run(name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			if !writeError(recorder, request, testCase.err) || recorder.Code != testCase.status ||
				!strings.Contains(recorder.Body.String(), `"code":"`+testCase.code+`"`) ||
				strings.Contains(recorder.Body.String(), testCase.err.Error()) {
				t.Fatalf("status/body = %d/%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestHTTPReadsBuildLogsWithOpaqueBuildBoundCursor(t *testing.T) {
	handler, repository := newBuildHTTPWithRepository(t)
	repository.builds["build-1"] = biz.Build{
		ID: "build-1", ProjectID: "project-1", Status: biz.BuildStatusBuilding,
	}
	for index, message := range []string{"Checking out source", "Building image", "Pushing image"} {
		if err := repository.AppendBuildLog(t.Context(), biz.BuildLogAppend{
			BuildID: "build-1", ProjectID: "project-1", Stage: biz.BuildLogStageBuild,
			Message: message, CreatedAt: time.Unix(int64(100+index), 0),
		}); err != nil {
			t.Fatal(err)
		}
	}
	request := withBuildPrincipal(httptest.NewRequest(http.MethodGet,
		"/api/v1/projects/project-1/builds/build-1/logs?limit=2", nil), security.RoleViewer)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("first logs status/headers/body = %d/%v/%s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
	var first buildLogPageResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if len(first.Items) != 2 || first.NextCursor == "" || first.Complete {
		t.Fatalf("first page = %+v", first)
	}
	next := withBuildPrincipal(httptest.NewRequest(http.MethodGet,
		"/api/v1/projects/project-1/builds/build-1/logs?cursor="+first.NextCursor+"&limit=2", nil), security.RoleViewer)
	nextRecorder := httptest.NewRecorder()
	handler.ServeHTTP(nextRecorder, next)
	if nextRecorder.Code != http.StatusOK || !strings.Contains(nextRecorder.Body.String(), "Pushing image") ||
		strings.Contains(nextRecorder.Body.String(), "Checking out source") {
		t.Fatalf("next logs status/body = %d/%s", nextRecorder.Code, nextRecorder.Body.String())
	}
	wrongBuild := withBuildPrincipal(httptest.NewRequest(http.MethodGet,
		"/api/v1/projects/project-1/builds/build-2/logs?cursor="+first.NextCursor, nil), security.RoleViewer)
	wrongRecorder := httptest.NewRecorder()
	handler.ServeHTTP(wrongRecorder, wrongBuild)
	if wrongRecorder.Code != http.StatusBadRequest {
		t.Fatalf("cross-Build cursor status/body = %d/%s", wrongRecorder.Code, wrongRecorder.Body.String())
	}
}

func newBuildHTTP(t *testing.T) *HTTP {
	t.Helper()
	handler, _ := newBuildHTTPWithRepository(t)
	return handler
}

func newBuildHTTPWithRepository(t *testing.T) (*HTTP, *serviceRepository) {
	t.Helper()
	repository := newServiceRepository()
	sequence := 0
	handler := NewHTTP(biz.NewUseCase(
		serviceProjects{}, repository, transaction.Passthrough{}, serviceAudit{},
		func() (string, error) {
			sequence++
			return fmt.Sprintf("id-%d", sequence), nil
		},
		func() time.Time { return time.Unix(100, 0) },
	).WithSourceProber(serviceProber{}).WithSourceRevisionResolver(serviceProber{}).
		WithWebhookVerifier(serviceWebhookVerifier{}).
		WithWebhookAdmission(serviceWebhookRateGuard{}, 120, time.Minute).
		WithBuildTriggerAutomation(serviceBuildTriggerTokens{}, serviceBuildTriggerGuard{}, 60, time.Minute).
		WithConfigurationReferences(
			serviceProjects{}, serviceProjects{},
		).WithAutomaticDeploymentReferences(serviceProjects{}).
		WithArtifactReleases(repository, serviceArtifactReleaseCreator{}).
		WithExternalArtifactRegistration(serviceArtifactEvidenceScheduler{}, serviceArtifactProbe{}).
		WithBuildLogs(repository))
	return handler, repository
}

func withBuildPrincipal(request *http.Request, role security.Role) *http.Request {
	return request.WithContext(security.WithPrincipal(request.Context(), security.Principal{
		UserID: "user-1", OrganizationID: "organization-1",
		SessionID: "session-1", Role: role,
	}))
}
