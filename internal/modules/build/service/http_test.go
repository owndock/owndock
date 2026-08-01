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
	"github.com/owndock/owndock/internal/shared/security"
	"github.com/owndock/owndock/internal/shared/transaction"
)

type serviceProjects struct{}

func (serviceProjects) ProjectExists(context.Context, string, string) (bool, error) {
	return true, nil
}

type serviceRepository struct {
	credentials map[string]biz.RepositoryCredential
	sources     map[string]biz.SourceRepository
}

func newServiceRepository() *serviceRepository {
	return &serviceRepository{
		credentials: make(map[string]biz.RepositoryCredential),
		sources:     make(map[string]biz.SourceRepository),
	}
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

func newBuildHTTP(t *testing.T) *HTTP {
	t.Helper()
	repository := newServiceRepository()
	sequence := 0
	return NewHTTP(biz.NewUseCase(
		serviceProjects{}, repository, transaction.Passthrough{}, serviceAudit{},
		func() (string, error) {
			sequence++
			return fmt.Sprintf("id-%d", sequence), nil
		},
		func() time.Time { return time.Unix(100, 0) },
	).WithSourceProber(serviceProber{}))
}

func withBuildPrincipal(request *http.Request, role security.Role) *http.Request {
	return request.WithContext(security.WithPrincipal(request.Context(), security.Principal{
		UserID: "user-1", OrganizationID: "organization-1",
		SessionID: "session-1", Role: role,
	}))
}
