package biz

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/security"
	"github.com/owndock/owndock/internal/shared/transaction"
)

type projectLookupStub struct {
	exists bool
}

func (s projectLookupStub) ProjectExists(
	context.Context,
	string,
	string,
) (bool, error) {
	return s.exists, nil
}

type repositoryStub struct {
	credentials map[string]RepositoryCredential
	sources     map[string]SourceRepository
}

func newRepositoryStub() *repositoryStub {
	return &repositoryStub{
		credentials: make(map[string]RepositoryCredential),
		sources:     make(map[string]SourceRepository),
	}
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

func testPrincipal(role security.Role) security.Principal {
	return security.Principal{
		UserID: "user-1", OrganizationID: "organization-1",
		SessionID: "session-1", Role: role,
	}
}
