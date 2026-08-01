package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/runtimeinventory/biz"
	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/security"
)

type httpViewRepository struct {
	page biz.StatePage
}

func (r *httpViewRepository) ListProject(
	context.Context, string, string, biz.ViewQuery,
) (biz.StatePage, error) {
	return r.page, nil
}

func (r *httpViewRepository) ListHost(
	context.Context, string, string, biz.ViewQuery,
) (biz.StatePage, error) {
	return r.page, nil
}

type httpAudit struct{}

func (httpAudit) Record(context.Context, sharedaudit.Event) error { return nil }

func TestHTTPProjectViewUsesSafeDTO(t *testing.T) {
	now := time.Date(2026, 7, 31, 10, 0, 0, 0, time.UTC)
	repository := &httpViewRepository{page: biz.StatePage{Items: []biz.State{{
		Resource: biz.Resource{
			ObservationID: "observation-1", OrganizationID: "organization-1",
			ManagedHostID: "host-1", RuntimeTargetID: "target-1",
			Kind: biz.KindContainer, RuntimeID: "container-1", Name: "api",
			Managed: true, ProjectID: "project-1", DeploymentID: "deployment-1",
			Container:  &biz.ContainerSummary{State: "running"},
			Labels:     map[string]string{"secret.label": "must-not-leak"},
			Attributes: map[string]string{"internal": "must-not-leak"},
			Ports:      []biz.Port{}, Mounts: []biz.Mount{}, Networks: []biz.NetworkAttachment{},
			ObservedAt: now, SchemaVersion: biz.CurrentSchemaVersion,
		},
		Presence: biz.PresencePresent, FirstSeenAt: now, LastSeenAt: now,
		ReconciledAt: now, Generation: 1,
	}}}}
	handler := newTestHTTP(t, repository, now)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/projects/project-1/runtime-inventory?limit=20", nil)
	request = request.WithContext(security.WithPrincipal(request.Context(), principal(security.RoleViewer)))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if strings.Contains(body, "must-not-leak") || strings.Contains(body, "labels") || strings.Contains(body, "attributes") {
		t.Fatalf("response leaked internal metadata: %s", body)
	}
	var decoded statePageResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &decoded); err != nil || len(decoded.Items) != 1 {
		t.Fatalf("response = %+v, error = %v", decoded, err)
	}
}

func TestHTTPRejectsDockerSelectorsAndSeparatesHostPermission(t *testing.T) {
	handler := newTestHTTP(t, &httpViewRepository{}, time.Now())
	for _, rawQuery := range []string{"filter=status%3Drunning", "endpoint=tcp%3A%2F%2Fhost", "limit=1&limit=2", "kind=image"} {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/projects/project-1/runtime-inventory?"+rawQuery, nil)
		request = request.WithContext(security.WithPrincipal(request.Context(), principal(security.RoleDeveloper)))
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnprocessableEntity {
			t.Errorf("query %q status = %d, body = %s", rawQuery, recorder.Code, recorder.Body.String())
		}
	}
	hostRequest := httptest.NewRequest(http.MethodGet, "/api/v1/managed-hosts/host-1/runtime-inventory", nil)
	hostRequest = hostRequest.WithContext(security.WithPrincipal(hostRequest.Context(), principal(security.RoleDeveloper)))
	hostRecorder := httptest.NewRecorder()
	handler.ServeHTTP(hostRecorder, hostRequest)
	if hostRecorder.Code != http.StatusForbidden {
		t.Fatalf("developer host status = %d, body = %s", hostRecorder.Code, hostRecorder.Body.String())
	}
}

func newTestHTTP(t *testing.T, repository biz.ViewRepository, now time.Time) *HTTP {
	t.Helper()
	useCase, err := biz.NewViewUseCase(
		repository, httpAudit{}, func() (string, error) { return "audit-1", nil }, func() time.Time { return now },
	)
	if err != nil {
		t.Fatalf("NewViewUseCase() error = %v", err)
	}
	return NewHTTP(useCase)
}

func principal(role security.Role) security.Principal {
	return security.Principal{
		UserID: "user-1", OrganizationID: "organization-1",
		SessionID: "session-1", Role: role,
	}
}
