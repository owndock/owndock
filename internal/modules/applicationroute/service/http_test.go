package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/applicationroute/biz"
	"github.com/owndock/owndock/internal/shared/security"
)

func TestHTTPApplicationRouteLifecycle(t *testing.T) {
	repository := &routeRepositoryStub{}
	now := time.Date(2026, time.October, 1, 9, 0, 0, 0, time.UTC)
	useCase, err := biz.NewUseCase(repository, routeReferencesStub{},
		func() (string, error) { return "route-1", nil }, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	useCase.WithRetirement(repository, routeRetirerStub{})
	handler := NewHTTP(useCase)
	principal := security.Principal{UserID: "user-1", OrganizationID: "organization-1",
		SessionID: "session-1", Role: security.RoleMaintainer}
	exchange := func(method, target, body string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, target, strings.NewReader(body))
		if body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		request = request.WithContext(security.WithPrincipal(request.Context(), principal))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	createBody := `{"application_id":"app-1","environment_id":"env-1","runtime_target_id":"target-1","hostname":"API.Example.com","port_name":"http","tls_mode":"disabled"}`
	created := exchange(http.MethodPost, "/api/v1/projects/project-1/application-routes", createBody)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status = %d: %s", created.Code, created.Body.String())
	}
	var createdRoute routeResponse
	if err := json.Unmarshal(created.Body.Bytes(), &createdRoute); err != nil {
		t.Fatal(err)
	}
	if createdRoute.Hostname != "api.example.com" || createdRoute.Status != biz.StatusPending || createdRoute.Revision != 1 {
		t.Fatalf("created route = %#v", createdRoute)
	}
	listed := exchange(http.MethodGet, "/api/v1/projects/project-1/application-routes", "")
	if listed.Code != http.StatusOK {
		t.Fatalf("list status = %d: %s", listed.Code, listed.Body.String())
	}
	got := exchange(http.MethodGet, "/api/v1/projects/project-1/application-routes/route-1", "")
	if got.Code != http.StatusOK {
		t.Fatalf("get status = %d: %s", got.Code, got.Body.String())
	}
	updateBody := `{"application_id":"app-1","environment_id":"env-1","runtime_target_id":"target-1","hostname":"www.example.com","port_name":"http","tls_mode":"disabled","expected_version":1}`
	updated := exchange(http.MethodPatch, "/api/v1/projects/project-1/application-routes/route-1", updateBody)
	if updated.Code != http.StatusOK {
		t.Fatalf("update status = %d: %s", updated.Code, updated.Body.String())
	}
	if replay := exchange(http.MethodPatch, "/api/v1/projects/project-1/application-routes/route-1", updateBody); replay.Code != http.StatusConflict {
		t.Fatalf("stale update status = %d: %s", replay.Code, replay.Body.String())
	}
	deleted := exchange(http.MethodDelete, "/api/v1/projects/project-1/application-routes/route-1", "")
	if deleted.Code != http.StatusAccepted || !strings.Contains(deleted.Body.String(), `"status":"retiring"`) {
		t.Fatalf("delete status = %d: %s", deleted.Code, deleted.Body.String())
	}
	invalidCreate := strings.TrimSuffix(createBody, "}") + `,"expected_version":1}`
	if response := exchange(http.MethodPost, "/api/v1/projects/project-1/application-routes", invalidCreate); response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("create with expected version status = %d: %s", response.Code, response.Body.String())
	}
}

func TestApplicationRouteResponseExposesOnlyStableFailureCode(t *testing.T) {
	input := biz.Input{ID: "route-1", OrganizationID: "organization-1", ProjectID: "project-1",
		ApplicationID: "app-1", EnvironmentID: "env-1", RuntimeTargetID: "target-1",
		Hostname: "api.example.com", PortName: "http", TLSMode: biz.TLSModeDisabled,
		Status: biz.StatusPending, Revision: 1, Version: 1,
		CreatedBy: "user-1", UpdatedBy: "user-1", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	route, err := biz.NewApplicationRoute(input)
	if err != nil {
		t.Fatal(err)
	}
	route, err = route.Transition(biz.StatusProvisioning, "controller", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	route, err = route.Degrade(biz.FailureCertificateUnavailable, "controller", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	response := responseFromDomain(route)
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if response.FailureCode != biz.FailureCertificateUnavailable ||
		strings.Contains(string(encoded), "private") {
		t.Fatalf("route response = %s", encoded)
	}
}

type routeReferencesStub struct{}

func (routeReferencesStub) Resolve(context.Context, string, string, string, string, string) (biz.References, error) {
	return biz.References{EnvironmentStage: "development", AgentTarget: true}, nil
}

type routeRepositoryStub struct{ item biz.ApplicationRoute }

type routeRetirerStub struct{}

func (routeRetirerStub) Retire(context.Context, string) (bool, error) {
	return false, biz.ErrRetirementPending
}

func (r *routeRepositoryStub) Create(_ context.Context, item biz.ApplicationRoute) (biz.ApplicationRoute, error) {
	r.item = item
	return item, nil
}
func (r *routeRepositoryStub) List(context.Context, string, string) ([]biz.ApplicationRoute, error) {
	return []biz.ApplicationRoute{r.item}, nil
}
func (r *routeRepositoryStub) Get(context.Context, string, string, string) (biz.ApplicationRoute, error) {
	if r.item.ID == "" {
		return biz.ApplicationRoute{}, biz.ErrNotFound
	}
	return r.item, nil
}
func (r *routeRepositoryStub) Save(_ context.Context, item biz.ApplicationRoute, expectedVersion uint64) (biz.ApplicationRoute, error) {
	if r.item.Version != expectedVersion {
		return biz.ApplicationRoute{}, biz.ErrRouteConflict
	}
	r.item = item
	return item, nil
}
func (r *routeRepositoryStub) ListRetiring(context.Context, int64) ([]biz.ApplicationRoute, error) {
	if r.item.Status == biz.StatusRetiring {
		return []biz.ApplicationRoute{r.item}, nil
	}
	return nil, nil
}
func (r *routeRepositoryStub) ListByProductResource(context.Context, string, string, string, string) ([]biz.ApplicationRoute, error) {
	return nil, nil
}
func (r *routeRepositoryStub) ListByRuntimeTarget(context.Context, string, string, string) ([]biz.ApplicationRoute, error) {
	return nil, nil
}
