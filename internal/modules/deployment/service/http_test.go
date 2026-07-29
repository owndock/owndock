package service

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	applicationbiz "github.com/owndock/owndock/internal/modules/application/biz"
	applicationdata "github.com/owndock/owndock/internal/modules/application/data"
	"github.com/owndock/owndock/internal/modules/deployment/biz"
	"github.com/owndock/owndock/internal/modules/deployment/data"
	environmentbiz "github.com/owndock/owndock/internal/modules/environment/biz"
	environmentdata "github.com/owndock/owndock/internal/modules/environment/data"
	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/security"
	"github.com/owndock/owndock/internal/shared/transaction"
)

type formalReferences struct {
	validateErr error
}

func (formalReferences) ValidateProject(context.Context, string, string) error { return nil }
func (r formalReferences) Validate(context.Context, string, string, string, string, string) error {
	return r.validateErr
}

type auditRecorder struct{}

func (auditRecorder) Record(context.Context, sharedaudit.Event) error { return nil }

func developerPrincipal() security.Principal {
	return security.Principal{UserID: "u", OrganizationID: "o", SessionID: "s", Role: security.RoleDeveloper}
}

func formalRequest(method, body string, principal security.Principal) *http.Request {
	return authenticatedRequest(method, "/api/v1/projects/p1/deployments", body, principal)
}

func authenticatedRequest(method, path, body string, principal security.Principal) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	if principal.Valid() {
		request = request.WithContext(security.WithPrincipal(request.Context(), principal))
	}
	return request
}

func newTestUseCase(t *testing.T, withReferences bool) *biz.UseCase {
	t.Helper()
	applications := applicationdata.NewMemoryRepository()
	environments := environmentdata.NewMemoryRepository()
	if withReferences {
		_, err := applications.Create(t.Context(), applicationbiz.Application{ID: "app-1", Name: "demo"})
		if err != nil {
			t.Fatal(err)
		}
		_, err = environments.Create(t.Context(), environmentbiz.Environment{ID: "env-1", Name: "local"})
		if err != nil {
			t.Fatal(err)
		}
	}
	sequence := 0
	return biz.NewUseCase(
		data.NewMemoryRepository(),
		data.NewApplicationLookup(applications),
		data.NewEnvironmentLookup(environments),
		func() (string, error) {
			sequence++
			return fmt.Sprintf("dep-%d", sequence), nil
		},
		func() time.Time { return time.Unix(0, 0) },
	).WithFormalReferences(formalReferences{}).
		WithFormalSecurity(transaction.Passthrough{}, auditRecorder{})
}

func TestCreateRejectsMissingReferences(t *testing.T) {
	service := NewHTTP(newTestUseCase(t, false))
	recorder := httptest.NewRecorder()
	service.Handle(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/deployments", strings.NewReader(`{"application_id":"missing","environment_id":"missing"}`)))
	if recorder.Code != http.StatusUnprocessableEntity || !strings.Contains(recorder.Body.String(), "application_not_found") {
		t.Fatalf("response = %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestCreateAndFilter(t *testing.T) {
	service := NewHTTP(newTestUseCase(t, true))
	create := httptest.NewRecorder()
	body := `{"application_id":"app-1","environment_id":"env-1","revision":"main@abc"}`
	service.Handle(create, httptest.NewRequest(http.MethodPost, "/api/v1/deployments", strings.NewReader(body)))
	if create.Code != http.StatusCreated || !strings.Contains(create.Body.String(), `"status":"queued"`) {
		t.Fatalf("create response = %d %s", create.Code, create.Body.String())
	}
	for _, internalField := range []string{"version", "lease", "updated_at"} {
		if strings.Contains(create.Body.String(), internalField) {
			t.Fatalf("create response leaked internal field %q: %s", internalField, create.Body.String())
		}
	}
}

func TestFormalCreateReturnsImmutableReferences(t *testing.T) {
	service := NewHTTP(newTestUseCase(t, true))
	recorder := httptest.NewRecorder()
	request := formalRequest(http.MethodPost, `{"release_id":"rel-1","application_id":"app-1","environment_id":"env-1","runtime_target_id":"target-1"}`, developerPrincipal())
	request.Header.Set("Idempotency-Key", "request-1")
	service.HandleFormal(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("formal create response = %d %s", recorder.Code, recorder.Body.String())
	}
	for _, field := range []string{"release_id", "runtime_target_id"} {
		if !strings.Contains(recorder.Body.String(), `"`+field+`"`) {
			t.Fatalf("response missing %s: %s", field, recorder.Body.String())
		}
	}
}

func TestFormalCreateAcceptsIdempotencyHeader(t *testing.T) {
	service := NewHTTP(newTestUseCase(t, true))
	recorder := httptest.NewRecorder()
	request := formalRequest(http.MethodPost, `{"release_id":"rel-1","application_id":"app-1","environment_id":"env-1","runtime_target_id":"target-1"}`, developerPrincipal())
	request.Header.Set("Idempotency-Key", "header-key")
	service.HandleFormal(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("response = %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestFormalCreateRequiresIdempotencyHeader(t *testing.T) {
	service := NewHTTP(newTestUseCase(t, true))
	recorder := httptest.NewRecorder()
	request := formalRequest(http.MethodPost, `{"release_id":"rel-1","application_id":"app-1","environment_id":"env-1","runtime_target_id":"target-1"}`, developerPrincipal())
	service.HandleFormal(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity || !strings.Contains(recorder.Body.String(), "invalid_deployment") {
		t.Fatalf("response = %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestFormalCreateRejectsRuntimeTargetThatIsNotReady(t *testing.T) {
	useCase := newTestUseCase(t, true).
		WithFormalReferences(formalReferences{validateErr: biz.ErrRuntimeTargetNotReady})
	service := NewHTTP(useCase)
	recorder := httptest.NewRecorder()
	request := formalRequest(
		http.MethodPost,
		`{"release_id":"rel-1","application_id":"app-1","environment_id":"env-1","runtime_target_id":"target-1"}`,
		developerPrincipal(),
	)
	request.Header.Set("Idempotency-Key", "request-1")
	service.HandleFormal(recorder, request)
	if recorder.Code != http.StatusConflict ||
		!strings.Contains(recorder.Body.String(), "runtime_target_not_ready") {
		t.Fatalf("response = %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestFormalAuthorizedRequiresDeploymentPermission(t *testing.T) {
	service := NewHTTP(newTestUseCase(t, true))
	unauthenticated := httptest.NewRecorder()
	service.HandleFormal(unauthenticated, formalRequest(http.MethodPost, `{}`, security.Principal{}))
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", unauthenticated.Code)
	}
	viewer := httptest.NewRecorder()
	service.HandleFormal(viewer, formalRequest(http.MethodPost, `{}`, security.Principal{UserID: "u", OrganizationID: "o", SessionID: "s", Role: security.RoleViewer}))
	if viewer.Code != http.StatusForbidden {
		t.Fatalf("viewer status = %d", viewer.Code)
	}
}

func TestFormalListGetAndCancel(t *testing.T) {
	service := NewHTTP(newTestUseCase(t, true))
	create := httptest.NewRecorder()
	createRequest := formalRequest(
		http.MethodPost,
		`{"release_id":"rel-1","application_id":"app-1","environment_id":"env-1","runtime_target_id":"target-1"}`,
		developerPrincipal(),
	)
	createRequest.Header.Set("Idempotency-Key", "request-1")
	service.HandleFormal(create, createRequest)
	if create.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", create.Code, create.Body.String())
	}

	list := httptest.NewRecorder()
	service.HandleFormal(list, formalRequest(http.MethodGet, "", developerPrincipal()))
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"id":"dep-1"`) {
		t.Fatalf("list = %d %s", list.Code, list.Body.String())
	}

	get := httptest.NewRecorder()
	service.HandleFormal(get, authenticatedRequest(
		http.MethodGet, "/api/v1/projects/p1/deployments/dep-1", "", developerPrincipal(),
	))
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), `"status":"queued"`) {
		t.Fatalf("get = %d %s", get.Code, get.Body.String())
	}

	maintainer := security.Principal{
		UserID: "m", OrganizationID: "o", SessionID: "s", Role: security.RoleMaintainer,
	}
	cancel := httptest.NewRecorder()
	service.HandleFormal(cancel, authenticatedRequest(
		http.MethodPost, "/api/v1/projects/p1/deployments/dep-1/cancel", "", maintainer,
	))
	if cancel.Code != http.StatusAccepted || !strings.Contains(cancel.Body.String(), `"status":"canceling"`) {
		t.Fatalf("cancel = %d %s", cancel.Code, cancel.Body.String())
	}
}

func TestFormalRetryAndRollbackCreateLinkedOperations(t *testing.T) {
	repository := data.NewMemoryRepository()
	sequence := 0
	now := time.Unix(100, 0)
	useCase := biz.NewUseCase(repository, nil, nil, func() (string, error) {
		sequence++
		return fmt.Sprintf("derived-%d", sequence), nil
	}, func() time.Time { return now }).
		WithFormalReferences(formalReferences{}).
		WithFormalSecurity(transaction.Passthrough{}, auditRecorder{})
	service := NewHTTP(useCase)

	source, err := biz.NewFormal(
		"source", "p1", "release-new", "app-1", "env-1", "target-1", "source-key", now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Transition(biz.StatusPreparing, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := source.Fail(biz.FailureImagePull, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Create(t.Context(), source); err != nil {
		t.Fatal(err)
	}
	previous, err := biz.NewFormal(
		"previous", "p1", "release-old", "app-1", "env-1", "target-1", "previous-key", now.Add(-time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := previous.Transition(biz.StatusPreparing, now.Add(-59*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := previous.Transition(biz.StatusDeploying, now.Add(-58*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := previous.Transition(biz.StatusSucceeded, now.Add(-57*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Create(t.Context(), previous); err != nil {
		t.Fatal(err)
	}

	getSource := httptest.NewRecorder()
	service.HandleFormal(getSource, authenticatedRequest(
		http.MethodGet, "/api/v1/projects/p1/deployments/source", "", developerPrincipal(),
	))
	if getSource.Code != http.StatusOK ||
		!strings.Contains(getSource.Body.String(), `"failure_category":"image_pull"`) {
		t.Fatalf("failed source = %d %s", getSource.Code, getSource.Body.String())
	}

	retry := httptest.NewRecorder()
	retryRequest := authenticatedRequest(
		http.MethodPost, "/api/v1/projects/p1/deployments/source/retry", "", developerPrincipal(),
	)
	retryRequest.Header.Set("Idempotency-Key", "retry-key")
	service.HandleFormal(retry, retryRequest)
	if retry.Code != http.StatusCreated ||
		!strings.Contains(retry.Body.String(), `"operation":"retry"`) ||
		!strings.Contains(retry.Body.String(), `"source_deployment_id":"source"`) {
		t.Fatalf("retry = %d %s", retry.Code, retry.Body.String())
	}

	maintainer := security.Principal{
		UserID: "m", OrganizationID: "o", SessionID: "s", Role: security.RoleMaintainer,
	}
	rollback := httptest.NewRecorder()
	rollbackRequest := authenticatedRequest(
		http.MethodPost,
		"/api/v1/projects/p1/deployments/source/rollback",
		`{"release_id":"release-old"}`,
		maintainer,
	)
	rollbackRequest.Header.Set("Content-Type", "application/json")
	rollbackRequest.Header.Set("Idempotency-Key", "rollback-key")
	service.HandleFormal(rollback, rollbackRequest)
	if rollback.Code != http.StatusCreated ||
		!strings.Contains(rollback.Body.String(), `"operation":"rollback"`) ||
		!strings.Contains(rollback.Body.String(), `"release_id":"release-old"`) ||
		!strings.Contains(rollback.Body.String(), `"source_deployment_id":"source"`) {
		t.Fatalf("rollback = %d %s", rollback.Code, rollback.Body.String())
	}
}

func TestFormalDerivedOperationsRejectInvalidSourceState(t *testing.T) {
	service := NewHTTP(newTestUseCase(t, true))
	create := httptest.NewRecorder()
	createRequest := formalRequest(
		http.MethodPost,
		`{"release_id":"rel-1","application_id":"app-1","environment_id":"env-1","runtime_target_id":"target-1"}`,
		developerPrincipal(),
	)
	createRequest.Header.Set("Idempotency-Key", "create-key")
	service.HandleFormal(create, createRequest)
	if create.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", create.Code, create.Body.String())
	}

	retry := httptest.NewRecorder()
	retryRequest := authenticatedRequest(
		http.MethodPost, "/api/v1/projects/p1/deployments/dep-1/retry", "", developerPrincipal(),
	)
	retryRequest.Header.Set("Idempotency-Key", "retry-key")
	service.HandleFormal(retry, retryRequest)
	if retry.Code != http.StatusConflict || !strings.Contains(retry.Body.String(), "deployment_conflict") {
		t.Fatalf("retry = %d %s", retry.Code, retry.Body.String())
	}
}
