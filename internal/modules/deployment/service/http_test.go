package service

import (
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
)

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
	return biz.NewUseCase(
		data.NewMemoryRepository(),
		data.NewApplicationLookup(applications),
		data.NewEnvironmentLookup(environments),
		func() (string, error) { return "dep-1", nil },
		func() time.Time { return time.Unix(0, 0) },
	)
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
