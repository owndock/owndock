package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-kratos/kratos/v2/log"

	applicationbiz "github.com/owndock/owndock/internal/modules/application/biz"
	applicationdata "github.com/owndock/owndock/internal/modules/application/data"
	applicationservice "github.com/owndock/owndock/internal/modules/application/service"
	deploymentbiz "github.com/owndock/owndock/internal/modules/deployment/biz"
	deploymentdata "github.com/owndock/owndock/internal/modules/deployment/data"
	deploymentservice "github.com/owndock/owndock/internal/modules/deployment/service"
	environmentbiz "github.com/owndock/owndock/internal/modules/environment/biz"
	environmentdata "github.com/owndock/owndock/internal/modules/environment/data"
	environmentservice "github.com/owndock/owndock/internal/modules/environment/service"
	"github.com/owndock/owndock/internal/modules/meta"
	platformconfig "github.com/owndock/owndock/internal/platform/config"
	"github.com/owndock/owndock/internal/platform/health"
	"github.com/owndock/owndock/internal/platform/httpx"
	"github.com/owndock/owndock/internal/platform/observability"
)

func TestHTTPRoutes(t *testing.T) {
	srv := newTestHTTPHandler(t, true)

	for _, path := range []string{"/livez", "/readyz", "/metrics", "/api/v1/meta/version", "/api/v1/applications", "/api/v1/environments", "/api/v1/deployments"} {
		recorder := httptest.NewRecorder()
		srv.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK {
			t.Errorf("GET %s status = %d, want %d", path, recorder.Code, http.StatusOK)
		}
	}

	create := httptest.NewRecorder()
	createRequest := httptest.NewRequest(http.MethodPost, "/api/v1/applications", strings.NewReader(`{"name":"demo"}`))
	createRequest.Header.Set("X-Request-ID", "test-request")
	srv.ServeHTTP(create, createRequest)
	if create.Code != http.StatusCreated {
		t.Fatalf("POST /api/v1/applications status = %d", create.Code)
	}
	if got := create.Header().Get("X-Request-ID"); got != "test-request" {
		t.Fatalf("request ID header = %q", got)
	}

	recorder := httptest.NewRecorder()
	srv.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/missing", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("missing route status = %d, want %d", recorder.Code, http.StatusNotFound)
	}
	if !strings.Contains(recorder.Body.String(), `"code":"not_found"`) || !strings.Contains(recorder.Body.String(), `"request_id":`) {
		t.Fatalf("missing route body = %s", recorder.Body.String())
	}
}

func TestEngineeringSampleRoutesAreDisabledByDefault(t *testing.T) {
	srv := newTestHTTPHandler(t, false)
	for _, path := range []string{"/api/v1/applications", "/api/v1/environments", "/api/v1/deployments"} {
		recorder := httptest.NewRecorder()
		srv.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusNotFound {
			t.Errorf("GET %s status = %d, want %d", path, recorder.Code, http.StatusNotFound)
		}
	}
}

func TestProductAPIRoutesAuthenticationBoundary(t *testing.T) {
	identity := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	controlPlane := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	authenticate := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer valid" {
				httpx.ErrorRequest(w, r, http.StatusUnauthorized, "unauthenticated")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
	api, err := NewProductAPI(identity, controlPlane, authenticate)
	if err != nil {
		t.Fatalf("NewProductAPI() error = %v", err)
	}

	public := httptest.NewRecorder()
	api.ServeHTTP(public, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil))
	if public.Code != http.StatusNoContent {
		t.Fatalf("public auth status = %d", public.Code)
	}

	denied := httptest.NewRecorder()
	api.ServeHTTP(denied, httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil))
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated project status = %d", denied.Code)
	}

	allowedRequest := httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil)
	allowedRequest.Header.Set("Authorization", "Bearer valid")
	allowed := httptest.NewRecorder()
	api.ServeHTTP(allowed, allowedRequest)
	if allowed.Code != http.StatusOK {
		t.Fatalf("authenticated project status = %d", allowed.Code)
	}
}

func newTestHTTPHandler(t *testing.T, enableEngineeringSamples bool) http.Handler {
	t.Helper()
	checker := health.NewChecker()
	checker.SetReady(true)
	applications := applicationdata.NewMemoryRepository()
	environments := environmentdata.NewMemoryRepository()
	newID := func() (string, error) { return "test-id", nil }
	now := func() time.Time { return time.Unix(0, 0) }
	tracing, err := observability.NewTracing(context.Background(), platformconfig.Tracing{}, "owndock", "test", "test-instance")
	if err != nil {
		t.Fatalf("NewTracing() error = %v", err)
	}
	var samples *EngineeringSamples
	if enableEngineeringSamples {
		samples = &EngineeringSamples{
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
	}
	srv, err := NewHTTPServer(
		platformconfig.HTTP{Address: "127.0.0.1:0", Timeout: "1s"},
		checker,
		meta.NewService(meta.BuildInfo{Service: "owndock", Version: "test"}),
		samples,
		nil,
		observability.NewMetrics(),
		tracing,
		log.NewStdLogger(httptest.NewRecorder()),
	)
	if err != nil {
		t.Fatalf("NewHTTPServer() error = %v", err)
	}
	return srv
}
