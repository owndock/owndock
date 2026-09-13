package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-kratos/kratos/v2/log"

	"github.com/owndock/owndock/internal/modules/meta"
	platformconfig "github.com/owndock/owndock/internal/platform/config"
	"github.com/owndock/owndock/internal/platform/health"
	"github.com/owndock/owndock/internal/platform/httpx"
	"github.com/owndock/owndock/internal/platform/observability"
)

func TestHTTPRoutes(t *testing.T) {
	srv := newTestHTTPHandler(t)

	for _, path := range []string{"/livez", "/readyz", "/metrics", "/api/v1/meta/version"} {
		recorder := httptest.NewRecorder()
		srv.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK {
			t.Errorf("GET %s status = %d, want %d", path, recorder.Code, http.StatusOK)
		}
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

func TestRetiredTopLevelResourceRoutesStayUnavailable(t *testing.T) {
	srv := newTestHTTPHandler(t)
	for _, path := range []string{"/api/v1/applications", "/api/v1/environments", "/api/v1/deployments"} {
		recorder := httptest.NewRecorder()
		srv.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusNotFound {
			t.Errorf("GET %s status = %d, want %d", path, recorder.Code, http.StatusNotFound)
		}
	}
}

func TestHTTPServerRejectsBrowserOriginsByDefault(t *testing.T) {
	srv := newTestHTTPHandler(t)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	request.Header.Set("Origin", "https://console.owndock.net")
	recorder := httptest.NewRecorder()
	srv.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden ||
		!strings.Contains(recorder.Body.String(), `"code":"origin_not_allowed"`) {
		t.Fatalf("response = %d %s", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("X-Request-ID") == "" {
		t.Fatal("rejected origin response has no request ID")
	}
}

func TestHTTPServerAllowsConfiguredBrowserOrigin(t *testing.T) {
	srv := newTestHTTPHandlerWithConfig(t, platformconfig.HTTP{
		Address: "127.0.0.1:0", Timeout: "1s",
		CORSAllowedOrigins: []string{"https://console.owndock.net"},
	})
	request := httptest.NewRequest(http.MethodOptions, "/api/v1/auth/login", nil)
	request.Header.Set("Origin", "https://console.owndock.net")
	request.Header.Set("Access-Control-Request-Method", http.MethodPost)
	request.Header.Set("Access-Control-Request-Headers", "content-type")
	recorder := httptest.NewRecorder()
	srv.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent ||
		recorder.Header().Get("Access-Control-Allow-Origin") != "https://console.owndock.net" ||
		recorder.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("response = %d, headers = %v", recorder.Code, recorder.Header())
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

func TestProductAPIIngressProtectionWrapsPublicAndProtectedRoutes(t *testing.T) {
	identity := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	controlPlane := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	api, err := NewProductAPI(identity, controlPlane, func(next http.Handler) http.Handler { return next })
	if err != nil {
		t.Fatal(err)
	}
	if err := api.WithIngressProtection(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			w.Header().Set("X-Ingress-Protected", "true")
			next.ServeHTTP(w, request)
		})
	}); err != nil {
		t.Fatalf("WithIngressProtection() error = %v", err)
	}
	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil),
		httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil),
	} {
		response := httptest.NewRecorder()
		api.ServeHTTP(response, request)
		if response.Header().Get("X-Ingress-Protected") != "true" {
			t.Fatalf("%s %s bypassed ingress protection", request.Method, request.URL.Path)
		}
	}
	if err := api.WithIngressProtection(nil); err == nil {
		t.Fatal("nil ingress protection was accepted")
	}
}

func TestProductAPIRoutesRuntimeInventoryBeforeOverlappingResources(t *testing.T) {
	identity := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	controlPlane := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "wrong control-plane handler", http.StatusTeapot)
	})
	authenticate := func(next http.Handler) http.Handler { return next }
	api, err := NewProductAPI(identity, controlPlane, authenticate)
	if err != nil {
		t.Fatalf("NewProductAPI() error = %v", err)
	}
	if err := api.WithRuntimeInventory(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), authenticate); err != nil {
		t.Fatalf("WithRuntimeInventory() error = %v", err)
	}
	for _, path := range []string{
		"/api/v1/projects/project-1/runtime-inventory",
		"/api/v1/managed-hosts/host-1/runtime-inventory",
	} {
		recorder := httptest.NewRecorder()
		api.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK {
			t.Errorf("GET %s status = %d, body = %s", path, recorder.Code, recorder.Body.String())
		}
	}
}

func TestProductAPIRoutesBuildBeforeControlPlane(t *testing.T) {
	identity := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	controlPlane := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "wrong control-plane handler", http.StatusTeapot)
	})
	authenticate := func(next http.Handler) http.Handler { return next }
	api, err := NewProductAPI(identity, controlPlane, authenticate)
	if err != nil {
		t.Fatalf("NewProductAPI() error = %v", err)
	}
	if err := api.WithBuild(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), authenticate); err != nil {
		t.Fatalf("WithBuild() error = %v", err)
	}
	for _, path := range []string{
		"/api/v1/projects/project-1/repository-credentials",
		"/api/v1/projects/project-1/source-repositories",
		"/api/v1/projects/project-1/source-repositories/source-1",
		"/api/v1/projects/project-1/applications/application-1/build-configurations",
		"/api/v1/projects/project-1/applications/application-1/build-configurations/configuration-1",
		"/api/v1/projects/project-1/applications/application-1/build-configurations/configuration-1/triggers",
		"/api/v1/projects/project-1/applications/application-1/build-configurations/configuration-1/triggers/trigger-1:revoke",
		"/api/v1/projects/project-1/applications/application-1/build-configurations/configuration-1/hooks",
		"/api/v1/projects/project-1/applications/application-1/build-configurations/configuration-1/hooks/hook-1:revoke",
		"/api/v1/projects/project-1/builds",
		"/api/v1/projects/project-1/builds/build-1",
		"/api/v1/projects/project-1/builds/build-1/logs",
		"/api/v1/projects/project-1/builds/build-1:cancel",
		"/api/v1/projects/project-1/builds/build-1:retry",
		"/api/v1/build-triggers/trigger-1",
		"/api/v1/build-hooks/github/hook-1",
	} {
		recorder := httptest.NewRecorder()
		api.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK {
			t.Errorf("GET %s status = %d, body = %s", path, recorder.Code, recorder.Body.String())
		}
	}
}

func TestProductAPIRoutesSupplyChainBeforeBuild(t *testing.T) {
	identity := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	wrong := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "wrong handler", http.StatusTeapot)
	})
	authenticate := func(next http.Handler) http.Handler { return next }
	api, err := NewProductAPI(identity, wrong, authenticate)
	if err != nil {
		t.Fatalf("NewProductAPI() error = %v", err)
	}
	if err := api.WithBuild(wrong, authenticate); err != nil {
		t.Fatalf("WithBuild() error = %v", err)
	}
	if err := api.WithSupplyChain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), authenticate); err != nil {
		t.Fatalf("WithSupplyChain() error = %v", err)
	}
	for _, path := range []string{
		"/api/v1/projects/project-1/artifacts/artifact-1/evidence",
		"/api/v1/projects/project-1/artifacts/artifact-1/evidence/evidence-1",
		"/api/v1/projects/project-1/vulnerability-waivers",
		"/api/v1/projects/project-1/vulnerability-waivers/waiver-1",
		"/api/v1/projects/project-1/vulnerability-waivers/waiver-1:revoke",
	} {
		recorder := httptest.NewRecorder()
		api.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK {
			t.Errorf("GET %s status = %d, body = %s", path, recorder.Code, recorder.Body.String())
		}
	}
}

func newTestHTTPHandler(t *testing.T) http.Handler {
	return newTestHTTPHandlerWithConfig(t, platformconfig.HTTP{
		Address: "127.0.0.1:0", Timeout: "1s",
	})
}

func newTestHTTPHandlerWithConfig(
	t *testing.T, httpConfig platformconfig.HTTP,
) http.Handler {
	t.Helper()
	checker := health.NewChecker()
	checker.SetReady(true)
	tracing, err := observability.NewTracing(context.Background(), platformconfig.Tracing{}, "owndock", "test", "test-instance")
	if err != nil {
		t.Fatalf("NewTracing() error = %v", err)
	}
	srv, err := NewHTTPServer(
		httpConfig,
		checker,
		meta.NewService(meta.BuildInfo{Service: "owndock", Version: "test"}),
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
