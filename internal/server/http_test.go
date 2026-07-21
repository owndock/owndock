package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-kratos/kratos/v2/log"

	"github.com/owndock/owndock/internal/modules/meta"
	platformconfig "github.com/owndock/owndock/internal/platform/config"
	"github.com/owndock/owndock/internal/platform/health"
)

func TestHTTPRoutes(t *testing.T) {
	checker := health.NewChecker()
	checker.SetReady(true)
	srv, err := NewHTTPServer(
		platformconfig.HTTP{Address: "127.0.0.1:0", Timeout: "1s"},
		checker,
		meta.NewService(meta.BuildInfo{Service: "owndock", Version: "test"}),
		log.NewStdLogger(httptest.NewRecorder()),
	)
	if err != nil {
		t.Fatalf("NewHTTPServer() error = %v", err)
	}

	for _, path := range []string{"/livez", "/readyz", "/api/meta/version"} {
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
}
