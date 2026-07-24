package health

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReadinessLifecycle(t *testing.T) {
	checker := NewChecker()

	before := httptest.NewRecorder()
	checker.Ready(before, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if before.Code != http.StatusServiceUnavailable {
		t.Fatalf("status before ready = %d, want %d", before.Code, http.StatusServiceUnavailable)
	}

	checker.SetReady(true)
	after := httptest.NewRecorder()
	checker.Ready(after, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if after.Code != http.StatusOK {
		t.Fatalf("status after ready = %d, want %d", after.Code, http.StatusOK)
	}
}

func TestReadinessIncludesDependencies(t *testing.T) {
	checker := NewChecker()
	checker.SetReady(true)
	checker.AddReadinessCheck("mongo", func(context.Context) error {
		return errors.New("unavailable")
	})

	recorder := httptest.NewRecorder()
	checker.Ready(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusServiceUnavailable)
	}
	if recorder.Body.String() != "{\"status\":\"not_ready\"}\n" {
		t.Fatalf("body = %q", recorder.Body.String())
	}
}
