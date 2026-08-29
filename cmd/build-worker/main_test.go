package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	platformobservability "github.com/owndock/owndock/internal/platform/observability"
)

func TestOperationsHandlerSeparatesLivenessAndDependencyReadiness(t *testing.T) {
	databaseAvailable := false
	handler := newOperationsHandler(
		platformobservability.NewMetrics(),
		func(context.Context) error {
			if databaseAvailable {
				return nil
			}
			return errors.New("database unavailable")
		},
	)

	assertStatus := func(path string, want int) {
		t.Helper()
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != want {
			t.Fatalf("GET %s status = %d, want %d", path, response.Code, want)
		}
	}
	assertStatus("/livez", http.StatusOK)
	assertStatus("/readyz", http.StatusServiceUnavailable)
	databaseAvailable = true
	assertStatus("/readyz", http.StatusOK)
	assertStatus("/metrics", http.StatusOK)
}

func TestStoragePreflightFailsClosedWithoutIndependentHardQuota(t *testing.T) {
	if err := run(t.Context(), []string{"-check-storage-root", t.TempDir()}); err == nil {
		t.Fatal("storage preflight accepted a missing hard-quota byte limit")
	}
	err := run(t.Context(), []string{
		"-check-storage-root", t.TempDir(),
		"-check-storage-hard-quota-bytes", strconv.FormatInt(8*1024*1024, 10),
	})
	if err == nil {
		t.Fatal("storage preflight accepted a directory on the shared test filesystem")
	}
}
