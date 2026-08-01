package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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
