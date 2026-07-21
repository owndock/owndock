package health

import (
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
