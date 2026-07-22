package meta

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVersion(t *testing.T) {
	service := NewService(BuildInfo{
		Service:   "owndock",
		Version:   "v0.1.0",
		Commit:    "abc123",
		BuildTime: "2026-07-21T00:00:00Z",
	})
	recorder := httptest.NewRecorder()
	service.Version(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/meta/version", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	var body versionResponse
	if err := json.NewDecoder(recorder.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Version != "v0.1.0" || body.Commit != "abc123" {
		t.Fatalf("unexpected response: %+v", body)
	}
}
