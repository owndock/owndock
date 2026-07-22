package httpx

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestIDGeneratesAndPropagatesID(t *testing.T) {
	middleware := RequestID(func() (string, error) { return "request-123", nil })
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := RequestIDFromContext(r.Context()); got != "request-123" {
			t.Fatalf("request ID = %q", got)
		}
		ErrorRequest(w, r, http.StatusBadRequest, "invalid_json")
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/applications", nil))
	if got := recorder.Header().Get(RequestIDHeader); got != "request-123" {
		t.Fatalf("response request ID = %q", got)
	}
	var response ErrorResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Error.Code != "invalid_json" || response.Error.RequestID != "request-123" {
		t.Fatalf("response = %+v", response)
	}
}

func TestRequestIDPreservesValidClientID(t *testing.T) {
	middleware := RequestID(func() (string, error) { return "generated", nil })
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "/livez", nil)
	request.Header.Set(RequestIDHeader, "client.request-1")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if got := recorder.Header().Get(RequestIDHeader); got != "client.request-1" {
		t.Fatalf("response request ID = %q", got)
	}
}

func TestRequestIDGenerationFailureIsSafe(t *testing.T) {
	middleware := RequestID(func() (string, error) { return "", errors.New("entropy unavailable") })
	recorder := httptest.NewRecorder()
	middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next handler should not run")
	})).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/livez", nil))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", recorder.Code)
	}
}
