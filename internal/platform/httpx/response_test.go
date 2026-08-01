package httpx

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/owndock/owndock/internal/platform/localization"
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
	if got := recorder.Header().Get("Content-Language"); got != "en-US" {
		t.Fatalf("error content language = %q", got)
	}
	var response ErrorResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Error.Code != "invalid_json" || response.Error.RequestID != "request-123" {
		t.Fatalf("response = %+v", response)
	}
}

func TestErrorRequestLocalizesSafeMessage(t *testing.T) {
	handler := localization.HTTP()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ErrorRequest(w, r, http.StatusBadRequest, "invalid_json")
	}))
	request := httptest.NewRequest(http.MethodPost, "/api/v1/projects", nil)
	request.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if got := recorder.Header().Get("Content-Language"); got != "zh-CN" {
		t.Fatalf("content language = %q", got)
	}
	if got := recorder.Header().Values("Vary"); len(got) != 1 || got[0] != "Accept-Language" {
		t.Fatalf("vary = %v", got)
	}
	var response ErrorResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Error.Code != "invalid_json" || response.Error.Message != "请求正文必须是有效的 JSON" {
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
	if got := recorder.Header().Get("Content-Language"); got != "en-US" {
		t.Fatalf("error content language = %q", got)
	}
}
