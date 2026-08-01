package httpx

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var errTestIDGeneration = errors.New("test ID generation failure")

func TestBrowserSecuritySameOriginAPIResponse(t *testing.T) {
	handler := BrowserSecurity(nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		JSON(w, http.StatusOK, map[string]bool{"ok": true})
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil))

	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("response = %d, cache = %q", recorder.Code, recorder.Header().Get("Cache-Control"))
	}
	for name, want := range map[string]string{
		"Content-Security-Policy": "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
		"Permissions-Policy":      "camera=(), geolocation=(), microphone=()",
		"Referrer-Policy":         "no-referrer",
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
	} {
		if got := recorder.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if got := recorder.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Fatalf("credentialed CORS was enabled: %q", got)
	}
}

func TestBrowserSecurityAllowsExactOriginAndPreflight(t *testing.T) {
	called := false
	handler := BrowserSecurity([]string{"https://console.owndock.net"})(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) { called = true },
	))
	request := httptest.NewRequest(http.MethodOptions, "/api/v1/projects", nil)
	request.Header.Set("Origin", "https://console.owndock.net")
	request.Header.Set("Access-Control-Request-Method", http.MethodPost)
	request.Header.Set("Access-Control-Request-Headers", "authorization, content-type, idempotency-key, traceparent")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if called || recorder.Code != http.StatusNoContent {
		t.Fatalf("next called = %v, status = %d", called, recorder.Code)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "https://console.owndock.net" {
		t.Fatalf("allow origin = %q", got)
	}
	if recorder.Header().Get("Access-Control-Allow-Credentials") != "" ||
		!strings.Contains(recorder.Header().Get("Access-Control-Allow-Headers"), "Authorization") {
		t.Fatalf("CORS headers = %v", recorder.Header())
	}
	for _, want := range []string{"Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"} {
		if !headerListContains(recorder.Header().Values("Vary"), want) {
			t.Errorf("Vary = %v, missing %q", recorder.Header().Values("Vary"), want)
		}
	}
}

func TestBrowserSecurityRejectsUntrustedOriginBeforeHandler(t *testing.T) {
	handler := BrowserSecurity([]string{"https://console.owndock.net"})(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) { t.Fatal("untrusted origin reached handler") },
	))
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	request.Header.Set("Origin", "https://attacker.example")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden ||
		!strings.Contains(recorder.Body.String(), `"code":"origin_not_allowed"`) ||
		recorder.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("response = %d %s, headers = %v", recorder.Code, recorder.Body.String(), recorder.Header())
	}
}

func TestBrowserSecurityRejectsUnsafePreflight(t *testing.T) {
	for _, test := range []struct {
		name    string
		method  string
		headers string
	}{
		{name: "method", method: "CONNECT", headers: "authorization"},
		{name: "header", method: http.MethodPost, headers: "x-unbounded-custom-header"},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := BrowserSecurity([]string{"https://console.owndock.net"})(http.HandlerFunc(
				func(http.ResponseWriter, *http.Request) { t.Fatal("invalid preflight reached handler") },
			))
			request := httptest.NewRequest(http.MethodOptions, "/api/v1/projects", nil)
			request.Header.Set("Origin", "https://console.owndock.net")
			request.Header.Set("Access-Control-Request-Method", test.method)
			request.Header.Set("Access-Control-Request-Headers", test.headers)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusForbidden ||
				!strings.Contains(recorder.Body.String(), `"code":"cors_preflight_invalid"`) {
				t.Fatalf("response = %d %s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestBrowserSecurityDoesNotApplyCORSToOperationsRoutes(t *testing.T) {
	handler := BrowserSecurity(nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	request := httptest.NewRequest(http.MethodGet, "/livez", nil)
	request.Header.Set("Origin", "https://attacker.example")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("operations response = %d, headers = %v", recorder.Code, recorder.Header())
	}
}

func TestBrowserHeadersCoverRequestIDGenerationFailure(t *testing.T) {
	handler := BrowserHeaders()(RequestID(func() (string, error) {
		return "", errTestIDGeneration
	})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("request ID failure reached handler")
	})))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil))
	if recorder.Code != http.StatusInternalServerError ||
		recorder.Header().Get("Cache-Control") != "no-store" ||
		recorder.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("response = %d, headers = %v", recorder.Code, recorder.Header())
	}
}

func headerListContains(values []string, want string) bool {
	for _, value := range values {
		for _, item := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(item), want) {
				return true
			}
		}
	}
	return false
}
