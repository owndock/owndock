package localization

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPNegotiatesRequestLocale(t *testing.T) {
	handler := HTTP()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := FromContext(r.Context()); got != SimplifiedChinese {
			t.Fatalf("locale = %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil)
	request.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	handler.ServeHTTP(httptest.NewRecorder(), request)
}

func TestHTTPIgnoresOversizedAcceptLanguage(t *testing.T) {
	handler := HTTP()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := FromContext(r.Context()); got != DefaultLocale {
			t.Fatalf("locale = %q", got)
		}
	}))
	request := httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil)
	request.Header.Set("Accept-Language", strings.Repeat("zh-CN,", 300))
	handler.ServeHTTP(httptest.NewRecorder(), request)
}
