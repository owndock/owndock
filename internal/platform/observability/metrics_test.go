package observability

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsInstrumentAndExpose(t *testing.T) {
	metrics := NewMetrics()
	handler := metrics.Instrument(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/applications", nil))
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d", recorder.Code)
	}

	metricsResponse := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(metricsResponse, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := metricsResponse.Body.String()
	for _, sample := range []string{
		`owndock_http_requests_total{code="201",method="post"} 1`,
		"owndock_http_request_duration_seconds_count{method=\"post\"} 1",
	} {
		if !strings.Contains(body, sample) {
			t.Fatalf("metrics output missing %q", sample)
		}
	}
}
