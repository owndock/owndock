package observability

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
	metrics.RecordBuildOperation("success", 2*time.Second)
	metrics.RecordBuildLog("build", 128, nil)
	metrics.RecordWorkerPoll("deployment", "success", 500*time.Millisecond)
	metrics.RecordWorkerPoll("unbounded-customer-value", "unexpected", time.Second)

	metricsResponse := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(metricsResponse, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := metricsResponse.Body.String()
	for _, sample := range []string{
		`owndock_http_requests_total{code="201",method="post"} 1`,
		"owndock_http_request_duration_seconds_count{method=\"post\"} 1",
		`owndock_build_worker_operations_total{result="success"} 1`,
		`owndock_build_worker_log_bytes_total{stage="build"} 128`,
		`owndock_worker_polls_total{result="success",worker="deployment"} 1`,
		`owndock_worker_polls_total{result="error",worker="unknown"} 1`,
		`owndock_worker_poll_duration_seconds_count{result="success",worker="deployment"} 1`,
		`owndock_worker_last_success_unixtime{worker="deployment"}`,
		`owndock_worker_last_error_unixtime{worker="unknown"}`,
	} {
		if !strings.Contains(body, sample) {
			t.Fatalf("metrics output missing %q", sample)
		}
	}
}
