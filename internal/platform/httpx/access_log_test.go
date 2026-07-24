package httpx

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-kratos/kratos/v2/log"
	"go.opentelemetry.io/otel/trace"
)

func TestAccessLogRecordsSafeRequestContext(t *testing.T) {
	loggerOutput := httptest.NewRecorder()
	logger := log.NewStdLogger(loggerOutput)
	traceID, err := trace.TraceIDFromHex("4bf92f3577b34da6a3ce929d0e0e4736")
	if err != nil {
		t.Fatal(err)
	}
	spanID, err := trace.SpanIDFromHex("00f067aa0ba902b7")
	if err != nil {
		t.Fatal(err)
	}

	handler := RequestID(func() (string, error) { return "request-123", nil })(
		AccessLog(logger)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte("created"))
		})),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/applications?token=must-not-leak", nil)
	request = request.WithContext(trace.ContextWithSpanContext(request.Context(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID,
		SpanID:  spanID,
	})))
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	output := loggerOutput.Body.String()
	for _, want := range []string{
		"component=http.access",
		"request.id=request-123",
		"method=POST",
		"path=/api/v1/applications",
		"status=201",
		"response.bytes=7",
		"trace.id=" + traceID.String(),
		"span.id=" + spanID.String(),
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("access log %q does not contain %q", output, want)
		}
	}
	if strings.Contains(output, "must-not-leak") || strings.Contains(output, "token=") {
		t.Fatalf("access log leaked query values: %q", output)
	}
}

func TestAccessLogRecordsRecoveredPanicAsServerError(t *testing.T) {
	loggerOutput := httptest.NewRecorder()
	logger := log.NewStdLogger(loggerOutput)
	handler := RequestID(func() (string, error) { return "panic-request", nil })(
		AccessLog(logger)(
			Recovery(logger)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				panic("failure detail")
			})),
		),
	)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/failure", nil))

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusInternalServerError)
	}
	output := loggerOutput.Body.String()
	if !strings.Contains(output, "component=http.access") || !strings.Contains(output, "status=500") {
		t.Fatalf("access log = %q", output)
	}
}
