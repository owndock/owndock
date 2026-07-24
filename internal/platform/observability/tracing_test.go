package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel/trace"

	platformconfig "github.com/owndock/owndock/internal/platform/config"
)

func TestDisabledTracingPropagatesTraceContext(t *testing.T) {
	tracing, err := NewTracing(context.Background(), platformconfig.Tracing{}, "owndock", "test", "test-instance")
	if err != nil {
		t.Fatalf("NewTracing() error = %v", err)
	}

	const wantTraceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	var gotTraceID string
	handler := tracing.Instrument(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTraceID = trace.SpanContextFromContext(r.Context()).TraceID().String()
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "/api/v1/applications", nil)
	request.Header.Set("traceparent", "00-"+wantTraceID+"-00f067aa0ba902b7-01")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNoContent)
	}
	if gotTraceID != wantTraceID {
		t.Fatalf("trace ID = %q, want %q", gotTraceID, wantTraceID)
	}
}

func TestTracingShutdownIsIdempotent(t *testing.T) {
	calls := 0
	tracing := &Tracing{shutdown: func(context.Context) error {
		calls++
		return nil
	}}

	if err := tracing.Shutdown(context.Background()); err != nil {
		t.Fatalf("first Shutdown() error = %v", err)
	}
	if err := tracing.Shutdown(context.Background()); err != nil {
		t.Fatalf("second Shutdown() error = %v", err)
	}
	if calls != 1 {
		t.Fatalf("shutdown calls = %d, want 1", calls)
	}
}
