package httpx

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-kratos/kratos/v2/log"
)

func TestRecoveryConvertsPanicToSafeError(t *testing.T) {
	loggerOutput := httptest.NewRecorder()
	handler := RequestID(func() (string, error) { return "panic-request", nil })(
		Recovery(log.NewStdLogger(loggerOutput))(
			http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("secret detail") }),
		),
	)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/failure", nil))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "secret detail") || !strings.Contains(recorder.Body.String(), `"request_id":"panic-request"`) {
		t.Fatalf("response body = %s", recorder.Body.String())
	}
	if !strings.Contains(loggerOutput.Body.String(), "secret detail") || !strings.Contains(loggerOutput.Body.String(), "panic-request") {
		t.Fatalf("log = %s", loggerOutput.Body.String())
	}
}
