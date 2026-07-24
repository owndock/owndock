package httpx

import (
	"net/http"
	"time"

	"github.com/felixge/httpsnoop"
	"github.com/go-kratos/kratos/v2/log"
	"go.opentelemetry.io/otel/trace"
)

func AccessLog(logger log.Logger) func(http.Handler) http.Handler {
	helper := log.NewHelper(log.With(logger, "component", "http.access"))
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			captured := httpsnoop.CaptureMetrics(next, w, r)
			fields := []any{
				"msg", "HTTP request completed",
				"request.id", RequestIDFromContext(r.Context()),
				"method", r.Method,
				"path", r.URL.Path,
				"status", captured.Code,
				"duration.ms", float64(captured.Duration) / float64(time.Millisecond),
				"response.bytes", captured.Written,
			}
			spanContext := trace.SpanContextFromContext(r.Context())
			if spanContext.IsValid() {
				fields = append(fields,
					"trace.id", spanContext.TraceID().String(),
					"span.id", spanContext.SpanID().String(),
				)
			}

			switch {
			case captured.Code >= http.StatusInternalServerError:
				helper.WithContext(r.Context()).Errorw(fields...)
			case captured.Code >= http.StatusBadRequest:
				helper.WithContext(r.Context()).Warnw(fields...)
			default:
				helper.WithContext(r.Context()).Infow(fields...)
			}
		})
	}
}
