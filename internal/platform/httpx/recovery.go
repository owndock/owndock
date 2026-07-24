package httpx

import (
	"fmt"
	"net/http"

	"github.com/go-kratos/kratos/v2/log"
	"go.opentelemetry.io/otel/trace"
)

func Recovery(logger log.Logger) func(http.Handler) http.Handler {
	helper := log.NewHelper(log.With(logger, "component", "http.recovery"))
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if recovered := recover(); recovered != nil {
					fields := []any{
						"msg", "recovered HTTP panic",
						"request.id", RequestIDFromContext(r.Context()),
						"method", r.Method,
						"path", r.URL.Path,
						"panic.type", fmt.Sprintf("%T", recovered),
					}
					spanContext := trace.SpanContextFromContext(r.Context())
					if spanContext.IsValid() {
						fields = append(fields,
							"trace.id", spanContext.TraceID().String(),
							"span.id", spanContext.SpanID().String(),
						)
					}
					helper.WithContext(r.Context()).Errorw(fields...)
					ErrorRequest(w, r, http.StatusInternalServerError, "internal_error")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
