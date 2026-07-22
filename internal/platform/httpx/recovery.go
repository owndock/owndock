package httpx

import (
	"net/http"

	"github.com/go-kratos/kratos/v2/log"
)

func Recovery(logger log.Logger) func(http.Handler) http.Handler {
	helper := log.NewHelper(log.With(logger, "component", "http.recovery"))
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if recovered := recover(); recovered != nil {
					helper.WithContext(r.Context()).Errorw(
						"msg", "recovered HTTP panic",
						"request.id", RequestIDFromContext(r.Context()),
						"method", r.Method,
						"path", r.URL.Path,
						"panic", recovered,
					)
					ErrorRequest(w, r, http.StatusInternalServerError, "internal_error")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
