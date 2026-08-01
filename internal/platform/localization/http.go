package localization

import "net/http"

const maxAcceptLanguageBytes = 1024

// HTTP negotiates a supported locale once and makes it available to all
// request handlers. Oversized headers are ignored instead of being reflected
// into responses or logs.
func HTTP() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			value := r.Header.Get("Accept-Language")
			if len(value) > maxAcceptLanguageBytes {
				value = ""
			}
			ctx := WithLocale(r.Context(), Match(value))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
