package httpx

import (
	"net/http"
	"strings"
)

const (
	apiPathPrefix = "/api/"

	allowedCORSHeaders = "Authorization, Content-Type, Idempotency-Key, Traceparent, Tracestate, X-OwnDock-Bootstrap-Token, X-Request-ID"
	exposedCORSHeaders = "Retry-After, X-Request-ID"
)

var corsRequestHeaders = map[string]struct{}{
	"authorization":             {},
	"content-type":              {},
	"idempotency-key":           {},
	"traceparent":               {},
	"tracestate":                {},
	"x-owndock-bootstrap-token": {},
	"x-request-id":              {},
}

// BrowserSecurity composes BrowserHeaders and BrowserCORS for handlers that do
// not need middleware between those two boundaries.
func BrowserSecurity(allowedOrigins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return BrowserHeaders()(BrowserCORS(allowedOrigins)(next))
	}
}

// BrowserHeaders applies API-safe browser response headers. Keep it outside
// request ID generation so even an early transport failure is non-cacheable.
func BrowserHeaders() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			setBrowserSecurityHeaders(w.Header())
			if strings.HasPrefix(r.URL.Path, apiPathPrefix) {
				w.Header().Set("Cache-Control", "no-store")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// BrowserCORS applies an exact-origin CORS policy. It never enables
// credentialed CORS because the API authenticates with an explicit
// Authorization header instead of ambient browser cookies.
func BrowserCORS(allowedOrigins []string) func(http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(allowedOrigins))
	for _, origin := range allowedOrigins {
		allowed[origin] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.URL.Path, apiPathPrefix) {
				next.ServeHTTP(w, r)
				return
			}
			originValues := r.Header.Values("Origin")
			if len(originValues) == 0 {
				next.ServeHTTP(w, r)
				return
			}
			addVary(w.Header(), "Origin")
			if len(originValues) != 1 {
				ErrorRequest(w, r, http.StatusForbidden, "origin_not_allowed")
				return
			}
			origin := strings.TrimSpace(originValues[0])
			if _, ok := allowed[origin]; !ok {
				ErrorRequest(w, r, http.StatusForbidden, "origin_not_allowed")
				return
			}

			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Expose-Headers", exposedCORSHeaders)
			if r.Method != http.MethodOptions ||
				r.Header.Get("Access-Control-Request-Method") == "" {
				next.ServeHTTP(w, r)
				return
			}
			addVary(w.Header(), "Access-Control-Request-Method")
			addVary(w.Header(), "Access-Control-Request-Headers")
			if !validCORSMethod(r.Header.Get("Access-Control-Request-Method")) ||
				!validCORSHeaders(r.Header.Values("Access-Control-Request-Headers")) {
				ErrorRequest(w, r, http.StatusForbidden, "cors_preflight_invalid")
				return
			}
			w.Header().Set("Access-Control-Allow-Methods", r.Header.Get("Access-Control-Request-Method"))
			w.Header().Set("Access-Control-Allow-Headers", allowedCORSHeaders)
			w.Header().Set("Access-Control-Max-Age", "600")
			w.WriteHeader(http.StatusNoContent)
		})
	}
}

func setBrowserSecurityHeaders(header http.Header) {
	header.Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
	header.Set("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
}

func validCORSMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func validCORSHeaders(values []string) bool {
	for _, value := range values {
		for _, header := range strings.Split(value, ",") {
			header = strings.ToLower(strings.TrimSpace(header))
			if header == "" {
				continue
			}
			if _, ok := corsRequestHeaders[header]; !ok {
				return false
			}
		}
	}
	return true
}

func addVary(header http.Header, value string) {
	for _, existing := range header.Values("Vary") {
		for _, item := range strings.Split(existing, ",") {
			if strings.EqualFold(strings.TrimSpace(item), value) {
				return
			}
		}
	}
	header.Add("Vary", value)
}
