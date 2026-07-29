package httpx

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

const RequestIDHeader = "X-Request-ID"

type requestIDKey struct{}

type ErrorResponse struct {
	Error ErrorDetail `json:"error"`
}

type ErrorDetail struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
}

func JSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

// ErrorRequest writes an API error using request-scoped metadata.
func ErrorRequest(w http.ResponseWriter, r *http.Request, status int, code string) {
	requestID := RequestIDFromContext(r.Context())
	JSON(w, status, ErrorResponse{Error: ErrorDetail{
		Code: code, Message: errorMessage(code), RequestID: requestID,
	}})
}

func RequestID(newID func() (string, error)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := strings.TrimSpace(r.Header.Get(RequestIDHeader))
			if !validRequestID(requestID) {
				var err error
				requestID, err = newID()
				if err != nil {
					JSON(w, http.StatusInternalServerError, ErrorResponse{Error: ErrorDetail{
						Code: "internal_error", Message: errorMessage("internal_error"),
					}})
					return
				}
			}
			w.Header().Set(RequestIDHeader, requestID)
			ctx := context.WithValue(r.Context(), requestIDKey{}, requestID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func RequestIDFromContext(ctx context.Context) string {
	requestID, _ := ctx.Value(requestIDKey{}).(string)
	return requestID
}

func validRequestID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '-' || char == '_' || char == '.' {
			continue
		}
		return false
	}
	return true
}

func errorMessage(code string) string {
	messages := map[string]string{
		"already_bootstrapped":        "identity has already been initialized",
		"application_not_found":       "application was not found",
		"bootstrap_token_invalid":     "bootstrap token is invalid",
		"environment_not_found":       "environment was not found",
		"forbidden":                   "permission is denied",
		"internal_error":              "an internal error occurred",
		"invalid_deployment":          "deployment input is invalid",
		"invalid_environment":         "environment input is invalid",
		"invalid_json":                "request body must be valid JSON",
		"invalid_identity":            "identity input is invalid",
		"invalid_image":               "image must be pinned by a sha256 digest",
		"invalid_limit":               "limit must be between 1 and 100",
		"invalid_name":                "application name is required",
		"invalid_registry_credential": "registry credential input is invalid",
		"invalid_runtime_spec":        "release runtime specification is invalid",
		"invalid_runtime_target":      "runtime target input is invalid",
		"method_not_allowed":          "method is not allowed",
		"name_conflict":               "resource name already exists",
		"not_found":                   "resource was not found",
		"release_conflict":            "an equivalent release already exists",
		"unauthenticated":             "authentication is required",
		"unsupported_media_type":      "content type must be application/json",
	}
	if message, ok := messages[code]; ok {
		return message
	}
	return "request failed"
}
