package httpx

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/owndock/owndock/internal/platform/localization"
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
	locale, message := localization.APIError(r.Context(), code)
	w.Header().Set("Content-Language", string(locale))
	w.Header().Add("Vary", "Accept-Language")
	JSON(w, status, ErrorResponse{Error: ErrorDetail{
		Code: code, Message: message, RequestID: requestID,
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
					locale, message := localization.APIError(r.Context(), "internal_error")
					w.Header().Set("Content-Language", string(locale))
					w.Header().Add("Vary", "Accept-Language")
					JSON(w, http.StatusInternalServerError, ErrorResponse{Error: ErrorDetail{
						Code: "internal_error", Message: message,
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
