package httpx

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeJSON(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		wantErr     bool
		unsupported bool
	}{
		{name: "valid", contentType: "application/json; charset=utf-8", body: `{"name":"demo"}`},
		{name: "unknown field", body: `{"name":"demo","unknown":true}`, wantErr: true},
		{name: "multiple values", body: `{"name":"demo"}{"name":"other"}`, wantErr: true},
		{name: "wrong media type", contentType: "text/plain", body: `{"name":"demo"}`, wantErr: true, unsupported: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/api/v1/applications", strings.NewReader(test.body))
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}
			var target struct {
				Name string `json:"name"`
			}
			err := DecodeJSON(httptest.NewRecorder(), request, &target)
			if (err != nil) != test.wantErr {
				t.Fatalf("DecodeJSON() error = %v", err)
			}
			if errors.Is(err, ErrUnsupportedMediaType) != test.unsupported {
				t.Fatalf("unsupported error = %v", err)
			}
		})
	}
}

func TestDecodeJSONRejectsOversizedBody(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/applications", strings.NewReader(`{"name":"`+strings.Repeat("x", maxJSONBodyBytes)+`"}`))
	var target struct {
		Name string `json:"name"`
	}
	if err := DecodeJSON(httptest.NewRecorder(), request, &target); err == nil {
		t.Fatal("DecodeJSON() should reject an oversized body")
	}
}
