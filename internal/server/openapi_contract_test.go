package server

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
)

func TestHTTPImplementationMatchesOpenAPI(t *testing.T) {
	document := loadOpenAPI(t)
	router, err := gorillamux.NewRouter(document)
	if err != nil {
		t.Fatalf("create OpenAPI router: %v", err)
	}
	handler := newProductContractHTTPHandler(t)
	coveredOperations := make(map[string]bool)

	tests := []struct {
		name       string
		method     string
		target     string
		body       string
		headers    map[string]string
		wantStatus int
	}{
		{name: "liveness", method: http.MethodGet, target: "/livez", wantStatus: http.StatusOK},
		{name: "readiness", method: http.MethodGet, target: "/readyz", wantStatus: http.StatusOK},
		{name: "version", method: http.MethodGet, target: "/api/v1/meta/version", wantStatus: http.StatusOK},
		{name: "empty application list", method: http.MethodGet, target: "/api/v1/applications", wantStatus: http.StatusOK},
		{name: "create application", method: http.MethodPost, target: "/api/v1/applications", body: `{"name":"demo"}`, wantStatus: http.StatusCreated},
		{name: "duplicate application", method: http.MethodPost, target: "/api/v1/applications", body: `{"name":"demo"}`, wantStatus: http.StatusConflict},
		{name: "invalid application", method: http.MethodPost, target: "/api/v1/applications", body: `{"name":""}`, wantStatus: http.StatusUnprocessableEntity},
		{name: "empty environment list", method: http.MethodGet, target: "/api/v1/environments", wantStatus: http.StatusOK},
		{name: "create environment", method: http.MethodPost, target: "/api/v1/environments", body: `{"name":"local","provider":"docker"}`, wantStatus: http.StatusCreated},
		{name: "create deployment", method: http.MethodPost, target: "/api/v1/deployments", body: `{"application_id":"test-id","environment_id":"test-id","revision":"main@abc"}`, wantStatus: http.StatusCreated},
		{name: "filtered deployment list", method: http.MethodGet, target: "/api/v1/deployments?application_id=test-id&environment_id=test-id", wantStatus: http.StatusOK},
		{
			name: "bootstrap identity", method: http.MethodPost, target: "/api/v1/auth/bootstrap",
			body:       `{"organization_name":"Example Company","email":"owner@example.com","password":"long-enough-password"}`,
			headers:    map[string]string{"X-OwnDock-Bootstrap-Token": "bootstrap-secret"},
			wantStatus: http.StatusCreated,
		},
		{
			name: "login", method: http.MethodPost, target: "/api/v1/auth/login",
			body:       `{"email":"owner@example.com","password":"long-enough-password"}`,
			wantStatus: http.StatusOK,
		},
		{
			name: "current identity", method: http.MethodGet, target: "/api/v1/auth/me",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "create project", method: http.MethodPost, target: "/api/v1/projects",
			body: `{"name":"Delivery"}`, headers: bearerHeaders(), wantStatus: http.StatusCreated,
		},
		{
			name: "list projects", method: http.MethodGet, target: "/api/v1/projects",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "create project application", method: http.MethodPost, target: "/api/v1/projects/test-id/applications",
			body: `{"name":"API"}`, headers: bearerHeaders(), wantStatus: http.StatusCreated,
		},
		{
			name: "list project applications", method: http.MethodGet, target: "/api/v1/projects/test-id/applications",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "create release", method: http.MethodPost, target: "/api/v1/projects/test-id/applications/test-id/releases",
			body:    `{"image":"registry.example.com/team/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`,
			headers: bearerHeaders(), wantStatus: http.StatusCreated,
		},
		{
			name: "list releases", method: http.MethodGet, target: "/api/v1/projects/test-id/applications/test-id/releases",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "create runtime target", method: http.MethodPost, target: "/api/v1/projects/test-id/runtime-targets",
			body:    `{"name":"Production","endpoint":"tcp://docker.example.com:2376","tls_server_name":"docker.example.com","credential_ref":"secret://docker"}`,
			headers: bearerHeaders(), wantStatus: http.StatusCreated,
		},
		{
			name: "list runtime targets", method: http.MethodGet, target: "/api/v1/projects/test-id/runtime-targets",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "create project environment", method: http.MethodPost, target: "/api/v1/projects/test-id/environments",
			body: `{"name":"Production","stage":"production"}`, headers: bearerHeaders(), wantStatus: http.StatusCreated,
		},
		{
			name: "list project environments", method: http.MethodGet, target: "/api/v1/projects/test-id/environments",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "list audit events", method: http.MethodGet, target: "/api/v1/audit-events?project_id=test-id&limit=100",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "logout", method: http.MethodPost, target: "/api/v1/auth/logout",
			headers: bearerHeaders(), wantStatus: http.StatusNoContent,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operationID := assertOpenAPIExchange(
				t, context.Background(), router, handler,
				test.method, test.target, []byte(test.body), test.headers, test.wantStatus,
			)
			coveredOperations[operationID] = true
		})
	}
	for path, item := range document.Paths.Map() {
		for method, operation := range item.Operations() {
			if !coveredOperations[operation.OperationID] {
				t.Errorf("OpenAPI operation %s %s (%s) has no implementation contract test", method, path, operation.OperationID)
			}
		}
	}
}

func loadOpenAPI(t *testing.T) *openapi3.T {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve contract test path")
	}
	path := filepath.Join(filepath.Dir(currentFile), "..", "..", "api", "openapi.yaml")
	document, err := openapi3.NewLoader().LoadFromFile(path)
	if err != nil {
		t.Fatalf("load OpenAPI document: %v", err)
	}
	if err := document.Validate(context.Background()); err != nil {
		t.Fatalf("validate OpenAPI document: %v", err)
	}
	return document
}

func assertOpenAPIExchange(
	t *testing.T,
	ctx context.Context,
	router routers.Router,
	handler http.Handler,
	method string,
	target string,
	body []byte,
	headers map[string]string,
	wantStatus int,
) string {
	t.Helper()
	contractRequest := httptest.NewRequest(method, target, bytes.NewReader(body))
	contractRequest.Header.Set("X-Request-ID", "contract-request")
	if len(body) > 0 {
		contractRequest.Header.Set("Content-Type", "application/json")
	}
	for key, value := range headers {
		contractRequest.Header.Set(key, value)
	}
	route, pathParams, err := router.FindRoute(contractRequest)
	if err != nil {
		t.Fatalf("find OpenAPI route: %v", err)
	}
	requestInput := &openapi3filter.RequestValidationInput{
		Request:    contractRequest,
		PathParams: pathParams,
		Route:      route,
		Options: &openapi3filter.Options{
			AuthenticationFunc: func(context.Context, *openapi3filter.AuthenticationInput) error { return nil },
		},
	}
	if err := openapi3filter.ValidateRequest(ctx, requestInput); err != nil {
		t.Fatalf("request does not match OpenAPI: %v", err)
	}

	actualRequest := httptest.NewRequest(method, target, bytes.NewReader(body))
	actualRequest.Header = contractRequest.Header.Clone()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, actualRequest)
	if recorder.Code != wantStatus {
		t.Fatalf("status = %d, want %d; body = %s", recorder.Code, wantStatus, recorder.Body.String())
	}

	responseInput := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: requestInput,
		Status:                 recorder.Code,
		Header:                 recorder.Header(),
	}
	responseInput.SetBodyBytes(recorder.Body.Bytes())
	if err := openapi3filter.ValidateResponse(ctx, responseInput); err != nil {
		t.Fatalf("response does not match OpenAPI: %v; body = %s", err, recorder.Body.String())
	}
	return route.Operation.OperationID
}

func bearerHeaders() map[string]string {
	return map[string]string{"Authorization": "Bearer " + contractAccessToken}
}
