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
			name: "list current user sessions", method: http.MethodGet,
			target:  "/api/v1/auth/sessions",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "reject unknown session revoke", method: http.MethodDelete,
			target:  "/api/v1/auth/sessions/missing-session",
			headers: bearerHeaders(), wantStatus: http.StatusNotFound,
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
			name: "list project runtime inventory", method: http.MethodGet,
			target:  "/api/v1/projects/test-id/runtime-inventory?kind=container&limit=100",
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
			name: "create registry credential", method: http.MethodPost, target: "/api/v1/projects/test-id/registry-credentials",
			body:    `{"name":"Private Registry","server":"registry.example.com","username":"robot","password_ref":"secret://registry-password"}`,
			headers: bearerHeaders(), wantStatus: http.StatusCreated,
		},
		{
			name: "list registry credentials", method: http.MethodGet, target: "/api/v1/projects/test-id/registry-credentials",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "create repository credential", method: http.MethodPost, target: "/api/v1/projects/test-id/repository-credentials",
			body:    `{"name":"Git token","type":"https_access_token","username":"builder","secret_ref":"secret://git-token"}`,
			headers: bearerHeaders(), wantStatus: http.StatusCreated,
		},
		{
			name: "list repository credentials", method: http.MethodGet, target: "/api/v1/projects/test-id/repository-credentials",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "create source repository", method: http.MethodPost, target: "/api/v1/projects/test-id/source-repositories",
			body:    `{"name":"API source","repository_url":"https://git.example.com/team/api.git","default_branch":"main","credential_id":"test-id"}`,
			headers: bearerHeaders(), wantStatus: http.StatusCreated,
		},
		{
			name: "list source repositories", method: http.MethodGet, target: "/api/v1/projects/test-id/source-repositories",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "get source repository", method: http.MethodGet, target: "/api/v1/projects/test-id/source-repositories/test-id",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "probe source repository", method: http.MethodPost, target: "/api/v1/projects/test-id/source-repositories/test-id/probe",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "create release", method: http.MethodPost, target: "/api/v1/projects/test-id/applications/test-id/releases",
			body:    `{"image":"registry.example.com/team/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","registry_credential_id":"test-id","runtime_spec":{"ports":[{"name":"http","container_port":8080,"protocol":"tcp"}],"environment_keys":["DATABASE_URL"],"resources":{"cpu_milli":500,"memory_bytes":268435456},"health_check":{"command":["/healthcheck"],"interval_seconds":30,"timeout_seconds":5,"retries":3,"start_period_seconds":0}}}`,
			headers: bearerHeaders(), wantStatus: http.StatusCreated,
		},
		{
			name: "list releases", method: http.MethodGet, target: "/api/v1/projects/test-id/applications/test-id/releases",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "create managed host", method: http.MethodPost, target: "/api/v1/managed-hosts",
			body:    `{"name":"Production Host","connection_mode":"direct"}`,
			headers: bearerHeaders(), wantStatus: http.StatusCreated,
		},
		{
			name: "list managed hosts", method: http.MethodGet, target: "/api/v1/managed-hosts",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "get managed host", method: http.MethodGet, target: "/api/v1/managed-hosts/test-id",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "list host runtime inventory", method: http.MethodGet,
			target:  "/api/v1/managed-hosts/test-id/runtime-inventory?include_absent=true&limit=100",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "agent enrollment is unavailable without PKI", method: http.MethodPost,
			target:  "/api/v1/managed-hosts/test-id/enrollments",
			headers: bearerHeaders(), wantStatus: http.StatusServiceUnavailable,
		},
		{
			name: "agent enrollment exchange is unavailable without PKI", method: http.MethodPost,
			target:     "/api/v1/agent/enrollments:exchange",
			body:       `{"enrollment_token":"01234567890123456789012345678901","instance_id":"instance-1","agent_version":"1.0.0","protocol_version":"v1","capabilities":["docker"],"csr_pem":"unavailable"}`,
			wantStatus: http.StatusServiceUnavailable,
		},
		{
			name: "create runtime target", method: http.MethodPost, target: "/api/v1/projects/test-id/runtime-targets",
			body:    `{"name":"Production","managed_host_id":"test-id","connection_mode":"direct","endpoint":"tcp://docker.example.com:2376","tls_server_name":"docker.example.com","credential_ref":"secret://docker"}`,
			headers: bearerHeaders(), wantStatus: http.StatusCreated,
		},
		{
			name: "probe runtime target", method: http.MethodPost,
			target:  "/api/v1/projects/test-id/runtime-targets/test-id/probe",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "list runtime targets", method: http.MethodGet, target: "/api/v1/projects/test-id/runtime-targets",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "create project environment", method: http.MethodPost, target: "/api/v1/projects/test-id/environments",
			body: `{"name":"Production","stage":"production","variables":{"DATABASE_URL":"secret://database-url"}}`, headers: bearerHeaders(), wantStatus: http.StatusCreated,
		},
		{
			name: "list project environments", method: http.MethodGet, target: "/api/v1/projects/test-id/environments",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "create project deployment", method: http.MethodPost, target: "/api/v1/projects/test-id/deployments",
			body: `{"release_id":"test-id","application_id":"test-id","environment_id":"test-id","runtime_target_id":"test-id"}`,
			headers: map[string]string{
				"Authorization":   "Bearer " + contractAccessToken,
				"Idempotency-Key": "contract-deployment",
			},
			wantStatus: http.StatusCreated,
		},
		{
			name: "list project deployments", method: http.MethodGet, target: "/api/v1/projects/test-id/deployments",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "get project deployment", method: http.MethodGet, target: "/api/v1/projects/test-id/deployments/test-id",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "reject retry while deployment is queued", method: http.MethodPost,
			target: "/api/v1/projects/test-id/deployments/test-id/retry",
			headers: map[string]string{
				"Authorization":   "Bearer " + contractAccessToken,
				"Idempotency-Key": "contract-retry",
			},
			wantStatus: http.StatusConflict,
		},
		{
			name: "reject rollback while deployment is queued", method: http.MethodPost,
			target: "/api/v1/projects/test-id/deployments/test-id/rollback",
			body:   `{"release_id":"test-id"}`,
			headers: map[string]string{
				"Authorization":   "Bearer " + contractAccessToken,
				"Idempotency-Key": "contract-rollback",
			},
			wantStatus: http.StatusConflict,
		},
		{
			name: "cancel project deployment", method: http.MethodPost, target: "/api/v1/projects/test-id/deployments/test-id/cancel",
			headers: bearerHeaders(), wantStatus: http.StatusAccepted,
		},
		{
			name: "list audit events", method: http.MethodGet, target: "/api/v1/audit-events?project_id=test-id&limit=100",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "disable managed host", method: http.MethodPost,
			target:  "/api/v1/managed-hosts/test-id:disable",
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
