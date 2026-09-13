package server

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
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
			name: "create user invitation", method: http.MethodPost,
			target: "/api/v1/auth/invitations", body: `{"email":"member@example.com"}`,
			headers: bearerHeaders(), wantStatus: http.StatusCreated,
		},
		{
			name: "list user invitations", method: http.MethodGet,
			target: "/api/v1/auth/invitations", headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "accept user invitation", method: http.MethodPost,
			target:     "/api/v1/auth/invitations:accept",
			body:       fmt.Sprintf(`{"token":%q,"password":"member-long-password"}`, contractInvitationToken),
			wantStatus: http.StatusCreated,
		},
		{
			name: "list organization users", method: http.MethodGet,
			target: "/api/v1/auth/users", headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "list member sessions as owner", method: http.MethodGet,
			target:  "/api/v1/auth/users/contract-member-id/sessions",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "revoke member session as owner", method: http.MethodDelete,
			target:  "/api/v1/auth/users/contract-member-id/sessions/contract-member-session",
			headers: bearerHeaders(), wantStatus: http.StatusNoContent,
		},
		{
			name: "revoke all member sessions as owner", method: http.MethodDelete,
			target:  "/api/v1/auth/users/contract-member-id/sessions",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "reject revoking accepted invitation", method: http.MethodPost,
			target:  "/api/v1/auth/invitations/test-id:revoke",
			headers: bearerHeaders(), wantStatus: http.StatusConflict,
		},
		{
			name: "create project", method: http.MethodPost, target: "/api/v1/projects",
			body: `{"name":"Delivery"}`, headers: bearerHeaders(), wantStatus: http.StatusCreated,
		},
		{
			name: "create deployment policy", method: http.MethodPost,
			target:  "/api/v1/projects/test-id/deployment-policies",
			body:    `{"name":"Release admission","scope":"project","mode":"enforced","requirements":{"require_sbom":true,"require_provenance":true,"allowed_signature_policy_ids":["signing-trust-policy"],"maximum_vulnerability_severity":"high","maximum_scan_age_seconds":86400},"enabled":true}`,
			headers: bearerHeaders(), wantStatus: http.StatusCreated,
		},
		{
			name: "list deployment policies", method: http.MethodGet,
			target:  "/api/v1/projects/test-id/deployment-policies",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "get deployment policy", method: http.MethodGet,
			target:  "/api/v1/projects/test-id/deployment-policies/test-id",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "update deployment policy", method: http.MethodPatch,
			target:  "/api/v1/projects/test-id/deployment-policies/test-id",
			body:    `{"name":"Updated release admission","scope":"project","mode":"enforced","requirements":{"require_sbom":true,"require_provenance":true,"allowed_signature_policy_ids":["signing-trust-policy"],"maximum_vulnerability_severity":"medium","maximum_scan_age_seconds":43200},"enabled":true,"expected_version":1}`,
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "create signature trust policy", method: http.MethodPost,
			target:  "/api/v1/projects/test-id/signature-trust-policies",
			body:    `{"name":"Release signer","mode":"keyless","trusted_root_id":"offline-root-1","trusted_root_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","certificate_identity":"https://github.com/owndock/owndock/.github/workflows/release.yml@refs/tags/v1.0.0","oidc_issuer":"https://token.actions.githubusercontent.com","enabled":true}`,
			headers: bearerHeaders(), wantStatus: http.StatusCreated,
		},
		{
			name: "list signature trust policies", method: http.MethodGet,
			target:  "/api/v1/projects/test-id/signature-trust-policies",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "get signature trust policy", method: http.MethodGet,
			target:  "/api/v1/projects/test-id/signature-trust-policies/test-id",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "list artifact signature verifications", method: http.MethodGet,
			target:  "/api/v1/projects/test-id/artifacts/test-id/verifications",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "create vulnerability waiver", method: http.MethodPost,
			target:  "/api/v1/projects/test-id/vulnerability-waivers",
			body:    `{"scope":"artifact","artifact_id":"test-id","vulnerability_id":"CVE-2026-12345","reason":"The affected feature is disabled until the maintenance window.","expires_at":"1970-01-02T00:01:40Z"}`,
			headers: bearerHeaders(), wantStatus: http.StatusCreated,
		},
		{
			name: "list vulnerability waivers", method: http.MethodGet,
			target:  "/api/v1/projects/test-id/vulnerability-waivers?status=active&limit=50",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "get vulnerability waiver", method: http.MethodGet,
			target:  "/api/v1/projects/test-id/vulnerability-waivers/test-id",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "revoke vulnerability waiver", method: http.MethodPost,
			target:  "/api/v1/projects/test-id/vulnerability-waivers/test-id:revoke",
			body:    `{"reason":"The patched Artifact is now available.","expected_version":1}`,
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "schedule artifact signature verification", method: http.MethodPost,
			target: "/api/v1/projects/test-id/artifacts/test-id/signature-verifications",
			body:   `{"policy_id":"test-id"}`, headers: idempotencyHeaders(), wantStatus: http.StatusAccepted,
		},
		{
			name: "rotate signature trust policy", method: http.MethodPatch,
			target:  "/api/v1/projects/test-id/signature-trust-policies/test-id",
			body:    `{"name":"Release signer","mode":"keyless","trusted_root_id":"offline-root-2","trusted_root_hash":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","certificate_identity":"https://github.com/owndock/owndock/.github/workflows/release.yml@refs/tags/v1.0.0","oidc_issuer":"https://token.actions.githubusercontent.com","enabled":true,"expected_version":1}`,
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "create signature signing profile", method: http.MethodPost,
			target:  "/api/v1/projects/test-id/signature-signing-profiles",
			body:    `{"name":"Release KMS","key_reference":"hashivault://release-signing-key","trust_policy_id":"signing-trust-policy","enabled":true}`,
			headers: bearerHeaders(), wantStatus: http.StatusCreated,
		},
		{
			name: "list signature signing profiles", method: http.MethodGet,
			target:  "/api/v1/projects/test-id/signature-signing-profiles",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "get signature signing profile", method: http.MethodGet,
			target:  "/api/v1/projects/test-id/signature-signing-profiles/test-id",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "rotate signature signing profile", method: http.MethodPatch,
			target:  "/api/v1/projects/test-id/signature-signing-profiles/test-id",
			body:    `{"name":"Release KMS","key_reference":"hashivault://release-signing-key-v2","trust_policy_id":"signing-trust-policy","enabled":true,"expected_version":1}`,
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "list projects", method: http.MethodGet, target: "/api/v1/projects",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "list built-in templates", method: http.MethodGet,
			target: "/api/v1/templates", headers: bearerHeaders(),
			wantStatus: http.StatusOK,
		},
		{
			name: "get built-in template", method: http.MethodGet,
			target: "/api/v1/templates/http-service", headers: bearerHeaders(),
			wantStatus: http.StatusOK,
		},
		{
			name: "create project member", method: http.MethodPost, target: "/api/v1/projects/test-id/members",
			body: `{"email":"member@example.com","role":"developer"}`, headers: bearerHeaders(), wantStatus: http.StatusCreated,
		},
		{
			name: "list project members", method: http.MethodGet, target: "/api/v1/projects/test-id/members",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "update project member", method: http.MethodPatch, target: "/api/v1/projects/test-id/members/contract-member-id",
			body: `{"role":"maintainer","expected_version":1}`, headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "delete project member", method: http.MethodDelete,
			target:  "/api/v1/projects/test-id/members/contract-member-id?expected_version=2",
			headers: bearerHeaders(), wantStatus: http.StatusNoContent,
		},
		{
			name: "list project runtime inventory", method: http.MethodGet,
			target:  "/api/v1/projects/test-id/runtime-inventory?kind=container&limit=100",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "create project application", method: http.MethodPost, target: "/api/v1/projects/test-id/applications",
			body: `{"name":"API","template_id":"http-service"}`, headers: bearerHeaders(), wantStatus: http.StatusCreated,
		},
		{
			name: "list project applications", method: http.MethodGet, target: "/api/v1/projects/test-id/applications",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "create registry credential", method: http.MethodPost, target: "/api/v1/projects/test-id/registry-credentials",
			body:    `{"name":"Private Registry","server":"registry.example.com","authentication_mode":"basic","username":"robot","password_ref":"secret://registry-password"}`,
			headers: bearerHeaders(), wantStatus: http.StatusCreated,
		},
		{
			name: "create anonymous registry connection", method: http.MethodPost, target: "/api/v1/projects/test-id/registry-credentials",
			body:    `{"name":"Public Registry","server":"registry-1.docker.io","authentication_mode":"anonymous"}`,
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
			name: "create build configuration", method: http.MethodPost,
			target:  "/api/v1/projects/test-id/applications/test-id/build-configurations",
			body:    `{"name":"API build","source_repository_id":"test-id","registry_credential_id":"test-id","image_repository":"registry.example.com/team/api","allowed_refs":["refs/heads/main"],"resources":{"cpu_milli":2000,"memory_bytes":2147483648,"disk_bytes":10737418240}}`,
			headers: bearerHeaders(), wantStatus: http.StatusCreated,
		},
		{
			name: "list build configurations", method: http.MethodGet,
			target:  "/api/v1/projects/test-id/applications/test-id/build-configurations",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "get build configuration", method: http.MethodGet,
			target:  "/api/v1/projects/test-id/applications/test-id/build-configurations/test-id",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "update build configuration", method: http.MethodPatch,
			target:  "/api/v1/projects/test-id/applications/test-id/build-configurations/test-id",
			body:    `{"expected_version":1,"timeout_seconds":900}`,
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "create build trigger", method: http.MethodPost,
			target:  "/api/v1/projects/test-id/applications/test-id/build-configurations/test-id/triggers",
			body:    `{"name":"Git automation","allowed_refs":["refs/heads/main"]}`,
			headers: bearerHeaders(), wantStatus: http.StatusCreated,
		},
		{
			name: "list build triggers", method: http.MethodGet,
			target:  "/api/v1/projects/test-id/applications/test-id/build-configurations/test-id/triggers",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "trigger external build", method: http.MethodPost,
			target: "/api/v1/build-triggers/test-id",
			body:   `{"commit_sha":"a975c10d68a2d7461634f13b15c52a2efba72d16","ref":"refs/heads/main"}`,
			headers: map[string]string{
				"Authorization":   "Bearer contract-build-trigger-token-01234567890123",
				"Idempotency-Key": "external-test-1",
			},
			wantStatus: http.StatusAccepted,
		},
		{
			name: "revoke build trigger", method: http.MethodPost,
			target:  "/api/v1/projects/test-id/applications/test-id/build-configurations/test-id/triggers/test-id:revoke",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "create build hook", method: http.MethodPost,
			target:  "/api/v1/projects/test-id/applications/test-id/build-configurations/test-id/hooks",
			body:    `{"name":"GitHub webhook","provider":"github","allowed_refs":["refs/heads/main"],"secret_ref":"secret://github-hook"}`,
			headers: bearerHeaders(), wantStatus: http.StatusCreated,
		},
		{
			name: "list build hooks", method: http.MethodGet,
			target:  "/api/v1/projects/test-id/applications/test-id/build-configurations/test-id/hooks",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "receive build webhook", method: http.MethodPost,
			target: "/api/v1/build-hooks/github/test-id", body: `{"ref":"refs/heads/main"}`,
			headers: map[string]string{
				"X-GitHub-Delivery":   "contract-delivery-1",
				"X-GitHub-Event":      "push",
				"X-Hub-Signature-256": "sha256=contract",
			},
			wantStatus: http.StatusAccepted,
		},
		{
			name: "revoke build hook", method: http.MethodPost,
			target:  "/api/v1/projects/test-id/applications/test-id/build-configurations/test-id/hooks/test-id:revoke",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "trigger manual build", method: http.MethodPost,
			target:  "/api/v1/projects/test-id/builds",
			body:    `{"application_id":"test-id","build_configuration_id":"test-id","ref":"refs/heads/main","expected_commit_sha":"a975c10d68a2d7461634f13b15c52a2efba72d16","idempotency_key":"manual-test-1"}`,
			headers: bearerHeaders(), wantStatus: http.StatusAccepted,
		},
		{
			name: "list builds", method: http.MethodGet,
			target:  "/api/v1/projects/test-id/builds",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "get build", method: http.MethodGet,
			target:  "/api/v1/projects/test-id/builds/test-id",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "read build logs", method: http.MethodGet,
			target:  "/api/v1/projects/test-id/builds/test-id/logs?limit=100",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "retry failed build", method: http.MethodPost,
			target:  "/api/v1/projects/test-id/builds/failed-build:retry",
			body:    `{"idempotency_key":"retry-test-1"}`,
			headers: bearerHeaders(), wantStatus: http.StatusAccepted,
		},
		{
			name: "cancel queued build", method: http.MethodPost,
			target:  "/api/v1/projects/test-id/builds/test-id:cancel",
			headers: bearerHeaders(), wantStatus: http.StatusAccepted,
		},
		{
			name: "list artifacts", method: http.MethodGet,
			target:  "/api/v1/projects/test-id/artifacts",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "get artifact", method: http.MethodGet,
			target:  "/api/v1/projects/test-id/artifacts/test-id",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "list artifact evidence", method: http.MethodGet,
			target:  "/api/v1/projects/test-id/artifacts/test-id/evidence",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "latest vulnerability observation unavailable without repository", method: http.MethodGet,
			target:  "/api/v1/projects/test-id/artifacts/test-id/vulnerability-observation",
			headers: bearerHeaders(), wantStatus: http.StatusServiceUnavailable,
		},
		{
			name: "vulnerability scan unavailable without scheduler", method: http.MethodPost,
			target: "/api/v1/projects/test-id/artifacts/test-id/vulnerability-scans",
			headers: map[string]string{"Authorization": "Bearer " + contractAccessToken,
				"Idempotency-Key": "contract-vulnerability-scan"}, wantStatus: http.StatusServiceUnavailable,
		},
		{
			name: "get artifact evidence", method: http.MethodGet,
			target:  "/api/v1/projects/test-id/artifacts/test-id/evidence/test-id",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "download artifact evidence", method: http.MethodGet,
			target:  "/api/v1/projects/test-id/artifacts/test-id/evidence/test-id:download",
			headers: bearerHeaders(), wantStatus: http.StatusServiceUnavailable,
		},
		{
			name: "create release from artifact", method: http.MethodPost,
			target:  "/api/v1/projects/test-id/artifacts/test-id:create-release",
			body:    `{"runtime_spec":{"ports":[],"environment_keys":[],"resources":{"cpu_milli":500,"memory_bytes":268435456}}}`,
			headers: bearerHeaders(), wantStatus: http.StatusCreated,
		},
		{
			name: "register external artifact", method: http.MethodPost,
			target: "/api/v1/projects/test-id/artifacts",
			body:   `{"application_id":"test-id","registry_credential_id":"test-id","image_digest":"registry.example.com/team/external@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","target_platform":"linux/amd64","producer":"github-actions/example/external"}`,
			headers: map[string]string{
				"Authorization":   "Bearer " + contractAccessToken,
				"Idempotency-Key": "external-delivery-1",
			},
			wantStatus: http.StatusCreated,
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
			name: "get default organization terminal policy", method: http.MethodGet,
			target: "/api/v1/terminal-policy", headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "save organization terminal policy", method: http.MethodPut,
			target:  "/api/v1/terminal-policy",
			body:    `{"enabled":true,"allowed_roles":["owner"],"environment_stages":[],"runtime_target_ids":[],"managed_host_ids":[],"idle_timeout":"5m","maximum_duration":"30m","maximum_per_user":1,"maximum_per_target":2,"revocation_grace_period":"30s","expected_version":0}`,
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "get default project terminal policy", method: http.MethodGet,
			target: "/api/v1/projects/test-id/terminal-policy", headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "save project terminal policy", method: http.MethodPut,
			target:  "/api/v1/projects/test-id/terminal-policy",
			body:    `{"enabled":true,"allowed_roles":["owner","maintainer"],"environment_stages":["development","staging","production"],"runtime_target_ids":[],"managed_host_ids":[],"idle_timeout":"10m","maximum_duration":"1h","maximum_per_user":2,"maximum_per_target":5,"revocation_grace_period":"30s","expected_version":0}`,
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "create host terminal session", method: http.MethodPost,
			target:  "/api/v1/managed-hosts/test-id/terminal-sessions",
			headers: terminalHeaders(), wantStatus: http.StatusCreated,
		},
		{
			name: "get terminal session", method: http.MethodGet,
			target:  "/api/v1/terminal-sessions/test-id",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "terminate terminal session", method: http.MethodPost,
			target:  "/api/v1/terminal-sessions/test-id:terminate",
			headers: bearerHeaders(), wantStatus: http.StatusOK,
		},
		{
			name: "create container terminal session", method: http.MethodPost,
			target:  "/api/v1/projects/test-id/terminal-sessions/container",
			body:    `{"deployment_id":"test-id"}`,
			headers: terminalHeaders(), wantStatus: http.StatusCreated,
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
			name: "reject terminal WebSocket without Origin", method: http.MethodGet,
			target: "/api/v1/terminal-sessions/terminal-session-1:connect",
			headers: map[string]string{
				"Connection": "Upgrade", "Upgrade": "websocket",
				"Cookie": "__Secure-owndock_terminal_ticket=one-time-ticket",
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "begin Application retirement", method: http.MethodDelete,
			target:  "/api/v1/projects/test-id/applications/test-id",
			headers: bearerHeaders(), wantStatus: http.StatusAccepted,
		},
		{
			name: "complete Application retirement", method: http.MethodDelete,
			target:  "/api/v1/projects/test-id/applications/test-id",
			headers: bearerHeaders(), wantStatus: http.StatusNoContent,
		},
		{
			name: "begin Environment retirement", method: http.MethodDelete,
			target:  "/api/v1/projects/test-id/environments/test-id",
			headers: bearerHeaders(), wantStatus: http.StatusAccepted,
		},
		{
			name: "complete Environment retirement", method: http.MethodDelete,
			target:  "/api/v1/projects/test-id/environments/test-id",
			headers: bearerHeaders(), wantStatus: http.StatusNoContent,
		},
		{
			name: "begin runtime target retirement", method: http.MethodDelete,
			target:  "/api/v1/projects/test-id/runtime-targets/test-id",
			headers: bearerHeaders(), wantStatus: http.StatusAccepted,
		},
		{
			name: "complete runtime target retirement", method: http.MethodDelete,
			target:  "/api/v1/projects/test-id/runtime-targets/test-id",
			headers: bearerHeaders(), wantStatus: http.StatusNoContent,
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
	assertContractResponseDoesNotEchoSecrets(t, body, headers, recorder)
	return route.Operation.OperationID
}

func assertContractResponseDoesNotEchoSecrets(
	t *testing.T,
	requestBody []byte,
	requestHeaders map[string]string,
	response *httptest.ResponseRecorder,
) {
	t.Helper()
	requestMaterial := string(requestBody)
	for name, value := range requestHeaders {
		requestMaterial += "\n" + name + ": " + value
	}
	responseMaterial := response.Body.String()
	for name, values := range response.Header() {
		responseMaterial += "\n" + name + ": " + fmt.Sprint(values)
	}
	for _, sentinel := range []string{
		"bootstrap-secret",
		"long-enough-password",
		"member-long-password",
		"secret://registry-password",
		"secret://git-token",
		"secret://github-hook",
		"secret://docker",
		"secret://database-url",
		"contract-build-trigger-token-01234567890123",
		"sha256=contract",
		contractInvitationToken,
		"one-time-ticket",
	} {
		if strings.Contains(requestMaterial, sentinel) && strings.Contains(responseMaterial, sentinel) {
			t.Fatalf("response echoed request secret sentinel %q", sentinel)
		}
	}
}

func bearerHeaders() map[string]string {
	return map[string]string{"Authorization": "Bearer " + contractAccessToken}
}

func idempotencyHeaders() map[string]string {
	headers := bearerHeaders()
	headers["Idempotency-Key"] = "contract-request-1"
	return headers
}

func terminalHeaders() map[string]string {
	headers := bearerHeaders()
	headers["User-Agent"] = "OwnDock-Contract/1.0"
	return headers
}
