package service

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/modules/controlplane/biz"
	"github.com/owndock/owndock/internal/platform/httpx"
	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/runtimespec"
	"github.com/owndock/owndock/internal/shared/security"
)

type HTTP struct {
	useCase *biz.UseCase
}

func NewHTTP(useCase *biz.UseCase) *HTTP {
	return &HTTP{useCase: useCase}
}

func (s *HTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.Handle(w, r)
}

func (s *HTTP) Handle(w http.ResponseWriter, r *http.Request) {
	principal, ok := security.PrincipalFromContext(r.Context())
	if !ok {
		writeError(w, r, security.ErrUnauthenticated)
		return
	}
	segments := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(segments) == 3 && segments[0] == "api" && segments[1] == "v1" && segments[2] == "projects" {
		s.projects(w, r, principal)
		return
	}
	if len(segments) == 3 && segments[0] == "api" && segments[1] == "v1" && segments[2] == "audit-events" {
		s.auditEvents(w, r, principal)
		return
	}
	if len(segments) >= 5 && segments[0] == "api" && segments[1] == "v1" && segments[2] == "projects" {
		projectID := segments[3]
		switch {
		case len(segments) == 5 && segments[4] == "applications":
			s.applications(w, r, principal, projectID)
			return
		case len(segments) == 7 && segments[4] == "applications" && segments[6] == "releases":
			s.releases(w, r, principal, projectID, segments[5])
			return
		case len(segments) == 5 && segments[4] == "runtime-targets":
			s.runtimeTargets(w, r, principal, projectID)
			return
		case len(segments) == 7 && segments[4] == "runtime-targets" && segments[6] == "probe":
			s.probeRuntimeTarget(w, r, principal, projectID, segments[5])
			return
		case len(segments) == 5 && segments[4] == "registry-credentials":
			s.registryCredentials(w, r, principal, projectID)
			return
		case len(segments) == 5 && segments[4] == "environments":
			s.environments(w, r, principal, projectID)
			return
		}
	}
	httpx.ErrorRequest(w, r, http.StatusNotFound, "not_found")
}

func (s *HTTP) probeRuntimeTarget(
	w http.ResponseWriter,
	r *http.Request,
	principal security.Principal,
	projectID, targetID string,
) {
	if r.Method != http.MethodPost {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	item, err := s.useCase.ProbeRuntimeTarget(
		r.Context(), principal, projectID, targetID,
		httpx.RequestIDFromContext(r.Context()),
	)
	if writeError(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, runtimeTargetResponseFromDomain(item))
}

func (s *HTTP) projects(w http.ResponseWriter, r *http.Request, principal security.Principal) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.useCase.ListProjects(r.Context(), principal)
		if writeError(w, r, err) {
			return
		}
		responses := make([]projectResponse, len(items))
		for i, item := range items {
			responses[i] = projectResponseFromDomain(item)
		}
		httpx.JSON(w, http.StatusOK, map[string]any{"items": responses})
	case http.MethodPost:
		var request struct {
			Name string `json:"name"`
		}
		if !decodeRequest(w, r, &request) {
			return
		}
		item, err := s.useCase.CreateProject(
			r.Context(), principal, request.Name, httpx.RequestIDFromContext(r.Context()),
		)
		if writeError(w, r, err) {
			return
		}
		httpx.JSON(w, http.StatusCreated, projectResponseFromDomain(item))
	default:
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func (s *HTTP) applications(
	w http.ResponseWriter,
	r *http.Request,
	principal security.Principal,
	projectID string,
) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.useCase.ListApplications(r.Context(), principal, projectID)
		if writeError(w, r, err) {
			return
		}
		responses := make([]applicationResponse, len(items))
		for i, item := range items {
			responses[i] = applicationResponseFromDomain(item)
		}
		httpx.JSON(w, http.StatusOK, map[string]any{"items": responses})
	case http.MethodPost:
		var request struct {
			Name string `json:"name"`
		}
		if !decodeRequest(w, r, &request) {
			return
		}
		item, err := s.useCase.CreateApplication(
			r.Context(), principal, projectID, request.Name, httpx.RequestIDFromContext(r.Context()),
		)
		if writeError(w, r, err) {
			return
		}
		httpx.JSON(w, http.StatusCreated, applicationResponseFromDomain(item))
	default:
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func (s *HTTP) releases(
	w http.ResponseWriter,
	r *http.Request,
	principal security.Principal,
	projectID, applicationID string,
) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.useCase.ListReleases(r.Context(), principal, projectID, applicationID)
		if writeError(w, r, err) {
			return
		}
		responses := make([]releaseResponse, len(items))
		for i, item := range items {
			responses[i] = releaseResponseFromDomain(item)
		}
		httpx.JSON(w, http.StatusOK, map[string]any{"items": responses})
	case http.MethodPost:
		var request struct {
			Image                string             `json:"image"`
			RegistryCredentialID string             `json:"registry_credential_id"`
			RuntimeSpec          runtimeSpecPayload `json:"runtime_spec"`
		}
		if !decodeRequest(w, r, &request) {
			return
		}
		item, err := s.useCase.CreateReleaseWithRuntimeSpec(
			r.Context(), principal, projectID, applicationID, request.Image,
			request.RegistryCredentialID,
			request.RuntimeSpec.domain(),
			httpx.RequestIDFromContext(r.Context()),
		)
		if writeError(w, r, err) {
			return
		}
		httpx.JSON(w, http.StatusCreated, releaseResponseFromDomain(item))
	default:
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func (s *HTTP) registryCredentials(
	w http.ResponseWriter,
	r *http.Request,
	principal security.Principal,
	projectID string,
) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.useCase.ListRegistryCredentials(r.Context(), principal, projectID)
		if writeError(w, r, err) {
			return
		}
		responses := make([]registryCredentialResponse, len(items))
		for i, item := range items {
			responses[i] = registryCredentialResponseFromDomain(item)
		}
		httpx.JSON(w, http.StatusOK, map[string]any{"items": responses})
	case http.MethodPost:
		var request struct {
			Name        string `json:"name"`
			Server      string `json:"server"`
			Username    string `json:"username"`
			PasswordRef string `json:"password_ref"`
		}
		if !decodeRequest(w, r, &request) {
			return
		}
		item, err := s.useCase.CreateRegistryCredential(
			r.Context(), principal, projectID,
			request.Name, request.Server, request.Username, request.PasswordRef,
			httpx.RequestIDFromContext(r.Context()),
		)
		if writeError(w, r, err) {
			return
		}
		httpx.JSON(w, http.StatusCreated, registryCredentialResponseFromDomain(item))
	default:
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func (s *HTTP) runtimeTargets(
	w http.ResponseWriter,
	r *http.Request,
	principal security.Principal,
	projectID string,
) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.useCase.ListRuntimeTargets(r.Context(), principal, projectID)
		if writeError(w, r, err) {
			return
		}
		responses := make([]runtimeTargetResponse, len(items))
		for i, item := range items {
			responses[i] = runtimeTargetResponseFromDomain(item)
		}
		httpx.JSON(w, http.StatusOK, map[string]any{"items": responses})
	case http.MethodPost:
		var request struct {
			Name           string             `json:"name"`
			ManagedHostID  string             `json:"managed_host_id"`
			ConnectionMode runtimeaccess.Mode `json:"connection_mode"`
			Endpoint       string             `json:"endpoint"`
			TLSServerName  string             `json:"tls_server_name"`
			CredentialRef  string             `json:"credential_ref"`
		}
		if !decodeRequest(w, r, &request) {
			return
		}
		item, err := s.useCase.CreateRuntimeTarget(
			r.Context(), principal, projectID,
			request.Name, request.ManagedHostID, request.ConnectionMode,
			request.Endpoint, request.TLSServerName, request.CredentialRef,
			httpx.RequestIDFromContext(r.Context()),
		)
		if writeError(w, r, err) {
			return
		}
		httpx.JSON(w, http.StatusCreated, runtimeTargetResponseFromDomain(item))
	default:
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func (s *HTTP) environments(w http.ResponseWriter, r *http.Request, principal security.Principal, projectID string) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.useCase.ListEnvironments(r.Context(), principal, projectID)
		if writeError(w, r, err) {
			return
		}
		responses := make([]environmentResponse, len(items))
		for i, item := range items {
			responses[i] = environmentResponseFromDomain(item)
		}
		httpx.JSON(w, http.StatusOK, map[string]any{"items": responses})
	case http.MethodPost:
		var request struct {
			Name      string            `json:"name"`
			Stage     string            `json:"stage"`
			Variables map[string]string `json:"variables"`
		}
		if !decodeRequest(w, r, &request) {
			return
		}
		item, err := s.useCase.CreateEnvironmentWithVariables(
			r.Context(), principal, projectID, request.Name, request.Stage, request.Variables,
			httpx.RequestIDFromContext(r.Context()),
		)
		if writeError(w, r, err) {
			return
		}
		httpx.JSON(w, http.StatusCreated, environmentResponseFromDomain(item))
	default:
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func (s *HTTP) auditEvents(w http.ResponseWriter, r *http.Request, principal security.Principal) {
	if r.Method != http.MethodGet {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	var limit int64 = 100
	if rawLimit := r.URL.Query().Get("limit"); rawLimit != "" {
		parsed, err := strconv.ParseInt(rawLimit, 10, 64)
		if err != nil || parsed < 1 || parsed > 100 {
			httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_limit")
			return
		}
		limit = parsed
	}
	items, err := s.useCase.ListAuditEvents(r.Context(), principal, r.URL.Query().Get("project_id"), limit)
	if writeError(w, r, err) {
		return
	}
	responses := make([]auditResponse, len(items))
	for i, item := range items {
		responses[i] = auditResponseFromDomain(item)
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": responses})
}

func decodeRequest(w http.ResponseWriter, r *http.Request, target any) bool {
	if err := httpx.DecodeJSON(w, r, target); errors.Is(err, httpx.ErrUnsupportedMediaType) {
		httpx.ErrorRequest(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return false
	} else if err != nil {
		httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_json")
		return false
	}
	return true
}

func writeError(w http.ResponseWriter, r *http.Request, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, security.ErrUnauthenticated):
		w.Header().Set("WWW-Authenticate", "Bearer")
		httpx.ErrorRequest(w, r, http.StatusUnauthorized, "unauthenticated")
	case errors.Is(err, security.ErrForbidden):
		httpx.ErrorRequest(w, r, http.StatusForbidden, "forbidden")
	case errors.Is(err, biz.ErrNotFound):
		httpx.ErrorRequest(w, r, http.StatusNotFound, "not_found")
	case errors.Is(err, biz.ErrDuplicateName):
		httpx.ErrorRequest(w, r, http.StatusConflict, "name_conflict")
	case errors.Is(err, biz.ErrDuplicateRelease):
		httpx.ErrorRequest(w, r, http.StatusConflict, "release_conflict")
	case errors.Is(err, biz.ErrInvalidImage):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_image")
	case errors.Is(err, biz.ErrInvalidRuntimeTarget):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_runtime_target")
	case errors.Is(err, biz.ErrManagedHostNotFound):
		httpx.ErrorRequest(w, r, http.StatusNotFound, "managed_host_not_found")
	case errors.Is(err, biz.ErrRuntimeTargetHostMismatch):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "runtime_target_host_mismatch")
	case errors.Is(err, biz.ErrRuntimeTargetProbeUnavailable):
		httpx.ErrorRequest(w, r, http.StatusConflict, "runtime_target_probe_unavailable")
	case errors.Is(err, biz.ErrInvalidRegistry):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_registry_credential")
	case errors.Is(err, biz.ErrInvalidRuntimeSpec):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_runtime_spec")
	case errors.Is(err, biz.ErrInvalidName):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_name")
	default:
		httpx.ErrorRequest(w, r, http.StatusInternalServerError, "internal_error")
	}
	return true
}

type projectResponse struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	Name           string    `json:"name"`
	CreatedBy      string    `json:"created_by"`
	CreatedAt      time.Time `json:"created_at"`
}

func projectResponseFromDomain(item biz.Project) projectResponse {
	return projectResponse{
		ID: item.ID, OrganizationID: item.OrganizationID, Name: item.Name,
		CreatedBy: item.CreatedBy, CreatedAt: item.CreatedAt,
	}
}

type applicationResponse struct {
	ID        string    `json:"id"`
	ProjectID string    `json:"project_id"`
	Name      string    `json:"name"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

func applicationResponseFromDomain(item biz.Application) applicationResponse {
	return applicationResponse{
		ID: item.ID, ProjectID: item.ProjectID, Name: item.Name,
		CreatedBy: item.CreatedBy, CreatedAt: item.CreatedAt,
	}
}

type releaseResponse struct {
	ID                   string             `json:"id"`
	ProjectID            string             `json:"project_id"`
	ApplicationID        string             `json:"application_id"`
	ImageDigest          string             `json:"image_digest"`
	RegistryCredentialID string             `json:"registry_credential_id,omitempty"`
	RuntimeSpec          runtimeSpecPayload `json:"runtime_spec"`
	CreatedBy            string             `json:"created_by"`
	CreatedAt            time.Time          `json:"created_at"`
}

func releaseResponseFromDomain(item biz.Release) releaseResponse {
	return releaseResponse{
		ID: item.ID, ProjectID: item.ProjectID, ApplicationID: item.ApplicationID,
		ImageDigest: item.ImageDigest, RegistryCredentialID: item.RegistryCredentialID,
		RuntimeSpec: runtimeSpecPayloadFromDomain(item.RuntimeSpec),
		CreatedBy:   item.CreatedBy, CreatedAt: item.CreatedAt,
	}
}

type registryCredentialResponse struct {
	ID          string    `json:"id"`
	ProjectID   string    `json:"project_id"`
	Name        string    `json:"name"`
	Server      string    `json:"server"`
	Username    string    `json:"username"`
	PasswordRef string    `json:"password_ref"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
}

func registryCredentialResponseFromDomain(item biz.RegistryCredential) registryCredentialResponse {
	return registryCredentialResponse{
		ID: item.ID, ProjectID: item.ProjectID, Name: item.Name,
		Server: item.Server, Username: item.Username, PasswordRef: item.PasswordRef,
		CreatedBy: item.CreatedBy, CreatedAt: item.CreatedAt,
	}
}

type runtimeTargetResponse struct {
	ID             string                  `json:"id"`
	ProjectID      string                  `json:"project_id"`
	Name           string                  `json:"name"`
	ManagedHostID  string                  `json:"managed_host_id"`
	ConnectionMode runtimeaccess.Mode      `json:"connection_mode"`
	Endpoint       string                  `json:"endpoint,omitempty"`
	TLSServerName  string                  `json:"tls_server_name,omitempty"`
	CredentialRef  string                  `json:"credential_ref,omitempty"`
	Status         biz.RuntimeTargetStatus `json:"status"`
	LastProbedAt   *time.Time              `json:"last_probed_at,omitempty"`
	CreatedBy      string                  `json:"created_by"`
	CreatedAt      time.Time               `json:"created_at"`
}

type environmentResponse struct {
	ID        string            `json:"id"`
	ProjectID string            `json:"project_id"`
	Name      string            `json:"name"`
	Stage     string            `json:"stage"`
	Variables map[string]string `json:"variables"`
	CreatedBy string            `json:"created_by"`
	CreatedAt time.Time         `json:"created_at"`
}

func environmentResponseFromDomain(item biz.Environment) environmentResponse {
	return environmentResponse{
		ID: item.ID, ProjectID: item.ProjectID, Name: item.Name, Stage: item.Stage,
		Variables: item.Variables,
		CreatedBy: item.CreatedBy, CreatedAt: item.CreatedAt,
	}
}

type runtimeSpecPayload struct {
	Ports           []runtimePortPayload `json:"ports"`
	EnvironmentKeys []string             `json:"environment_keys"`
	Resources       resourcePayload      `json:"resources"`
	HealthCheck     *healthCheckPayload  `json:"health_check,omitempty"`
}

type runtimePortPayload struct {
	Name          string `json:"name"`
	ContainerPort uint16 `json:"container_port"`
	Protocol      string `json:"protocol"`
}

type resourcePayload struct {
	CPUMilli    int64 `json:"cpu_milli"`
	MemoryBytes int64 `json:"memory_bytes"`
}

type healthCheckPayload struct {
	Command            []string `json:"command"`
	IntervalSeconds    int      `json:"interval_seconds"`
	TimeoutSeconds     int      `json:"timeout_seconds"`
	Retries            int      `json:"retries"`
	StartPeriodSeconds int      `json:"start_period_seconds"`
}

func (p runtimeSpecPayload) domain() runtimespec.Spec {
	ports := make([]runtimespec.Port, len(p.Ports))
	for i, port := range p.Ports {
		ports[i] = runtimespec.Port{
			Name: port.Name, ContainerPort: port.ContainerPort, Protocol: port.Protocol,
		}
	}
	spec := runtimespec.Spec{
		Ports: ports, EnvironmentKeys: p.EnvironmentKeys,
		Resources: runtimespec.Resources{
			CPUMilli: p.Resources.CPUMilli, MemoryBytes: p.Resources.MemoryBytes,
		},
	}
	if p.HealthCheck != nil {
		spec.HealthCheck = &runtimespec.HealthCheck{
			Command:            p.HealthCheck.Command,
			IntervalSeconds:    p.HealthCheck.IntervalSeconds,
			TimeoutSeconds:     p.HealthCheck.TimeoutSeconds,
			Retries:            p.HealthCheck.Retries,
			StartPeriodSeconds: p.HealthCheck.StartPeriodSeconds,
		}
	}
	return spec
}

func runtimeSpecPayloadFromDomain(spec runtimespec.Spec) runtimeSpecPayload {
	ports := make([]runtimePortPayload, len(spec.Ports))
	for i, port := range spec.Ports {
		ports[i] = runtimePortPayload{
			Name: port.Name, ContainerPort: port.ContainerPort, Protocol: port.Protocol,
		}
	}
	payload := runtimeSpecPayload{
		Ports: ports, EnvironmentKeys: append([]string{}, spec.EnvironmentKeys...),
		Resources: resourcePayload{
			CPUMilli: spec.Resources.CPUMilli, MemoryBytes: spec.Resources.MemoryBytes,
		},
	}
	if spec.HealthCheck != nil {
		payload.HealthCheck = &healthCheckPayload{
			Command:            spec.HealthCheck.Command,
			IntervalSeconds:    spec.HealthCheck.IntervalSeconds,
			TimeoutSeconds:     spec.HealthCheck.TimeoutSeconds,
			Retries:            spec.HealthCheck.Retries,
			StartPeriodSeconds: spec.HealthCheck.StartPeriodSeconds,
		}
	}
	return payload
}

func runtimeTargetResponseFromDomain(item biz.RuntimeTarget) runtimeTargetResponse {
	var lastProbedAt *time.Time
	if !item.LastProbedAt.IsZero() {
		value := item.LastProbedAt
		lastProbedAt = &value
	}
	return runtimeTargetResponse{
		ID: item.ID, ProjectID: item.ProjectID, Name: item.Name,
		ManagedHostID: item.ManagedHostID, ConnectionMode: item.ConnectionMode,
		Endpoint:      item.Endpoint,
		TLSServerName: item.TLSServerName, CredentialRef: item.CredentialRef,
		Status: item.Status, LastProbedAt: lastProbedAt,
		CreatedBy: item.CreatedBy, CreatedAt: item.CreatedAt,
	}
}

type auditResponse struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	ProjectID      string    `json:"project_id,omitempty"`
	ActorID        string    `json:"actor_id"`
	Action         string    `json:"action"`
	ResourceType   string    `json:"resource_type"`
	ResourceID     string    `json:"resource_id"`
	RequestID      string    `json:"request_id,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

func auditResponseFromDomain(item sharedaudit.Event) auditResponse {
	return auditResponse{
		ID: item.ID, OrganizationID: item.OrganizationID, ProjectID: item.ProjectID,
		ActorID: item.ActorID, Action: item.Action, ResourceType: item.ResourceType,
		ResourceID: item.ResourceID, RequestID: item.RequestID, CreatedAt: item.CreatedAt,
	}
}
