package service

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/modules/runtimeinventory/biz"
	"github.com/owndock/owndock/internal/platform/httpx"
	"github.com/owndock/owndock/internal/shared/security"
)

type HTTP struct {
	useCase *biz.ViewUseCase
}

func NewHTTP(useCase *biz.ViewUseCase) *HTTP {
	return &HTTP{useCase: useCase}
}

type statePageResponse struct {
	Items      []stateResponse `json:"items"`
	NextCursor string          `json:"next_cursor,omitempty"`
}

// stateResponse is intentionally separate from both the Mongo document and
// domain Resource. Internal labels and attributes never cross the public API.
type stateResponse struct {
	ObservationID   string                      `json:"observation_id"`
	OrganizationID  string                      `json:"organization_id"`
	ManagedHostID   string                      `json:"managed_host_id"`
	RuntimeTargetID string                      `json:"runtime_target_id"`
	Kind            biz.Kind                    `json:"kind"`
	RuntimeID       string                      `json:"runtime_id"`
	Name            string                      `json:"name"`
	Managed         bool                        `json:"managed"`
	ProjectID       string                      `json:"project_id,omitempty"`
	DeploymentID    string                      `json:"deployment_id,omitempty"`
	Container       *containerResponse          `json:"container,omitempty"`
	Image           *imageResponse              `json:"image,omitempty"`
	Network         *networkResponse            `json:"network,omitempty"`
	Volume          *volumeResponse             `json:"volume,omitempty"`
	Ports           []portResponse              `json:"ports"`
	Mounts          []mountResponse             `json:"mounts"`
	Networks        []networkAttachmentResponse `json:"networks"`
	ObservedAt      time.Time                   `json:"observed_at"`
	SchemaVersion   int                         `json:"schema_version"`
	Presence        biz.Presence                `json:"presence"`
	FirstSeenAt     time.Time                   `json:"first_seen_at"`
	LastSeenAt      time.Time                   `json:"last_seen_at"`
	AbsentAt        *time.Time                  `json:"absent_at,omitempty"`
	ReconciledAt    time.Time                   `json:"reconciled_at"`
	Generation      uint64                      `json:"generation"`
}

type containerResponse struct {
	ImageReference string     `json:"image_reference,omitempty"`
	ImageDigest    string     `json:"image_digest,omitempty"`
	State          string     `json:"state,omitempty"`
	Health         string     `json:"health,omitempty"`
	ExitCode       int        `json:"exit_code"`
	OOMKilled      bool       `json:"oom_killed"`
	CreatedAt      *time.Time `json:"created_at,omitempty"`
	StartedAt      *time.Time `json:"started_at,omitempty"`
}

type imageResponse struct {
	RepoTags     []string   `json:"repo_tags"`
	RepoDigests  []string   `json:"repo_digests"`
	SizeBytes    int64      `json:"size_bytes"`
	OS           string     `json:"os,omitempty"`
	Architecture string     `json:"architecture,omitempty"`
	CreatedAt    *time.Time `json:"created_at,omitempty"`
}

type networkResponse struct {
	Driver     string         `json:"driver,omitempty"`
	Scope      string         `json:"scope,omitempty"`
	Internal   bool           `json:"internal"`
	Attachable bool           `json:"attachable"`
	Ingress    bool           `json:"ingress"`
	EnableIPv4 bool           `json:"enable_ipv4"`
	EnableIPv6 bool           `json:"enable_ipv6"`
	IPAM       []ipamResponse `json:"ipam"`
}

type volumeResponse struct {
	Driver     string     `json:"driver,omitempty"`
	Scope      string     `json:"scope,omitempty"`
	InUse      bool       `json:"in_use"`
	UsageKnown bool       `json:"usage_known"`
	CreatedAt  *time.Time `json:"created_at,omitempty"`
}

type ipamResponse struct {
	Subnet  string `json:"subnet,omitempty"`
	IPRange string `json:"ip_range,omitempty"`
	Gateway string `json:"gateway,omitempty"`
}

type portResponse struct {
	Name          string `json:"name,omitempty"`
	ContainerPort uint16 `json:"container_port"`
	HostIP        string `json:"host_ip,omitempty"`
	HostPort      uint16 `json:"host_port"`
	Protocol      string `json:"protocol"`
}

type mountResponse struct {
	Name        string `json:"name,omitempty"`
	Type        string `json:"type"`
	Destination string `json:"destination"`
	ReadOnly    bool   `json:"read_only"`
}

type networkAttachmentResponse struct {
	NetworkID string `json:"network_id,omitempty"`
	Name      string `json:"name,omitempty"`
	Driver    string `json:"driver,omitempty"`
	IPAddress string `json:"ip_address,omitempty"`
	Gateway   string `json:"gateway,omitempty"`
	MAC       string `json:"mac,omitempty"`
}

func (s *HTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	principal, ok := security.PrincipalFromContext(r.Context())
	if !ok {
		httpx.ErrorRequest(w, r, http.StatusUnauthorized, "unauthenticated")
		return
	}
	segments := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(segments) != 5 || segments[0] != "api" || segments[1] != "v1" ||
		segments[3] == "" || segments[4] != "runtime-inventory" ||
		(segments[2] != "projects" && segments[2] != "managed-hosts") {
		httpx.ErrorRequest(w, r, http.StatusNotFound, "not_found")
		return
	}
	if r.Method != http.MethodGet {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	query, err := parseViewQuery(r)
	if err != nil {
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_runtime_inventory_query")
		return
	}
	if segments[2] == "projects" && query.Kind != "" &&
		query.Kind != biz.KindContainer {
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_runtime_inventory_query")
		return
	}
	var page biz.StatePage
	if segments[2] == "projects" {
		page, err = s.useCase.ListProject(
			r.Context(), principal, segments[3], query,
			httpx.RequestIDFromContext(r.Context()),
		)
	} else {
		page, err = s.useCase.ListHost(
			r.Context(), principal, segments[3], query,
			httpx.RequestIDFromContext(r.Context()),
		)
	}
	if writeError(w, r, err) {
		return
	}
	response := statePageResponse{
		Items: make([]stateResponse, len(page.Items)), NextCursor: page.NextCursor,
	}
	for index := range page.Items {
		response.Items[index] = toStateResponse(page.Items[index])
	}
	httpx.JSON(w, http.StatusOK, response)
}

func parseViewQuery(r *http.Request) (biz.ViewQuery, error) {
	values := r.URL.Query()
	allowed := map[string]bool{
		"runtime_target_id": true,
		"kind":              true,
		"include_absent":    true,
		"limit":             true,
		"cursor":            true,
	}
	for key, items := range values {
		if !allowed[key] || len(items) != 1 {
			return biz.ViewQuery{}, biz.ErrInvalidViewQuery
		}
	}
	query := biz.ViewQuery{
		RuntimeTargetID: values.Get("runtime_target_id"),
		Kind:            biz.Kind(values.Get("kind")),
		Cursor:          values.Get("cursor"),
	}
	if value := values.Get("include_absent"); value != "" {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return biz.ViewQuery{}, biz.ErrInvalidViewQuery
		}
		query.IncludeAbsent = parsed
	}
	if value := values.Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return biz.ViewQuery{}, biz.ErrInvalidViewQuery
		}
		query.Limit = parsed
	}
	return query, nil
}

func toStateResponse(state biz.State) stateResponse {
	response := stateResponse{
		ObservationID: state.ObservationID, OrganizationID: state.OrganizationID,
		ManagedHostID: state.ManagedHostID, RuntimeTargetID: state.RuntimeTargetID,
		Kind: state.Kind, RuntimeID: state.RuntimeID, Name: state.Name,
		Managed: state.Managed, ProjectID: state.ProjectID,
		DeploymentID: state.DeploymentID,
		Ports:        make([]portResponse, len(state.Ports)),
		Mounts:       make([]mountResponse, len(state.Mounts)),
		Networks:     make([]networkAttachmentResponse, len(state.Networks)),
		ObservedAt:   state.ObservedAt, SchemaVersion: state.SchemaVersion,
		Presence: state.Presence, FirstSeenAt: state.FirstSeenAt,
		LastSeenAt: state.LastSeenAt, ReconciledAt: state.ReconciledAt,
		Generation: state.Generation,
	}
	response.Container = toContainerResponse(state.Container)
	response.Image = toImageResponse(state.Image)
	response.Network = toNetworkResponse(state.Network)
	response.Volume = toVolumeResponse(state.Volume)
	for index, item := range state.Ports {
		response.Ports[index] = portResponse{
			Name: item.Name, ContainerPort: item.ContainerPort, HostIP: item.HostIP,
			HostPort: item.HostPort, Protocol: item.Protocol,
		}
	}
	for index, item := range state.Mounts {
		response.Mounts[index] = mountResponse{
			Name: item.Name, Type: item.Type, Destination: item.Destination,
			ReadOnly: item.ReadOnly,
		}
	}
	for index, item := range state.Networks {
		response.Networks[index] = networkAttachmentResponse{
			NetworkID: item.NetworkID, Name: item.Name, Driver: item.Driver,
			IPAddress: item.IPAddress, Gateway: item.Gateway, MAC: item.MAC,
		}
	}
	if !state.AbsentAt.IsZero() {
		absentAt := state.AbsentAt
		response.AbsentAt = &absentAt
	}
	return response
}

func optionalTime(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	copy := value
	return &copy
}

func toContainerResponse(item *biz.ContainerSummary) *containerResponse {
	if item == nil {
		return nil
	}
	return &containerResponse{
		ImageReference: item.ImageReference, ImageDigest: item.ImageDigest,
		State: item.State, Health: item.Health, ExitCode: item.ExitCode,
		OOMKilled: item.OOMKilled, CreatedAt: optionalTime(item.CreatedAt),
		StartedAt: optionalTime(item.StartedAt),
	}
}

func toImageResponse(item *biz.ImageSummary) *imageResponse {
	if item == nil {
		return nil
	}
	return &imageResponse{
		RepoTags:    append([]string{}, item.RepoTags...),
		RepoDigests: append([]string{}, item.RepoDigests...),
		SizeBytes:   item.SizeBytes, OS: item.OS, Architecture: item.Architecture,
		CreatedAt: optionalTime(item.CreatedAt),
	}
}

func toNetworkResponse(item *biz.NetworkSummary) *networkResponse {
	if item == nil {
		return nil
	}
	response := &networkResponse{
		Driver: item.Driver, Scope: item.Scope, Internal: item.Internal,
		Attachable: item.Attachable, Ingress: item.Ingress,
		EnableIPv4: item.EnableIPv4, EnableIPv6: item.EnableIPv6,
		IPAM: make([]ipamResponse, len(item.IPAM)),
	}
	for index, config := range item.IPAM {
		response.IPAM[index] = ipamResponse{
			Subnet: config.Subnet, IPRange: config.IPRange, Gateway: config.Gateway,
		}
	}
	return response
}

func toVolumeResponse(item *biz.VolumeSummary) *volumeResponse {
	if item == nil {
		return nil
	}
	return &volumeResponse{
		Driver: item.Driver, Scope: item.Scope, InUse: item.InUse,
		UsageKnown: item.UsageKnown, CreatedAt: optionalTime(item.CreatedAt),
	}
}

func writeError(w http.ResponseWriter, r *http.Request, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, security.ErrUnauthenticated):
		httpx.ErrorRequest(w, r, http.StatusUnauthorized, "unauthenticated")
	case errors.Is(err, security.ErrForbidden):
		httpx.ErrorRequest(w, r, http.StatusForbidden, "forbidden")
	case errors.Is(err, biz.ErrInvalidViewQuery):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_runtime_inventory_query")
	case errors.Is(err, biz.ErrNotFound):
		httpx.ErrorRequest(w, r, http.StatusNotFound, "runtime_inventory_scope_not_found")
	default:
		httpx.ErrorRequest(w, r, http.StatusInternalServerError, "internal_error")
	}
	return true
}
