// Package runtimeinventory defines the safe, Docker-SDK-independent payload
// exchanged by runtime collectors and the Server.
package runtimeinventory

import (
	"errors"
	"net"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	SchemaVersion        = 1
	MaxResources         = 100_000
	MaxResourcesPerChunk = 500
	MaxChunks            = 10_000
	MaxSnapshotBytes     = 64 * 1024 * 1024
	DefaultChunkBytes    = 48 * 1024
	MaxChunkBytes        = 512 * 1024
)

var (
	ErrInvalidResource  = errors.New("runtime inventory transport resource is invalid")
	ErrInvalidChunk     = errors.New("runtime inventory transport chunk is invalid")
	ErrSnapshotTooLarge = errors.New("runtime inventory snapshot exceeds the configured limit")
)

var ownershipLabelValue = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$`)

type Kind string

const (
	KindContainer Kind = "container"
	KindImage     Kind = "image"
	KindNetwork   Kind = "network"
	KindVolume    Kind = "volume"
)

func (k Kind) Valid() bool {
	return slices.Contains(
		[]Kind{KindContainer, KindImage, KindNetwork, KindVolume},
		k,
	)
}

type Resource struct {
	Kind          Kind                `json:"kind"`
	RuntimeID     string              `json:"runtime_id"`
	Name          string              `json:"name"`
	Container     *ContainerSummary   `json:"container,omitempty"`
	Image         *ImageSummary       `json:"image,omitempty"`
	Network       *NetworkSummary     `json:"network,omitempty"`
	Volume        *VolumeSummary      `json:"volume,omitempty"`
	Labels        map[string]string   `json:"labels,omitempty"`
	Ports         []Port              `json:"ports,omitempty"`
	Mounts        []Mount             `json:"mounts,omitempty"`
	Networks      []NetworkAttachment `json:"networks,omitempty"`
	ObservedAt    time.Time           `json:"observed_at"`
	SchemaVersion int                 `json:"schema_version"`
}

type ContainerSummary struct {
	ImageReference string    `json:"image_reference,omitempty"`
	ImageDigest    string    `json:"image_digest,omitempty"`
	State          string    `json:"state,omitempty"`
	Health         string    `json:"health,omitempty"`
	CreatedAt      time.Time `json:"created_at,omitempty"`
}

type ImageSummary struct {
	RepoTags    []string  `json:"repo_tags,omitempty"`
	RepoDigests []string  `json:"repo_digests,omitempty"`
	SizeBytes   int64     `json:"size_bytes"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
}

type NetworkSummary struct {
	Driver     string       `json:"driver,omitempty"`
	Scope      string       `json:"scope,omitempty"`
	Internal   bool         `json:"internal"`
	Attachable bool         `json:"attachable"`
	Ingress    bool         `json:"ingress"`
	EnableIPv4 bool         `json:"enable_ipv4"`
	EnableIPv6 bool         `json:"enable_ipv6"`
	IPAM       []IPAMConfig `json:"ipam,omitempty"`
}

type IPAMConfig struct {
	Subnet  string `json:"subnet,omitempty"`
	IPRange string `json:"ip_range,omitempty"`
	Gateway string `json:"gateway,omitempty"`
}

type VolumeSummary struct {
	Driver     string    `json:"driver,omitempty"`
	Scope      string    `json:"scope,omitempty"`
	InUse      bool      `json:"in_use"`
	UsageKnown bool      `json:"usage_known"`
	CreatedAt  time.Time `json:"created_at,omitempty"`
}

type Port struct {
	ContainerPort uint16 `json:"container_port"`
	HostIP        string `json:"host_ip,omitempty"`
	HostPort      uint16 `json:"host_port,omitempty"`
	Protocol      string `json:"protocol"`
}

type Mount struct {
	Name        string `json:"name,omitempty"`
	Type        string `json:"type"`
	Destination string `json:"destination"`
	ReadOnly    bool   `json:"read_only"`
}

type NetworkAttachment struct {
	NetworkID string `json:"network_id,omitempty"`
	Name      string `json:"name"`
	IPAddress string `json:"ip_address,omitempty"`
	Gateway   string `json:"gateway,omitempty"`
	MAC       string `json:"mac,omitempty"`
}

func (r Resource) Validate() error {
	if !r.Kind.Valid() || !validText(r.RuntimeID, 512) ||
		!validText(r.Name, 256) || r.ObservedAt.IsZero() ||
		r.SchemaVersion != SchemaVersion {
		return ErrInvalidResource
	}
	present := 0
	for _, value := range []bool{
		r.Container != nil, r.Image != nil, r.Network != nil, r.Volume != nil,
	} {
		if value {
			present++
		}
	}
	if present != 1 ||
		(r.Kind == KindContainer) != (r.Container != nil) ||
		(r.Kind == KindImage) != (r.Image != nil) ||
		(r.Kind == KindNetwork) != (r.Network != nil) ||
		(r.Kind == KindVolume) != (r.Volume != nil) ||
		len(r.Labels) > 16 || len(r.Ports) > 128 ||
		len(r.Mounts) > 128 || len(r.Networks) > 64 {
		return ErrInvalidResource
	}
	for key, value := range r.Labels {
		if !AllowedLabel(key) || !ownershipLabelValue.MatchString(value) {
			return ErrInvalidResource
		}
	}
	for _, item := range r.Ports {
		if item.ContainerPort == 0 ||
			!slices.Contains([]string{"tcp", "udp", "sctp"}, item.Protocol) ||
			(item.HostIP != "" && net.ParseIP(item.HostIP) == nil) {
			return ErrInvalidResource
		}
	}
	for _, item := range r.Mounts {
		destination := strings.TrimSpace(item.Destination)
		if !slices.Contains([]string{"bind", "volume", "tmpfs"}, item.Type) ||
			!validOptionalText(item.Name, 128) ||
			!strings.HasPrefix(destination, "/") ||
			path.Clean(destination) != destination ||
			len(destination) > 512 {
			return ErrInvalidResource
		}
	}
	for _, item := range r.Networks {
		if !validText(item.Name, 256) ||
			!validOptionalText(item.NetworkID, 256) ||
			(item.IPAddress != "" && net.ParseIP(item.IPAddress) == nil) ||
			(item.Gateway != "" && net.ParseIP(item.Gateway) == nil) {
			return ErrInvalidResource
		}
		if item.MAC != "" {
			if _, err := net.ParseMAC(item.MAC); err != nil {
				return ErrInvalidResource
			}
		}
	}
	return r.validateSummary()
}

func (r Resource) validateSummary() error {
	switch r.Kind {
	case KindContainer:
		if !validOptionalText(r.Container.ImageReference, 512) ||
			!validOptionalText(r.Container.ImageDigest, 512) ||
			!validOptionalText(r.Container.State, 64) ||
			!validOptionalText(r.Container.Health, 64) {
			return ErrInvalidResource
		}
	case KindImage:
		if r.Image.SizeBytes < 0 || len(r.Image.RepoTags) > 128 ||
			len(r.Image.RepoDigests) > 128 {
			return ErrInvalidResource
		}
		for _, value := range append(
			append([]string{}, r.Image.RepoTags...),
			r.Image.RepoDigests...,
		) {
			if !validText(value, 512) || strings.Contains(value, "://") {
				return ErrInvalidResource
			}
		}
	case KindNetwork:
		if !validOptionalText(r.Network.Driver, 128) ||
			!validOptionalText(r.Network.Scope, 64) ||
			len(r.Network.IPAM) > 64 {
			return ErrInvalidResource
		}
		for _, item := range r.Network.IPAM {
			for _, prefix := range []string{item.Subnet, item.IPRange} {
				if prefix == "" {
					continue
				}
				if _, _, err := net.ParseCIDR(prefix); err != nil {
					return ErrInvalidResource
				}
			}
			if item.Gateway != "" && net.ParseIP(item.Gateway) == nil {
				return ErrInvalidResource
			}
		}
	case KindVolume:
		if !validOptionalText(r.Volume.Driver, 128) ||
			!validOptionalText(r.Volume.Scope, 64) {
			return ErrInvalidResource
		}
	}
	return nil
}

// AllowedLabel is deliberately exact-match. Prefix allowlists would let a
// caller smuggle arbitrary data under a trusted namespace.
func AllowedLabel(key string) bool {
	switch key {
	case "net.owndock.project_id",
		"net.owndock.application_id",
		"net.owndock.deployment_id":
		return true
	default:
		return false
	}
}

func validText(value string, maximum int) bool {
	value = strings.TrimSpace(value)
	return value != "" && validOptionalText(value, maximum)
}

func validOptionalText(value string, maximum int) bool {
	return len(value) <= maximum && !strings.ContainsRune(value, '\x00')
}
