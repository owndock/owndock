package biz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path"
	"slices"
	"strings"
	"time"
	"unicode"
)

const (
	CurrentSchemaVersion = 1
	MaxResourcesPerChunk = 500
	MaxObservationChunks = 10_000
	MaxObservationItems  = 100_000
)

var (
	ErrConflict           = errors.New("runtime inventory conflict")
	ErrInvalidChunk       = errors.New("runtime inventory chunk is invalid")
	ErrInvalidObservation = errors.New("runtime inventory observation is invalid")
	ErrInvalidResource    = errors.New("runtime inventory resource is invalid")
	ErrNotFound           = errors.New("runtime inventory was not found")
)

type Kind string

const (
	KindContainer Kind = "container"
	KindImage     Kind = "image"
	KindNetwork   Kind = "network"
	KindVolume    Kind = "volume"
)

func (k Kind) Valid() bool {
	switch k {
	case KindContainer, KindImage, KindNetwork, KindVolume:
		return true
	default:
		return false
	}
}

type ObservationStatus string

const (
	ObservationOpen     ObservationStatus = "open"
	ObservationComplete ObservationStatus = "complete"
)

type Observation struct {
	ID                string
	OrganizationID    string
	ManagedHostID     string
	RuntimeTargetID   string
	ExpectedChunks    int
	ExpectedResources int
	ReceivedChunks    int
	ReceivedResources int
	Status            ObservationStatus
	StartedAt         time.Time
	CompletedAt       time.Time
}

func NewObservation(
	id, organizationID, managedHostID, runtimeTargetID string,
	expectedChunks, expectedResources int,
	startedAt time.Time,
) (Observation, error) {
	if !validID(id) || !validID(organizationID) || !validID(managedHostID) ||
		!validID(runtimeTargetID) || startedAt.IsZero() ||
		expectedChunks < 0 || expectedChunks > MaxObservationChunks ||
		expectedResources < 0 || expectedResources > MaxObservationItems ||
		(expectedResources == 0 && expectedChunks != 0) ||
		(expectedResources > 0 && expectedChunks == 0) ||
		expectedResources > expectedChunks*MaxResourcesPerChunk {
		return Observation{}, ErrInvalidObservation
	}
	return Observation{
		ID:                strings.TrimSpace(id),
		OrganizationID:    strings.TrimSpace(organizationID),
		ManagedHostID:     strings.TrimSpace(managedHostID),
		RuntimeTargetID:   strings.TrimSpace(runtimeTargetID),
		ExpectedChunks:    expectedChunks,
		ExpectedResources: expectedResources,
		Status:            ObservationOpen,
		StartedAt:         startedAt.UTC(),
	}, nil
}

type ContainerSummary struct {
	ImageReference string
	ImageDigest    string
	State          string
	Health         string
	ExitCode       int
	OOMKilled      bool
	CreatedAt      time.Time
	StartedAt      time.Time
}

type ImageSummary struct {
	RepoTags     []string
	RepoDigests  []string
	SizeBytes    int64
	OS           string
	Architecture string
	CreatedAt    time.Time
}

type NetworkSummary struct {
	Driver     string
	Scope      string
	Internal   bool
	Attachable bool
	Ingress    bool
	EnableIPv4 bool
	EnableIPv6 bool
	IPAM       []IPAMConfig
}

type VolumeSummary struct {
	Driver     string
	Scope      string
	InUse      bool
	UsageKnown bool
	CreatedAt  time.Time
}

type IPAMConfig struct {
	Subnet  string
	IPRange string
	Gateway string
}

type Port struct {
	Name          string
	ContainerPort uint16
	HostIP        string
	HostPort      uint16
	Protocol      string
}

type Mount struct {
	Name        string
	Type        string
	Destination string
	ReadOnly    bool
}

type NetworkAttachment struct {
	NetworkID string
	Name      string
	Driver    string
	IPAddress string
	Gateway   string
	MAC       string
}

// Resource is an OwnDock projection of a Docker object. It deliberately has
// no raw Inspect, environment values, registry authorization or host source
// path field.
type Resource struct {
	ObservationID   string
	OrganizationID  string
	ManagedHostID   string
	RuntimeTargetID string
	Kind            Kind
	RuntimeID       string
	Name            string
	Managed         bool
	ProjectID       string
	DeploymentID    string
	Container       *ContainerSummary
	Image           *ImageSummary
	Network         *NetworkSummary
	Volume          *VolumeSummary
	Labels          map[string]string
	Attributes      map[string]string
	Ports           []Port
	Mounts          []Mount
	Networks        []NetworkAttachment
	ObservedAt      time.Time
	SchemaVersion   int
}

func NewResource(
	observation Observation,
	kind Kind,
	runtimeID, name string,
	observedAt time.Time,
) (Resource, error) {
	if observation.Status != ObservationOpen || !kind.Valid() ||
		!validRuntimeID(runtimeID) || !validText(name, 256) ||
		observedAt.IsZero() {
		return Resource{}, ErrInvalidResource
	}
	return Resource{
		ObservationID:   observation.ID,
		OrganizationID:  observation.OrganizationID,
		ManagedHostID:   observation.ManagedHostID,
		RuntimeTargetID: observation.RuntimeTargetID,
		Kind:            kind,
		RuntimeID:       strings.TrimSpace(runtimeID),
		Name:            strings.TrimSpace(name),
		Labels:          map[string]string{},
		Attributes:      map[string]string{},
		Ports:           []Port{},
		Mounts:          []Mount{},
		Networks:        []NetworkAttachment{},
		ObservedAt:      observedAt.UTC(),
		SchemaVersion:   CurrentSchemaVersion,
	}, nil
}

func (r Resource) Validate() error {
	if !validID(r.ObservationID) || !validID(r.OrganizationID) ||
		!validID(r.ManagedHostID) || !validID(r.RuntimeTargetID) ||
		!r.Kind.Valid() || !validRuntimeID(r.RuntimeID) ||
		!validText(r.Name, 256) || r.ObservedAt.IsZero() ||
		r.SchemaVersion != CurrentSchemaVersion {
		return ErrInvalidResource
	}
	if r.Managed && !validID(r.ProjectID) {
		return ErrInvalidResource
	}
	if r.DeploymentID != "" &&
		(r.Kind != KindContainer || !r.Managed || !validID(r.DeploymentID)) {
		return ErrInvalidResource
	}
	summaryCount := 0
	for _, present := range []bool{
		r.Container != nil, r.Image != nil, r.Network != nil, r.Volume != nil,
	} {
		if present {
			summaryCount++
		}
	}
	if summaryCount != 1 ||
		(r.Kind == KindContainer) != (r.Container != nil) ||
		(r.Kind == KindImage) != (r.Image != nil) ||
		(r.Kind == KindNetwork) != (r.Network != nil) ||
		(r.Kind == KindVolume) != (r.Volume != nil) {
		return ErrInvalidResource
	}
	if err := validateMetadata(r.Labels, 64, 128, 512); err != nil {
		return err
	}
	if err := validateMetadata(r.Attributes, 64, 128, 1024); err != nil {
		return err
	}
	if len(r.Ports) > 128 || len(r.Mounts) > 128 || len(r.Networks) > 64 {
		return ErrInvalidResource
	}
	for _, item := range r.Ports {
		if err := item.validate(); err != nil {
			return err
		}
	}
	for _, item := range r.Mounts {
		if err := item.validate(); err != nil {
			return err
		}
	}
	for _, item := range r.Networks {
		if err := item.validate(); err != nil {
			return err
		}
	}
	return validateSummary(r)
}

type Chunk struct {
	ObservationID string
	Index         int
	Digest        string
	Resources     []Resource
}

func NewChunk(observation Observation, index int, resources []Resource) (Chunk, error) {
	if observation.Status != ObservationOpen || index < 0 ||
		index >= observation.ExpectedChunks || len(resources) == 0 ||
		len(resources) > MaxResourcesPerChunk {
		return Chunk{}, ErrInvalidChunk
	}
	copied := append([]Resource(nil), resources...)
	seen := make(map[string]struct{}, len(copied))
	for _, item := range copied {
		if err := item.Validate(); err != nil ||
			item.ObservationID != observation.ID ||
			item.OrganizationID != observation.OrganizationID ||
			item.ManagedHostID != observation.ManagedHostID ||
			item.RuntimeTargetID != observation.RuntimeTargetID {
			return Chunk{}, ErrInvalidChunk
		}
		key := string(item.Kind) + "\x00" + item.RuntimeID
		if _, exists := seen[key]; exists {
			return Chunk{}, ErrInvalidChunk
		}
		seen[key] = struct{}{}
	}
	digest, err := chunkDigest(index, copied)
	if err != nil {
		return Chunk{}, ErrInvalidChunk
	}
	return Chunk{
		ObservationID: observation.ID,
		Index:         index, Digest: digest, Resources: copied,
	}, nil
}

func (c Chunk) Validate() error {
	if !validID(c.ObservationID) || c.Index < 0 ||
		len(c.Resources) == 0 || len(c.Resources) > MaxResourcesPerChunk ||
		len(c.Digest) != sha256.Size*2 {
		return ErrInvalidChunk
	}
	if _, err := hex.DecodeString(c.Digest); err != nil {
		return ErrInvalidChunk
	}
	expected, err := chunkDigest(c.Index, c.Resources)
	if err != nil || expected != c.Digest {
		return ErrInvalidChunk
	}
	for _, item := range c.Resources {
		if item.ObservationID != c.ObservationID {
			return ErrInvalidChunk
		}
		if err := item.Validate(); err != nil {
			return ErrInvalidChunk
		}
	}
	return nil
}

type Query struct {
	OrganizationID  string
	RuntimeTargetID string
	Kind            Kind
}

// Presence describes whether the latest complete observation still contains
// a runtime object. An incomplete observation can never change this value.
type Presence string

const (
	PresencePresent Presence = "present"
	PresenceAbsent  Presence = "absent"
)

func (p Presence) Valid() bool {
	return p == PresencePresent || p == PresenceAbsent
}

// State is the materialized current view of a runtime object. Resource keeps
// the last safe Docker projection, including after the object becomes absent,
// so callers can explain what disappeared without retaining raw Inspect data.
type State struct {
	Resource
	Presence     Presence
	FirstSeenAt  time.Time
	LastSeenAt   time.Time
	AbsentAt     time.Time
	ReconciledAt time.Time
	Generation   uint64
}

func (s State) Validate() error {
	if err := s.Resource.Validate(); err != nil || !s.Presence.Valid() ||
		s.FirstSeenAt.IsZero() || s.LastSeenAt.Before(s.FirstSeenAt) ||
		s.ReconciledAt.Before(s.LastSeenAt) || s.Generation == 0 {
		return ErrInvalidResource
	}
	if (s.Presence == PresencePresent && !s.AbsentAt.IsZero()) ||
		(s.Presence == PresenceAbsent &&
			(s.AbsentAt.IsZero() || s.AbsentAt.Before(s.LastSeenAt) ||
				s.ReconciledAt.Before(s.AbsentAt))) {
		return ErrInvalidResource
	}
	return nil
}

type StateQuery struct {
	OrganizationID  string
	RuntimeTargetID string
	Kind            Kind
	IncludeAbsent   bool
}

type Repository interface {
	Begin(context.Context, Observation) error
	Append(context.Context, Chunk) error
	Complete(context.Context, string, string, time.Time) error
	Current(context.Context, Query) ([]Resource, error)
}

// StateRepository exposes explicit presence without widening the ingestion
// contract used by collectors and Agent reconnect tests.
type StateRepository interface {
	Repository
	CurrentState(context.Context, StateQuery) ([]State, error)
}

func chunkDigest(index int, resources []Resource) (string, error) {
	payload, err := json.Marshal(struct {
		Index     int
		Resources []Resource
	}{Index: index, Resources: resources})
	if err != nil {
		return "", fmt.Errorf("marshal runtime inventory chunk: %w", err)
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func validateSummary(resource Resource) error {
	switch resource.Kind {
	case KindContainer:
		item := resource.Container
		if !validOptionalText(item.ImageReference, 512) ||
			!validOptionalText(item.ImageDigest, 512) ||
			!validOptionalText(item.State, 64) ||
			!validOptionalText(item.Health, 64) {
			return ErrInvalidResource
		}
	case KindImage:
		item := resource.Image
		if item.SizeBytes < 0 || !validOptionalText(item.OS, 64) ||
			!validOptionalText(item.Architecture, 64) ||
			len(item.RepoTags) > 128 || len(item.RepoDigests) > 128 {
			return ErrInvalidResource
		}
		for _, value := range append(
			append([]string(nil), item.RepoTags...),
			item.RepoDigests...,
		) {
			if !validText(value, 512) || strings.Contains(value, "://") {
				return ErrInvalidResource
			}
		}
	case KindNetwork:
		if !validOptionalText(resource.Network.Driver, 128) ||
			!validOptionalText(resource.Network.Scope, 64) ||
			len(resource.Network.IPAM) > 64 {
			return ErrInvalidResource
		}
		for _, item := range resource.Network.IPAM {
			if err := item.validate(); err != nil {
				return err
			}
		}
	case KindVolume:
		if !validOptionalText(resource.Volume.Driver, 128) ||
			!validOptionalText(resource.Volume.Scope, 64) {
			return ErrInvalidResource
		}
	}
	return nil
}

func (i IPAMConfig) validate() error {
	for _, prefix := range []string{i.Subnet, i.IPRange} {
		if prefix == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(prefix); err != nil {
			return ErrInvalidResource
		}
	}
	if i.Gateway != "" && net.ParseIP(i.Gateway) == nil {
		return ErrInvalidResource
	}
	return nil
}

func (p Port) validate() error {
	if p.ContainerPort == 0 || !validOptionalText(p.Name, 64) {
		return ErrInvalidResource
	}
	switch strings.ToLower(strings.TrimSpace(p.Protocol)) {
	case "tcp", "udp", "sctp":
	default:
		return ErrInvalidResource
	}
	if p.HostIP != "" && net.ParseIP(p.HostIP) == nil {
		return ErrInvalidResource
	}
	return nil
}

func (m Mount) validate() error {
	destination := strings.TrimSpace(m.Destination)
	if !validOptionalText(m.Name, 128) ||
		!slices.Contains([]string{"bind", "volume", "tmpfs"}, m.Type) ||
		destination == "" || !strings.HasPrefix(destination, "/") ||
		path.Clean(destination) != destination || len(destination) > 512 {
		return ErrInvalidResource
	}
	return nil
}

func (n NetworkAttachment) validate() error {
	if !validOptionalText(n.NetworkID, 256) ||
		!validOptionalText(n.Name, 256) ||
		!validOptionalText(n.Driver, 128) {
		return ErrInvalidResource
	}
	for _, address := range []string{n.IPAddress, n.Gateway} {
		if address != "" && net.ParseIP(address) == nil {
			return ErrInvalidResource
		}
	}
	if n.MAC != "" {
		if _, err := net.ParseMAC(n.MAC); err != nil {
			return ErrInvalidResource
		}
	}
	return nil
}

func validateMetadata(
	values map[string]string,
	maxEntries, maxKeyLength, maxValueLength int,
) error {
	if len(values) > maxEntries {
		return ErrInvalidResource
	}
	for key, value := range values {
		if !validText(key, maxKeyLength) ||
			!validOptionalText(value, maxValueLength) ||
			forbiddenMetadataKey(key) {
			return ErrInvalidResource
		}
	}
	return nil
}

func forbiddenMetadataKey(value string) bool {
	var normalized strings.Builder
	for _, character := range strings.ToLower(value) {
		if unicode.IsLetter(character) || unicode.IsDigit(character) {
			normalized.WriteRune(character)
		}
	}
	key := normalized.String()
	for _, forbidden := range []string{
		"authorization", "credential", "env", "environment", "password", "passwd",
		"privatekey", "registryauth", "secret", "token",
	} {
		if strings.Contains(key, forbidden) {
			return true
		}
	}
	return false
}

func validID(value string) bool {
	return validText(value, 160)
}

func validRuntimeID(value string) bool {
	return validText(value, 512)
}

func validText(value string, maximum int) bool {
	value = strings.TrimSpace(value)
	return value != "" && validOptionalText(value, maximum)
}

func validOptionalText(value string, maximum int) bool {
	return len(value) <= maximum && !strings.ContainsRune(value, '\x00')
}
