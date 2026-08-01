package agentprotocol

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"

	"github.com/owndock/owndock/internal/shared/runtimeinventory"
	"github.com/owndock/owndock/internal/shared/runtimespec"
)

var (
	ErrCommandInvalid = errors.New("agent command is invalid")
	ErrResultInvalid  = errors.New("agent command result is invalid")
)

const maximumCommandDocumentBytes = 60 * 1024

var (
	containerNameRule   = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,127}$`)
	environmentNameRule = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

type AgentCommandKind string

const (
	AgentCommandRuntimeProbe       AgentCommandKind = "runtime.probe"
	AgentCommandDeploymentPrepare  AgentCommandKind = "deployment.prepare"
	AgentCommandDeploymentStage    AgentCommandKind = "deployment.stage"
	AgentCommandDeploymentActivate AgentCommandKind = "deployment.activate"
	AgentCommandDeploymentCancel   AgentCommandKind = "deployment.cancel"
	AgentCommandInventoryPrepare   AgentCommandKind = "runtime.inventory.prepare"
	AgentCommandInventoryChunk     AgentCommandKind = "runtime.inventory.chunk"
	AgentCommandInventoryRelease   AgentCommandKind = "runtime.inventory.release"
	AgentCommandInventoryEvents    AgentCommandKind = "runtime.inventory.events"
)

func (k AgentCommandKind) Valid() bool {
	switch k {
	case AgentCommandRuntimeProbe,
		AgentCommandDeploymentPrepare,
		AgentCommandDeploymentStage,
		AgentCommandDeploymentActivate,
		AgentCommandDeploymentCancel,
		AgentCommandInventoryPrepare,
		AgentCommandInventoryChunk,
		AgentCommandInventoryRelease,
		AgentCommandInventoryEvents:
		return true
	default:
		return false
	}
}

type AgentCommand struct {
	ID           string
	Kind         AgentCommandKind
	Deadline     time.Time
	RuntimeProbe *RuntimeProbeCommand
	Deployment   *DeploymentCommand
	Inventory    *RuntimeInventoryCommand
}

type RuntimeProbeCommand struct {
	RuntimeTargetID string
}

type RuntimeInventoryCommand struct {
	RuntimeTargetID  string
	ObservationID    string
	MaxChunkBytes    int
	ChunkIndex       int
	EventSince       time.Time
	EventWaitSeconds int
}

// DeploymentCommand is an internal, versioned transport contract. Secret
// fields are present only for the operation that consumes them and must never
// be persisted; durable idempotency stores CommandFingerprint instead.
type DeploymentCommand struct {
	DeploymentID    string
	WorkerID        string
	FencingToken    uint64
	CutoverSequence uint64
	RuntimeTargetID string
	ContainerName   string

	ProjectID     string
	ApplicationID string
	EnvironmentID string
	ImageDigest   string

	RegistryAuthorization []byte
	RuntimeSpec           runtimespec.Spec
	Environment           []string
}

func (c AgentCommand) Validate() error {
	if !validIdentifier(c.ID) || c.Deadline.IsZero() || !c.Kind.Valid() {
		return ErrCommandInvalid
	}
	switch c.Kind {
	case AgentCommandRuntimeProbe:
		if c.Deployment != nil || c.Inventory != nil ||
			c.RuntimeProbe == nil ||
			!validIdentifier(c.RuntimeProbe.RuntimeTargetID) {
			return ErrCommandInvalid
		}
	case AgentCommandDeploymentPrepare,
		AgentCommandDeploymentStage,
		AgentCommandDeploymentActivate,
		AgentCommandDeploymentCancel:
		if c.RuntimeProbe != nil || c.Inventory != nil ||
			c.Deployment == nil ||
			!validDeploymentCommand(c.Kind, *c.Deployment) {
			return ErrCommandInvalid
		}
	case AgentCommandInventoryPrepare,
		AgentCommandInventoryChunk,
		AgentCommandInventoryRelease,
		AgentCommandInventoryEvents:
		if c.RuntimeProbe != nil || c.Deployment != nil ||
			c.Inventory == nil ||
			!validInventoryCommand(c.Kind, *c.Inventory) {
			return ErrCommandInvalid
		}
	default:
		return ErrCommandInvalid
	}
	encoded, err := json.Marshal(NewCommandDocument(c))
	if err != nil || len(encoded) > maximumCommandDocumentBytes {
		return ErrCommandInvalid
	}
	return nil
}

func (c AgentCommand) Equivalent(other AgentCommand) bool {
	left, leftErr := c.Fingerprint()
	right, rightErr := other.Fingerprint()
	return leftErr == nil && rightErr == nil && left == right
}

// Fingerprint produces a stable one-way identity for durable replay checks.
// It deliberately hashes secret-bearing fields instead of exposing them to the
// result-cache document.
func (c AgentCommand) Fingerprint() ([sha256.Size]byte, error) {
	if err := c.Validate(); err != nil {
		return [sha256.Size]byte{}, err
	}
	hasher := sha256.New()
	writeFingerprintString(hasher, "owndock-agent-command-v1")
	writeFingerprintString(hasher, c.ID)
	writeFingerprintString(hasher, string(c.Kind))
	writeFingerprintInt64(hasher, c.Deadline.UTC().Unix())
	writeFingerprintInt64(
		hasher,
		int64(c.Deadline.UTC().Nanosecond()),
	)
	if c.RuntimeProbe != nil {
		writeFingerprintString(hasher, c.RuntimeProbe.RuntimeTargetID)
	}
	if c.Deployment != nil {
		deployment := c.Deployment
		writeFingerprintString(hasher, deployment.DeploymentID)
		writeFingerprintString(hasher, deployment.WorkerID)
		writeFingerprintUint64(hasher, deployment.FencingToken)
		writeFingerprintUint64(hasher, deployment.CutoverSequence)
		writeFingerprintString(hasher, deployment.RuntimeTargetID)
		writeFingerprintString(hasher, deployment.ContainerName)
		writeFingerprintString(hasher, deployment.ProjectID)
		writeFingerprintString(hasher, deployment.ApplicationID)
		writeFingerprintString(hasher, deployment.EnvironmentID)
		writeFingerprintString(hasher, deployment.ImageDigest)
		writeFingerprintBytes(hasher, deployment.RegistryAuthorization)
		writeRuntimeSpecFingerprint(hasher, deployment.RuntimeSpec)
		writeFingerprintUint64(hasher, uint64(len(deployment.Environment)))
		for _, value := range deployment.Environment {
			writeFingerprintString(hasher, value)
		}
	}
	if c.Inventory != nil {
		writeFingerprintString(hasher, c.Inventory.RuntimeTargetID)
		writeFingerprintString(hasher, c.Inventory.ObservationID)
		writeFingerprintInt64(hasher, int64(c.Inventory.MaxChunkBytes))
		writeFingerprintInt64(hasher, int64(c.Inventory.ChunkIndex))
		writeFingerprintInt64(hasher, c.Inventory.EventSince.UTC().UnixNano())
		writeFingerprintInt64(hasher, int64(c.Inventory.EventWaitSeconds))
	}
	var fingerprint [sha256.Size]byte
	copy(fingerprint[:], hasher.Sum(nil))
	return fingerprint, nil
}

type AgentCommandStatus string

const (
	AgentCommandSucceeded AgentCommandStatus = "succeeded"
	AgentCommandFailed    AgentCommandStatus = "failed"
)

type RuntimeProbeStatus string

const (
	RuntimeProbeReady       RuntimeProbeStatus = "ready"
	RuntimeProbeUnreachable RuntimeProbeStatus = "unreachable"
	RuntimeProbeUnsupported RuntimeProbeStatus = "unsupported"
)

func (s RuntimeProbeStatus) Valid() bool {
	switch s {
	case RuntimeProbeReady, RuntimeProbeUnreachable, RuntimeProbeUnsupported:
		return true
	default:
		return false
	}
}

type AgentCommandResult struct {
	CommandID    string
	Status       AgentCommandStatus
	ErrorCode    string
	RuntimeProbe *RuntimeProbeResult
	Inventory    *RuntimeInventoryResult
}

type RuntimeProbeResult struct {
	Status RuntimeProbeStatus
}

type RuntimeInventoryResult struct {
	Manifest *RuntimeInventoryManifest
	Chunk    *runtimeinventory.Chunk
	Events   *runtimeinventory.EventBatch
}

type RuntimeInventoryManifest struct {
	ObservationID     string
	SchemaVersion     int
	ExpectedChunks    int
	ExpectedResources int
	RetentionSeconds  int
	Events            []runtimeinventory.Event
	EventsTruncated   bool
}

func (r AgentCommandResult) Validate(command AgentCommand) error {
	if command.Validate() != nil || r.CommandID != command.ID {
		return ErrResultInvalid
	}
	if err := r.ValidateShape(command.Kind); err != nil {
		return err
	}
	if command.Inventory == nil || r.Status != AgentCommandSucceeded {
		return nil
	}
	switch command.Kind {
	case AgentCommandInventoryPrepare:
		if r.Inventory.Manifest.ObservationID != command.Inventory.ObservationID {
			return ErrResultInvalid
		}
	case AgentCommandInventoryChunk:
		if r.Inventory.Chunk.Index != command.Inventory.ChunkIndex ||
			r.Inventory.Chunk.Validate(command.Inventory.MaxChunkBytes) != nil {
			return ErrResultInvalid
		}
	case AgentCommandInventoryEvents:
		if r.Inventory.Events.Validate() != nil {
			return ErrResultInvalid
		}
	}
	return nil
}

// ValidateShape validates a cached result without requiring the secret-bearing
// command payload to be persisted.
func (r AgentCommandResult) ValidateShape(kind AgentCommandKind) error {
	if !validIdentifier(r.CommandID) || !kind.Valid() {
		return ErrResultInvalid
	}
	switch r.Status {
	case AgentCommandSucceeded:
		if r.ErrorCode != "" {
			return ErrResultInvalid
		}
		switch kind {
		case AgentCommandRuntimeProbe:
			if r.RuntimeProbe == nil || r.Inventory != nil ||
				!r.RuntimeProbe.Status.Valid() {
				return ErrResultInvalid
			}
		case AgentCommandDeploymentPrepare,
			AgentCommandDeploymentStage,
			AgentCommandDeploymentActivate,
			AgentCommandDeploymentCancel:
			if r.RuntimeProbe != nil || r.Inventory != nil {
				return ErrResultInvalid
			}
		case AgentCommandInventoryPrepare:
			if r.RuntimeProbe != nil || r.Inventory == nil ||
				!validInventoryManifest(r.Inventory.Manifest) ||
				r.Inventory.Chunk != nil || r.Inventory.Events != nil {
				return ErrResultInvalid
			}
		case AgentCommandInventoryChunk:
			if r.RuntimeProbe != nil || r.Inventory == nil ||
				r.Inventory.Manifest != nil || r.Inventory.Chunk == nil ||
				r.Inventory.Events != nil ||
				r.Inventory.Chunk.Validate(
					runtimeinventory.MaxChunkBytes,
				) != nil {
				return ErrResultInvalid
			}
		case AgentCommandInventoryRelease:
			if r.RuntimeProbe != nil || r.Inventory != nil {
				return ErrResultInvalid
			}
		case AgentCommandInventoryEvents:
			if r.RuntimeProbe != nil || r.Inventory == nil ||
				r.Inventory.Manifest != nil || r.Inventory.Chunk != nil ||
				r.Inventory.Events == nil || r.Inventory.Events.Validate() != nil {
				return ErrResultInvalid
			}
		default:
			return ErrResultInvalid
		}
	case AgentCommandFailed:
		if !validErrorCode(r.ErrorCode) || r.RuntimeProbe != nil ||
			r.Inventory != nil {
			return ErrResultInvalid
		}
	default:
		return ErrResultInvalid
	}
	return nil
}

func (r AgentCommandResult) Equivalent(other AgentCommandResult) bool {
	if r.CommandID != other.CommandID || r.Status != other.Status ||
		r.ErrorCode != other.ErrorCode {
		return false
	}
	switch {
	case r.RuntimeProbe == nil && other.RuntimeProbe == nil:
		return reflect.DeepEqual(r.Inventory, other.Inventory)
	case r.RuntimeProbe == nil || other.RuntimeProbe == nil:
		return false
	default:
		return r.RuntimeProbe.Status == other.RuntimeProbe.Status
	}
}

func (k AgentCommandKind) DurableResult() bool {
	switch k {
	case AgentCommandInventoryPrepare,
		AgentCommandInventoryChunk,
		AgentCommandInventoryRelease,
		AgentCommandInventoryEvents:
		return false
	default:
		return k.Valid()
	}
}

func validInventoryCommand(
	kind AgentCommandKind,
	command RuntimeInventoryCommand,
) bool {
	if !validIdentifier(command.RuntimeTargetID) {
		return false
	}
	switch kind {
	case AgentCommandInventoryPrepare:
		return validIdentifier(command.ObservationID) &&
			command.MaxChunkBytes >= 4*1024 &&
			command.MaxChunkBytes <= runtimeinventory.DefaultChunkBytes &&
			command.ChunkIndex == 0 && command.EventSince.IsZero() &&
			command.EventWaitSeconds == 0
	case AgentCommandInventoryChunk:
		return validIdentifier(command.ObservationID) &&
			command.MaxChunkBytes >= 4*1024 &&
			command.MaxChunkBytes <= runtimeinventory.DefaultChunkBytes &&
			command.ChunkIndex >= 0 &&
			command.ChunkIndex < runtimeinventory.MaxChunks &&
			command.EventSince.IsZero() && command.EventWaitSeconds == 0
	case AgentCommandInventoryRelease:
		return validIdentifier(command.ObservationID) &&
			command.MaxChunkBytes == 0 && command.ChunkIndex == 0 &&
			command.EventSince.IsZero() && command.EventWaitSeconds == 0
	case AgentCommandInventoryEvents:
		return command.ObservationID == "" && command.MaxChunkBytes == 0 &&
			command.ChunkIndex == 0 && command.EventWaitSeconds >= 1 &&
			command.EventWaitSeconds <= 10
	default:
		return false
	}
}

func validInventoryManifest(value *RuntimeInventoryManifest) bool {
	if value == nil ||
		len(value.Events) > runtimeinventory.MaxEventsPerWindow ||
		(value.EventsTruncated &&
			len(value.Events) != runtimeinventory.MaxEventsPerWindow) {
		return false
	}
	for _, event := range value.Events {
		if event.Validate() != nil {
			return false
		}
	}
	return validIdentifier(value.ObservationID) &&
		value.SchemaVersion == runtimeinventory.SchemaVersion &&
		value.ExpectedChunks >= 0 &&
		value.ExpectedChunks <= runtimeinventory.MaxChunks &&
		value.ExpectedResources >= 0 &&
		value.ExpectedResources <= runtimeinventory.MaxResources &&
		(value.ExpectedResources == 0) == (value.ExpectedChunks == 0) &&
		value.ExpectedResources <=
			value.ExpectedChunks*runtimeinventory.MaxResourcesPerChunk &&
		value.RetentionSeconds >= 1 &&
		value.RetentionSeconds <= 3600
}

func validDeploymentCommand(
	kind AgentCommandKind,
	command DeploymentCommand,
) bool {
	if !validIdentifier(command.DeploymentID) ||
		!validIdentifier(command.WorkerID) ||
		command.FencingToken == 0 ||
		command.CutoverSequence == 0 ||
		!validIdentifier(command.RuntimeTargetID) ||
		!containerNameRule.MatchString(command.ContainerName) {
		return false
	}
	switch kind {
	case AgentCommandDeploymentPrepare:
		return validImageDigest(command.ImageDigest) &&
			len(command.RegistryAuthorization) <= 16*1024 &&
			command.ProjectID == "" &&
			command.ApplicationID == "" &&
			command.EnvironmentID == "" &&
			zeroRuntimeSpec(command.RuntimeSpec) &&
			len(command.Environment) == 0
	case AgentCommandDeploymentStage:
		return validIdentifier(command.ProjectID) &&
			validIdentifier(command.ApplicationID) &&
			validIdentifier(command.EnvironmentID) &&
			validImageDigest(command.ImageDigest) &&
			len(command.RegistryAuthorization) == 0 &&
			validNormalizedRuntimeSpec(command.RuntimeSpec) &&
			validEnvironment(command.Environment) &&
			environmentMatchesSpec(
				command.Environment,
				command.RuntimeSpec.EnvironmentKeys,
			)
	case AgentCommandDeploymentActivate,
		AgentCommandDeploymentCancel:
		return command.ProjectID == "" &&
			command.ApplicationID == "" &&
			command.EnvironmentID == "" &&
			command.ImageDigest == "" &&
			len(command.RegistryAuthorization) == 0 &&
			zeroRuntimeSpec(command.RuntimeSpec) &&
			len(command.Environment) == 0
	default:
		return false
	}
}

func validImageDigest(value string) bool {
	named, err := reference.ParseNormalizedNamed(strings.TrimSpace(value))
	if err != nil {
		return false
	}
	digested, ok := named.(reference.Digested)
	return ok &&
		digested.Digest().Algorithm() == digest.SHA256 &&
		digested.Digest().Validate() == nil &&
		reference.FamiliarString(named) == value
}

func environmentMatchesSpec(values, names []string) bool {
	if len(values) != len(names) {
		return false
	}
	expected := make(map[string]struct{}, len(names))
	for _, name := range names {
		expected[name] = struct{}{}
	}
	for _, value := range values {
		name, _, _ := strings.Cut(value, "=")
		if _, exists := expected[name]; !exists {
			return false
		}
		delete(expected, name)
	}
	return len(expected) == 0
}

func validNormalizedRuntimeSpec(spec runtimespec.Spec) bool {
	cloned := cloneRuntimeSpec(spec)
	normalized, err := runtimespec.Normalize(cloned)
	return err == nil && reflect.DeepEqual(normalized, spec)
}

func cloneRuntimeSpec(spec runtimespec.Spec) runtimespec.Spec {
	cloned := spec
	cloned.Ports = append([]runtimespec.Port(nil), spec.Ports...)
	cloned.EnvironmentKeys = append([]string(nil), spec.EnvironmentKeys...)
	if spec.HealthCheck != nil {
		health := *spec.HealthCheck
		health.Command = append([]string(nil), spec.HealthCheck.Command...)
		cloned.HealthCheck = &health
	}
	return cloned
}

func zeroRuntimeSpec(spec runtimespec.Spec) bool {
	return len(spec.Ports) == 0 &&
		len(spec.EnvironmentKeys) == 0 &&
		spec.Resources == (runtimespec.Resources{}) &&
		spec.HealthCheck == nil
}

func validEnvironment(values []string) bool {
	if len(values) > 100 {
		return false
	}
	total := 0
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		total += len(value)
		if len(value) > 4096 || total > 24*1024 ||
			strings.ContainsRune(value, '\x00') {
			return false
		}
		name, _, found := strings.Cut(value, "=")
		if !found || !environmentNameRule.MatchString(name) {
			return false
		}
		if _, exists := seen[name]; exists {
			return false
		}
		seen[name] = struct{}{}
	}
	return true
}

type fingerprintWriter interface {
	Write([]byte) (int, error)
}

func writeFingerprintString(writer fingerprintWriter, value string) {
	writeFingerprintBytes(writer, []byte(value))
}

func writeFingerprintBytes(writer fingerprintWriter, value []byte) {
	writeFingerprintUint64(writer, uint64(len(value)))
	_, _ = writer.Write(value)
}

func writeFingerprintUint64(writer fingerprintWriter, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = writer.Write(encoded[:])
}

func writeFingerprintInt64(writer fingerprintWriter, value int64) {
	writeFingerprintUint64(writer, uint64(value))
}

func writeRuntimeSpecFingerprint(
	writer fingerprintWriter,
	spec runtimespec.Spec,
) {
	writeFingerprintUint64(writer, uint64(len(spec.Ports)))
	for _, port := range spec.Ports {
		writeFingerprintString(writer, port.Name)
		writeFingerprintUint64(writer, uint64(port.ContainerPort))
		writeFingerprintString(writer, port.Protocol)
	}
	writeFingerprintUint64(writer, uint64(len(spec.EnvironmentKeys)))
	for _, name := range spec.EnvironmentKeys {
		writeFingerprintString(writer, name)
	}
	writeFingerprintInt64(writer, spec.Resources.CPUMilli)
	writeFingerprintInt64(writer, spec.Resources.MemoryBytes)
	if spec.HealthCheck == nil {
		writeFingerprintUint64(writer, 0)
		return
	}
	writeFingerprintUint64(writer, 1)
	writeFingerprintUint64(
		writer,
		uint64(len(spec.HealthCheck.Command)),
	)
	for _, value := range spec.HealthCheck.Command {
		writeFingerprintString(writer, value)
	}
	writeFingerprintInt64(
		writer,
		int64(spec.HealthCheck.IntervalSeconds),
	)
	writeFingerprintInt64(
		writer,
		int64(spec.HealthCheck.TimeoutSeconds),
	)
	writeFingerprintInt64(writer, int64(spec.HealthCheck.Retries))
	writeFingerprintInt64(
		writer,
		int64(spec.HealthCheck.StartPeriodSeconds),
	)
}

func validIdentifier(value string) bool {
	if value == "" || len(value) > 128 || value == "." || value == ".." ||
		value[0] == '.' {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func validErrorCode(value string) bool {
	if value == "" || len(value) > 64 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			character == '_' {
			continue
		}
		return false
	}
	return true
}
