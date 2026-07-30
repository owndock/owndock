package agentprotocol

import (
	"time"

	"github.com/owndock/owndock/internal/shared/runtimespec"
)

// CommandDocument is the canonical v1 JSON representation shared by the
// Server and Agent transports. It remains separate from AgentCommand so JSON
// evolution cannot silently change the domain/idempotency representation.
type CommandDocument struct {
	CommandID    string                    `json:"command_id"`
	Kind         AgentCommandKind          `json:"kind"`
	Deadline     time.Time                 `json:"deadline"`
	RuntimeProbe *RuntimeProbeDocument     `json:"runtime_probe,omitempty"`
	Deployment   *DeploymentDocument       `json:"deployment,omitempty"`
	Inventory    *RuntimeInventoryDocument `json:"runtime_inventory,omitempty"`
}

type RuntimeProbeDocument struct {
	RuntimeTargetID string `json:"runtime_target_id"`
}

type RuntimeInventoryDocument struct {
	RuntimeTargetID string `json:"runtime_target_id"`
	ObservationID   string `json:"observation_id"`
	MaxChunkBytes   int    `json:"max_chunk_bytes,omitempty"`
	ChunkIndex      int    `json:"chunk_index,omitempty"`
}

type DeploymentDocument struct {
	DeploymentID    string `json:"deployment_id"`
	WorkerID        string `json:"worker_id"`
	FencingToken    uint64 `json:"fencing_token"`
	CutoverSequence uint64 `json:"cutover_sequence"`
	RuntimeTargetID string `json:"runtime_target_id"`
	ContainerName   string `json:"container_name"`

	ProjectID     string `json:"project_id,omitempty"`
	ApplicationID string `json:"application_id,omitempty"`
	EnvironmentID string `json:"environment_id,omitempty"`
	ImageDigest   string `json:"image_digest,omitempty"`

	RegistryAuthorization []byte              `json:"registry_authorization,omitempty"`
	RuntimeSpec           RuntimeSpecDocument `json:"runtime_spec,omitzero"`
	Environment           []string            `json:"environment,omitempty"`
}

type RuntimeSpecDocument struct {
	Ports           []RuntimePortDocument   `json:"ports,omitempty"`
	EnvironmentKeys []string                `json:"environment_keys,omitempty"`
	Resources       RuntimeResourceDocument `json:"resources,omitzero"`
	HealthCheck     *RuntimeHealthDocument  `json:"health_check,omitempty"`
}

type RuntimePortDocument struct {
	Name          string `json:"name"`
	ContainerPort uint16 `json:"container_port"`
	Protocol      string `json:"protocol"`
}

type RuntimeResourceDocument struct {
	CPUMilli    int64 `json:"cpu_milli,omitempty"`
	MemoryBytes int64 `json:"memory_bytes,omitempty"`
}

type RuntimeHealthDocument struct {
	Command            []string `json:"command"`
	IntervalSeconds    int      `json:"interval_seconds"`
	TimeoutSeconds     int      `json:"timeout_seconds"`
	Retries            int      `json:"retries"`
	StartPeriodSeconds int      `json:"start_period_seconds"`
}

func NewCommandDocument(command AgentCommand) *CommandDocument {
	document := &CommandDocument{
		CommandID: command.ID,
		Kind:      command.Kind,
		Deadline:  command.Deadline.UTC(),
	}
	if command.RuntimeProbe != nil {
		document.RuntimeProbe = &RuntimeProbeDocument{
			RuntimeTargetID: command.RuntimeProbe.RuntimeTargetID,
		}
	}
	if command.Deployment != nil {
		document.Deployment = newDeploymentDocument(*command.Deployment)
	}
	if command.Inventory != nil {
		document.Inventory = &RuntimeInventoryDocument{
			RuntimeTargetID: command.Inventory.RuntimeTargetID,
			ObservationID:   command.Inventory.ObservationID,
			MaxChunkBytes:   command.Inventory.MaxChunkBytes,
			ChunkIndex:      command.Inventory.ChunkIndex,
		}
	}
	return document
}

func (d CommandDocument) Domain() AgentCommand {
	command := AgentCommand{
		ID:       d.CommandID,
		Kind:     d.Kind,
		Deadline: d.Deadline.UTC(),
	}
	if d.RuntimeProbe != nil {
		command.RuntimeProbe = &RuntimeProbeCommand{
			RuntimeTargetID: d.RuntimeProbe.RuntimeTargetID,
		}
	}
	if d.Deployment != nil {
		command.Deployment = d.Deployment.domain()
	}
	if d.Inventory != nil {
		command.Inventory = &RuntimeInventoryCommand{
			RuntimeTargetID: d.Inventory.RuntimeTargetID,
			ObservationID:   d.Inventory.ObservationID,
			MaxChunkBytes:   d.Inventory.MaxChunkBytes,
			ChunkIndex:      d.Inventory.ChunkIndex,
		}
	}
	return command
}

func newDeploymentDocument(
	command DeploymentCommand,
) *DeploymentDocument {
	return &DeploymentDocument{
		DeploymentID:    command.DeploymentID,
		WorkerID:        command.WorkerID,
		FencingToken:    command.FencingToken,
		CutoverSequence: command.CutoverSequence,
		RuntimeTargetID: command.RuntimeTargetID,
		ContainerName:   command.ContainerName,
		ProjectID:       command.ProjectID,
		ApplicationID:   command.ApplicationID,
		EnvironmentID:   command.EnvironmentID,
		ImageDigest:     command.ImageDigest,
		RegistryAuthorization: append(
			[]byte(nil),
			command.RegistryAuthorization...,
		),
		RuntimeSpec: newRuntimeSpecDocument(command.RuntimeSpec),
		Environment: append([]string(nil), command.Environment...),
	}
}

func (d DeploymentDocument) domain() *DeploymentCommand {
	return &DeploymentCommand{
		DeploymentID:    d.DeploymentID,
		WorkerID:        d.WorkerID,
		FencingToken:    d.FencingToken,
		CutoverSequence: d.CutoverSequence,
		RuntimeTargetID: d.RuntimeTargetID,
		ContainerName:   d.ContainerName,
		ProjectID:       d.ProjectID,
		ApplicationID:   d.ApplicationID,
		EnvironmentID:   d.EnvironmentID,
		ImageDigest:     d.ImageDigest,
		RegistryAuthorization: append(
			[]byte(nil),
			d.RegistryAuthorization...,
		),
		RuntimeSpec: d.RuntimeSpec.domain(),
		Environment: append([]string(nil), d.Environment...),
	}
}

func newRuntimeSpecDocument(spec runtimespec.Spec) RuntimeSpecDocument {
	document := RuntimeSpecDocument{
		Ports: make([]RuntimePortDocument, 0, len(spec.Ports)),
		EnvironmentKeys: append(
			[]string(nil),
			spec.EnvironmentKeys...,
		),
		Resources: RuntimeResourceDocument{
			CPUMilli:    spec.Resources.CPUMilli,
			MemoryBytes: spec.Resources.MemoryBytes,
		},
	}
	for _, port := range spec.Ports {
		document.Ports = append(document.Ports, RuntimePortDocument{
			Name:          port.Name,
			ContainerPort: port.ContainerPort,
			Protocol:      port.Protocol,
		})
	}
	if spec.HealthCheck != nil {
		document.HealthCheck = &RuntimeHealthDocument{
			Command: append(
				[]string(nil),
				spec.HealthCheck.Command...,
			),
			IntervalSeconds:    spec.HealthCheck.IntervalSeconds,
			TimeoutSeconds:     spec.HealthCheck.TimeoutSeconds,
			Retries:            spec.HealthCheck.Retries,
			StartPeriodSeconds: spec.HealthCheck.StartPeriodSeconds,
		}
	}
	return document
}

func (d RuntimeSpecDocument) domain() runtimespec.Spec {
	spec := runtimespec.Spec{
		Ports: make([]runtimespec.Port, 0, len(d.Ports)),
		EnvironmentKeys: append(
			[]string(nil),
			d.EnvironmentKeys...,
		),
		Resources: runtimespec.Resources{
			CPUMilli:    d.Resources.CPUMilli,
			MemoryBytes: d.Resources.MemoryBytes,
		},
	}
	for _, port := range d.Ports {
		spec.Ports = append(spec.Ports, runtimespec.Port{
			Name:          port.Name,
			ContainerPort: port.ContainerPort,
			Protocol:      port.Protocol,
		})
	}
	if d.HealthCheck != nil {
		spec.HealthCheck = &runtimespec.HealthCheck{
			Command:            append([]string(nil), d.HealthCheck.Command...),
			IntervalSeconds:    d.HealthCheck.IntervalSeconds,
			TimeoutSeconds:     d.HealthCheck.TimeoutSeconds,
			Retries:            d.HealthCheck.Retries,
			StartPeriodSeconds: d.HealthCheck.StartPeriodSeconds,
		}
	}
	return spec
}
