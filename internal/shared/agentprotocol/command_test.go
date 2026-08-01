package agentprotocol

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/shared/runtimeinventory"
	"github.com/owndock/owndock/internal/shared/runtimespec"
)

func TestAgentRuntimeProbeCommandAndResultValidation(t *testing.T) {
	command := AgentCommand{
		ID: "command-1", Kind: AgentCommandRuntimeProbe,
		Deadline:     time.Unix(1000, 0).UTC(),
		RuntimeProbe: &RuntimeProbeCommand{RuntimeTargetID: "target-1"},
	}
	if err := command.Validate(); err != nil {
		t.Fatalf("valid command error = %v", err)
	}
	result := AgentCommandResult{
		CommandID: command.ID, Status: AgentCommandSucceeded,
		RuntimeProbe: &RuntimeProbeResult{Status: RuntimeProbeReady},
	}
	if err := result.Validate(command); err != nil {
		t.Fatalf("valid result error = %v", err)
	}
	if !command.Equivalent(command) || !result.Equivalent(result) {
		t.Fatal("values must be equivalent to themselves")
	}
}

func TestDeploymentCommandsAreStrictAndFingerprintSecrets(t *testing.T) {
	prepare := deploymentCommand(AgentCommandDeploymentPrepare)
	prepare.Deployment.ImageDigest =
		"registry.example.com/team/app@sha256:" + strings.Repeat("a", 64)
	prepare.Deployment.RegistryAuthorization =
		[]byte("registry-secret")
	if err := prepare.Validate(); err != nil {
		t.Fatalf("prepare error = %v", err)
	}
	prepareFingerprint, err := prepare.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	changed := prepare
	deployment := *prepare.Deployment
	deployment.RegistryAuthorization = []byte("different-secret")
	changed.Deployment = &deployment
	changedFingerprint, err := changed.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if prepareFingerprint == changedFingerprint ||
		prepare.Equivalent(changed) {
		t.Fatal("secret change must alter command identity")
	}

	stage := deploymentCommand(AgentCommandDeploymentStage)
	stage.Deployment.ProjectID = "project-1"
	stage.Deployment.ApplicationID = "application-1"
	stage.Deployment.EnvironmentID = "environment-1"
	stage.Deployment.ImageDigest =
		"registry.example.com/team/app@sha256:" + strings.Repeat("a", 64)
	stage.Deployment.RuntimeSpec = runtimespec.Spec{
		EnvironmentKeys: []string{"DATABASE_URL"},
		Resources: runtimespec.Resources{
			CPUMilli: 500, MemoryBytes: 256 * 1024 * 1024,
		},
	}
	stage.Deployment.Environment = []string{
		"DATABASE_URL=mongodb://secret",
	}
	if err := stage.Validate(); err != nil {
		t.Fatalf("stage error = %v", err)
	}
	for _, kind := range []AgentCommandKind{
		AgentCommandDeploymentActivate,
		AgentCommandDeploymentCancel,
	} {
		command := deploymentCommand(kind)
		if err := command.Validate(); err != nil {
			t.Fatalf("%s error = %v", kind, err)
		}
		result := AgentCommandResult{
			CommandID: command.ID,
			Status:    AgentCommandSucceeded,
		}
		if err := result.Validate(command); err != nil {
			t.Fatalf("%s result error = %v", kind, err)
		}
	}
}

func TestDeploymentCommandRejectsUnexpectedSecretFields(t *testing.T) {
	activate := deploymentCommand(AgentCommandDeploymentActivate)
	activate.Deployment.RegistryAuthorization = []byte("must-not-travel")
	if !errors.Is(activate.Validate(), ErrCommandInvalid) {
		t.Fatal("activate accepted registry authorization")
	}
	stage := deploymentCommand(AgentCommandDeploymentStage)
	stage.Deployment.ProjectID = "project-1"
	stage.Deployment.ApplicationID = "application-1"
	stage.Deployment.EnvironmentID = "environment-1"
	stage.Deployment.ImageDigest =
		"registry.example.com/team/app@sha256:" + strings.Repeat("a", 64)
	stage.Deployment.RuntimeSpec = runtimespec.Spec{
		EnvironmentKeys: []string{"EXPECTED"},
		Resources: runtimespec.Resources{
			CPUMilli: 500, MemoryBytes: 256 * 1024 * 1024,
		},
	}
	stage.Deployment.Environment = []string{"EXTRA=value"}
	if !errors.Is(stage.Validate(), ErrCommandInvalid) {
		t.Fatal("stage accepted environment outside RuntimeSpec")
	}
}

func TestDeploymentCommandRequiresCutoverSequence(t *testing.T) {
	command := deploymentCommand(AgentCommandDeploymentActivate)
	command.Deployment.CutoverSequence = 0
	if !errors.Is(command.Validate(), ErrCommandInvalid) {
		t.Fatal("deployment command accepted a zero cutover sequence")
	}
}

func TestCommandDocumentRoundTripsDeploymentWithoutAliasingSecrets(t *testing.T) {
	command := deploymentCommand(AgentCommandDeploymentPrepare)
	command.Deployment.ImageDigest =
		"registry.example.com/team/app@sha256:" + strings.Repeat("a", 64)
	command.Deployment.RegistryAuthorization = []byte("registry-secret")
	document := NewCommandDocument(command)
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "RegistryAuthorization") ||
		!strings.Contains(string(encoded), `"registry_authorization"`) {
		t.Fatalf("wire document = %s", encoded)
	}
	var decoded CommandDocument
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	document = &decoded
	roundTrip := document.Domain()
	if !command.Equivalent(roundTrip) {
		t.Fatalf("round trip = %+v", roundTrip)
	}
	document.Deployment.RegistryAuthorization[0] = 'X'
	if string(command.Deployment.RegistryAuthorization) != "registry-secret" {
		t.Fatal("wire document aliases command secret bytes")
	}
}

func TestAgentCommandRejectsUntypedOrUnsafePayload(t *testing.T) {
	deadline := time.Unix(1000, 0).UTC()
	tests := []AgentCommand{
		{ID: "command-1", Kind: AgentCommandRuntimeProbe, Deadline: deadline},
		{
			ID: "command-1", Kind: AgentCommandRuntimeProbe, Deadline: deadline,
			RuntimeProbe: &RuntimeProbeCommand{
				RuntimeTargetID: "unix:///var/run/docker.sock",
			},
		},
		{
			ID: "command-1", Kind: "shell.exec", Deadline: deadline,
			RuntimeProbe: &RuntimeProbeCommand{RuntimeTargetID: "target-1"},
		},
	}
	for _, command := range tests {
		if !errors.Is(command.Validate(), ErrCommandInvalid) {
			t.Fatalf("unsafe command accepted: %+v", command)
		}
	}
}

func TestRuntimeInventoryCommandsAndResultsAreBoundedAndNonDurable(t *testing.T) {
	prepare := runtimeInventoryCommand(AgentCommandInventoryPrepare, 0)
	if err := prepare.Validate(); err != nil {
		t.Fatal(err)
	}
	if prepare.Kind.DurableResult() {
		t.Fatal("inventory result must not enter the durable command cache")
	}
	manifest := AgentCommandResult{
		CommandID: prepare.ID,
		Status:    AgentCommandSucceeded,
		Inventory: &RuntimeInventoryResult{
			Manifest: &RuntimeInventoryManifest{
				ObservationID:     prepare.Inventory.ObservationID,
				SchemaVersion:     runtimeinventory.SchemaVersion,
				ExpectedChunks:    1,
				ExpectedResources: 1,
				RetentionSeconds:  600,
				Events: []runtimeinventory.Event{{
					Kind: runtimeinventory.KindContainer, RuntimeID: "container-removed",
					Action:     runtimeinventory.EventActionDestroy,
					OccurredAt: time.Unix(1001, 0).UTC(),
				}},
			},
		},
	}
	if err := manifest.Validate(prepare); err != nil {
		t.Fatal(err)
	}
	invalidManifest := manifest
	invalidInventory := *manifest.Inventory
	invalidValue := *manifest.Inventory.Manifest
	invalidValue.EventsTruncated = true
	invalidInventory.Manifest = &invalidValue
	invalidManifest.Inventory = &invalidInventory
	if !errors.Is(invalidManifest.Validate(prepare), ErrResultInvalid) {
		t.Fatal("short event list accepted as a truncated manifest")
	}

	chunkCommand := runtimeInventoryCommand(AgentCommandInventoryChunk, 0)
	chunk := runtimeinventory.Chunk{
		SchemaVersion: runtimeinventory.SchemaVersion,
		Index:         0,
		Resources: []runtimeinventory.Resource{{
			Kind:          runtimeinventory.KindContainer,
			RuntimeID:     "container-1",
			Name:          "api",
			Container:     &runtimeinventory.ContainerSummary{State: "running"},
			ObservedAt:    time.Unix(1000, 0).UTC(),
			SchemaVersion: runtimeinventory.SchemaVersion,
		}},
	}
	chunkResult := AgentCommandResult{
		CommandID: chunkCommand.ID,
		Status:    AgentCommandSucceeded,
		Inventory: &RuntimeInventoryResult{Chunk: &chunk},
	}
	if err := chunkResult.Validate(chunkCommand); err != nil {
		t.Fatal(err)
	}
	changed := chunkCommand
	inventoryCommand := *changed.Inventory
	inventoryCommand.ChunkIndex = 1
	changed.Inventory = &inventoryCommand
	if !errors.Is(chunkResult.Validate(changed), ErrResultInvalid) {
		t.Fatal("chunk result accepted a different requested index")
	}

	release := runtimeInventoryCommand(AgentCommandInventoryRelease, 0)
	if err := (AgentCommandResult{
		CommandID: release.ID,
		Status:    AgentCommandSucceeded,
	}).Validate(release); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeInventoryCommandDocumentRoundTrip(t *testing.T) {
	command := runtimeInventoryCommand(AgentCommandInventoryChunk, 7)
	document := NewCommandDocument(command)
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	var decoded CommandDocument
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !command.Equivalent(decoded.Domain()) {
		t.Fatalf("round trip = %+v", decoded.Domain())
	}
}

func TestRuntimeInventoryEventPollIsTypedBoundedAndNonDurable(t *testing.T) {
	command := AgentCommand{
		ID:       "inventory-event-command-1",
		Kind:     AgentCommandInventoryEvents,
		Deadline: time.Unix(1500, 0).UTC(),
		Inventory: &RuntimeInventoryCommand{
			RuntimeTargetID:  "target-1",
			EventSince:       time.Unix(1400, 0).UTC(),
			EventWaitSeconds: 2,
		},
	}
	if err := command.Validate(); err != nil || command.Kind.DurableResult() {
		t.Fatalf("event command validation/durability = %v/%v", err, command.Kind.DurableResult())
	}
	document := NewCommandDocument(command)
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "observation_id") {
		t.Fatalf("event command leaked unrelated observation field: %s", encoded)
	}
	var decoded CommandDocument
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !command.Equivalent(decoded.Domain()) {
		t.Fatalf("event command round trip = %+v", decoded.Domain())
	}
	batch := runtimeinventory.EventBatch{Events: []runtimeinventory.Event{{
		Kind: runtimeinventory.KindContainer, RuntimeID: "container-1",
		Action:     runtimeinventory.EventActionStart,
		OccurredAt: time.Unix(1401, 0).UTC(),
	}}}
	result := AgentCommandResult{
		CommandID: command.ID, Status: AgentCommandSucceeded,
		Inventory: &RuntimeInventoryResult{Events: &batch},
	}
	if err := result.Validate(command); err != nil {
		t.Fatal(err)
	}
	command.Inventory.EventWaitSeconds = 11
	if !errors.Is(command.Validate(), ErrCommandInvalid) {
		t.Fatal("event command accepted an unbounded wait")
	}
}

func deploymentCommand(kind AgentCommandKind) AgentCommand {
	return AgentCommand{
		ID:       "command-1",
		Kind:     kind,
		Deadline: time.Unix(1000, 0).UTC(),
		Deployment: &DeploymentCommand{
			DeploymentID:    "deployment-1",
			WorkerID:        "worker-1",
			FencingToken:    1,
			CutoverSequence: 1,
			RuntimeTargetID: "target-1",
			ContainerName:   "owndock-container",
		},
	}
}

func runtimeInventoryCommand(
	kind AgentCommandKind,
	index int,
) AgentCommand {
	command := &RuntimeInventoryCommand{
		RuntimeTargetID: "target-1",
		ObservationID:   "observation-1",
	}
	switch kind {
	case AgentCommandInventoryPrepare, AgentCommandInventoryChunk:
		command.MaxChunkBytes = runtimeinventory.DefaultChunkBytes
		command.ChunkIndex = index
	}
	return AgentCommand{
		ID:        "inventory-command-1",
		Kind:      kind,
		Deadline:  time.Unix(1500, 0).UTC(),
		Inventory: command,
	}
}

func TestAgentResultRejectsMismatchedAndFreeFormValues(t *testing.T) {
	command := AgentCommand{
		ID: "command-1", Kind: AgentCommandRuntimeProbe,
		Deadline:     time.Unix(1000, 0).UTC(),
		RuntimeProbe: &RuntimeProbeCommand{RuntimeTargetID: "target-1"},
	}
	tests := []AgentCommandResult{
		{
			CommandID: "different", Status: AgentCommandSucceeded,
			RuntimeProbe: &RuntimeProbeResult{Status: RuntimeProbeReady},
		},
		{
			CommandID: command.ID, Status: AgentCommandSucceeded,
			ErrorCode:    "unexpected",
			RuntimeProbe: &RuntimeProbeResult{Status: RuntimeProbeReady},
		},
		{
			CommandID: command.ID, Status: AgentCommandFailed,
			ErrorCode: "unsafe error message",
		},
	}
	for _, result := range tests {
		if !errors.Is(result.Validate(command), ErrResultInvalid) {
			t.Fatalf("invalid result accepted: %+v", result)
		}
	}
}
