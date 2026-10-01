package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentconfig "github.com/owndock/owndock/internal/agent/config"
	"github.com/owndock/owndock/internal/shared/agentprotocol"
	"github.com/owndock/owndock/internal/shared/runtimeinventory"
)

func TestMaterialsAndConfigCreateStrictRunnableInputs(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "materials")
	if err := runMaterials([]string{"--output", directory}); err != nil {
		t.Fatal(err)
	}
	paths, err := pathsFor(directory)
	if err != nil {
		t.Fatal(err)
	}
	for path, expected := range map[string]os.FileMode{
		paths.ca:           0o644,
		paths.caKey:        0o600,
		paths.serverBundle: 0o600,
		paths.clientCert:   0o644,
		paths.clientKey:    0o600,
		paths.clientBundle: 0o600,
		paths.bootID:       0o600,
		paths.state:        0o700,
	} {
		info, statErr := os.Stat(path)
		if statErr != nil {
			t.Fatalf("stat %s: %v", path, statErr)
		}
		if info.Mode().Perm() != expected {
			t.Fatalf("%s mode = %#o, want %#o", path, info.Mode().Perm(), expected)
		}
	}
	serverPEM, err := os.ReadFile(paths.serverBundle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.X509KeyPair(serverPEM, serverPEM); err != nil {
		t.Fatalf("server bundle: %v", err)
	}
	clientCertificatePEM, err := os.ReadFile(paths.clientCert)
	if err != nil {
		t.Fatal(err)
	}
	clientPrivateKeyPEM, err := os.ReadFile(paths.clientKey)
	if err != nil {
		t.Fatal(err)
	}
	clientPair, err := tls.X509KeyPair(clientCertificatePEM, clientPrivateKeyPEM)
	if err != nil {
		t.Fatalf("client pair: %v", err)
	}
	leaf, err := x509.ParseCertificate(clientPair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth ||
		len(leaf.URIs) != 1 || leaf.URIs[0].String() !=
		"spiffe://owndock/organizations/conformance-organization/managed-hosts/"+
			"conformance-host/agents/conformance-identity/instances/conformance-instance" {
		t.Fatalf("client identity = %+v", leaf)
	}

	endpoint := "https://127.0.0.1:18443/api/v1/agent/connect"
	dockerSocket := filepath.Join(directory, "docker.sock")
	if err := runConfig([]string{
		"--output", directory,
		"--endpoint", endpoint,
		"--docker-socket", dockerSocket,
	}); err != nil {
		t.Fatal(err)
	}
	config, err := agentconfig.Load(paths.config)
	if err != nil {
		t.Fatal(err)
	}
	if config.Control.Endpoint != endpoint ||
		config.Control.OrganizationID != organizationID ||
		config.Control.ManagedHostID != hostID ||
		config.Control.IdentityID != identityID ||
		config.Control.InstanceID != instanceID ||
		config.Runtime.DockerSocket != dockerSocket ||
		len(config.Control.Capabilities) != 1 ||
		config.Control.Capabilities[0] != agentprotocol.CapabilityRuntimeProbe ||
		config.CertificateRotation.Enabled {
		t.Fatalf("generated config = %+v", config)
	}
}

func TestConformanceRuntimeProbeExpectations(t *testing.T) {
	for _, test := range []struct {
		name     string
		expected string
		result   agentprotocol.AgentCommandResult
		valid    bool
		status   string
	}{
		{
			name: "expired", expected: "expired", valid: true,
			status: "command_expired",
			result: agentprotocol.AgentCommandResult{
				Status: agentprotocol.AgentCommandFailed, ErrorCode: "command_expired",
			},
		},
		{
			name: "ready", expected: "ready", valid: true, status: "runtime_ready",
			result: agentprotocol.AgentCommandResult{
				Status: agentprotocol.AgentCommandSucceeded,
				RuntimeProbe: &agentprotocol.RuntimeProbeResult{
					Status: agentprotocol.RuntimeProbeReady,
				},
			},
		},
		{
			name: "unreachable", expected: "unreachable", valid: true,
			status: "runtime_unreachable",
			result: agentprotocol.AgentCommandResult{
				Status: agentprotocol.AgentCommandSucceeded,
				RuntimeProbe: &agentprotocol.RuntimeProbeResult{
					Status: agentprotocol.RuntimeProbeUnreachable,
				},
			},
		},
		{
			name: "wrong status", expected: "ready",
			result: agentprotocol.AgentCommandResult{
				Status: agentprotocol.AgentCommandSucceeded,
				RuntimeProbe: &agentprotocol.RuntimeProbeResult{
					Status: agentprotocol.RuntimeProbeUnreachable,
				},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if actual := validConformanceRuntimeProbe(test.result, test.expected); actual != test.valid {
				t.Fatalf("valid = %t, want %t", actual, test.valid)
			}
			if test.valid && conformanceRuntimeProbeStatus(test.expected) != test.status {
				t.Fatalf("status = %q", conformanceRuntimeProbeStatus(test.expected))
			}
		})
	}
}

func TestConformanceDeploymentCommandsAreCanonical(t *testing.T) {
	handler := conformanceHandler{
		identity:               fixtureIdentity{hostID: "host-a"},
		commandSuffix:          "dual-runtime",
		runtimeDeadline:        time.Now().Add(time.Minute).UTC(),
		deploymentContainer:    "owndock-conformance",
		deploymentCapabilities: true,
	}
	for _, kind := range []agentprotocol.AgentCommandKind{
		agentprotocol.AgentCommandDeploymentPrepare,
		agentprotocol.AgentCommandDeploymentStage,
		agentprotocol.AgentCommandDeploymentActivate,
	} {
		handler.deploymentCommand = string(kind)
		command, err := handler.conformanceCommand("ready")
		if err != nil {
			t.Fatalf("%s command: %v", kind, err)
		}
		if err := command.Validate(); err != nil {
			t.Fatalf("%s validation: %v", kind, err)
		}
		result := agentprotocol.AgentCommandResult{
			CommandID: command.ID, Status: agentprotocol.AgentCommandSucceeded,
		}
		if !handler.validConformanceResult(result, "ready") ||
			handler.conformanceCommandStatus("ready") != "deployment_succeeded" {
			t.Fatalf("%s result was not accepted", kind)
		}
	}
	capabilities := conformanceCapabilities(true, false)
	if len(capabilities) != 5 ||
		capabilities[0] != agentprotocol.CapabilityRuntimeProbe ||
		capabilities[4] != agentprotocol.CapabilityDeploymentCancel {
		t.Fatalf("deployment capabilities = %v", capabilities)
	}
}

func TestConformanceDeploymentSequenceAndStaleResultAreCanonical(t *testing.T) {
	handler := conformanceHandler{
		identity:               fixtureIdentity{hostID: "host-a"},
		commandSuffix:          "after-restart",
		runtimeDeadline:        time.Now().Add(time.Minute).UTC(),
		deploymentCommand:      string(agentprotocol.AgentCommandDeploymentActivate),
		deploymentContainer:    "owndock-conformance",
		deploymentResult:       "stale_execution",
		deploymentSequence:     2,
		deploymentCapabilities: true,
	}
	command, err := handler.conformanceCommand("ready")
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Validate(); err != nil {
		t.Fatalf("sequence-aware command validation: %v", err)
	}
	if command.Deployment.DeploymentID != "conformance-deployment-host-a-v2" ||
		command.Deployment.CutoverSequence != 2 {
		t.Fatalf("sequence-aware deployment = %+v", command.Deployment)
	}
	result := agentprotocol.AgentCommandResult{
		CommandID: command.ID,
		Status:    agentprotocol.AgentCommandFailed,
		ErrorCode: "stale_execution",
	}
	if err := result.Validate(command); err != nil {
		t.Fatalf("stale result validation: %v", err)
	}
	if !handler.validConformanceResult(result, "ready") ||
		handler.conformanceCommandStatus("ready") != "deployment_stale_execution" {
		t.Fatal("stale deployment result was not accepted")
	}
}

func TestConformanceInventoryCommandsAndOwnershipAreCanonical(t *testing.T) {
	handler := conformanceHandler{
		identity:              fixtureIdentity{hostID: "host-a"},
		commandSuffix:         "dual-runtime",
		runtimeDeadline:       time.Now().Add(time.Minute).UTC(),
		deploymentContainer:   "owndock-conformance",
		inventoryCapabilities: true,
	}
	for _, kind := range []agentprotocol.AgentCommandKind{
		agentprotocol.AgentCommandInventoryPrepare,
		agentprotocol.AgentCommandInventoryChunk,
		agentprotocol.AgentCommandInventoryRelease,
	} {
		handler.inventoryCommand = string(kind)
		command, err := handler.conformanceCommand("ready")
		if err != nil {
			t.Fatalf("%s command: %v", kind, err)
		}
		if err := command.Validate(); err != nil {
			t.Fatalf("%s validation: %v", kind, err)
		}
		if command.Inventory.RuntimeTargetID != "conformance-target-host-a" ||
			command.Inventory.ObservationID != "conformance-observation-host-a" {
			t.Fatalf("%s inventory identity = %+v", kind, command.Inventory)
		}
	}
	capabilities := conformanceCapabilities(true, true)
	if len(capabilities) != 9 ||
		capabilities[5] != agentprotocol.CapabilityInventoryPrepare ||
		capabilities[8] != agentprotocol.CapabilityInventoryEvents {
		t.Fatalf("combined capabilities = %v", capabilities)
	}

	handler.inventoryCommand = string(agentprotocol.AgentCommandInventoryChunk)
	result := agentprotocol.AgentCommandResult{
		Inventory: &agentprotocol.RuntimeInventoryResult{
			Chunk: &runtimeinventory.Chunk{Resources: []runtimeinventory.Resource{{
				Kind: runtimeinventory.KindContainer,
				Name: "owndock-conformance",
				Labels: map[string]string{
					"net.owndock.deployment_id": "conformance-deployment-host-a",
				},
			}}},
		},
	}
	details, err := handler.conformanceInventoryDetails(result)
	if err != nil || details != "inventory_resources=1\ninventory_deployment_id=conformance-deployment-host-a\n" {
		t.Fatalf("inventory details = %q, %v", details, err)
	}
	result.Inventory.Chunk.Resources[0].Labels["net.owndock.deployment_id"] =
		"conformance-deployment-host-b"
	if _, err := handler.conformanceInventoryDetails(result); err == nil {
		t.Fatal("cross-Host inventory ownership unexpectedly passed")
	}

	handler.inventoryCommand = string(agentprotocol.AgentCommandInventoryEvents)
	handler.inventoryEventID = strings.Repeat("a", 64)
	handler.inventoryForbiddenID = strings.Repeat("b", 64)
	eventCommand, err := handler.conformanceCommand("ready")
	if err != nil {
		t.Fatal(err)
	}
	if err := eventCommand.Validate(); err != nil {
		t.Fatalf("inventory Event validation: %v", err)
	}
	if eventCommand.Inventory.ObservationID != "" {
		t.Fatalf("inventory Event observation ID = %q", eventCommand.Inventory.ObservationID)
	}
	if eventCommand.Inventory.EventSince.IsZero() ||
		eventCommand.Inventory.EventWaitSeconds != 2 {
		t.Fatalf("inventory Event window = %+v", eventCommand.Inventory)
	}
	eventResult := agentprotocol.AgentCommandResult{
		Inventory: &agentprotocol.RuntimeInventoryResult{
			Events: &runtimeinventory.EventBatch{Events: []runtimeinventory.Event{{
				Kind:       runtimeinventory.KindContainer,
				RuntimeID:  handler.inventoryEventID,
				Action:     runtimeinventory.EventActionCreate,
				OccurredAt: time.Now().UTC(),
			}}},
		},
	}
	details, err = handler.conformanceInventoryDetails(eventResult)
	if err != nil || details != "inventory_events=1\ninventory_event_runtime_id="+
		handler.inventoryEventID+"\n" {
		t.Fatalf("inventory Event details = %q, %v", details, err)
	}
	eventResult.Inventory.Events.Events[0].RuntimeID = handler.inventoryForbiddenID
	if _, err := handler.conformanceInventoryDetails(eventResult); err == nil {
		t.Fatal("cross-Host inventory Event unexpectedly passed")
	}
	handler.inventoryResult = "unavailable"
	unavailable := agentprotocol.AgentCommandResult{
		CommandID: eventCommand.ID,
		Status:    agentprotocol.AgentCommandFailed,
		ErrorCode: "inventory_unavailable",
	}
	if err := unavailable.Validate(eventCommand); err != nil {
		t.Fatalf("inventory unavailable validation: %v", err)
	}
	if !handler.validConformanceResult(unavailable, "ready") ||
		handler.conformanceCommandStatus("ready") != "inventory_unavailable" {
		t.Fatal("inventory unavailable result was not accepted")
	}
}

func TestCommandSuffixValidation(t *testing.T) {
	for value, expected := range map[string]bool{
		"initial": true, "host-a-recovery": true,
		"": false, "-prefix": false, "suffix-": false,
		"UPPER": false, "contains/slash": false,
	} {
		if actual := validCommandSuffix(value); actual != expected {
			t.Fatalf("validCommandSuffix(%q) = %t, want %t", value, actual, expected)
		}
	}
}

func TestConformanceInputsFailClosed(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "materials")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "unexpected"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runMaterials([]string{"--output", directory}); err == nil {
		t.Fatal("non-empty material directory unexpectedly succeeded")
	}
	if err := runConfig([]string{
		"--output", directory,
		"--endpoint", "https://example.com/api/v1/agent/connect",
	}); err == nil {
		t.Fatal("non-loopback conformance endpoint unexpectedly succeeded")
	}
	if err := runConfig([]string{
		"--output", directory,
		"--endpoint", "https://127.0.0.1:18443/api/v1/agent/connect",
		"--docker-socket", "relative.sock",
	}); err == nil {
		t.Fatal("relative Docker socket unexpectedly succeeded")
	}
	if _, err := pathsFor("relative"); err == nil {
		t.Fatal("relative conformance directory unexpectedly succeeded")
	}
}

func TestRotationConfigUsesOnePrivateIdentityBundle(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "materials")
	if err := runMaterials([]string{"--output", directory}); err != nil {
		t.Fatal(err)
	}
	paths, err := pathsFor(directory)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "https://127.0.0.1:18444/api/v1/agent/connect"
	if err := runConfig([]string{
		"--output", directory, "--endpoint", endpoint, "--enable-rotation",
	}); err != nil {
		t.Fatal(err)
	}
	config, err := agentconfig.Load(paths.config)
	if err != nil {
		t.Fatal(err)
	}
	if !config.CertificateRotation.Enabled ||
		config.Control.ClientCertificateFile != paths.clientBundle ||
		config.Control.ClientPrivateKeyFile != paths.clientBundle {
		t.Fatalf("rotation config = %+v", config)
	}
	info, err := os.Lstat(paths.clientBundle)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("rotation identity mode = %v", info.Mode())
	}
	bundle, err := os.ReadFile(paths.clientBundle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.X509KeyPair(bundle, bundle); err != nil {
		t.Fatalf("rotation identity bundle: %v", err)
	}
}

func TestAdditionalHostIdentityUsesSharedAuthority(t *testing.T) {
	root := t.TempDir()
	authority := filepath.Join(root, "authority")
	additional := filepath.Join(root, "additional")
	if err := runMaterials([]string{
		"--output", authority, "--host-id", "conformance-host-a",
	}); err != nil {
		t.Fatal(err)
	}
	if err := runIdentity([]string{
		"--authority", authority, "--output", additional,
		"--host-id", "conformance-host-b",
	}); err != nil {
		t.Fatal(err)
	}
	authorityPaths, _ := pathsFor(authority)
	additionalPaths, _ := pathsFor(additional)
	authorityCA, err := os.ReadFile(authorityPaths.ca)
	if err != nil {
		t.Fatal(err)
	}
	additionalCA, err := os.ReadFile(additionalPaths.ca)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(authorityCA, additionalCA) {
		t.Fatal("additional Host did not reuse the shared control authority")
	}
	certificatePEM, err := os.ReadFile(additionalPaths.clientCert)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPEM, err := os.ReadFile(additionalPaths.clientKey)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.SerialNumber.String() != "5" || len(leaf.URIs) != 1 ||
		leaf.URIs[0].String() !=
			"spiffe://owndock/organizations/conformance-organization/managed-hosts/"+
				"conformance-host-b/agents/conformance-identity/instances/conformance-instance" {
		t.Fatalf("additional Host certificate = %+v", leaf)
	}
	endpoint := "https://127.0.0.1:18445/api/v1/agent/connect"
	if err := runConfig([]string{
		"--output", additional, "--endpoint", endpoint,
		"--host-id", "conformance-host-b",
	}); err != nil {
		t.Fatal(err)
	}
	config, err := agentconfig.Load(additionalPaths.config)
	if err != nil {
		t.Fatal(err)
	}
	if config.Control.ManagedHostID != "conformance-host-b" {
		t.Fatalf("additional Host config = %+v", config.Control)
	}
}
