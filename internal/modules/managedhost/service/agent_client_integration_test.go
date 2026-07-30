package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	agentcontrol "github.com/owndock/owndock/internal/agent/control"
	"github.com/owndock/owndock/internal/modules/managedhost/biz"
	managedhostdata "github.com/owndock/owndock/internal/modules/managedhost/data"
	"github.com/owndock/owndock/internal/shared/agentprotocol"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/transaction"
)

type conformanceExecutor struct {
	calls atomic.Int64
}

func (e *conformanceExecutor) Execute(
	_ context.Context,
	command agentprotocol.AgentCommand,
) (agentprotocol.AgentCommandResult, error) {
	e.calls.Add(1)
	result := agentprotocol.AgentCommandResult{
		CommandID: command.ID,
		Status:    agentprotocol.AgentCommandSucceeded,
	}
	if command.Kind == agentprotocol.AgentCommandRuntimeProbe {
		result.RuntimeProbe = &agentprotocol.RuntimeProbeResult{
			Status: agentprotocol.RuntimeProbeReady,
		}
	}
	return result, nil
}

func TestAgentClientAndServerStreamConformance(t *testing.T) {
	rawCertificate := []byte("Agent conformance certificate")
	fingerprint := sha256.Sum256(rawCertificate)
	repository := &agentControlRepositoryStub{
		identity: biz.AgentIdentity{
			ID: "identity-1", OrganizationID: "organization-1",
			ManagedHostID: "host-1", InstanceID: "instance-1",
			CertificateSerial:  "2a",
			CertificateSHA256:  hex.EncodeToString(fingerprint[:]),
			CertificateExpires: time.Now().Add(time.Hour),
			Capabilities:       agentprotocol.SupportedCapabilities(),
		},
		host: biz.ManagedHost{
			ID: "host-1", OrganizationID: "organization-1",
			Status: biz.StatusOffline, ConnectionMode: runtimeaccess.ModeAgent,
			AgentIdentityID: "identity-1", AgentInstanceID: "instance-1",
		},
	}
	registry, err := managedhostdata.NewConnectionRegistry(2, 4)
	if err != nil {
		t.Fatal(err)
	}
	var identifier atomic.Int64
	useCase := biz.NewUseCase(
		repository,
		transaction.Passthrough{},
		&agentAuditStub{},
		func() (string, error) {
			return fmt.Sprintf("generated-%d", identifier.Add(1)), nil
		},
		time.Now,
	).WithAgentControl(repository, registry, []string{"v1"})
	stream, err := NewAgentStream(
		useCase,
		registry,
		time.Second,
		time.Second,
		3*time.Second,
		64*1024,
	)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(
		func(writer http.ResponseWriter, request *http.Request) {
			request.TLS = testAgentTLSState(t, rawCertificate)
			stream.ServeHTTP(writer, request)
		},
	))
	defer server.Close()

	executor := &conformanceExecutor{}
	client, err := agentcontrol.NewClient(
		server.Client(),
		executor,
		agentcontrol.ClientConfig{
			Endpoint: server.URL + "/api/v1/agent/connect",
			Identity: agentcontrol.Identity{
				OrganizationID: "organization-1",
				ManagedHostID:  "host-1",
				IdentityID:     "identity-1",
				InstanceID:     "instance-1",
				BootID:         "boot-1",
				AgentVersion:   "1.0.0",
			},
			HandshakeTimeout:      time.Second,
			ServerSilenceTimeout:  4 * time.Second,
			MaxFrameBytes:         64 * 1024,
			MaxConcurrentCommands: 2,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	clientDone := make(chan error, 1)
	go func() { clientDone <- client.Run(ctx) }()

	command := biz.AgentCommand{
		ID: "command-1", Kind: biz.AgentCommandRuntimeProbe,
		Deadline: time.Now().Add(5 * time.Second).UTC(),
		RuntimeProbe: &biz.RuntimeProbeCommand{
			RuntimeTargetID: "target-1",
		},
	}
	var result biz.AgentCommandResult
	timeout := time.NewTimer(3 * time.Second)
	defer timeout.Stop()
	for {
		dispatchContext, dispatchCancel :=
			context.WithTimeout(t.Context(), 500*time.Millisecond)
		result, err = registry.Dispatch(
			dispatchContext,
			"host-1",
			command,
		)
		dispatchCancel()
		if err == nil {
			break
		}
		if !errors.Is(err, biz.ErrAgentNotConnected) {
			t.Fatalf("dispatch error = %v", err)
		}
		select {
		case <-time.After(10 * time.Millisecond):
		case <-timeout.C:
			t.Fatal("Agent did not connect")
		}
	}
	if result.RuntimeProbe == nil ||
		result.RuntimeProbe.Status != biz.RuntimeProbeReady ||
		executor.calls.Load() != 1 {
		t.Fatalf(
			"result = %#v, executor calls = %d",
			result,
			executor.calls.Load(),
		)
	}
	activate := biz.AgentCommand{
		ID:       "command-2",
		Kind:     biz.AgentCommandDeploymentActivate,
		Deadline: time.Now().Add(5 * time.Second).UTC(),
		Deployment: &biz.DeploymentCommand{
			DeploymentID:    "deployment-1",
			WorkerID:        "worker-1",
			FencingToken:    1,
			CutoverSequence: 1,
			RuntimeTargetID: "target-1",
			ContainerName:   "owndock-runtime",
		},
	}
	result, err = registry.Dispatch(
		t.Context(),
		"host-1",
		activate,
	)
	if err != nil ||
		result.Status != biz.AgentCommandSucceeded ||
		result.RuntimeProbe != nil ||
		executor.calls.Load() != 2 {
		t.Fatalf(
			"deployment result = %#v, error = %v, executor calls = %d",
			result,
			err,
			executor.calls.Load(),
		)
	}
	cancel()
	select {
	case err := <-clientDone:
		if err != nil {
			t.Fatalf("client error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Agent client did not stop")
	}
}
