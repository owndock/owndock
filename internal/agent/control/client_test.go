package agentcontrol

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/shared/agentprotocol"
	inventory "github.com/owndock/owndock/internal/shared/runtimeinventory"
)

type probeExecutorStub struct {
	mu       sync.Mutex
	commands []agentprotocol.AgentCommand
}

func TestMaximumInventoryEventManifestFitsDefaultControlFrame(t *testing.T) {
	events := make([]inventory.Event, inventory.MaxEventsPerWindow)
	for index := range events {
		events[index] = inventory.Event{
			Kind:       inventory.KindContainer,
			RuntimeID:  strings.Repeat("a", 508) + string(rune('A'+index%26)),
			Action:     inventory.EventActionUpdate,
			OccurredAt: time.Unix(1000+int64(index), 0).UTC(),
		}
	}
	result := agentprotocol.AgentCommandResult{
		CommandID: "inventory-command-1",
		Status:    agentprotocol.AgentCommandSucceeded,
		Inventory: &agentprotocol.RuntimeInventoryResult{
			Manifest: &agentprotocol.RuntimeInventoryManifest{
				ObservationID:    "observation-1",
				SchemaVersion:    inventory.SchemaVersion,
				RetentionSeconds: 600,
				Events:           events,
				EventsTruncated:  true,
			},
		},
	}
	encoded, err := json.Marshal(agentFrame{
		Type: "command_result", Sequence: 2,
		CommandResult: newAgentResult(result),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) >= 64*1024 {
		t.Fatalf("maximum inventory event frame = %d bytes", len(encoded))
	}
}

func (e *probeExecutorStub) Execute(
	_ context.Context,
	command agentprotocol.AgentCommand,
) (agentprotocol.AgentCommandResult, error) {
	e.mu.Lock()
	e.commands = append(e.commands, command)
	e.mu.Unlock()
	return agentprotocol.AgentCommandResult{
		CommandID: command.ID,
		Status:    agentprotocol.AgentCommandSucceeded,
		RuntimeProbe: &agentprotocol.RuntimeProbeResult{
			Status: agentprotocol.RuntimeProbeReady,
		},
	}, nil
}

func TestClientNegotiatesExecutesAndReturnsTypedResult(t *testing.T) {
	resultReceived := make(chan agentCommandResult, 1)
	releaseHandler := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(
		func(w http.ResponseWriter, request *http.Request) {
			controller := http.NewResponseController(w)
			if err := controller.EnableFullDuplex(); err != nil {
				t.Errorf("enable full duplex: %v", err)
				return
			}
			scanner := bufio.NewScanner(request.Body)
			if !scanner.Scan() {
				t.Error("missing hello")
				return
			}
			var hello agentFrame
			if err := json.Unmarshal(scanner.Bytes(), &hello); err != nil {
				t.Errorf("decode hello: %v", err)
				return
			}
			if hello.Type != "hello" || hello.Sequence != 1 ||
				hello.Hello == nil ||
				hello.Hello.ProtocolVersion != protocolVersion {
				t.Errorf("hello = %#v", hello)
				return
			}
			w.Header().Set("Content-Type", contentType)
			w.WriteHeader(http.StatusOK)
			encoder := json.NewEncoder(w)
			_ = encoder.Encode(serverFrame{
				Type: "hello_ack", Sequence: 1,
				SessionID: "session-1", ProtocolVersion: protocolVersion,
				HeartbeatIntervalSeconds: 1,
				MaxFrameBytes:            64 * 1024,
				ServerTime:               time.Now().UTC(),
			})
			_ = encoder.Encode(serverFrame{
				Type: "command", Sequence: 2,
				Command: agentprotocol.NewCommandDocument(
					agentprotocol.AgentCommand{
						ID:       "command-1",
						Kind:     agentprotocol.AgentCommandRuntimeProbe,
						Deadline: time.Now().Add(time.Minute).UTC(),
						RuntimeProbe: &agentprotocol.RuntimeProbeCommand{
							RuntimeTargetID: "target-1",
						},
					},
				),
			})
			w.(http.Flusher).Flush()
			for scanner.Scan() {
				var frame agentFrame
				if err := json.Unmarshal(scanner.Bytes(), &frame); err != nil {
					t.Errorf("decode Agent frame: %v", err)
					return
				}
				if frame.Type != "command_result" {
					continue
				}
				if frame.CommandResult == nil {
					t.Error("missing command result")
					return
				}
				select {
				case resultReceived <- *frame.CommandResult:
				default:
				}
				_ = encoder.Encode(serverFrame{
					Type: "command_result_ack", Sequence: 3,
					AcknowledgedSequence: frame.Sequence,
					CommandID:            frame.CommandResult.CommandID,
					ServerTime:           time.Now().UTC(),
				})
				w.(http.Flusher).Flush()
				<-releaseHandler
				return
			}
		},
	))
	defer server.Close()

	executor := &probeExecutorStub{}
	client, err := NewClient(
		server.Client(),
		executor,
		ClientConfig{
			Endpoint:              server.URL + "/api/v1/agent/connect",
			Identity:              testIdentity(),
			HandshakeTimeout:      2 * time.Second,
			ServerSilenceTimeout:  3 * time.Second,
			MaxFrameBytes:         64 * 1024,
			MaxConcurrentCommands: 2,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()

	select {
	case result := <-resultReceived:
		if result.CommandID != "command-1" ||
			result.Status != agentprotocol.AgentCommandSucceeded ||
			result.RuntimeProbe == nil ||
			result.RuntimeProbe.Status != agentprotocol.RuntimeProbeReady {
			t.Fatalf("result = %#v", result)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Agent did not return command result")
	}
	cancel()
	close(releaseHandler)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Agent did not stop")
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if len(executor.commands) != 1 ||
		executor.commands[0].RuntimeProbe == nil ||
		executor.commands[0].RuntimeProbe.RuntimeTargetID != "target-1" {
		t.Fatalf("commands = %#v", executor.commands)
	}
}

func TestClientRejectsInvalidServerFramePermanently(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(
		func(w http.ResponseWriter, request *http.Request) {
			controller := http.NewResponseController(w)
			_ = controller.EnableFullDuplex()
			scanner := bufio.NewScanner(request.Body)
			if !scanner.Scan() {
				return
			}
			w.Header().Set("Content-Type", contentType)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(
				`{"type":"hello_ack","sequence":1,"unknown":true}` + "\n",
			))
			w.(http.Flusher).Flush()
		},
	))
	defer server.Close()
	client, err := NewClient(
		server.Client(),
		&probeExecutorStub{},
		ClientConfig{
			Endpoint:              server.URL + "/api/v1/agent/connect",
			Identity:              testIdentity(),
			HandshakeTimeout:      time.Second,
			ServerSilenceTimeout:  2 * time.Second,
			MaxFrameBytes:         64 * 1024,
			MaxConcurrentCommands: 1,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	err = client.Run(t.Context())
	if !IsPermanent(err) {
		t.Fatalf("error = %v", err)
	}
}

func TestNewClientRejectsUnsafeEndpointAndIdentity(t *testing.T) {
	tests := []ClientConfig{
		{
			Endpoint:         "http://control.example/api/v1/agent/connect",
			Identity:         testIdentity(),
			HandshakeTimeout: time.Second, ServerSilenceTimeout: 2 * time.Second,
			MaxFrameBytes: 65536, MaxConcurrentCommands: 1,
		},
		{
			Endpoint:         "https://control.example/api/v1/agent/connect?token=x",
			Identity:         testIdentity(),
			HandshakeTimeout: time.Second, ServerSilenceTimeout: 2 * time.Second,
			MaxFrameBytes: 65536, MaxConcurrentCommands: 1,
		},
	}
	for _, config := range tests {
		if _, err := NewClient(
			http.DefaultClient,
			&probeExecutorStub{},
			config,
		); !errors.Is(err, ErrConfigurationInvalid) {
			t.Fatalf("error = %v", err)
		}
	}
}

func TestOutboundQueueFailsClosedWhenWriterIsBackpressured(t *testing.T) {
	outbound := make(chan outboundFrame, 1)
	outbound <- outboundFrame{heartbeat: true}
	err := enqueueOutbound(
		t.Context(),
		outbound,
		outboundFrame{heartbeat: true},
	)
	if !errors.Is(err, ErrConnectionUnavailable) {
		t.Fatalf("error = %v", err)
	}
}

func testIdentity() Identity {
	return Identity{
		OrganizationID: "organization-1",
		ManagedHostID:  "host-1",
		IdentityID:     "identity-1",
		InstanceID:     "instance-1",
		BootID:         "boot-1",
		AgentVersion:   "1.0.0",
	}
}
