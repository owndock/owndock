package agentcontrol

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/shared/agentprotocol"
	inventory "github.com/owndock/owndock/internal/shared/runtimeinventory"
)

type containerTerminalExecutorStub struct {
	stream *controlTerminalStreamStub
	opens  chan agentprotocol.TerminalOpen
}

type hostTerminalExecutorStub struct {
	stream *controlTerminalStreamStub
	opens  chan agentprotocol.TerminalOpen
}

func (e *hostTerminalExecutorStub) OpenHostTerminal(
	_ context.Context,
	open agentprotocol.TerminalOpen,
) (agentprotocol.TerminalStream, error) {
	e.opens <- open
	return e.stream, nil
}

func (e *containerTerminalExecutorStub) OpenContainerTerminal(
	_ context.Context,
	open agentprotocol.TerminalOpen,
) (agentprotocol.TerminalStream, error) {
	e.opens <- open
	return e.stream, nil
}

type controlTerminalRead struct {
	payload []byte
	err     error
}

type controlTerminalStreamStub struct {
	writes  chan []byte
	resizes chan [2]uint16
	reads   chan controlTerminalRead
	closed  chan struct{}
	once    sync.Once
}

func newControlTerminalStreamStub() *controlTerminalStreamStub {
	return &controlTerminalStreamStub{
		writes: make(chan []byte, 1), resizes: make(chan [2]uint16, 1),
		reads: make(chan controlTerminalRead, 1), closed: make(chan struct{}),
	}
}

func (s *controlTerminalStreamStub) Read(payload []byte) (int, error) {
	select {
	case result := <-s.reads:
		return copy(payload, result.payload), result.err
	case <-s.closed:
		return 0, io.EOF
	}
}

func (s *controlTerminalStreamStub) Write(payload []byte) (int, error) {
	copyOfPayload := append([]byte(nil), payload...)
	select {
	case s.writes <- copyOfPayload:
		return len(payload), nil
	case <-s.closed:
		return 0, io.ErrClosedPipe
	}
}

func (s *controlTerminalStreamStub) Resize(
	_ context.Context,
	columns, rows uint16,
) error {
	s.resizes <- [2]uint16{columns, rows}
	return nil
}

func (s *controlTerminalStreamStub) Close() error {
	s.once.Do(func() { close(s.closed) })
	return nil
}

func TestClientBridgesContainerTerminalFrames(t *testing.T) {
	stream := newControlTerminalStreamStub()
	terminalExecutor := &containerTerminalExecutorStub{
		stream: stream, opens: make(chan agentprotocol.TerminalOpen, 1),
	}
	client, err := NewClient(
		http.DefaultClient,
		&probeExecutorStub{},
		ClientConfig{
			Endpoint: "https://control.example.com/api/v1/agent/connect",
			Identity: testIdentity(), HandshakeTimeout: time.Second,
			ServerSilenceTimeout: 2 * time.Second, MaxFrameBytes: 64 * 1024,
			MaxConcurrentCommands: 1,
			Capabilities:          []string{agentprotocol.CapabilityTerminalContainer},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	client.WithContainerTerminal(terminalExecutor)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	outbound := make(chan outboundFrame, 8)
	results := make(chan commandExecution, 1)
	semaphore := make(chan struct{}, 1)
	var workers sync.WaitGroup
	open := agentprotocol.TerminalOpen{
		Kind:         agentprotocol.TerminalKindContainer,
		DeploymentID: "deployment-1", ProjectID: "project-1",
		ApplicationID: "application-1", EnvironmentID: "environment-1",
		RuntimeTargetID: "target-1", ContainerName: "owndock-container-1",
		CutoverSequence: 7, Columns: 120, Rows: 30,
	}
	if err := client.handleServerFrame(
		ctx,
		serverFrame{Type: "terminal", Terminal: &agentprotocol.TerminalFrame{
			SessionID: "terminal-session-1", Sequence: 1,
			Type: agentprotocol.TerminalFrameOpen, Open: &open,
		}},
		results,
		semaphore,
		&workers,
		outbound,
	); err != nil {
		t.Fatal(err)
	}
	if got := <-terminalExecutor.opens; got != open {
		t.Fatalf("terminal open = %+v", got)
	}
	ready := <-outbound
	if ready.terminal == nil || ready.terminal.Type != agentprotocol.TerminalFrameReady ||
		ready.terminal.Sequence != 1 {
		t.Fatalf("ready frame = %+v", ready.terminal)
	}
	for _, frame := range []agentprotocol.TerminalFrame{
		{SessionID: "terminal-session-1", Sequence: 2,
			Type: agentprotocol.TerminalFrameStdin, Data: []byte("pwd\n")},
		{SessionID: "terminal-session-1", Sequence: 3,
			Type: agentprotocol.TerminalFrameResize, Columns: 132, Rows: 43},
	} {
		if err := client.handleServerFrame(
			ctx, serverFrame{Type: "terminal", Terminal: &frame},
			results, semaphore, &workers, outbound,
		); err != nil {
			t.Fatal(err)
		}
	}
	if payload := <-stream.writes; string(payload) != "pwd\n" {
		t.Fatalf("terminal input = %q", payload)
	}
	if size := <-stream.resizes; size != [2]uint16{132, 43} {
		t.Fatalf("terminal resize = %v", size)
	}
	stream.reads <- controlTerminalRead{payload: []byte("/workspace\n")}
	output := <-outbound
	if output.terminal == nil || output.terminal.Type != agentprotocol.TerminalFrameStdout ||
		output.terminal.Sequence != 2 || string(output.terminal.Data) != "/workspace\n" {
		t.Fatalf("terminal output frame = %+v", output.terminal)
	}
	closeFrame := agentprotocol.TerminalFrame{
		SessionID: "terminal-session-1", Sequence: 4,
		Type: agentprotocol.TerminalFrameClose,
	}
	if err := client.handleServerFrame(
		ctx, serverFrame{Type: "terminal", Terminal: &closeFrame},
		results, semaphore, &workers, outbound,
	); err != nil {
		t.Fatal(err)
	}
	workers.Wait()
	select {
	case <-stream.closed:
	default:
		t.Fatal("terminal stream was not closed")
	}
}

func TestClientRoutesHostTerminalOnlyToHostCapability(t *testing.T) {
	stream := newControlTerminalStreamStub()
	executor := &hostTerminalExecutorStub{
		stream: stream, opens: make(chan agentprotocol.TerminalOpen, 1),
	}
	client, err := NewClient(
		http.DefaultClient,
		&probeExecutorStub{},
		ClientConfig{
			Endpoint: "https://control.example.com/api/v1/agent/connect",
			Identity: testIdentity(), HandshakeTimeout: time.Second,
			ServerSilenceTimeout: 2 * time.Second, MaxFrameBytes: 64 * 1024,
			MaxConcurrentCommands: 1,
			Capabilities:          []string{agentprotocol.CapabilityTerminalHost},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	client.WithHostTerminal(executor)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	outbound := make(chan outboundFrame, 4)
	var workers sync.WaitGroup
	open := agentprotocol.TerminalOpen{
		Kind: agentprotocol.TerminalKindHost, Columns: 100, Rows: 40,
	}
	if err := client.handleTerminalFrame(
		ctx,
		agentprotocol.TerminalFrame{
			SessionID: "host-terminal-1", Sequence: 1,
			Type: agentprotocol.TerminalFrameOpen, Open: &open,
		},
		outbound,
		&workers,
	); err != nil {
		t.Fatal(err)
	}
	if got := <-executor.opens; got != open {
		t.Fatalf("host terminal open = %+v", got)
	}
	ready := <-outbound
	if ready.terminal == nil || ready.terminal.Type != agentprotocol.TerminalFrameReady {
		t.Fatalf("ready = %+v", ready.terminal)
	}
	if err := client.handleTerminalFrame(
		ctx,
		agentprotocol.TerminalFrame{
			SessionID: "host-terminal-1", Sequence: 2,
			Type: agentprotocol.TerminalFrameClose,
		},
		outbound,
		&workers,
	); err != nil {
		t.Fatal(err)
	}
	workers.Wait()
	select {
	case <-stream.closed:
	default:
		t.Fatal("host terminal stream was not closed")
	}

	containerOpen := agentprotocol.TerminalOpen{
		Kind:         agentprotocol.TerminalKindContainer,
		DeploymentID: "deployment-1", ProjectID: "project-1",
		ApplicationID: "application-1", EnvironmentID: "environment-1",
		RuntimeTargetID: "target-1", ContainerName: "owndock-container-1",
		CutoverSequence: 1, Columns: 100, Rows: 40,
	}
	if err := client.handleTerminalFrame(
		ctx,
		agentprotocol.TerminalFrame{
			SessionID: "container-terminal-1", Sequence: 1,
			Type: agentprotocol.TerminalFrameOpen, Open: &containerOpen,
		},
		outbound,
		&workers,
	); !IsPermanent(err) {
		t.Fatalf("container open without capability error = %v", err)
	}
}

type probeExecutorStub struct {
	mu       sync.Mutex
	commands []agentprotocol.AgentCommand
}

type reconnectTransport struct {
	ready      chan struct{}
	closeCalls atomic.Int32
}

func (t *reconnectTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	responseReader, responseWriter := io.Pipe()
	go func() {
		defer responseWriter.Close()
		encoded, _ := json.Marshal(serverFrame{
			Type: "hello_ack", Sequence: 1,
			SessionID: "session-reconnect", ProtocolVersion: protocolVersion,
			HeartbeatIntervalSeconds: 30, MaxFrameBytes: 64 * 1024,
			ServerTime: time.Now().UTC(),
		})
		_, _ = responseWriter.Write(append(encoded, '\n'))
		close(t.ready)
		<-request.Context().Done()
	}()
	go func() { _, _ = io.Copy(io.Discard, request.Body) }()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{contentType}},
		Body:       responseReader,
		Request:    request,
	}, nil
}

func (t *reconnectTransport) CloseIdleConnections() {
	t.closeCalls.Add(1)
}

func TestClientReconnectDiscardsOldTLSConnection(t *testing.T) {
	transport := &reconnectTransport{ready: make(chan struct{})}
	client, err := NewClient(
		&http.Client{Transport: transport},
		&probeExecutorStub{},
		ClientConfig{
			Endpoint: "https://control.example.com/api/v1/agent/connect",
			Identity: testIdentity(), HandshakeTimeout: time.Second,
			ServerSilenceTimeout: time.Minute, MaxFrameBytes: 64 * 1024,
			MaxConcurrentCommands: 1,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- client.Run(t.Context()) }()
	select {
	case <-transport.ready:
	case <-time.After(time.Second):
		t.Fatal("Agent control stream did not become ready")
	}
	client.Reconnect()
	if err := <-result; !errors.Is(err, ErrReconnectRequested) {
		t.Fatalf("reconnect result = %v", err)
	}
	if calls := transport.closeCalls.Load(); calls != 1 {
		t.Fatalf("CloseIdleConnections calls = %d", calls)
	}
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

func TestMaximumInventoryEventPollFitsDefaultControlFrame(t *testing.T) {
	events := make([]inventory.Event, inventory.MaxEventsPerWindow)
	for index := range events {
		events[index] = inventory.Event{
			Kind:       inventory.KindContainer,
			RuntimeID:  strings.Repeat("b", 508) + string(rune('A'+index%26)),
			Action:     inventory.EventActionUpdate,
			OccurredAt: time.Unix(2000+int64(index), 0).UTC(),
		}
	}
	result := agentprotocol.AgentCommandResult{
		CommandID: "inventory-events-1",
		Status:    agentprotocol.AgentCommandSucceeded,
		Inventory: &agentprotocol.RuntimeInventoryResult{
			Events: &inventory.EventBatch{Events: events, Truncated: true},
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
		t.Fatalf("maximum inventory event poll frame = %d bytes", len(encoded))
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
