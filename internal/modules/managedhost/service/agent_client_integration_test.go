package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentcontrol "github.com/owndock/owndock/internal/agent/control"
	"github.com/owndock/owndock/internal/modules/managedhost/biz"
	managedhostdata "github.com/owndock/owndock/internal/modules/managedhost/data"
	runtimeinventorybiz "github.com/owndock/owndock/internal/modules/runtimeinventory/biz"
	runtimeinventorydata "github.com/owndock/owndock/internal/modules/runtimeinventory/data"
	"github.com/owndock/owndock/internal/shared/agentprotocol"
	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	transport "github.com/owndock/owndock/internal/shared/runtimeinventory"
	"github.com/owndock/owndock/internal/shared/transaction"
)

func commandCapabilities() []string {
	capabilities := agentprotocol.SupportedCapabilities()
	result := capabilities[:0]
	for _, capability := range capabilities {
		if capability != agentprotocol.CapabilityTerminalContainer &&
			capability != agentprotocol.CapabilityTerminalHost {
			result = append(result, capability)
		}
	}
	return result
}

type conformanceExecutor struct {
	calls             atomic.Int64
	containerTerminal *conformanceTerminalStream
	hostTerminal      *conformanceTerminalStream
	opens             chan agentprotocol.TerminalOpen
}

func (e *conformanceExecutor) OpenContainerTerminal(
	_ context.Context,
	open agentprotocol.TerminalOpen,
) (agentprotocol.TerminalStream, error) {
	e.opens <- open
	return e.containerTerminal, nil
}

func (e *conformanceExecutor) OpenHostTerminal(
	_ context.Context,
	open agentprotocol.TerminalOpen,
) (agentprotocol.TerminalStream, error) {
	e.opens <- open
	return e.hostTerminal, nil
}

type conformanceTerminalStream struct {
	input   chan []byte
	output  chan []byte
	resizes chan [2]uint16
	closed  chan struct{}
	once    sync.Once
}

func newConformanceTerminalStream() *conformanceTerminalStream {
	return &conformanceTerminalStream{
		input: make(chan []byte, 1), output: make(chan []byte, 1),
		resizes: make(chan [2]uint16, 1), closed: make(chan struct{}),
	}
}

func (s *conformanceTerminalStream) Read(payload []byte) (int, error) {
	select {
	case value := <-s.output:
		return copy(payload, value), nil
	case <-s.closed:
		return 0, io.EOF
	}
}

func (s *conformanceTerminalStream) Write(payload []byte) (int, error) {
	copyOfPayload := append([]byte(nil), payload...)
	select {
	case s.input <- copyOfPayload:
		return len(payload), nil
	case <-s.closed:
		return 0, io.ErrClosedPipe
	}
}

func (s *conformanceTerminalStream) Resize(
	_ context.Context,
	columns, rows uint16,
) error {
	s.resizes <- [2]uint16{columns, rows}
	return nil
}

func (s *conformanceTerminalStream) Close() error {
	s.once.Do(func() { close(s.closed) })
	return nil
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

	executor := &conformanceExecutor{
		containerTerminal: newConformanceTerminalStream(),
		hostTerminal:      newConformanceTerminalStream(),
		opens:             make(chan agentprotocol.TerminalOpen, 1),
	}
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
			Capabilities:          agentprotocol.SupportedCapabilities(),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	client.WithContainerTerminal(executor)
	client.WithHostTerminal(executor)
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
	terminalResult := make(chan agentprotocol.TerminalStream, 1)
	terminalErrors := make(chan error, 1)
	terminalRequest := agentprotocol.TerminalOpen{
		Kind:         agentprotocol.TerminalKindContainer,
		DeploymentID: "deployment-1", ProjectID: "project-1",
		ApplicationID: "application-1", EnvironmentID: "environment-1",
		RuntimeTargetID: "target-1", ContainerName: "owndock-container-1",
		CutoverSequence: 1, Columns: 120, Rows: 30,
	}
	go func() {
		terminalStream, terminalErr := registry.OpenTerminal(
			t.Context(), "host-1", "terminal-session-1", terminalRequest,
		)
		terminalResult <- terminalStream
		terminalErrors <- terminalErr
	}()
	select {
	case got := <-executor.opens:
		if got != terminalRequest {
			t.Fatalf("Agent terminal open = %+v", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Agent did not receive terminal open")
	}
	terminalStream := <-terminalResult
	if terminalErr := <-terminalErrors; terminalErr != nil {
		t.Fatal(terminalErr)
	}
	if _, err := terminalStream.Write([]byte("pwd\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case input := <-executor.containerTerminal.input:
		if string(input) != "pwd\n" {
			t.Fatalf("Agent terminal input = %q", input)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Agent did not receive terminal input")
	}
	if err := terminalStream.Resize(t.Context(), 132, 43); err != nil {
		t.Fatal(err)
	}
	select {
	case size := <-executor.containerTerminal.resizes:
		if size != [2]uint16{132, 43} {
			t.Fatalf("Agent terminal resize = %v", size)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Agent did not receive terminal resize")
	}
	executor.containerTerminal.output <- []byte("/workspace\n")
	buffer := make([]byte, 32)
	read, err := terminalStream.Read(buffer)
	if err != nil || string(buffer[:read]) != "/workspace\n" {
		t.Fatalf("Agent terminal output = %q, error = %v", buffer[:read], err)
	}
	if err := terminalStream.Close(); err != nil {
		t.Fatal(err)
	}

	hostResult := make(chan agentprotocol.TerminalStream, 1)
	hostErrors := make(chan error, 1)
	hostRequest := agentprotocol.TerminalOpen{
		Kind: agentprotocol.TerminalKindHost, Columns: 100, Rows: 40,
	}
	go func() {
		hostStream, hostErr := registry.OpenTerminal(
			t.Context(), "host-1", "host-terminal-session-1", hostRequest,
		)
		hostResult <- hostStream
		hostErrors <- hostErr
	}()
	select {
	case got := <-executor.opens:
		if got != hostRequest {
			t.Fatalf("Agent host terminal open = %+v", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Agent did not receive host terminal open")
	}
	hostStream := <-hostResult
	if hostErr := <-hostErrors; hostErr != nil {
		t.Fatal(hostErr)
	}
	if _, err := hostStream.Write([]byte("whoami\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case input := <-executor.hostTerminal.input:
		if string(input) != "whoami\n" {
			t.Fatalf("Agent host terminal input = %q", input)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Agent did not receive host terminal input")
	}
	if err := hostStream.Resize(t.Context(), 140, 50); err != nil {
		t.Fatal(err)
	}
	select {
	case size := <-executor.hostTerminal.resizes:
		if size != [2]uint16{140, 50} {
			t.Fatalf("Agent host terminal resize = %v", size)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Agent did not receive host terminal resize")
	}
	executor.hostTerminal.output <- []byte("owndock-terminal\n")
	read, err = hostStream.Read(buffer)
	if err != nil || string(buffer[:read]) != "owndock-terminal\n" {
		t.Fatalf("Agent host terminal output = %q, error = %v", buffer[:read], err)
	}
	if err := hostStream.Close(); err != nil {
		t.Fatal(err)
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

type synchronizedAgentRepository struct {
	mu    sync.Mutex
	inner agentControlRepositoryStub
}

func (r *synchronizedAgentRepository) List(
	ctx context.Context,
	organizationID string,
) ([]biz.ManagedHost, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.inner.List(ctx, organizationID)
}

func (r *synchronizedAgentRepository) Get(
	ctx context.Context,
	organizationID, hostID string,
) (biz.ManagedHost, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.inner.Get(ctx, organizationID, hostID)
}

func (r *synchronizedAgentRepository) Create(
	ctx context.Context,
	host biz.ManagedHost,
) (biz.ManagedHost, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.inner.Create(ctx, host)
}

func (r *synchronizedAgentRepository) Disable(
	ctx context.Context,
	organizationID, hostID string,
	now time.Time,
) (biz.ManagedHost, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.inner.Disable(ctx, organizationID, hostID, now)
}

func (r *synchronizedAgentRepository) ConnectionMode(
	ctx context.Context,
	organizationID, hostID string,
) (runtimeaccess.Mode, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.inner.ConnectionMode(ctx, organizationID, hostID)
}

func (r *synchronizedAgentRepository) AuthenticateAgent(
	ctx context.Context,
	certificate biz.AgentCertificateIdentity,
	now time.Time,
) (biz.AgentIdentity, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.inner.AuthenticateAgent(ctx, certificate, now)
}

func (r *synchronizedAgentRepository) ConnectAgent(
	ctx context.Context,
	session biz.AgentSession,
	now time.Time,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.inner.ConnectAgent(ctx, session, now)
}

func (r *synchronizedAgentRepository) HeartbeatAgent(
	ctx context.Context,
	session biz.AgentSession,
	now time.Time,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.inner.HeartbeatAgent(ctx, session, now)
}

func (r *synchronizedAgentRepository) DisconnectAgent(
	ctx context.Context,
	session biz.AgentSession,
	now time.Time,
) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.inner.DisconnectAgent(ctx, session, now)
}

type synchronizedAgentAudit struct {
	mu sync.Mutex
}

func (a *synchronizedAgentAudit) Record(
	context.Context,
	sharedaudit.Event,
) error {
	a.mu.Lock()
	a.mu.Unlock()
	return nil
}

type reconnectInventoryExecutor struct {
	firstChunkStarted chan struct{}
	firstChunkOnce    sync.Once
	chunkCalls        atomic.Int64
	mu                sync.Mutex
	snapshots         map[string]struct{}
}

func (e *reconnectInventoryExecutor) Execute(
	ctx context.Context,
	command agentprotocol.AgentCommand,
) (agentprotocol.AgentCommandResult, error) {
	result := agentprotocol.AgentCommandResult{
		CommandID: command.ID,
		Status:    agentprotocol.AgentCommandSucceeded,
	}
	switch command.Kind {
	case agentprotocol.AgentCommandInventoryPrepare:
		e.mu.Lock()
		if e.snapshots == nil {
			e.snapshots = make(map[string]struct{})
		}
		e.snapshots[command.Inventory.ObservationID] = struct{}{}
		e.mu.Unlock()
		result.Inventory = &agentprotocol.RuntimeInventoryResult{
			Manifest: &agentprotocol.RuntimeInventoryManifest{
				ObservationID:     command.Inventory.ObservationID,
				SchemaVersion:     transport.SchemaVersion,
				ExpectedChunks:    1,
				ExpectedResources: 1,
				RetentionSeconds:  600,
				Events: []transport.Event{{
					Kind:       transport.KindContainer,
					RuntimeID:  "container-changed-during-agent-snapshot",
					Action:     transport.EventActionUpdate,
					OccurredAt: time.Now().UTC(),
				}},
			},
		}
	case agentprotocol.AgentCommandInventoryChunk:
		if e.chunkCalls.Add(1) == 1 {
			e.firstChunkOnce.Do(func() { close(e.firstChunkStarted) })
			<-ctx.Done()
			return agentprotocol.AgentCommandResult{}, ctx.Err()
		}
		e.mu.Lock()
		_, snapshotExists := e.snapshots[command.Inventory.ObservationID]
		e.mu.Unlock()
		if !snapshotExists {
			result.Status = agentprotocol.AgentCommandFailed
			result.ErrorCode = "inventory_snapshot_missing"
			return result, nil
		}
		result.Inventory = &agentprotocol.RuntimeInventoryResult{
			Chunk: &transport.Chunk{
				SchemaVersion: transport.SchemaVersion,
				Index:         command.Inventory.ChunkIndex,
				Resources: []transport.Resource{{
					Kind:          transport.KindContainer,
					RuntimeID:     "container-reconnected",
					Name:          "api",
					Container:     &transport.ContainerSummary{State: "running"},
					ObservedAt:    time.Now().UTC(),
					SchemaVersion: transport.SchemaVersion,
				}},
			},
		}
	case agentprotocol.AgentCommandInventoryRelease:
		e.mu.Lock()
		delete(e.snapshots, command.Inventory.ObservationID)
		e.mu.Unlock()
	default:
		return agentprotocol.AgentCommandResult{},
			agentprotocol.ErrCommandInvalid
	}
	return result, nil
}

func (e *reconnectInventoryExecutor) loseSnapshots() {
	e.mu.Lock()
	e.snapshots = make(map[string]struct{})
	e.mu.Unlock()
}

type reconnectInventoryRepository struct {
	mu          sync.Mutex
	observation runtimeinventorybiz.Observation
	chunks      []runtimeinventorybiz.Chunk
	completed   bool
}

type reconnectEventHints struct {
	mu    sync.Mutex
	hints []runtimeinventorybiz.EventHint
}

func (r *reconnectEventHints) RecordEventHint(
	_ context.Context,
	hint runtimeinventorybiz.EventHint,
) error {
	r.mu.Lock()
	r.hints = append(r.hints, hint)
	r.mu.Unlock()
	return nil
}

func (r *reconnectEventHints) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.hints)
}

func (r *reconnectInventoryRepository) Begin(
	_ context.Context,
	observation runtimeinventorybiz.Observation,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.observation = observation
	return nil
}

func (r *reconnectInventoryRepository) Append(
	_ context.Context,
	chunk runtimeinventorybiz.Chunk,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.chunks = append(r.chunks, chunk)
	return nil
}

func (r *reconnectInventoryRepository) Complete(
	_ context.Context,
	observationID, targetID string,
	_ time.Time,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if observationID != r.observation.ID ||
		targetID != r.observation.RuntimeTargetID {
		return runtimeinventorybiz.ErrConflict
	}
	r.completed = true
	return nil
}

func (*reconnectInventoryRepository) Current(
	context.Context,
	runtimeinventorybiz.Query,
) ([]runtimeinventorybiz.Resource, error) {
	return nil, runtimeinventorybiz.ErrNotFound
}

func (r *reconnectInventoryRepository) state() (bool, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.completed, len(r.chunks)
}

func TestRuntimeInventoryContinuesAfterRealAgentReconnect(t *testing.T) {
	runRuntimeInventoryReconnectScenario(t, false)
}

func TestRuntimeInventoryStartsNewObservationAfterSnapshotLossAcrossRealAgentReconnect(
	t *testing.T,
) {
	runRuntimeInventoryReconnectScenario(t, true)
}

func runRuntimeInventoryReconnectScenario(t *testing.T, loseSnapshot bool) {
	t.Helper()
	rawCertificate := []byte("Agent reconnect certificate")
	fingerprint := sha256.Sum256(rawCertificate)
	repository := &synchronizedAgentRepository{inner: agentControlRepositoryStub{
		identity: biz.AgentIdentity{
			ID: "identity-1", OrganizationID: "organization-1",
			ManagedHostID: "host-1", InstanceID: "instance-1",
			CertificateSerial:  "2a",
			CertificateSHA256:  hex.EncodeToString(fingerprint[:]),
			CertificateExpires: time.Now().Add(time.Hour),
			Capabilities:       commandCapabilities(),
		},
		host: biz.ManagedHost{
			ID: "host-1", OrganizationID: "organization-1",
			Status: biz.StatusOffline, ConnectionMode: runtimeaccess.ModeAgent,
			AgentIdentityID: "identity-1", AgentInstanceID: "instance-1",
		},
	}}
	registry, err := managedhostdata.NewConnectionRegistry(2, 4)
	if err != nil {
		t.Fatal(err)
	}
	var serverIdentifier atomic.Int64
	useCase := biz.NewUseCase(
		repository,
		transaction.Passthrough{},
		&synchronizedAgentAudit{},
		func() (string, error) {
			return fmt.Sprintf("server-reconnect-%d", serverIdentifier.Add(1)), nil
		},
		time.Now,
	).WithAgentControl(repository, registry, []string{"v1"})
	stream, err := NewAgentStream(
		useCase, registry, time.Second, time.Second, 3*time.Second, 64*1024,
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

	executor := &reconnectInventoryExecutor{
		firstChunkStarted: make(chan struct{}),
	}
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
				BootID:         "boot-reconnect",
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
	agentRunner, err := agentcontrol.NewRunner(
		client,
		agentcontrol.RunnerConfig{
			MinimumDelay: 5 * time.Millisecond,
			MaximumDelay: 20 * time.Millisecond,
			StableAfter:  time.Second,
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	runContext, stopAgent := context.WithCancel(t.Context())
	agentDone := make(chan error, 1)
	go func() { agentDone <- agentRunner.Run(runContext) }()

	inventoryRepository := &reconnectInventoryRepository{}
	var inventoryIdentifier atomic.Int64
	collector, err := runtimeinventorydata.NewAgentCollector(
		registry,
		inventoryRepository,
		func() (string, error) {
			return fmt.Sprintf("inventory-reconnect-%d", inventoryIdentifier.Add(1)), nil
		},
		time.Now,
		3*time.Second,
		transport.DefaultChunkBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	eventHints := &reconnectEventHints{}
	collector.WithEventHints(eventHints)
	collectionDone := make(chan error, 1)
	go func() {
		collectionDone <- collector.Synchronize(
			t.Context(), "organization-1", "host-1", "target-1",
		)
	}()
	select {
	case <-executor.firstChunkStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("first inventory chunk did not reach Agent")
	}
	if loseSnapshot {
		executor.loseSnapshots()
	}
	registry.DisconnectHost("host-1")
	select {
	case err := <-collectionDone:
		if loseSnapshot && err == nil {
			t.Fatal("Agent restart unexpectedly reused the lost snapshot")
		}
		if !loseSnapshot && err != nil {
			t.Fatalf("inventory collection after reconnect: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("inventory collection did not recover after Agent reconnect")
	}
	if loseSnapshot {
		completed, chunks := inventoryRepository.state()
		if completed || chunks != 0 {
			t.Fatalf(
				"lost snapshot completed / chunks = %v / %d",
				completed,
				chunks,
			)
		}
		collectionDone = make(chan error, 1)
		go func() {
			collectionDone <- collector.Synchronize(
				t.Context(), "organization-1", "host-1", "target-1",
			)
		}()
		select {
		case err := <-collectionDone:
			if err != nil {
				t.Fatalf("new observation after Agent restart: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("new observation did not complete after Agent restart")
		}
	}
	completed, chunks := inventoryRepository.state()
	if !completed || chunks != 1 || executor.chunkCalls.Load() < 2 {
		t.Fatalf(
			"completed / chunks / Agent chunk calls = %v / %d / %d",
			completed,
			chunks,
			executor.chunkCalls.Load(),
		)
	}
	if eventHints.count() != 1 {
		t.Fatalf("Agent event hints crossing real HTTP stream = %d, want 1", eventHints.count())
	}
	stopAgent()
	select {
	case err := <-agentDone:
		if err != nil {
			t.Fatalf("Agent runner stop error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Agent runner did not stop")
	}
}
