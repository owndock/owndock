package agentruntime

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	mobyclient "github.com/moby/moby/client"

	"github.com/owndock/owndock/internal/shared/agentprotocol"
	"github.com/owndock/owndock/internal/shared/runtimeidentity"
)

type dockerTerminalEngineStub struct {
	mu       sync.Mutex
	inspect  mobyclient.ContainerInspectResult
	creates  []mobyclient.ExecCreateOptions
	attaches []mobyclient.ExecAttachOptions
	resizes  []mobyclient.ExecResizeOptions
	client   net.Conn
	server   net.Conn
	closed   bool
}

func newDockerTerminalEngineStub(
	inspect mobyclient.ContainerInspectResult,
) *dockerTerminalEngineStub {
	clientConnection, serverConnection := net.Pipe()
	return &dockerTerminalEngineStub{
		inspect: inspect, client: clientConnection, server: serverConnection,
	}
}

func (e *dockerTerminalEngineStub) ContainerInspect(
	context.Context,
	string,
	mobyclient.ContainerInspectOptions,
) (mobyclient.ContainerInspectResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.inspect, nil
}

func (e *dockerTerminalEngineStub) ExecCreate(
	_ context.Context,
	_ string,
	options mobyclient.ExecCreateOptions,
) (mobyclient.ExecCreateResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.creates = append(e.creates, options)
	return mobyclient.ExecCreateResult{ID: "exec-1"}, nil
}

func (e *dockerTerminalEngineStub) ExecAttach(
	_ context.Context,
	_ string,
	options mobyclient.ExecAttachOptions,
) (mobyclient.ExecAttachResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.attaches = append(e.attaches, options)
	return mobyclient.ExecAttachResult{HijackedResponse: mobyclient.NewHijackedResponse(
		e.client,
		"application/vnd.docker.raw-stream",
	)}, nil
}

func (e *dockerTerminalEngineStub) ExecInspect(
	_ context.Context,
	execID string,
	_ mobyclient.ExecInspectOptions,
) (mobyclient.ExecInspectResult, error) {
	return mobyclient.ExecInspectResult{
		ID: execID, ContainerID: e.inspect.Container.ID, Running: false,
	}, nil
}

func (e *dockerTerminalEngineStub) ExecStart(
	context.Context,
	string,
	mobyclient.ExecStartOptions,
) (mobyclient.ExecStartResult, error) {
	return mobyclient.ExecStartResult{}, nil
}

func (e *dockerTerminalEngineStub) ExecResize(
	_ context.Context,
	_ string,
	options mobyclient.ExecResizeOptions,
) (mobyclient.ExecResizeResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.resizes = append(e.resizes, options)
	return mobyclient.ExecResizeResult{}, nil
}

func (e *dockerTerminalEngineStub) Close() error {
	e.mu.Lock()
	e.closed = true
	e.mu.Unlock()
	return nil
}

func TestDockerExecutorOpensConstrainedContainerTerminal(t *testing.T) {
	open := agentTerminalOpen(t)
	engine := newDockerTerminalEngineStub(agentTerminalInspection(open, "container-1"))
	defer func() { _ = engine.server.Close() }()
	executor := &DockerExecutor{
		socketPath:        "/var/run/docker.sock",
		newTerminalEngine: func(string) (dockerTerminalEngine, error) { return engine, nil },
		pollInterval:      time.Hour,
	}
	stream, err := executor.OpenContainerTerminal(context.Background(), open)
	if err != nil {
		t.Fatalf("OpenContainerTerminal() error = %v", err)
	}
	defer stream.Close()
	if len(engine.creates) != 1 {
		t.Fatalf("ExecCreate calls = %d", len(engine.creates))
	}
	created := engine.creates[0]
	if !created.TTY || !created.AttachStdin || !created.AttachStdout || !created.AttachStderr ||
		created.Privileged || created.User != "" || created.WorkingDir != "" ||
		len(created.Env) != 0 || created.DetachKeys != "" ||
		len(created.Cmd) != 6 || created.Cmd[0] != "/bin/sh" ||
		created.Cmd[1] != "-c" || created.Cmd[2] != terminalShellWrapper ||
		created.Cmd[3] != "owndock-terminal" ||
		!terminalMarkerRule.MatchString(created.Cmd[4]) ||
		created.Cmd[5] != "/bin/sh" ||
		created.ConsoleSize.Width != 120 || created.ConsoleSize.Height != 30 {
		t.Fatalf("unsafe or unexpected exec options: %#v", created)
	}
	if err := stream.Resize(context.Background(), 132, 43); err != nil {
		t.Fatalf("Resize() error = %v", err)
	}
	if len(engine.resizes) != 1 || engine.resizes[0].Width != 132 ||
		engine.resizes[0].Height != 43 {
		t.Fatalf("resize options = %#v", engine.resizes)
	}
}

func TestDockerExecutorRejectsServerContainerNameMismatch(t *testing.T) {
	open := agentTerminalOpen(t)
	open.ContainerName = "owndock-attacker-selected"
	engine := newDockerTerminalEngineStub(agentTerminalInspection(open, "container-1"))
	defer func() {
		_ = engine.client.Close()
		_ = engine.server.Close()
	}()
	executor := &DockerExecutor{
		socketPath:        "/var/run/docker.sock",
		newTerminalEngine: func(string) (dockerTerminalEngine, error) { return engine, nil },
	}
	_, err := executor.OpenContainerTerminal(context.Background(), open)
	if !errors.Is(err, ErrTerminalTargetUnavailable) {
		t.Fatalf("OpenContainerTerminal() error = %v", err)
	}
	if len(engine.creates) != 0 {
		t.Fatal("exec was created for a non-derived container name")
	}
}

func TestDockerExecutorRecoveryFencesActiveTerminal(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewFileTerminalExecutionStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	containerID := strings.Repeat("c", 64)
	active := terminalExecution{
		execID: strings.Repeat("a", 64), containerID: containerID,
		marker: "/tmp/.owndock-terminal-" + strings.Repeat("d", 32),
		shell:  "/bin/sh",
	}
	inactive := terminalExecution{
		execID: strings.Repeat("b", 64), containerID: containerID,
		marker: "/tmp/.owndock-terminal-" + strings.Repeat("e", 32),
		shell:  "/bin/sh",
	}
	if err := store.Add(active); err != nil {
		t.Fatal(err)
	}
	if err := store.Add(inactive); err != nil {
		t.Fatal(err)
	}
	engine := newDockerTerminalEngineStub(mobyclient.ContainerInspectResult{
		Container: container.InspectResponse{ID: containerID},
	})
	defer func() {
		_ = engine.client.Close()
		_ = engine.server.Close()
	}()
	executor := &DockerExecutor{
		newTerminalEngine: func(string) (dockerTerminalEngine, error) {
			return engine, nil
		},
		terminalExecutions: store,
	}
	executor.markTerminalActive(active.execID)
	if err := executor.RecoverContainerTerminals(t.Context()); err != nil {
		t.Fatalf("RecoverContainerTerminals() error = %v", err)
	}
	entries, err := store.List()
	if err != nil || len(entries) != 1 || entries[0] != active {
		t.Fatalf("entries after fenced recovery = %#v, %v", entries, err)
	}
	executor.markTerminalInactive(active.execID)
	if err := executor.RecoverContainerTerminals(t.Context()); err != nil {
		t.Fatalf("second RecoverContainerTerminals() error = %v", err)
	}
	entries, err = store.List()
	if err != nil || len(entries) != 0 {
		t.Fatalf("entries after inactive recovery = %#v, %v", entries, err)
	}
}

func TestDockerTerminalClosingReleasesRecoveryFenceBeforeCleanup(t *testing.T) {
	engine := newDockerTerminalEngineStub(mobyclient.ContainerInspectResult{})
	defer func() { _ = engine.server.Close() }()
	executor := &DockerExecutor{}
	executor.markTerminalActive("exec-1")
	closing := make(chan struct{})
	stream := &dockerTerminalStream{
		engine: engine,
		attachment: mobyclient.ExecAttachResult{
			HijackedResponse: mobyclient.NewHijackedResponse(
				engine.client,
				"application/vnd.docker.raw-stream",
			),
		},
		execID: "exec-1",
		onClosing: func() {
			executor.markTerminalInactive("exec-1")
			close(closing)
		},
		cancel: func() {},
		closed: make(chan struct{}),
	}
	done := make(chan struct{})
	go func() {
		_ = stream.Close()
		close(done)
	}()
	select {
	case <-closing:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("terminal recovery fence was not released before cleanup")
	}
	if executor.terminalIsActive("exec-1") {
		t.Fatal("closing terminal remained fenced as active")
	}
	select {
	case <-done:
		t.Fatal("terminal cleanup unexpectedly completed before blocked write")
	default:
	}
	_ = engine.server.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("terminal cleanup did not finish")
	}
}

func agentTerminalOpen(t *testing.T) agentprotocol.TerminalOpen {
	t.Helper()
	containerName, err := runtimeidentity.ContainerName(
		"project-1",
		"application-1",
		"environment-1",
		"target-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	return agentprotocol.TerminalOpen{
		Kind:         agentprotocol.TerminalKindContainer,
		DeploymentID: "deployment-1", ProjectID: "project-1",
		ApplicationID: "application-1", EnvironmentID: "environment-1",
		RuntimeTargetID: "target-1", ContainerName: containerName,
		CutoverSequence: 7, Columns: 120, Rows: 30,
	}
}

func agentTerminalInspection(
	open agentprotocol.TerminalOpen,
	containerID string,
) mobyclient.ContainerInspectResult {
	return mobyclient.ContainerInspectResult{Container: container.InspectResponse{
		ID:    containerID,
		State: &container.State{Running: true},
		Config: &container.Config{Labels: map[string]string{
			runtimeidentity.DeploymentIDLabel:    open.DeploymentID,
			runtimeidentity.CutoverSequenceLabel: "7",
			runtimeidentity.ProjectIDLabel:       open.ProjectID,
			runtimeidentity.ApplicationIDLabel:   open.ApplicationID,
			runtimeidentity.EnvironmentIDLabel:   open.EnvironmentID,
		}},
	}}
}
