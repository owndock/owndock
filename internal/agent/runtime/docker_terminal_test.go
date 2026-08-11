package agentruntime

import (
	"context"
	"errors"
	"net"
	"slices"
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
		!slices.Equal(created.Cmd, []string{"/bin/sh"}) ||
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
