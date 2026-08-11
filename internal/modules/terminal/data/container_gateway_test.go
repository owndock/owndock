package data

import (
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	mobyclient "github.com/moby/moby/client"

	"github.com/owndock/owndock/internal/adapters/dockerengine"
	terminalbiz "github.com/owndock/owndock/internal/modules/terminal/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/runtimeidentity"
)

type containerCredentialResolverStub struct {
	credential dockerengine.TLSCredential
	err        error
}

func (r *containerCredentialResolverStub) ResolveDirectCredential(
	context.Context,
	runtimeaccess.Connection,
) (dockerengine.TLSCredential, error) {
	return r.credential, r.err
}

type containerExecEngineStub struct {
	mu            sync.Mutex
	inspect       mobyclient.ContainerInspectResult
	inspectErr    error
	createOptions []mobyclient.ExecCreateOptions
	attachOptions []mobyclient.ExecAttachOptions
	resizeOptions []mobyclient.ExecResizeOptions
	clientConn    net.Conn
	serverConn    net.Conn
	closed        bool
}

func newContainerExecEngineStub(
	inspect mobyclient.ContainerInspectResult,
) *containerExecEngineStub {
	clientConnection, serverConnection := net.Pipe()
	return &containerExecEngineStub{
		inspect: inspect, clientConn: clientConnection, serverConn: serverConnection,
	}
}

func (e *containerExecEngineStub) ContainerInspect(
	context.Context,
	string,
	mobyclient.ContainerInspectOptions,
) (mobyclient.ContainerInspectResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.inspect, e.inspectErr
}

func (e *containerExecEngineStub) ExecCreate(
	_ context.Context,
	containerID string,
	options mobyclient.ExecCreateOptions,
) (mobyclient.ExecCreateResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.createOptions = append(e.createOptions, options)
	if containerID != e.inspect.Container.ID {
		return mobyclient.ExecCreateResult{}, errors.New("unexpected container")
	}
	return mobyclient.ExecCreateResult{ID: "exec-1"}, nil
}

func (e *containerExecEngineStub) ExecAttach(
	_ context.Context,
	_ string,
	options mobyclient.ExecAttachOptions,
) (mobyclient.ExecAttachResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.attachOptions = append(e.attachOptions, options)
	return mobyclient.ExecAttachResult{HijackedResponse: mobyclient.NewHijackedResponse(
		e.clientConn,
		"application/vnd.docker.raw-stream",
	)}, nil
}

func (e *containerExecEngineStub) ExecResize(
	_ context.Context,
	_ string,
	options mobyclient.ExecResizeOptions,
) (mobyclient.ExecResizeResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.resizeOptions = append(e.resizeOptions, options)
	return mobyclient.ExecResizeResult{}, nil
}

func (e *containerExecEngineStub) Close() error {
	e.mu.Lock()
	e.closed = true
	e.mu.Unlock()
	return nil
}

func (e *containerExecEngineStub) replaceContainerID(id string) {
	e.mu.Lock()
	e.inspect.Container.ID = id
	e.mu.Unlock()
}

func TestDirectContainerGatewayOpensConstrainedCurrentContainer(t *testing.T) {
	target := directContainerTarget(t)
	engine := newContainerExecEngineStub(authorizedContainer(target, "container-1"))
	credential := dockerengine.TLSCredential{
		CACertificate: []byte("ca"), ClientCertificate: []byte("cert"), ClientKey: []byte("key"),
	}
	resolver := &containerCredentialResolverStub{credential: credential}
	gateway, err := NewDirectContainerGateway(resolver)
	if err != nil {
		t.Fatalf("NewDirectContainerGateway() error = %v", err)
	}
	gateway.pollInterval = time.Hour
	gateway.openEngine = func(
		runtimeaccess.Connection,
		dockerengine.TLSCredential,
	) (containerExecEngine, error) {
		return engine, nil
	}

	stream, err := gateway.OpenContainer(
		context.Background(),
		"terminal-session-1",
		target,
		terminalbiz.TerminalSize{Columns: 100, Rows: 40},
	)
	if err != nil {
		t.Fatalf("OpenContainer() error = %v", err)
	}
	defer func() {
		_ = stream.Close()
		_ = engine.serverConn.Close()
	}()
	if len(engine.createOptions) != 1 {
		t.Fatalf("ExecCreate calls = %d, want 1", len(engine.createOptions))
	}
	created := engine.createOptions[0]
	if !created.TTY || !created.AttachStdin || !created.AttachStdout || !created.AttachStderr ||
		created.Privileged || created.User != "" || created.WorkingDir != "" ||
		created.DetachKeys != "" || len(created.Env) != 0 ||
		!slices.Equal(created.Cmd, []string{"/bin/sh"}) ||
		created.ConsoleSize.Height != 40 || created.ConsoleSize.Width != 100 {
		t.Fatalf("unsafe or unexpected exec options: %#v", created)
	}
	if len(engine.attachOptions) != 1 || !engine.attachOptions[0].TTY ||
		engine.attachOptions[0].ConsoleSize.Height != 40 ||
		engine.attachOptions[0].ConsoleSize.Width != 100 {
		t.Fatalf("unexpected attach options: %#v", engine.attachOptions)
	}
	if !allZero(credential.CACertificate) || !allZero(credential.ClientCertificate) ||
		!allZero(credential.ClientKey) {
		t.Fatal("credential bytes were not cleared after opening Docker client")
	}

	readDone := make(chan error, 1)
	go func() {
		_, writeErr := engine.serverConn.Write([]byte("ready"))
		readDone <- writeErr
	}()
	payload := make([]byte, 5)
	if _, err := io.ReadFull(stream, payload); err != nil || string(payload) != "ready" {
		t.Fatalf("Read() = %q, %v", payload, err)
	}
	if err := <-readDone; err != nil {
		t.Fatalf("peer Write() error = %v", err)
	}
	writeDone := make(chan string, 1)
	go func() {
		incoming := make([]byte, 3)
		_, _ = io.ReadFull(engine.serverConn, incoming)
		writeDone <- string(incoming)
	}()
	if _, err := stream.Write([]byte("pwd")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if incoming := <-writeDone; incoming != "pwd" {
		t.Fatalf("peer received %q, want pwd", incoming)
	}
	if err := stream.Resize(
		context.Background(),
		terminalbiz.TerminalSize{Columns: 132, Rows: 43},
	); err != nil {
		t.Fatalf("Resize() error = %v", err)
	}
	if len(engine.resizeOptions) != 1 || engine.resizeOptions[0].Width != 132 ||
		engine.resizeOptions[0].Height != 43 {
		t.Fatalf("unexpected resize options: %#v", engine.resizeOptions)
	}
}

func TestDirectContainerGatewayRejectsContainerIdentityMismatch(t *testing.T) {
	target := directContainerTarget(t)
	inspection := authorizedContainer(target, "container-1")
	inspection.Container.Config.Labels[runtimeidentity.DeploymentIDLabel] = "another-deployment"
	engine := newContainerExecEngineStub(inspection)
	defer func() { _ = engine.serverConn.Close() }()
	gateway := testDirectContainerGateway(engine)

	_, err := gateway.OpenContainer(
		context.Background(), "terminal-session-1", target, terminalbiz.DefaultTerminalSize(),
	)
	if !errors.Is(err, terminalbiz.ErrTargetUnavailable) {
		t.Fatalf("OpenContainer() error = %v, want target unavailable", err)
	}
	if len(engine.createOptions) != 0 {
		t.Fatal("gateway created an exec before validating container identity")
	}
}

func TestDirectContainerGatewayClosesWhenDeploymentIsReplaced(t *testing.T) {
	target := directContainerTarget(t)
	engine := newContainerExecEngineStub(authorizedContainer(target, "container-1"))
	defer func() { _ = engine.serverConn.Close() }()
	gateway := testDirectContainerGateway(engine)
	gateway.pollInterval = time.Millisecond
	stream, err := gateway.OpenContainer(
		context.Background(), "terminal-session-1", target, terminalbiz.DefaultTerminalSize(),
	)
	if err != nil {
		t.Fatalf("OpenContainer() error = %v", err)
	}
	engine.replaceContainerID("container-2")
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		engine.mu.Lock()
		closed := engine.closed
		engine.mu.Unlock()
		if closed {
			if err := stream.Resize(context.Background(), terminalbiz.DefaultTerminalSize()); !errors.Is(err, terminalbiz.ErrStreamUnavailable) {
				t.Fatalf("Resize() after replacement error = %v", err)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("stream was not closed after deployment replacement")
}

func testDirectContainerGateway(engine containerExecEngine) *DirectContainerGateway {
	gateway, _ := NewDirectContainerGateway(&containerCredentialResolverStub{
		credential: dockerengine.TLSCredential{
			CACertificate: []byte("ca"), ClientCertificate: []byte("cert"), ClientKey: []byte("key"),
		},
	})
	gateway.openEngine = func(
		runtimeaccess.Connection,
		dockerengine.TLSCredential,
	) (containerExecEngine, error) {
		return engine, nil
	}
	return gateway
}

func directContainerTarget(t *testing.T) terminalbiz.Target {
	t.Helper()
	connection, err := runtimeaccess.NewDirectDocker(
		"host-1",
		"tcp://docker.example.invalid:2376",
		"docker.example.invalid",
		"secret://runtime/docker-production",
	)
	if err != nil {
		t.Fatalf("NewDirectDocker() error = %v", err)
	}
	name, err := runtimeidentity.ContainerName("project-1", "application-1", "production", "target-1")
	if err != nil {
		t.Fatalf("ContainerName() error = %v", err)
	}
	return terminalbiz.Target{
		Kind: terminalbiz.KindContainer, OrganizationID: "organization-1", ProjectID: "project-1",
		ApplicationID: "application-1", EnvironmentID: "production",
		ManagedHostID: "host-1", RuntimeTargetID: "target-1", DeploymentID: "deployment-1",
		RunningInstanceID: "deployment-1:7", InstanceGeneration: 7, ContainerName: name,
		EnvironmentStage: "production", ConnectionMode: runtimeaccess.ModeDirectDocker,
		Connection: connection,
	}
}

func authorizedContainer(
	target terminalbiz.Target,
	containerID string,
) mobyclient.ContainerInspectResult {
	return mobyclient.ContainerInspectResult{Container: container.InspectResponse{
		ID:    containerID,
		State: &container.State{Running: true},
		Config: &container.Config{Labels: map[string]string{
			runtimeidentity.DeploymentIDLabel:    target.DeploymentID,
			runtimeidentity.CutoverSequenceLabel: "7",
			runtimeidentity.ProjectIDLabel:       target.ProjectID,
			runtimeidentity.ApplicationIDLabel:   target.ApplicationID,
			runtimeidentity.EnvironmentIDLabel:   target.EnvironmentID,
		}},
	}}
}

func allZero(value []byte) bool {
	return !slices.ContainsFunc(value, func(item byte) bool { return item != 0 })
}
