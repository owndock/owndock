package agentruntime

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	mobyclient "github.com/moby/moby/client"

	"github.com/owndock/owndock/internal/shared/agentprotocol"
	"github.com/owndock/owndock/internal/shared/runtimeidentity"
)

const terminalContainerPollInterval = 2 * time.Second

var (
	ErrTerminalTargetUnavailable = errors.New("Agent terminal target is unavailable")
	ErrTerminalStreamUnavailable = errors.New("Agent terminal stream is unavailable")
)

type dockerTerminalEngine interface {
	ContainerInspect(
		context.Context,
		string,
		mobyclient.ContainerInspectOptions,
	) (mobyclient.ContainerInspectResult, error)
	ExecCreate(
		context.Context,
		string,
		mobyclient.ExecCreateOptions,
	) (mobyclient.ExecCreateResult, error)
	ExecAttach(
		context.Context,
		string,
		mobyclient.ExecAttachOptions,
	) (mobyclient.ExecAttachResult, error)
	ExecResize(
		context.Context,
		string,
		mobyclient.ExecResizeOptions,
	) (mobyclient.ExecResizeResult, error)
	Close() error
}

type dockerTerminalEngineFactory func(string) (dockerTerminalEngine, error)

// OpenContainerTerminal creates a fixed-shell TTY against the exact current
// managed container described by the Server. It never accepts an endpoint,
// socket, shell, command, user, environment, workdir, or privilege option.
func (e *DockerExecutor) OpenContainerTerminal(
	ctx context.Context,
	open agentprotocol.TerminalOpen,
) (agentprotocol.TerminalStream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := open.Validate(); err != nil {
		return nil, ErrTerminalTargetUnavailable
	}
	expectedName, err := runtimeidentity.ContainerName(
		open.ProjectID,
		open.ApplicationID,
		open.EnvironmentID,
		open.RuntimeTargetID,
	)
	if err != nil || expectedName != open.ContainerName {
		return nil, ErrTerminalTargetUnavailable
	}
	engine, err := e.newTerminalEngine(e.socketPath)
	if err != nil {
		return nil, ErrTerminalStreamUnavailable
	}
	closeEngine := true
	defer func() {
		if closeEngine {
			_ = engine.Close()
		}
	}()
	initial, err := inspectAgentTerminalContainer(ctx, engine, open)
	if err != nil {
		return nil, err
	}
	var attachment mobyclient.ExecAttachResult
	var execID string
	for _, shell := range []string{"/bin/sh", "/bin/bash", "/bin/ash"} {
		created, createErr := engine.ExecCreate(
			ctx,
			initial.Container.ID,
			mobyclient.ExecCreateOptions{
				TTY: true, AttachStdin: true, AttachStdout: true, AttachStderr: true,
				ConsoleSize: mobyclient.ConsoleSize{
					Height: uint(open.Rows), Width: uint(open.Columns),
				},
				Cmd: []string{shell},
			},
		)
		if createErr != nil || created.ID == "" {
			continue
		}
		attached, attachErr := engine.ExecAttach(
			ctx,
			created.ID,
			mobyclient.ExecAttachOptions{
				TTY: true,
				ConsoleSize: mobyclient.ConsoleSize{
					Height: uint(open.Rows), Width: uint(open.Columns),
				},
			},
		)
		if attachErr != nil {
			continue
		}
		attachment, execID = attached, created.ID
		break
	}
	if execID == "" {
		return nil, ErrTerminalStreamUnavailable
	}
	current, err := inspectAgentTerminalContainer(ctx, engine, open)
	if err != nil || current.Container.ID != initial.Container.ID {
		attachment.Close()
		return nil, ErrTerminalTargetUnavailable
	}
	streamContext, cancel := context.WithCancel(ctx)
	stream := &dockerTerminalStream{
		engine: engine, attachment: attachment, execID: execID,
		containerID: initial.Container.ID, open: open, cancel: cancel,
		closed: make(chan struct{}),
	}
	closeEngine = false
	go stream.watchContainer(streamContext, e.pollInterval)
	return stream, nil
}

func inspectAgentTerminalContainer(
	ctx context.Context,
	engine dockerTerminalEngine,
	open agentprotocol.TerminalOpen,
) (mobyclient.ContainerInspectResult, error) {
	result, err := engine.ContainerInspect(
		ctx,
		open.ContainerName,
		mobyclient.ContainerInspectOptions{},
	)
	if err != nil || !matchesAgentTerminalContainer(result, open) {
		return mobyclient.ContainerInspectResult{}, ErrTerminalTargetUnavailable
	}
	return result, nil
}

func matchesAgentTerminalContainer(
	result mobyclient.ContainerInspectResult,
	open agentprotocol.TerminalOpen,
) bool {
	if result.Container.ID == "" || result.Container.State == nil ||
		!result.Container.State.Running || result.Container.Config == nil {
		return false
	}
	labels := result.Container.Config.Labels
	return labels[runtimeidentity.DeploymentIDLabel] == open.DeploymentID &&
		labels[runtimeidentity.CutoverSequenceLabel] == fmt.Sprint(open.CutoverSequence) &&
		labels[runtimeidentity.ProjectIDLabel] == open.ProjectID &&
		labels[runtimeidentity.ApplicationIDLabel] == open.ApplicationID &&
		labels[runtimeidentity.EnvironmentIDLabel] == open.EnvironmentID
}

type dockerTerminalStream struct {
	engine      dockerTerminalEngine
	attachment  mobyclient.ExecAttachResult
	execID      string
	containerID string
	open        agentprotocol.TerminalOpen
	cancel      context.CancelFunc
	closeOnce   sync.Once
	closed      chan struct{}
}

func (s *dockerTerminalStream) Read(payload []byte) (int, error) {
	return s.attachment.Reader.Read(payload)
}

func (s *dockerTerminalStream) Write(payload []byte) (int, error) {
	return s.attachment.Conn.Write(payload)
}

func (s *dockerTerminalStream) Resize(
	ctx context.Context,
	columns, rows uint16,
) error {
	if columns < 1 || rows < 1 || columns > agentprotocol.MaximumTerminalColumns ||
		rows > agentprotocol.MaximumTerminalRows {
		return agentprotocol.ErrTerminalFrameInvalid
	}
	select {
	case <-s.closed:
		return ErrTerminalStreamUnavailable
	default:
	}
	_, err := s.engine.ExecResize(ctx, s.execID, mobyclient.ExecResizeOptions{
		Height: uint(rows), Width: uint(columns),
	})
	if err != nil {
		return ErrTerminalStreamUnavailable
	}
	return nil
}

func (s *dockerTerminalStream) Close() error {
	s.closeOnce.Do(func() {
		s.cancel()
		s.attachment.Close()
		_ = s.engine.Close()
		close(s.closed)
	})
	return nil
}

func (s *dockerTerminalStream) watchContainer(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = terminalContainerPollInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = s.Close()
			return
		case <-ticker.C:
			result, err := inspectAgentTerminalContainer(ctx, s.engine, s.open)
			if err != nil || result.Container.ID != s.containerID {
				_ = s.Close()
				return
			}
		}
	}
}

func newLocalDockerTerminalEngine(socketPath string) (dockerTerminalEngine, error) {
	return mobyclient.New(mobyclient.WithHost("unix://" + socketPath))
}

var _ agentprotocol.TerminalStream = (*dockerTerminalStream)(nil)
