package agentruntime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	cerrdefs "github.com/containerd/errdefs"
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
	ExecInspect(
		context.Context,
		string,
		mobyclient.ExecInspectOptions,
	) (mobyclient.ExecInspectResult, error)
	ExecStart(
		context.Context,
		string,
		mobyclient.ExecStartOptions,
	) (mobyclient.ExecStartResult, error)
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
	var execution terminalExecution
	for _, shell := range []string{"/bin/sh", "/bin/bash", "/bin/ash"} {
		marker, markerErr := newTerminalMarker()
		if markerErr != nil {
			return nil, ErrTerminalStreamUnavailable
		}
		created, createErr := engine.ExecCreate(
			ctx,
			initial.Container.ID,
			mobyclient.ExecCreateOptions{
				TTY: true, AttachStdin: true, AttachStdout: true, AttachStderr: true,
				ConsoleSize: mobyclient.ConsoleSize{
					Height: uint(open.Rows), Width: uint(open.Columns),
				},
				Cmd: []string{
					shell, "-c", terminalShellWrapper,
					"owndock-terminal", marker, shell,
				},
			},
		)
		if createErr != nil || created.ID == "" {
			continue
		}
		execution = terminalExecution{
			execID: created.ID, containerID: initial.Container.ID,
			marker: marker, shell: shell,
		}
		if e.terminalExecutions != nil {
			if storeErr := e.terminalExecutions.Add(execution); storeErr != nil {
				return nil, ErrTerminalStreamUnavailable
			}
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
			if e.terminalExecutions != nil {
				_ = e.terminalExecutions.Remove(created.ID)
			}
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
		requestTerminalExit(&attachment)
		if e.terminalExecutions != nil {
			cleanupContext, cancel := context.WithTimeout(ctx, 4*time.Second)
			_ = signalTerminalExecutionStop(cleanupContext, engine, execution)
			if waitForTerminalExecutionStop(cleanupContext, engine, execID) == nil {
				_ = e.terminalExecutions.Remove(execID)
			}
			cancel()
		}
		return nil, ErrTerminalTargetUnavailable
	}
	streamContext, cancel := context.WithCancel(ctx)
	stream := &dockerTerminalStream{
		engine: engine, attachment: attachment, execID: execID,
		containerID: initial.Container.ID, open: open, cancel: cancel,
		terminalExecutions: e.terminalExecutions,
		execution:          execution,
		closed:             make(chan struct{}),
	}
	closeEngine = false
	go stream.watchContainer(streamContext, e.pollInterval)
	return stream, nil
}

const terminalShellWrapper = `marker=$1
shell=$2
/bin/mkdir -- "$marker" || exit 125
(
	trap '' HUP
	while [ -d "$marker" ]; do sleep 1; done
	kill -TERM "$$" 2>/dev/null || true
	sleep 1
	kill -KILL "$$" 2>/dev/null || true
) </dev/null >/dev/null 2>&1 &
exec "$shell"
`

func newTerminalMarker() (string, error) {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", err
	}
	return "/tmp/.owndock-terminal-" + hex.EncodeToString(token[:]), nil
}

// RecoverContainerTerminals closes every fixed-shell exec left in the durable
// registry by an abruptly terminated Agent. A terminal stays fail-closed until
// the old process has stopped and its record is durably removed.
func (e *DockerExecutor) RecoverContainerTerminals(ctx context.Context) error {
	if e.terminalExecutions == nil {
		return nil
	}
	entries, err := e.terminalExecutions.List()
	if err != nil {
		return fmt.Errorf("list terminal recovery records: %w", ErrTerminalStreamUnavailable)
	}
	if len(entries) == 0 {
		return nil
	}
	engine, err := e.newTerminalEngine(e.socketPath)
	if err != nil {
		return fmt.Errorf("open terminal recovery engine: %w", ErrTerminalStreamUnavailable)
	}
	defer func() { _ = engine.Close() }()
	for _, entry := range entries {
		if err := recoverTerminalExecution(ctx, engine, entry); err != nil {
			return err
		}
		if err := e.terminalExecutions.Remove(entry.execID); err != nil {
			return fmt.Errorf("commit terminal recovery: %w", ErrTerminalStreamUnavailable)
		}
	}
	return nil
}

func recoverTerminalExecution(
	ctx context.Context,
	engine dockerTerminalEngine,
	entry terminalExecution,
) error {
	inspection, err := engine.ExecInspect(
		ctx,
		entry.execID,
		mobyclient.ExecInspectOptions{},
	)
	if cerrdefs.IsNotFound(err) {
		return nil
	}
	if err != nil || inspection.ID != entry.execID ||
		inspection.ContainerID != entry.containerID {
		return fmt.Errorf("inspect terminal recovery target: %w", ErrTerminalStreamUnavailable)
	}
	if !inspection.Running {
		return nil
	}
	if err := signalTerminalExecutionStop(ctx, engine, entry); err != nil {
		return fmt.Errorf("signal terminal recovery target: %w", ErrTerminalStreamUnavailable)
	}
	if err := waitForTerminalExecutionStop(ctx, engine, entry.execID); err != nil {
		return fmt.Errorf("wait for terminal recovery target: %w", ErrTerminalStreamUnavailable)
	}
	return nil
}

func signalTerminalExecutionStop(
	ctx context.Context,
	engine dockerTerminalEngine,
	entry terminalExecution,
) error {
	created, err := engine.ExecCreate(
		ctx,
		entry.containerID,
		mobyclient.ExecCreateOptions{
			Cmd: []string{"/bin/rmdir", "--", entry.marker},
		},
	)
	if err != nil || created.ID == "" {
		return ErrTerminalStreamUnavailable
	}
	if _, err := engine.ExecStart(
		ctx,
		created.ID,
		mobyclient.ExecStartOptions{Detach: true},
	); err != nil {
		return ErrTerminalStreamUnavailable
	}
	return nil
}

func requestTerminalExit(attachment *mobyclient.ExecAttachResult) {
	_ = attachment.Conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	_, _ = attachment.Conn.Write([]byte("exit\n"))
	_ = attachment.CloseWrite()
	attachment.Close()
}

func waitForTerminalExecutionStop(
	ctx context.Context,
	engine dockerTerminalEngine,
	execID string,
) error {
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		inspection, err := engine.ExecInspect(
			ctx,
			execID,
			mobyclient.ExecInspectOptions{},
		)
		if cerrdefs.IsNotFound(err) || err == nil && !inspection.Running {
			return nil
		}
		if err != nil {
			return ErrTerminalStreamUnavailable
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return ErrTerminalStreamUnavailable
		case <-ticker.C:
		}
	}
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
	engine             dockerTerminalEngine
	attachment         mobyclient.ExecAttachResult
	execID             string
	containerID        string
	open               agentprotocol.TerminalOpen
	terminalExecutions terminalExecutionStore
	execution          terminalExecution
	cancel             context.CancelFunc
	closeOnce          sync.Once
	closed             chan struct{}
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
		requestTerminalExit(&s.attachment)
		if s.terminalExecutions != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			_ = signalTerminalExecutionStop(ctx, s.engine, s.execution)
			if waitForTerminalExecutionStop(ctx, s.engine, s.execID) == nil {
				_ = s.terminalExecutions.Remove(s.execID)
			}
			cancel()
		}
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
