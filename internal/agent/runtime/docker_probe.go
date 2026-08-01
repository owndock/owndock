package agentruntime

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/moby/moby/client"

	"github.com/owndock/owndock/internal/shared/agentprotocol"
)

var (
	ErrInvalidDockerSocket    = errors.New("Agent Docker socket path is invalid")
	ErrRuntimeExecutorMissing = errors.New(
		"Agent runtime executor dependency is missing",
	)
)

type dockerProbeEngine interface {
	Ping(context.Context, client.PingOptions) (client.PingResult, error)
	Close() error
}

type dockerProbeEngineFactory func(string) (dockerProbeEngine, error)

type DockerExecutor struct {
	mu sync.Mutex

	socketPath          string
	newEngine           dockerProbeEngineFactory
	newDeploymentEngine dockerDeploymentEngineFactory
	newInventoryEngine  dockerInventoryEngineFactory
	cache               ResultCache
	cutovers            CutoverStore
	now                 func() time.Time
	pollInterval        time.Duration
	pending             map[string]*pendingProbeExecution
	inventorySnapshots  map[string]*inventorySnapshot
}

type pendingProbeExecution struct {
	command agentprotocol.AgentCommand
	done    chan struct{}
	result  agentprotocol.AgentCommandResult
	err     error
}

func NewDockerExecutor(
	socketPath string,
	cache ResultCache,
	cutovers CutoverStore,
) (*DockerExecutor, error) {
	socketPath = strings.TrimSpace(socketPath)
	if !validDockerSocketPath(socketPath) {
		return nil, ErrInvalidDockerSocket
	}
	if cache == nil || cutovers == nil {
		return nil, ErrRuntimeExecutorMissing
	}
	return &DockerExecutor{
		socketPath:          socketPath,
		newEngine:           newLocalDockerProbeEngine,
		newDeploymentEngine: newLocalDockerDeploymentEngine,
		newInventoryEngine:  newLocalDockerInventoryEngine,
		cache:               cache,
		cutovers:            cutovers,
		now:                 time.Now,
		pollInterval:        500 * time.Millisecond,
		pending:             make(map[string]*pendingProbeExecution),
		inventorySnapshots:  make(map[string]*inventorySnapshot),
	}, nil
}

func (e *DockerExecutor) Execute(
	ctx context.Context,
	command agentprotocol.AgentCommand,
) (agentprotocol.AgentCommandResult, error) {
	if err := command.Validate(); err != nil {
		return agentprotocol.AgentCommandResult{}, err
	}
	if command.Kind.DurableResult() {
		if result, exists, err := e.cache.Lookup(command); err != nil || exists {
			return result, err
		}
	}
	pending, owner, err := e.begin(command)
	if err != nil {
		return agentprotocol.AgentCommandResult{}, err
	}
	if !owner {
		return waitForProbeExecution(ctx, pending)
	}
	result, executeError := e.execute(ctx, command)
	e.finish(command.ID, pending, result, executeError)
	return result, executeError
}

func (e *DockerExecutor) execute(
	ctx context.Context,
	command agentprotocol.AgentCommand,
) (agentprotocol.AgentCommandResult, error) {
	result := agentprotocol.AgentCommandResult{
		CommandID: command.ID,
	}
	if !command.Deadline.After(e.now()) {
		result.Status = agentprotocol.AgentCommandFailed
		result.ErrorCode = "command_expired"
		return result, e.store(command, result)
	}

	commandContext, cancel := context.WithDeadline(ctx, command.Deadline)
	defer cancel()
	var executeError error
	switch command.Kind {
	case agentprotocol.AgentCommandRuntimeProbe:
		result, executeError = e.probeRuntime(commandContext, command)
	case agentprotocol.AgentCommandDeploymentPrepare,
		agentprotocol.AgentCommandDeploymentStage,
		agentprotocol.AgentCommandDeploymentActivate,
		agentprotocol.AgentCommandDeploymentCancel:
		result, executeError = e.executeDeployment(
			commandContext,
			command,
		)
	case agentprotocol.AgentCommandInventoryPrepare,
		agentprotocol.AgentCommandInventoryChunk,
		agentprotocol.AgentCommandInventoryRelease,
		agentprotocol.AgentCommandInventoryEvents:
		result, executeError = e.executeInventory(commandContext, command)
	default:
		return agentprotocol.AgentCommandResult{},
			agentprotocol.ErrCommandInvalid
	}
	if executeError != nil {
		if parentError := ctx.Err(); parentError != nil {
			return agentprotocol.AgentCommandResult{}, parentError
		}
		if errors.Is(executeError, context.DeadlineExceeded) {
			result = agentprotocol.AgentCommandResult{
				CommandID: command.ID,
				Status:    agentprotocol.AgentCommandFailed,
				ErrorCode: "command_expired",
			}
		} else {
			return agentprotocol.AgentCommandResult{}, executeError
		}
	}
	if err := result.Validate(command); err != nil {
		return agentprotocol.AgentCommandResult{}, err
	}
	return result, e.store(command, result)
}

func (e *DockerExecutor) begin(
	command agentprotocol.AgentCommand,
) (*pendingProbeExecution, bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if pending := e.pending[command.ID]; pending != nil {
		if !pending.command.Equivalent(command) {
			return nil, false, agentprotocol.ErrCommandInvalid
		}
		return pending, false, nil
	}
	pending := &pendingProbeExecution{
		command: command,
		done:    make(chan struct{}),
	}
	e.pending[command.ID] = pending
	return pending, true, nil
}

func (e *DockerExecutor) finish(
	commandID string,
	pending *pendingProbeExecution,
	result agentprotocol.AgentCommandResult,
	err error,
) {
	e.mu.Lock()
	delete(e.pending, commandID)
	pending.result = result
	pending.err = err
	close(pending.done)
	e.mu.Unlock()
}

func waitForProbeExecution(
	ctx context.Context,
	pending *pendingProbeExecution,
) (agentprotocol.AgentCommandResult, error) {
	select {
	case <-pending.done:
		return pending.result, pending.err
	case <-ctx.Done():
		return agentprotocol.AgentCommandResult{}, ctx.Err()
	}
}

func (e *DockerExecutor) probeRuntime(
	ctx context.Context,
	command agentprotocol.AgentCommand,
) (agentprotocol.AgentCommandResult, error) {
	result := agentprotocol.AgentCommandResult{
		CommandID: command.ID,
		Status:    agentprotocol.AgentCommandSucceeded,
		RuntimeProbe: &agentprotocol.RuntimeProbeResult{
			Status: agentprotocol.RuntimeProbeUnreachable,
		},
	}
	engine, err := e.newEngine(e.socketPath)
	if err != nil {
		result.Status = agentprotocol.AgentCommandFailed
		result.ErrorCode = "runtime_configuration"
		result.RuntimeProbe = nil
		return result, nil
	}
	defer func() { _ = engine.Close() }()
	if _, err := engine.Ping(ctx, client.PingOptions{}); err != nil {
		if contextError := ctx.Err(); contextError != nil {
			return agentprotocol.AgentCommandResult{}, contextError
		}
		return result, nil
	}
	result.RuntimeProbe.Status = agentprotocol.RuntimeProbeReady
	return result, nil
}

func (e *DockerExecutor) store(
	command agentprotocol.AgentCommand,
	result agentprotocol.AgentCommandResult,
) error {
	if !command.Kind.DurableResult() {
		return nil
	}
	if err := e.cache.Store(command, result); err != nil {
		return fmt.Errorf("persist Agent command result: %w", err)
	}
	return nil
}

func validDockerSocketPath(value string) bool {
	return value != "" && len(value) <= 4096 &&
		!strings.ContainsRune(value, '\x00') &&
		filepath.IsAbs(value) && filepath.Clean(value) == value
}

func newLocalDockerProbeEngine(socketPath string) (dockerProbeEngine, error) {
	return client.New(
		client.WithHost("unix://" + socketPath),
	)
}
