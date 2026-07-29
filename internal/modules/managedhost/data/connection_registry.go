package data

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/owndock/owndock/internal/modules/managedhost/biz"
)

type pendingAgentCommand struct {
	command    biz.AgentCommand
	done       chan struct{}
	expiration chan struct{}
	result     biz.AgentCommandResult
	err        error
}

type agentConnection struct {
	sessionID string
	cancel    context.CancelFunc
	commands  chan biz.AgentCommand
	pending   map[string]*pendingAgentCommand
}

type completedCommandKey struct {
	hostID    string
	commandID string
}

type completedAgentCommand struct {
	command biz.AgentCommand
	result  biz.AgentCommandResult
}

// ConnectionRegistry owns only process-local routing, backpressure, command
// de-duplication, and cancellation. Agent identity and session state remain
// authoritative in MongoDB.
type ConnectionRegistry struct {
	mu sync.Mutex

	outboundBuffer     int
	completedCacheSize int
	connections        map[string]*agentConnection
	completed          map[completedCommandKey]completedAgentCommand
	completedInsertion []completedCommandKey
}

func NewConnectionRegistry(
	outboundBuffer, completedCacheSize int,
) (*ConnectionRegistry, error) {
	if outboundBuffer < 1 || outboundBuffer > 1024 {
		return nil, fmt.Errorf("Agent outbound buffer must be between 1 and 1024")
	}
	if completedCacheSize < 1 || completedCacheSize > 4096 {
		return nil, fmt.Errorf("Agent completed command cache must be between 1 and 4096")
	}
	return &ConnectionRegistry{
		outboundBuffer:     outboundBuffer,
		completedCacheSize: completedCacheSize,
		connections:        make(map[string]*agentConnection),
		completed:          make(map[completedCommandKey]completedAgentCommand),
	}, nil
}

func (r *ConnectionRegistry) Register(
	hostID, sessionID string,
	cancel context.CancelFunc,
) <-chan biz.AgentCommand {
	if cancel == nil {
		cancel = func() {}
	}
	connection := &agentConnection{
		sessionID: sessionID,
		cancel:    cancel,
		commands:  make(chan biz.AgentCommand, r.outboundBuffer),
		pending:   make(map[string]*pendingAgentCommand),
	}

	r.mu.Lock()
	previous := r.connections[hostID]
	if previous != nil {
		r.terminateLocked(previous, biz.ErrAgentDisconnected)
	}
	r.connections[hostID] = connection
	r.mu.Unlock()

	return connection.commands
}

func (r *ConnectionRegistry) Unregister(hostID, sessionID string) {
	r.mu.Lock()
	current := r.connections[hostID]
	if current == nil || current.sessionID != sessionID {
		r.mu.Unlock()
		return
	}
	delete(r.connections, hostID)
	r.terminateLocked(current, biz.ErrAgentDisconnected)
	r.mu.Unlock()
}

func (r *ConnectionRegistry) Dispatch(
	ctx context.Context,
	hostID string,
	command biz.AgentCommand,
) (biz.AgentCommandResult, error) {
	if err := command.Validate(); err != nil {
		return biz.AgentCommandResult{}, err
	}

	r.mu.Lock()
	key := completedCommandKey{hostID: hostID, commandID: command.ID}
	if completed, exists := r.completed[key]; exists {
		r.mu.Unlock()
		if !completed.command.Equivalent(command) {
			return biz.AgentCommandResult{}, biz.ErrAgentCommandInvalid
		}
		return completed.result, nil
	}
	if !command.Deadline.After(time.Now()) {
		r.mu.Unlock()
		return biz.AgentCommandResult{}, biz.ErrAgentCommandExpired
	}
	connection := r.connections[hostID]
	if connection == nil {
		r.mu.Unlock()
		return biz.AgentCommandResult{}, biz.ErrAgentNotConnected
	}
	pending := connection.pending[command.ID]
	if pending != nil {
		r.mu.Unlock()
		if !pending.command.Equivalent(command) {
			return biz.AgentCommandResult{}, biz.ErrAgentCommandInvalid
		}
		return waitForAgentCommand(ctx, pending)
	}

	pending = &pendingAgentCommand{
		command:    command,
		done:       make(chan struct{}),
		expiration: make(chan struct{}),
	}
	connection.pending[command.ID] = pending
	select {
	case connection.commands <- command:
		r.mu.Unlock()
		go r.expireCommand(
			hostID, connection.sessionID, command.ID, command.Deadline,
		)
		return waitForAgentCommand(ctx, pending)
	default:
		delete(connection.pending, command.ID)
		r.mu.Unlock()
		return biz.AgentCommandResult{}, biz.ErrAgentBackpressure
	}
}

func (r *ConnectionRegistry) Complete(
	hostID, sessionID string,
	result biz.AgentCommandResult,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	connection := r.connections[hostID]
	if connection == nil || connection.sessionID != sessionID {
		return biz.ErrAgentDisconnected
	}
	pending := connection.pending[result.CommandID]
	if pending == nil {
		key := completedCommandKey{hostID: hostID, commandID: result.CommandID}
		if completed, exists := r.completed[key]; exists {
			if completed.result.Equivalent(result) {
				return nil
			}
			return biz.ErrAgentResultInvalid
		}
		return biz.ErrAgentResultUnavailable
	}
	if err := result.Validate(pending.command); err != nil {
		return err
	}

	delete(connection.pending, result.CommandID)
	pending.result = result
	r.cacheCompletedLocked(hostID, pending.command, result)
	close(pending.expiration)
	close(pending.done)
	return nil
}

func (r *ConnectionRegistry) DisconnectHost(hostID string) {
	r.mu.Lock()
	connection := r.connections[hostID]
	if connection != nil {
		delete(r.connections, hostID)
		r.terminateLocked(connection, biz.ErrAgentDisconnected)
	}
	r.mu.Unlock()
}

func (r *ConnectionRegistry) Close() {
	r.mu.Lock()
	connections := r.connections
	r.connections = make(map[string]*agentConnection)
	for _, connection := range connections {
		r.terminateLocked(connection, biz.ErrAgentDisconnected)
	}
	r.mu.Unlock()
}

func (r *ConnectionRegistry) expireCommand(
	hostID, sessionID, commandID string,
	deadline time.Time,
) {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	r.mu.Lock()
	connection := r.connections[hostID]
	var expiration <-chan struct{}
	if connection != nil && connection.sessionID == sessionID {
		if pending := connection.pending[commandID]; pending != nil {
			expiration = pending.expiration
		}
	}
	r.mu.Unlock()
	if expiration == nil {
		return
	}
	select {
	case <-timer.C:
	case <-expiration:
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	connection = r.connections[hostID]
	if connection == nil || connection.sessionID != sessionID {
		return
	}
	pending := connection.pending[commandID]
	if pending == nil || !pending.command.Deadline.Equal(deadline) {
		return
	}
	delete(connection.pending, commandID)
	pending.err = biz.ErrAgentCommandExpired
	close(pending.done)
}

func (r *ConnectionRegistry) terminateLocked(
	connection *agentConnection,
	err error,
) {
	connection.cancel()
	close(connection.commands)
	for commandID, pending := range connection.pending {
		delete(connection.pending, commandID)
		pending.err = err
		close(pending.expiration)
		close(pending.done)
	}
}

func (r *ConnectionRegistry) cacheCompletedLocked(
	hostID string,
	command biz.AgentCommand,
	result biz.AgentCommandResult,
) {
	key := completedCommandKey{hostID: hostID, commandID: command.ID}
	r.completed[key] = completedAgentCommand{command: command, result: result}
	r.completedInsertion = append(r.completedInsertion, key)
	if len(r.completedInsertion) <= r.completedCacheSize {
		return
	}
	evicted := r.completedInsertion[0]
	r.completedInsertion = r.completedInsertion[1:]
	delete(r.completed, evicted)
}

func waitForAgentCommand(
	ctx context.Context,
	pending *pendingAgentCommand,
) (biz.AgentCommandResult, error) {
	select {
	case <-pending.done:
		return pending.result, pending.err
	default:
	}
	select {
	case <-pending.done:
		return pending.result, pending.err
	case <-ctx.Done():
		return biz.AgentCommandResult{}, ctx.Err()
	}
}
