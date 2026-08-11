package data

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/owndock/owndock/internal/modules/managedhost/biz"
	"github.com/owndock/owndock/internal/shared/agentprotocol"
)

var ErrAgentTerminalUnavailable = errors.New("Agent terminal stream is unavailable")

type pendingAgentCommand struct {
	command     biz.AgentCommand
	fingerprint [sha256.Size]byte
	done        chan struct{}
	expiration  chan struct{}
	result      biz.AgentCommandResult
	err         error
}

type agentConnection struct {
	sessionID      string
	capabilities   map[string]struct{}
	cancel         context.CancelFunc
	commands       chan biz.AgentCommand
	pending        map[string]*pendingAgentCommand
	terminalFrames chan agentprotocol.TerminalFrame
	terminals      map[string]*agentTerminalState
}

type agentTerminalState struct {
	ready             chan struct{}
	done              chan struct{}
	output            chan []byte
	lastAgentSequence uint64
	serverSequence    uint64
	readyReceived     bool
	err               error
}

type completedCommandKey struct {
	hostID    string
	commandID string
}

type completedAgentCommand struct {
	kind        biz.AgentCommandKind
	fingerprint [sha256.Size]byte
	result      biz.AgentCommandResult
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
	capabilities []string,
	cancel context.CancelFunc,
) <-chan biz.AgentCommand {
	if cancel == nil {
		cancel = func() {}
	}
	connection := &agentConnection{
		sessionID:      sessionID,
		capabilities:   capabilitySet(capabilities),
		cancel:         cancel,
		commands:       make(chan biz.AgentCommand, r.outboundBuffer),
		pending:        make(map[string]*pendingAgentCommand),
		terminalFrames: make(chan agentprotocol.TerminalFrame, r.outboundBuffer),
		terminals:      make(map[string]*agentTerminalState),
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

func (r *ConnectionRegistry) TerminalFrames(
	hostID, sessionID string,
) <-chan agentprotocol.TerminalFrame {
	r.mu.Lock()
	defer r.mu.Unlock()
	connection := r.connections[hostID]
	if connection != nil && connection.sessionID == sessionID {
		return connection.terminalFrames
	}
	closed := make(chan agentprotocol.TerminalFrame)
	close(closed)
	return closed
}

func (r *ConnectionRegistry) OpenTerminal(
	ctx context.Context,
	hostID, terminalSessionID string,
	open agentprotocol.TerminalOpen,
) (agentprotocol.TerminalStream, error) {
	frame := agentprotocol.TerminalFrame{
		SessionID: terminalSessionID, Sequence: 1,
		Type: agentprotocol.TerminalFrameOpen, Open: &open,
	}
	if err := frame.Validate(agentprotocol.TerminalServerToAgent); err != nil {
		return nil, err
	}
	r.mu.Lock()
	connection := r.connections[hostID]
	if connection == nil {
		r.mu.Unlock()
		return nil, biz.ErrAgentNotConnected
	}
	requiredCapability := agentprotocol.CapabilityTerminalContainer
	if open.Kind == agentprotocol.TerminalKindHost {
		requiredCapability = agentprotocol.CapabilityTerminalHost
	}
	if _, supported := connection.capabilities[requiredCapability]; !supported {
		r.mu.Unlock()
		return nil, biz.ErrAgentCapabilityUnavailable
	}
	if connection.terminals[terminalSessionID] != nil {
		r.mu.Unlock()
		return nil, biz.ErrAgentCommandInvalid
	}
	state := &agentTerminalState{
		ready: make(chan struct{}), done: make(chan struct{}),
		output: make(chan []byte, min(r.outboundBuffer, 16)), serverSequence: 1,
	}
	connection.terminals[terminalSessionID] = state
	select {
	case connection.terminalFrames <- frame:
		r.mu.Unlock()
	case <-ctx.Done():
		delete(connection.terminals, terminalSessionID)
		r.mu.Unlock()
		return nil, ctx.Err()
	default:
		delete(connection.terminals, terminalSessionID)
		r.mu.Unlock()
		return nil, biz.ErrAgentBackpressure
	}
	select {
	case <-state.ready:
		return &registryTerminalStream{
			registry: r, hostID: hostID, sessionID: terminalSessionID,
			state: state,
		}, nil
	case <-state.done:
		return nil, terminalStateError(state)
	case <-ctx.Done():
		r.finishTerminal(hostID, terminalSessionID, ctx.Err(), true)
		return nil, ctx.Err()
	}
}

func (r *ConnectionRegistry) CompleteTerminalFrame(
	hostID, agentSessionID string,
	frame agentprotocol.TerminalFrame,
) error {
	if err := frame.Validate(agentprotocol.TerminalAgentToServer); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	connection := r.connections[hostID]
	if connection == nil || connection.sessionID != agentSessionID {
		return biz.ErrAgentDisconnected
	}
	state := connection.terminals[frame.SessionID]
	if state == nil || frame.Sequence != state.lastAgentSequence+1 {
		return agentprotocol.ErrTerminalFrameInvalid
	}
	state.lastAgentSequence = frame.Sequence
	switch frame.Type {
	case agentprotocol.TerminalFrameReady:
		if state.readyReceived {
			return agentprotocol.ErrTerminalFrameInvalid
		}
		state.readyReceived = true
		close(state.ready)
	case agentprotocol.TerminalFrameStdout:
		if !state.readyReceived {
			return agentprotocol.ErrTerminalFrameInvalid
		}
		payload := append([]byte(nil), frame.Data...)
		select {
		case state.output <- payload:
		default:
			r.finishTerminalLocked(connection, frame.SessionID, biz.ErrAgentBackpressure, true)
			return biz.ErrAgentBackpressure
		}
	case agentprotocol.TerminalFrameClose:
		r.finishTerminalLocked(connection, frame.SessionID, io.EOF, false)
	case agentprotocol.TerminalFrameError:
		r.finishTerminalLocked(connection, frame.SessionID, ErrAgentTerminalUnavailable, false)
	default:
		return agentprotocol.ErrTerminalFrameInvalid
	}
	return nil
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
	fingerprint, err := command.Fingerprint()
	if err != nil {
		return biz.AgentCommandResult{}, err
	}

	r.mu.Lock()
	key := completedCommandKey{hostID: hostID, commandID: command.ID}
	if completed, exists := r.completed[key]; command.Kind.DurableResult() && exists {
		r.mu.Unlock()
		if completed.kind != command.Kind ||
			completed.fingerprint != fingerprint {
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
	requiredCapability, exists := agentprotocol.RequiredCapability(
		command.Kind,
	)
	if !exists {
		r.mu.Unlock()
		return biz.AgentCommandResult{}, biz.ErrAgentCommandInvalid
	}
	if _, supported := connection.capabilities[requiredCapability]; !supported {
		r.mu.Unlock()
		return biz.AgentCommandResult{},
			biz.ErrAgentCapabilityUnavailable
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
		command:     command,
		fingerprint: fingerprint,
		done:        make(chan struct{}),
		expiration:  make(chan struct{}),
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

func capabilitySet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
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
	if pending.command.Kind.DurableResult() {
		r.cacheCompletedLocked(
			hostID,
			pending.command.ID,
			pending.command.Kind,
			pending.fingerprint,
			result,
		)
	}
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
	for sessionID := range connection.terminals {
		r.finishTerminalLocked(connection, sessionID, err, false)
	}
	close(connection.commands)
	close(connection.terminalFrames)
	for commandID, pending := range connection.pending {
		delete(connection.pending, commandID)
		pending.err = err
		close(pending.expiration)
		close(pending.done)
	}
}

type registryTerminalStream struct {
	registry  *ConnectionRegistry
	hostID    string
	sessionID string
	state     *agentTerminalState
	current   []byte
	closeOnce sync.Once
}

func (s *registryTerminalStream) Read(payload []byte) (int, error) {
	for len(s.current) == 0 {
		select {
		case next := <-s.state.output:
			s.current = next
		case <-s.state.done:
			select {
			case next := <-s.state.output:
				s.current = next
			default:
				return 0, terminalStateError(s.state)
			}
		}
	}
	read := copy(payload, s.current)
	s.current = s.current[read:]
	return read, nil
}

func (s *registryTerminalStream) Write(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	written := 0
	for len(payload) > 0 {
		chunkSize := min(len(payload), agentprotocol.MaximumTerminalDataBytes)
		chunk := append([]byte(nil), payload[:chunkSize]...)
		if err := s.registry.sendTerminal(
			s.hostID,
			s.sessionID,
			agentprotocol.TerminalFrameStdin,
			0,
			0,
			chunk,
		); err != nil {
			return written, err
		}
		written += chunkSize
		payload = payload[chunkSize:]
	}
	return written, nil
}

func (s *registryTerminalStream) Resize(
	_ context.Context,
	columns, rows uint16,
) error {
	return s.registry.sendTerminal(
		s.hostID,
		s.sessionID,
		agentprotocol.TerminalFrameResize,
		columns,
		rows,
		nil,
	)
}

func (s *registryTerminalStream) Close() error {
	s.closeOnce.Do(func() {
		s.registry.finishTerminal(
			s.hostID,
			s.sessionID,
			io.EOF,
			true,
		)
	})
	return nil
}

func (r *ConnectionRegistry) sendTerminal(
	hostID, terminalSessionID string,
	frameType agentprotocol.TerminalFrameType,
	columns, rows uint16,
	payload []byte,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	connection := r.connections[hostID]
	if connection == nil {
		return biz.ErrAgentNotConnected
	}
	state := connection.terminals[terminalSessionID]
	if state == nil || !state.readyReceived {
		return ErrAgentTerminalUnavailable
	}
	state.serverSequence++
	frame := agentprotocol.TerminalFrame{
		SessionID: terminalSessionID, Sequence: state.serverSequence,
		Type: frameType, Columns: columns, Rows: rows, Data: payload,
	}
	if err := frame.Validate(agentprotocol.TerminalServerToAgent); err != nil {
		return err
	}
	select {
	case connection.terminalFrames <- frame:
		return nil
	default:
		r.finishTerminalLocked(connection, terminalSessionID, biz.ErrAgentBackpressure, true)
		return biz.ErrAgentBackpressure
	}
}

func (r *ConnectionRegistry) finishTerminal(
	hostID, terminalSessionID string,
	err error,
	notifyAgent bool,
) {
	r.mu.Lock()
	connection := r.connections[hostID]
	if connection != nil {
		r.finishTerminalLocked(connection, terminalSessionID, err, notifyAgent)
	}
	r.mu.Unlock()
}

func (r *ConnectionRegistry) finishTerminalLocked(
	connection *agentConnection,
	terminalSessionID string,
	err error,
	notifyAgent bool,
) {
	state := connection.terminals[terminalSessionID]
	if state == nil {
		return
	}
	delete(connection.terminals, terminalSessionID)
	if notifyAgent {
		state.serverSequence++
		frame := agentprotocol.TerminalFrame{
			SessionID: terminalSessionID, Sequence: state.serverSequence,
			Type: agentprotocol.TerminalFrameClose,
		}
		select {
		case connection.terminalFrames <- frame:
		default:
		}
	}
	state.err = err
	close(state.done)
}

func terminalStateError(state *agentTerminalState) error {
	if state.err == nil {
		return ErrAgentTerminalUnavailable
	}
	return state.err
}

var _ agentprotocol.TerminalStream = (*registryTerminalStream)(nil)

func (r *ConnectionRegistry) cacheCompletedLocked(
	hostID string,
	commandID string,
	kind biz.AgentCommandKind,
	fingerprint [sha256.Size]byte,
	result biz.AgentCommandResult,
) {
	key := completedCommandKey{hostID: hostID, commandID: commandID}
	r.completed[key] = completedAgentCommand{
		kind:        kind,
		fingerprint: fingerprint,
		result:      result,
	}
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
