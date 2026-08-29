package agentcontrol

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/owndock/owndock/internal/shared/agentprotocol"
)

var (
	ErrConfigurationInvalid  = errors.New("Agent control configuration is invalid")
	ErrConnectionUnavailable = errors.New("Agent control connection is unavailable")
	ErrReconnectRequested    = errors.New("Agent control reconnect was requested")
	ErrProtocolViolation     = errors.New("Agent control protocol violation")
)

const (
	maximumConcurrentTerminals     = 16
	maximumConcurrentHostTerminals = 4
)

type PermanentError struct {
	Code string
}

func (e *PermanentError) Error() string {
	return "Agent control stopped: " + e.Code
}

func IsPermanent(err error) bool {
	var permanent *PermanentError
	return errors.As(err, &permanent)
}

type CommandExecutor interface {
	Execute(
		context.Context,
		agentprotocol.AgentCommand,
	) (agentprotocol.AgentCommandResult, error)
}

type ContainerTerminalExecutor interface {
	OpenContainerTerminal(
		context.Context,
		agentprotocol.TerminalOpen,
	) (agentprotocol.TerminalStream, error)
}

type HostTerminalExecutor interface {
	OpenHostTerminal(
		context.Context,
		agentprotocol.TerminalOpen,
	) (agentprotocol.TerminalStream, error)
}

type Identity struct {
	OrganizationID string
	ManagedHostID  string
	IdentityID     string
	InstanceID     string
	BootID         string
	AgentVersion   string
}

type ClientConfig struct {
	Endpoint              string
	Identity              Identity
	HandshakeTimeout      time.Duration
	ServerSilenceTimeout  time.Duration
	MaxFrameBytes         int
	MaxConcurrentCommands int
	Capabilities          []string
}

type Client struct {
	httpClient         *http.Client
	executor           CommandExecutor
	config             ClientConfig
	terminal           ContainerTerminalExecutor
	hostTerminal       HostTerminalExecutor
	terminalMu         sync.Mutex
	terminals          map[string]*clientTerminalState
	sessionMu          sync.Mutex
	sessionCancel      context.CancelFunc
	reconnectRequested bool
}

// Reconnect discards idle authenticated connections immediately and closes the
// current control stream. Immediate cleanup matters during startup recovery:
// certificate rotation can finish before a control stream exists, and the next
// hello must not reuse the rotation request's old-certificate TLS connection.
func (c *Client) Reconnect() {
	c.httpClient.CloseIdleConnections()
	c.sessionMu.Lock()
	c.reconnectRequested = true
	cancel := c.sessionCancel
	c.sessionMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

type clientTerminalState struct {
	kind               agentprotocol.TerminalKind
	lastServerSequence uint64
	inbound            chan agentprotocol.TerminalFrame
	cancel             context.CancelFunc
}

func NewClient(
	httpClient *http.Client,
	executor CommandExecutor,
	config ClientConfig,
) (*Client, error) {
	if len(config.Capabilities) == 0 {
		for _, capability := range agentprotocol.SupportedCapabilities() {
			if capability != agentprotocol.CapabilityTerminalContainer &&
				capability != agentprotocol.CapabilityTerminalHost {
				config.Capabilities = append(config.Capabilities, capability)
			}
		}
	}
	if httpClient == nil || executor == nil || validateClientConfig(config) != nil {
		return nil, ErrConfigurationInvalid
	}
	return &Client{
		httpClient: httpClient,
		executor:   executor,
		config:     config,
		terminals:  make(map[string]*clientTerminalState),
	}, nil
}

func (c *Client) WithContainerTerminal(executor ContainerTerminalExecutor) *Client {
	c.terminal = executor
	return c
}

func (c *Client) WithHostTerminal(executor HostTerminalExecutor) *Client {
	c.hostTerminal = executor
	return c
}

func validateClientConfig(config ClientConfig) error {
	endpoint, err := url.Parse(strings.TrimSpace(config.Endpoint))
	if err != nil || endpoint.Scheme != "https" ||
		endpoint.Host == "" || endpoint.User != nil ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" ||
		endpoint.Path != "/api/v1/agent/connect" {
		return ErrConfigurationInvalid
	}
	identity := config.Identity
	for _, value := range []string{
		identity.OrganizationID,
		identity.ManagedHostID,
		identity.IdentityID,
		identity.InstanceID,
		identity.BootID,
		identity.AgentVersion,
	} {
		if !validIdentity(value) {
			return ErrConfigurationInvalid
		}
	}
	if config.HandshakeTimeout <= 0 ||
		config.ServerSilenceTimeout <= config.HandshakeTimeout ||
		config.MaxFrameBytes < 1024 || config.MaxFrameBytes > 1024*1024 ||
		config.MaxConcurrentCommands < 1 ||
		config.MaxConcurrentCommands > 64 {
		return ErrConfigurationInvalid
	}
	if (hasCapability(config.Capabilities, agentprotocol.CapabilityTerminalContainer) ||
		hasCapability(config.Capabilities, agentprotocol.CapabilityTerminalHost)) &&
		config.MaxFrameBytes < agentprotocol.MinimumTerminalFrameBytes {
		return ErrConfigurationInvalid
	}
	seen := make(map[string]struct{}, len(config.Capabilities))
	for _, capability := range config.Capabilities {
		if !agentprotocol.SupportsCapability(capability) {
			return ErrConfigurationInvalid
		}
		if _, exists := seen[capability]; exists {
			return ErrConfigurationInvalid
		}
		seen[capability] = struct{}{}
	}
	if len(seen) == 0 {
		return ErrConfigurationInvalid
	}
	return nil
}

func (c *Client) Run(ctx context.Context) (result error) {
	if hasCapability(c.config.Capabilities, agentprotocol.CapabilityTerminalContainer) &&
		c.terminal == nil {
		return ErrConfigurationInvalid
	}
	if hasCapability(c.config.Capabilities, agentprotocol.CapabilityTerminalHost) &&
		c.hostTerminal == nil {
		return ErrConfigurationInvalid
	}
	sessionContext, cancel := context.WithCancel(ctx)
	defer cancel()
	c.sessionMu.Lock()
	c.sessionCancel = cancel
	c.reconnectRequested = false
	c.sessionMu.Unlock()
	defer func() {
		c.sessionMu.Lock()
		c.sessionCancel = nil
		reconnectRequested := c.reconnectRequested
		c.reconnectRequested = false
		c.sessionMu.Unlock()
		if reconnectRequested && ctx.Err() == nil {
			// The certificate rotation request and control stream can share an
			// HTTP/2 TLS connection. Once the stream has closed, discard every
			// idle connection so the next hello must perform a new handshake and
			// load the freshly installed identity bundle.
			c.httpClient.CloseIdleConnections()
			result = ErrReconnectRequested
		}
	}()

	requestReader, requestWriter := io.Pipe()
	defer func() { _ = requestReader.Close() }()
	defer func() { _ = requestWriter.Close() }()
	outbound := make(chan outboundFrame, c.config.MaxConcurrentCommands+64)
	writerErrors := make(chan error, 1)
	go writeAgentFrames(
		sessionContext,
		requestWriter,
		c.config.Identity,
		c.config.Capabilities,
		outbound,
		writerErrors,
	)

	request, err := http.NewRequestWithContext(
		sessionContext,
		http.MethodPost,
		c.config.Endpoint,
		requestReader,
	)
	if err != nil {
		return ErrConfigurationInvalid
	}
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Accept", contentType)
	response, err := c.httpClient.Do(request)
	if err != nil {
		return ErrConnectionUnavailable
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		if response.StatusCode >= 400 && response.StatusCode < 500 {
			return &PermanentError{Code: "server_rejected_identity"}
		}
		return ErrConnectionUnavailable
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != contentType {
		return &PermanentError{Code: "invalid_content_type"}
	}

	scanner := bufio.NewScanner(response.Body)
	scanner.Buffer(make([]byte, 4096), c.config.MaxFrameBytes)
	first, err := readServerFrame(
		sessionContext,
		scanner,
		c.config.HandshakeTimeout,
		c.config.MaxFrameBytes,
	)
	if err != nil {
		return err
	}
	heartbeatInterval, negotiatedMaximum, err :=
		validateHelloAcknowledgement(
			first,
			c.config.MaxFrameBytes,
			c.config.ServerSilenceTimeout,
		)
	if err != nil {
		return err
	}

	reads := make(chan serverRead, 1)
	go readServerFrames(
		sessionContext,
		scanner,
		negotiatedMaximum,
		reads,
	)
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	silence := time.NewTimer(c.config.ServerSilenceTimeout)
	defer silence.Stop()
	results := make(chan commandExecution, c.config.MaxConcurrentCommands)
	semaphore := make(chan struct{}, c.config.MaxConcurrentCommands)
	var workers sync.WaitGroup
	defer func() {
		cancel()
		c.closeContainerTerminals()
		workers.Wait()
	}()
	lastServerSequence := first.Sequence

	for {
		select {
		case <-ctx.Done():
			return nil
		case writeError := <-writerErrors:
			if ctx.Err() != nil {
				return nil
			}
			if writeError == nil {
				return ErrConnectionUnavailable
			}
			return ErrConnectionUnavailable
		case read := <-reads:
			if read.err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return read.err
			}
			if read.frame.Sequence <= lastServerSequence {
				return &PermanentError{Code: "non_monotonic_server_sequence"}
			}
			lastServerSequence = read.frame.Sequence
			if !silence.Stop() {
				select {
				case <-silence.C:
				default:
				}
			}
			silence.Reset(c.config.ServerSilenceTimeout)
			if err := c.handleServerFrame(
				sessionContext,
				read.frame,
				results,
				semaphore,
				&workers,
				outbound,
			); err != nil {
				return err
			}
		case execution := <-results:
			if execution.err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return ErrConnectionUnavailable
			}
			if err := enqueueOutbound(
				sessionContext,
				outbound,
				outboundFrame{commandResult: &execution.result},
			); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
		case <-ticker.C:
			if err := enqueueOutbound(
				sessionContext,
				outbound,
				outboundFrame{heartbeat: true},
			); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
		case <-silence.C:
			return ErrConnectionUnavailable
		}
	}
}

type outboundFrame struct {
	heartbeat     bool
	commandResult *agentprotocol.AgentCommandResult
	terminal      *agentprotocol.TerminalFrame
}

func writeAgentFrames(
	ctx context.Context,
	writer *io.PipeWriter,
	identity Identity,
	capabilities []string,
	outbound <-chan outboundFrame,
	failures chan<- error,
) {
	encoder := json.NewEncoder(writer)
	sequence := uint64(1)
	err := encoder.Encode(agentFrame{
		Type:     "hello",
		Sequence: sequence,
		Hello: &agentHello{
			OrganizationID:  identity.OrganizationID,
			ManagedHostID:   identity.ManagedHostID,
			AgentIdentityID: identity.IdentityID,
			InstanceID:      identity.InstanceID,
			BootID:          identity.BootID,
			AgentVersion:    identity.AgentVersion,
			ProtocolVersion: protocolVersion,
			Capabilities:    append([]string(nil), capabilities...),
		},
	})
	for err == nil {
		select {
		case <-ctx.Done():
			_ = writer.CloseWithError(ctx.Err())
			return
		case value := <-outbound:
			sequence++
			frame := agentFrame{Sequence: sequence}
			switch {
			case value.heartbeat:
				frame.Type = "heartbeat"
			case value.commandResult != nil:
				frame.Type = "command_result"
				frame.CommandResult = newAgentResult(*value.commandResult)
			case value.terminal != nil:
				frame.Type = "terminal"
				terminal := *value.terminal
				frame.Terminal = &terminal
			default:
				err = ErrProtocolViolation
				continue
			}
			err = encoder.Encode(frame)
		}
	}
	_ = writer.CloseWithError(err)
	select {
	case failures <- err:
	default:
	}
}

type serverRead struct {
	frame serverFrame
	err   error
}

func readServerFrames(
	ctx context.Context,
	scanner *bufio.Scanner,
	maximum int,
	reads chan<- serverRead,
) {
	for {
		if !scanner.Scan() {
			err := scanner.Err()
			if err == nil {
				err = io.EOF
			}
			sendServerRead(ctx, reads, serverRead{err: classifyReadError(err)})
			return
		}
		if len(scanner.Bytes()) > maximum {
			sendServerRead(
				ctx,
				reads,
				serverRead{err: &PermanentError{Code: "server_frame_too_large"}},
			)
			return
		}
		var frame serverFrame
		if err := decodeServerFrame(scanner.Bytes(), &frame); err != nil {
			sendServerRead(
				ctx,
				reads,
				serverRead{err: &PermanentError{Code: "invalid_server_frame"}},
			)
			return
		}
		if !sendServerRead(ctx, reads, serverRead{frame: frame}) {
			return
		}
	}
}

func readServerFrame(
	ctx context.Context,
	scanner *bufio.Scanner,
	timeout time.Duration,
	maximum int,
) (serverFrame, error) {
	result := make(chan serverRead, 1)
	go func() {
		if !scanner.Scan() {
			err := scanner.Err()
			if err == nil {
				err = io.EOF
			}
			sendServerRead(
				ctx,
				result,
				serverRead{err: classifyReadError(err)},
			)
			return
		}
		if len(scanner.Bytes()) > maximum {
			sendServerRead(
				ctx,
				result,
				serverRead{
					err: &PermanentError{Code: "server_frame_too_large"},
				},
			)
			return
		}
		var frame serverFrame
		if err := decodeServerFrame(scanner.Bytes(), &frame); err != nil {
			sendServerRead(
				ctx,
				result,
				serverRead{
					err: &PermanentError{Code: "invalid_server_frame"},
				},
			)
			return
		}
		sendServerRead(ctx, result, serverRead{frame: frame})
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case read := <-result:
		return read.frame, read.err
	case <-timer.C:
		return serverFrame{}, ErrConnectionUnavailable
	case <-ctx.Done():
		return serverFrame{}, ctx.Err()
	}
}

func sendServerRead(
	ctx context.Context,
	reads chan<- serverRead,
	read serverRead,
) bool {
	select {
	case reads <- read:
		return true
	case <-ctx.Done():
		return false
	}
}

func classifyReadError(err error) error {
	if errors.Is(err, bufio.ErrTooLong) {
		return &PermanentError{Code: "server_frame_too_large"}
	}
	return ErrConnectionUnavailable
}

func validateHelloAcknowledgement(
	frame serverFrame,
	localMaximum int,
	serverSilenceTimeout time.Duration,
) (time.Duration, int, error) {
	if frame.Type != "hello_ack" || frame.Sequence == 0 ||
		!validIdentity(frame.SessionID) ||
		frame.ProtocolVersion != protocolVersion ||
		frame.HeartbeatIntervalSeconds < 1 ||
		frame.HeartbeatIntervalSeconds > 3600 ||
		frame.MaxFrameBytes < 1024 ||
		frame.MaxFrameBytes > 1024*1024 ||
		frame.Command != nil || frame.Terminal != nil || frame.Code != "" {
		return 0, 0, &PermanentError{Code: "invalid_hello_ack"}
	}
	maximum := frame.MaxFrameBytes
	if maximum > localMaximum {
		maximum = localMaximum
	}
	heartbeatInterval :=
		time.Duration(frame.HeartbeatIntervalSeconds) * time.Second
	if heartbeatInterval >= serverSilenceTimeout {
		return 0, 0, &PermanentError{Code: "invalid_hello_ack"}
	}
	return heartbeatInterval, maximum, nil
}

type commandExecution struct {
	result agentprotocol.AgentCommandResult
	err    error
}

func (c *Client) handleServerFrame(
	ctx context.Context,
	frame serverFrame,
	results chan<- commandExecution,
	semaphore chan struct{},
	workers *sync.WaitGroup,
	outbound chan<- outboundFrame,
) error {
	switch frame.Type {
	case "heartbeat_ack":
		if frame.AcknowledgedSequence == 0 || frame.Command != nil ||
			frame.Terminal != nil || frame.Code != "" || frame.CommandID != "" {
			return &PermanentError{Code: "invalid_heartbeat_ack"}
		}
		return nil
	case "command_result_ack":
		if frame.AcknowledgedSequence == 0 ||
			!validIdentity(frame.CommandID) ||
			frame.Command != nil || frame.Terminal != nil || frame.Code != "" {
			return &PermanentError{Code: "invalid_command_result_ack"}
		}
		return nil
	case "command":
		if frame.Command == nil || frame.Terminal != nil || frame.Code != "" ||
			frame.AcknowledgedSequence != 0 || frame.CommandID != "" {
			return &PermanentError{Code: "invalid_command"}
		}
		command := frame.Command.Domain()
		if err := command.Validate(); err != nil {
			return &PermanentError{Code: "invalid_command"}
		}
		select {
		case semaphore <- struct{}{}:
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() { <-semaphore }()
				result, err := c.executor.Execute(ctx, command)
				select {
				case results <- commandExecution{result: result, err: err}:
				case <-ctx.Done():
				}
			}()
		default:
			// Do not acknowledge a command whose result cannot pass through the
			// durable executor/cache boundary. Disconnecting makes the Server
			// fail the pending dispatch explicitly instead of creating a false
			// idempotent result.
			return ErrConnectionUnavailable
		}
		return nil
	case "terminal":
		if frame.Terminal == nil || frame.Command != nil || frame.Code != "" ||
			frame.AcknowledgedSequence != 0 || frame.CommandID != "" {
			return &PermanentError{Code: "invalid_terminal_frame"}
		}
		return c.handleTerminalFrame(ctx, *frame.Terminal, outbound, workers)
	case "error":
		if !validSafeCode(frame.Code) || frame.Command != nil || frame.Terminal != nil {
			return &PermanentError{Code: "invalid_server_error"}
		}
		return &PermanentError{Code: frame.Code}
	default:
		return &PermanentError{Code: "unknown_server_frame"}
	}
}

type terminalRead struct {
	payload []byte
	err     error
}

func (c *Client) handleTerminalFrame(
	ctx context.Context,
	frame agentprotocol.TerminalFrame,
	outbound chan<- outboundFrame,
	workers *sync.WaitGroup,
) error {
	if err := frame.Validate(agentprotocol.TerminalServerToAgent); err != nil {
		return &PermanentError{Code: "invalid_terminal_frame"}
	}
	if frame.Type == agentprotocol.TerminalFrameOpen {
		if frame.Sequence != 1 || !c.terminalOpenSupported(*frame.Open) {
			return &PermanentError{Code: "invalid_terminal_frame"}
		}
		terminalContext, cancel := context.WithCancel(ctx)
		state := &clientTerminalState{
			kind:               frame.Open.Kind,
			lastServerSequence: frame.Sequence,
			inbound:            make(chan agentprotocol.TerminalFrame, 16),
			cancel:             cancel,
		}
		c.terminalMu.Lock()
		if c.terminals[frame.SessionID] != nil {
			c.terminalMu.Unlock()
			cancel()
			return &PermanentError{Code: "invalid_terminal_frame"}
		}
		if len(c.terminals) >= maximumConcurrentTerminals ||
			frame.Open.Kind == agentprotocol.TerminalKindHost &&
				c.hostTerminalCountLocked() >= maximumConcurrentHostTerminals {
			c.terminalMu.Unlock()
			cancel()
			return enqueueTerminalFrame(ctx, outbound, agentprotocol.TerminalFrame{
				SessionID: frame.SessionID,
				Sequence:  1,
				Type:      agentprotocol.TerminalFrameError,
				Code:      "terminal_capacity_exceeded",
			})
		}
		c.terminals[frame.SessionID] = state
		c.terminalMu.Unlock()
		workers.Add(1)
		go func() {
			defer workers.Done()
			c.runTerminal(terminalContext, frame, state, outbound)
		}()
		return nil
	}

	c.terminalMu.Lock()
	state := c.terminals[frame.SessionID]
	if state == nil || frame.Sequence != state.lastServerSequence+1 {
		c.terminalMu.Unlock()
		return &PermanentError{Code: "invalid_terminal_frame"}
	}
	select {
	case state.inbound <- frame:
		state.lastServerSequence = frame.Sequence
		if frame.Type == agentprotocol.TerminalFrameClose {
			state.cancel()
		}
		c.terminalMu.Unlock()
		return nil
	default:
		c.terminalMu.Unlock()
		return ErrConnectionUnavailable
	}
}

func (c *Client) terminalOpenSupported(open agentprotocol.TerminalOpen) bool {
	switch open.Kind {
	case agentprotocol.TerminalKindContainer:
		return c.terminal != nil && hasCapability(
			c.config.Capabilities,
			agentprotocol.CapabilityTerminalContainer,
		)
	case agentprotocol.TerminalKindHost:
		return c.hostTerminal != nil && hasCapability(
			c.config.Capabilities,
			agentprotocol.CapabilityTerminalHost,
		)
	default:
		return false
	}
}

func (c *Client) hostTerminalCountLocked() int {
	count := 0
	for _, state := range c.terminals {
		if state.kind == agentprotocol.TerminalKindHost {
			count++
		}
	}
	return count
}

func (c *Client) runTerminal(
	ctx context.Context,
	openFrame agentprotocol.TerminalFrame,
	state *clientTerminalState,
	outbound chan<- outboundFrame,
) {
	defer c.removeContainerTerminal(openFrame.SessionID, state)
	var stream agentprotocol.TerminalStream
	var err error
	switch openFrame.Open.Kind {
	case agentprotocol.TerminalKindContainer:
		stream, err = c.terminal.OpenContainerTerminal(ctx, *openFrame.Open)
	case agentprotocol.TerminalKindHost:
		stream, err = c.hostTerminal.OpenHostTerminal(ctx, *openFrame.Open)
	default:
		err = ErrProtocolViolation
	}
	if err != nil {
		if ctx.Err() == nil {
			_ = enqueueTerminalFrame(ctx, outbound, agentprotocol.TerminalFrame{
				SessionID: openFrame.SessionID, Sequence: 1,
				Type: agentprotocol.TerminalFrameError, Code: "terminal_open_failed",
			})
		}
		return
	}
	defer stream.Close()
	sequence := uint64(1)
	if enqueueTerminalFrame(ctx, outbound, agentprotocol.TerminalFrame{
		SessionID: openFrame.SessionID, Sequence: sequence,
		Type: agentprotocol.TerminalFrameReady,
	}) != nil {
		return
	}
	reads := make(chan terminalRead, 1)
	go readContainerTerminal(ctx, stream, reads)
	for {
		select {
		case frame := <-state.inbound:
			switch frame.Type {
			case agentprotocol.TerminalFrameStdin:
				if writeTerminalPayload(stream, frame.Data) != nil {
					sequence++
					_ = enqueueTerminalFrame(ctx, outbound, agentprotocol.TerminalFrame{
						SessionID: openFrame.SessionID, Sequence: sequence,
						Type: agentprotocol.TerminalFrameError, Code: "terminal_io_failed",
					})
					return
				}
			case agentprotocol.TerminalFrameResize:
				if stream.Resize(ctx, frame.Columns, frame.Rows) != nil {
					sequence++
					_ = enqueueTerminalFrame(ctx, outbound, agentprotocol.TerminalFrame{
						SessionID: openFrame.SessionID, Sequence: sequence,
						Type: agentprotocol.TerminalFrameError, Code: "terminal_resize_failed",
					})
					return
				}
			case agentprotocol.TerminalFrameClose:
				return
			}
		case result := <-reads:
			if len(result.payload) > 0 {
				sequence++
				if enqueueTerminalFrame(ctx, outbound, agentprotocol.TerminalFrame{
					SessionID: openFrame.SessionID, Sequence: sequence,
					Type: agentprotocol.TerminalFrameStdout, Data: result.payload,
				}) != nil {
					return
				}
			}
			if result.err != nil {
				sequence++
				frameType, code := agentprotocol.TerminalFrameClose, ""
				if !errors.Is(result.err, io.EOF) {
					frameType, code = agentprotocol.TerminalFrameError, "terminal_io_failed"
				}
				_ = enqueueTerminalFrame(ctx, outbound, agentprotocol.TerminalFrame{
					SessionID: openFrame.SessionID, Sequence: sequence,
					Type: frameType, Code: code,
				})
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func readContainerTerminal(
	ctx context.Context,
	stream agentprotocol.TerminalStream,
	results chan<- terminalRead,
) {
	buffer := make([]byte, agentprotocol.MaximumTerminalDataBytes)
	for {
		read, err := stream.Read(buffer)
		result := terminalRead{err: err}
		if read > 0 {
			result.payload = append([]byte(nil), buffer[:read]...)
		}
		select {
		case results <- result:
		case <-ctx.Done():
			return
		}
		if err != nil {
			return
		}
	}
}

func writeTerminalPayload(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written < 1 || written > len(payload) {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}

func enqueueTerminalFrame(
	ctx context.Context,
	outbound chan<- outboundFrame,
	frame agentprotocol.TerminalFrame,
) error {
	if err := frame.Validate(agentprotocol.TerminalAgentToServer); err != nil {
		return ErrProtocolViolation
	}
	return enqueueOutbound(ctx, outbound, outboundFrame{terminal: &frame})
}

func (c *Client) removeContainerTerminal(
	sessionID string,
	state *clientTerminalState,
) {
	state.cancel()
	c.terminalMu.Lock()
	if c.terminals[sessionID] == state {
		delete(c.terminals, sessionID)
	}
	c.terminalMu.Unlock()
}

func (c *Client) closeContainerTerminals() {
	c.terminalMu.Lock()
	states := make([]*clientTerminalState, 0, len(c.terminals))
	for _, state := range c.terminals {
		states = append(states, state)
	}
	c.terminalMu.Unlock()
	for _, state := range states {
		state.cancel()
	}
}

func hasCapability(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func enqueueOutbound(
	ctx context.Context,
	outbound chan<- outboundFrame,
	frame outboundFrame,
) error {
	select {
	case outbound <- frame:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		return ErrConnectionUnavailable
	}
}

func (c *Client) CloseIdleConnections() {
	c.httpClient.CloseIdleConnections()
}
