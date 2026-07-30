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
	ErrProtocolViolation     = errors.New("Agent control protocol violation")
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
	httpClient *http.Client
	executor   CommandExecutor
	config     ClientConfig
}

func NewClient(
	httpClient *http.Client,
	executor CommandExecutor,
	config ClientConfig,
) (*Client, error) {
	if len(config.Capabilities) == 0 {
		config.Capabilities = agentprotocol.SupportedCapabilities()
	}
	if httpClient == nil || executor == nil || validateClientConfig(config) != nil {
		return nil, ErrConfigurationInvalid
	}
	return &Client{
		httpClient: httpClient,
		executor:   executor,
		config:     config,
	}, nil
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

func (c *Client) Run(ctx context.Context) error {
	sessionContext, cancel := context.WithCancel(ctx)
	defer cancel()

	requestReader, requestWriter := io.Pipe()
	defer func() { _ = requestReader.Close() }()
	defer func() { _ = requestWriter.Close() }()
	outbound := make(chan outboundFrame, c.config.MaxConcurrentCommands+2)
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
		frame.Command != nil || frame.Code != "" {
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
) error {
	switch frame.Type {
	case "heartbeat_ack":
		if frame.AcknowledgedSequence == 0 || frame.Command != nil ||
			frame.Code != "" || frame.CommandID != "" {
			return &PermanentError{Code: "invalid_heartbeat_ack"}
		}
		return nil
	case "command_result_ack":
		if frame.AcknowledgedSequence == 0 ||
			!validIdentity(frame.CommandID) ||
			frame.Command != nil || frame.Code != "" {
			return &PermanentError{Code: "invalid_command_result_ack"}
		}
		return nil
	case "command":
		if frame.Command == nil || frame.Code != "" ||
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
	case "error":
		if !validSafeCode(frame.Code) || frame.Command != nil {
			return &PermanentError{Code: "invalid_server_error"}
		}
		return &PermanentError{Code: frame.Code}
	default:
		return &PermanentError{Code: "unknown_server_frame"}
	}
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
