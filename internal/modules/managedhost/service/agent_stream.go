package service

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/modules/managedhost/biz"
	"github.com/owndock/owndock/internal/platform/httpx"
)

const agentStreamContentType = "application/x-ndjson"

type AgentStream struct {
	useCase           *biz.UseCase
	registry          biz.AgentConnectionRegistry
	handshakeTimeout  time.Duration
	heartbeatInterval time.Duration
	heartbeatTimeout  time.Duration
	maxFrameBytes     int
}

func NewAgentStream(
	useCase *biz.UseCase,
	registry biz.AgentConnectionRegistry,
	handshakeTimeout, heartbeatInterval, heartbeatTimeout time.Duration,
	maxFrameBytes int,
) (*AgentStream, error) {
	if useCase == nil || registry == nil ||
		handshakeTimeout <= 0 || heartbeatInterval <= 0 ||
		heartbeatTimeout <= heartbeatInterval ||
		maxFrameBytes < 1024 || maxFrameBytes > 1024*1024 {
		return nil, biz.ErrAgentControlUnavailable
	}
	return &AgentStream{
		useCase: useCase, registry: registry,
		handshakeTimeout:  handshakeTimeout,
		heartbeatInterval: heartbeatInterval,
		heartbeatTimeout:  heartbeatTimeout,
		maxFrameBytes:     maxFrameBytes,
	}, nil
}

func (s *AgentStream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != agentStreamContentType {
		httpx.ErrorRequest(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return
	}
	certificate, err := agentCertificateIdentity(r)
	if err != nil {
		httpx.ErrorRequest(w, r, http.StatusUnauthorized, "invalid_agent_identity")
		return
	}
	controller := http.NewResponseController(w)
	if err := controller.EnableFullDuplex(); err != nil {
		httpx.ErrorRequest(w, r, http.StatusInternalServerError, "agent_stream_unavailable")
		return
	}
	if err := controller.SetReadDeadline(time.Now().Add(s.handshakeTimeout)); err != nil {
		httpx.ErrorRequest(w, r, http.StatusInternalServerError, "agent_stream_unavailable")
		return
	}
	scanner := bufio.NewScanner(r.Body)
	scanner.Buffer(make([]byte, 4096), s.maxFrameBytes)
	if !scanner.Scan() {
		httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_agent_hello")
		return
	}
	var first agentFrame
	if err := decodeAgentFrame(scanner.Bytes(), &first); err != nil ||
		first.Type != "hello" || first.Sequence == 0 || first.Hello == nil ||
		first.CommandResult != nil {
		httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_agent_hello")
		return
	}
	session, err := s.useCase.OpenAgentSession(
		r.Context(),
		certificate,
		biz.AgentHello{
			OrganizationID:  first.Hello.OrganizationID,
			ManagedHostID:   first.Hello.ManagedHostID,
			IdentityID:      first.Hello.AgentIdentityID,
			InstanceID:      first.Hello.InstanceID,
			BootID:          first.Hello.BootID,
			AgentVersion:    first.Hello.AgentVersion,
			ProtocolVersion: first.Hello.ProtocolVersion,
			Capabilities:    first.Hello.Capabilities,
		},
		httpx.RequestIDFromContext(r.Context()),
	)
	if writeAgentOpenError(w, r, err) {
		return
	}

	streamContext, cancel := context.WithCancel(r.Context())
	commands := s.registry.Register(session.ManagedHostID, session.ID, cancel)
	defer func() {
		cancel()
		s.registry.Unregister(session.ManagedHostID, session.ID)
		closeContext, closeCancel := context.WithTimeout(
			context.Background(), 5*time.Second,
		)
		defer closeCancel()
		_ = s.useCase.CloseAgentSession(closeContext, session, session.ID)
	}()
	go func() {
		<-streamContext.Done()
		_ = controller.SetReadDeadline(time.Now())
		_ = controller.SetWriteDeadline(time.Now())
	}()

	w.Header().Set("Content-Type", agentStreamContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	encoder := json.NewEncoder(w)
	flusher, _ := w.(http.Flusher)
	writeFrame := func(frame serverFrame) error {
		if err := controller.SetWriteDeadline(
			time.Now().Add(s.heartbeatTimeout),
		); err != nil {
			return err
		}
		if err := encoder.Encode(frame); err != nil {
			return err
		}
		if flusher != nil {
			flusher.Flush()
		}
		return nil
	}
	serverSequence := uint64(1)
	if err := writeFrame(serverFrame{
		Type: "hello_ack", Sequence: serverSequence,
		SessionID: session.ID, ProtocolVersion: session.ProtocolVersion,
		HeartbeatIntervalSeconds: int64(s.heartbeatInterval / time.Second),
		MaxFrameBytes:            s.maxFrameBytes, ServerTime: time.Now().UTC(),
	}); err != nil {
		return
	}

	lastAgentSequence := first.Sequence
	reads := make(chan agentRead, 1)
	go s.readAgentFrames(streamContext, controller, scanner, reads)
	for {
		select {
		case read := <-reads:
			if read.eof {
				return
			}
			frame := read.frame
			if read.err != nil || frame.Sequence <= lastAgentSequence ||
				frame.Hello != nil {
				serverSequence++
				_ = writeFrame(serverFrame{
					Type: "error", Sequence: serverSequence,
					Code: "invalid_agent_frame",
				})
				return
			}
			lastAgentSequence = frame.Sequence
			switch frame.Type {
			case "heartbeat":
				if frame.CommandResult != nil {
					serverSequence++
					_ = writeFrame(serverFrame{
						Type: "error", Sequence: serverSequence,
						Code: "invalid_agent_frame",
					})
					return
				}
				if err := s.useCase.HeartbeatAgentSession(
					streamContext, session,
				); err != nil {
					serverSequence++
					_ = writeFrame(serverFrame{
						Type: "error", Sequence: serverSequence,
						Code: "agent_identity_revoked",
					})
					return
				}
				serverSequence++
				if err := writeFrame(serverFrame{
					Type: "heartbeat_ack", Sequence: serverSequence,
					AcknowledgedSequence: frame.Sequence,
					ServerTime:           time.Now().UTC(),
				}); err != nil {
					return
				}
			case "command_result":
				if frame.CommandResult == nil {
					serverSequence++
					_ = writeFrame(serverFrame{
						Type: "error", Sequence: serverSequence,
						Code: "invalid_agent_frame",
					})
					return
				}
				result := frame.CommandResult.domain()
				if err := s.registry.Complete(
					session.ManagedHostID, session.ID, result,
				); err != nil {
					serverSequence++
					_ = writeFrame(serverFrame{
						Type: "error", Sequence: serverSequence,
						Code: "invalid_command_result",
					})
					return
				}
				serverSequence++
				if err := writeFrame(serverFrame{
					Type: "command_result_ack", Sequence: serverSequence,
					AcknowledgedSequence: frame.Sequence,
					CommandID:            result.CommandID,
					ServerTime:           time.Now().UTC(),
				}); err != nil {
					return
				}
			default:
				serverSequence++
				_ = writeFrame(serverFrame{
					Type: "error", Sequence: serverSequence,
					Code: "invalid_agent_frame",
				})
				return
			}
		case command, open := <-commands:
			if !open {
				return
			}
			select {
			case <-streamContext.Done():
				return
			default:
			}
			serverSequence++
			if err := writeFrame(serverFrame{
				Type:     "command",
				Sequence: serverSequence,
				Command:  newServerCommand(command),
			}); err != nil {
				return
			}
		case <-streamContext.Done():
			return
		}
	}
}

type agentFrame struct {
	Type          string              `json:"type"`
	Sequence      uint64              `json:"sequence"`
	Hello         *agentHello         `json:"hello,omitempty"`
	CommandResult *agentCommandResult `json:"command_result,omitempty"`
}

type agentHello struct {
	OrganizationID  string   `json:"organization_id"`
	ManagedHostID   string   `json:"managed_host_id"`
	AgentIdentityID string   `json:"agent_identity_id"`
	InstanceID      string   `json:"instance_id"`
	BootID          string   `json:"boot_id"`
	AgentVersion    string   `json:"agent_version"`
	ProtocolVersion string   `json:"protocol_version"`
	Capabilities    []string `json:"capabilities"`
}

type serverFrame struct {
	Type                     string         `json:"type"`
	Sequence                 uint64         `json:"sequence"`
	SessionID                string         `json:"session_id,omitempty"`
	ProtocolVersion          string         `json:"protocol_version,omitempty"`
	HeartbeatIntervalSeconds int64          `json:"heartbeat_interval_seconds,omitempty"`
	MaxFrameBytes            int            `json:"max_frame_bytes,omitempty"`
	AcknowledgedSequence     uint64         `json:"acknowledged_sequence,omitempty"`
	ServerTime               time.Time      `json:"server_time,omitzero"`
	Code                     string         `json:"code,omitempty"`
	CommandID                string         `json:"command_id,omitempty"`
	Command                  *serverCommand `json:"command,omitempty"`
}

type agentCommandResult struct {
	CommandID    string                   `json:"command_id"`
	Status       biz.AgentCommandStatus   `json:"status"`
	ErrorCode    string                   `json:"error_code,omitempty"`
	RuntimeProbe *agentRuntimeProbeResult `json:"runtime_probe,omitempty"`
}

type agentRuntimeProbeResult struct {
	Status biz.RuntimeProbeStatus `json:"status"`
}

func (r agentCommandResult) domain() biz.AgentCommandResult {
	result := biz.AgentCommandResult{
		CommandID: r.CommandID,
		Status:    r.Status,
		ErrorCode: r.ErrorCode,
	}
	if r.RuntimeProbe != nil {
		result.RuntimeProbe = &biz.RuntimeProbeResult{
			Status: r.RuntimeProbe.Status,
		}
	}
	return result
}

type serverCommand struct {
	CommandID    string                     `json:"command_id"`
	Kind         biz.AgentCommandKind       `json:"kind"`
	Deadline     time.Time                  `json:"deadline"`
	RuntimeProbe *serverRuntimeProbeCommand `json:"runtime_probe,omitempty"`
}

type serverRuntimeProbeCommand struct {
	RuntimeTargetID string `json:"runtime_target_id"`
}

func newServerCommand(command biz.AgentCommand) *serverCommand {
	result := &serverCommand{
		CommandID: command.ID,
		Kind:      command.Kind,
		Deadline:  command.Deadline.UTC(),
	}
	if command.RuntimeProbe != nil {
		result.RuntimeProbe = &serverRuntimeProbeCommand{
			RuntimeTargetID: command.RuntimeProbe.RuntimeTargetID,
		}
	}
	return result
}

type agentRead struct {
	frame agentFrame
	err   error
	eof   bool
}

func (s *AgentStream) readAgentFrames(
	ctx context.Context,
	controller *http.ResponseController,
	scanner *bufio.Scanner,
	reads chan<- agentRead,
) {
	for {
		if err := controller.SetReadDeadline(
			time.Now().Add(s.heartbeatTimeout),
		); err != nil {
			sendAgentRead(ctx, reads, agentRead{err: err})
			return
		}
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				sendAgentRead(ctx, reads, agentRead{err: err})
			} else {
				sendAgentRead(ctx, reads, agentRead{eof: true})
			}
			return
		}
		var frame agentFrame
		if err := decodeAgentFrame(scanner.Bytes(), &frame); err != nil {
			sendAgentRead(ctx, reads, agentRead{err: err})
			return
		}
		if !sendAgentRead(ctx, reads, agentRead{frame: frame}) {
			return
		}
	}
}

func sendAgentRead(
	ctx context.Context,
	reads chan<- agentRead,
	read agentRead,
) bool {
	select {
	case reads <- read:
		return true
	case <-ctx.Done():
		return false
	}
}

func decodeAgentFrame(value []byte, target *agentFrame) error {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("agent frame must contain one JSON value")
	}
	return nil
}

func writeAgentOpenError(w http.ResponseWriter, r *http.Request, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, biz.ErrAgentProtocolUnsupported):
		httpx.ErrorRequest(w, r, http.StatusConflict, "agent_protocol_unsupported")
	case errors.Is(err, biz.ErrInvalidAgentIdentity),
		errors.Is(err, biz.ErrAgentSessionInvalid):
		httpx.ErrorRequest(w, r, http.StatusUnauthorized, "invalid_agent_identity")
	case errors.Is(err, biz.ErrAgentControlUnavailable):
		httpx.ErrorRequest(w, r, http.StatusServiceUnavailable, "agent_control_unavailable")
	default:
		httpx.ErrorRequest(w, r, http.StatusInternalServerError, "internal_error")
	}
	return true
}

func agentCertificateIdentity(r *http.Request) (biz.AgentCertificateIdentity, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 ||
		len(r.TLS.VerifiedChains) == 0 {
		return biz.AgentCertificateIdentity{}, biz.ErrInvalidAgentIdentity
	}
	certificate := r.TLS.PeerCertificates[0]
	if len(certificate.URIs) != 1 {
		return biz.AgentCertificateIdentity{}, biz.ErrInvalidAgentIdentity
	}
	identityURI := certificate.URIs[0]
	if identityURI.Scheme != "spiffe" || identityURI.Host != "owndock" {
		return biz.AgentCertificateIdentity{}, biz.ErrInvalidAgentIdentity
	}
	segments := strings.Split(strings.Trim(identityURI.Path, "/"), "/")
	if len(segments) != 8 ||
		segments[0] != "organizations" ||
		segments[2] != "managed-hosts" ||
		segments[4] != "agents" ||
		segments[6] != "instances" {
		return biz.AgentCertificateIdentity{}, biz.ErrInvalidAgentIdentity
	}
	fingerprint := sha256.Sum256(certificate.Raw)
	return biz.AgentCertificateIdentity{
		OrganizationID: segments[1], ManagedHostID: segments[3],
		IdentityID: segments[5], InstanceID: segments[7],
		CertificateSerial: certificate.SerialNumber.Text(16),
		CertificateSHA256: hex.EncodeToString(fingerprint[:]),
	}, nil
}
