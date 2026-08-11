package service

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/owndock/owndock/internal/modules/terminal/biz"
	"github.com/owndock/owndock/internal/platform/httpx"
	"github.com/owndock/owndock/internal/shared/terminalprotocol"
)

const (
	terminalSubprotocol    = "owndock.terminal.v1"
	terminalOpenTimeout    = 10 * time.Second
	terminalWriteTimeout   = 10 * time.Second
	terminalCloseTimeout   = 5 * time.Second
	terminalReviewInterval = 2 * time.Second
	terminalReviewTimeout  = time.Second
)

var errTerminalClientClosed = errors.New("terminal client closed")

type terminalConnector interface {
	ConnectWithTicket(
		context.Context,
		string,
		string,
		string,
		biz.TerminalSize,
	) (biz.TerminalSession, biz.TerminalStream, error)
	CloseConnectedSession(
		context.Context,
		biz.TerminalSession,
		biz.CloseReason,
		string,
		string,
	) (biz.TerminalSession, error)
	ReviewConnectedSession(
		context.Context,
		biz.TerminalSession,
	) (biz.ConnectionReview, error)
}

// TerminalConnectionObserver receives only bounded product dimensions. It must
// never receive session, actor, target, payload or error-detail values.
type TerminalConnectionObserver interface {
	TerminalConnectionOpened(kind, connectionMode string)
	TerminalConnectionClosed(
		kind, connectionMode, reason string,
		duration time.Duration,
	)
}

type TerminalWSS struct {
	connector      terminalConnector
	observer       TerminalConnectionObserver
	now            func() time.Time
	reviewInterval time.Duration
	reviewTimeout  time.Duration
}

func NewTerminalWSS(
	connector terminalConnector,
	observers ...TerminalConnectionObserver,
) *TerminalWSS {
	service := &TerminalWSS{
		connector: connector, now: time.Now,
		reviewInterval: terminalReviewInterval,
		reviewTimeout:  terminalReviewTimeout,
	}
	if len(observers) > 0 {
		service.observer = observers[0]
	}
	return service
}

func (s *TerminalWSS) ServeHTTP(w http.ResponseWriter, r *http.Request, sessionID string) {
	if r.Method != http.MethodGet {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if s.connector == nil || strings.TrimSpace(sessionID) == "" {
		httpx.ErrorRequest(w, r, http.StatusServiceUnavailable, "terminal_unavailable")
		return
	}
	if !validTerminalOrigin(r) {
		httpx.ErrorRequest(w, r, http.StatusForbidden, "origin_not_allowed")
		return
	}
	ticket, err := r.Cookie(ticketCookieName)
	if err != nil || strings.TrimSpace(ticket.Value) == "" {
		httpx.ErrorRequest(w, r, http.StatusUnauthorized, "terminal_ticket_invalid")
		return
	}
	connection, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols:    []string{terminalSubprotocol},
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	defer connection.CloseNow()
	if connection.Subprotocol() != terminalSubprotocol {
		_ = connection.Close(websocket.StatusPolicyViolation, "terminal_protocol_required")
		return
	}
	connection.SetReadLimit(terminalprotocol.MaximumDataMessageBytes)

	streamContext, cancelStream := context.WithCancel(context.Background())
	defer cancelStream()
	openContext, cancelOpen := context.WithTimeout(streamContext, terminalOpenTimeout)
	messageType, payload, err := connection.Read(openContext)
	cancelOpen()
	if err != nil || messageType != websocket.MessageText {
		_ = connection.Close(websocket.StatusPolicyViolation, "terminal_open_required")
		return
	}
	open, err := terminalprotocol.DecodeControl(
		payload,
		terminalprotocol.DirectionClientToServer,
	)
	if err != nil || open.Type != terminalprotocol.TypeOpen {
		_ = connection.Close(websocket.StatusPolicyViolation, "terminal_open_invalid")
		return
	}
	session, stream, err := s.connector.ConnectWithTicket(
		streamContext,
		sessionID,
		ticket.Value,
		httpx.RequestIDFromContext(r.Context()),
		biz.TerminalSize{Columns: open.Columns, Rows: open.Rows},
	)
	if err != nil {
		_ = connection.Close(statusForTerminalError(err), safeTerminalErrorCode(err))
		return
	}
	defer stream.Close()
	ready, _ := terminalprotocol.EncodeControl(terminalprotocol.Control{
		Version: terminalprotocol.Version, Type: terminalprotocol.TypeReady, Sequence: 1,
	}, terminalprotocol.DirectionServerToClient)
	writeContext, cancelWrite := context.WithTimeout(streamContext, terminalWriteTimeout)
	err = connection.Write(writeContext, websocket.MessageText, ready)
	cancelWrite()
	if err != nil {
		s.closeSession(session, biz.CloseReasonConnectionFailed, "terminal_connection_failed", r)
		return
	}
	connectedAt := s.now()
	s.observeOpened(session)

	reason, safeCode, closeStatus := s.bridge(
		streamContext,
		connection,
		stream,
		session,
		open.Sequence,
	)
	_ = stream.Close()
	_ = connection.Close(closeStatus, safeCode)
	s.observeClosed(session, reason, s.now().Sub(connectedAt))
	s.closeSession(session, reason, safeCode, r)
}

func (s *TerminalWSS) observeOpened(session biz.TerminalSession) {
	if s.observer != nil {
		s.observer.TerminalConnectionOpened(
			string(session.Kind),
			string(session.ConnectionMode),
		)
	}
}

func (s *TerminalWSS) observeClosed(
	session biz.TerminalSession,
	reason biz.CloseReason,
	duration time.Duration,
) {
	if s.observer != nil {
		s.observer.TerminalConnectionClosed(
			string(session.Kind),
			string(session.ConnectionMode),
			string(reason),
			duration,
		)
	}
}

type terminalBridgeResult struct {
	err      error
	client   bool
	safeCode string
}

func (s *TerminalWSS) bridge(
	ctx context.Context,
	connection *websocket.Conn,
	stream biz.TerminalStream,
	session biz.TerminalSession,
	clientSequence uint64,
) (biz.CloseReason, string, websocket.StatusCode) {
	results := make(chan terminalBridgeResult, 2)
	activity := make(chan struct{}, 1)
	var serverSequence atomic.Uint64
	serverSequence.Store(1)
	go func() {
		results <- s.readClient(ctx, connection, stream, clientSequence, &serverSequence, activity)
	}()
	go func() {
		results <- s.writeOutput(ctx, connection, stream, activity)
	}()
	idleDuration := session.IdleDeadline.Sub(session.LastActivityAt)
	if idleDuration <= 0 {
		idleDuration = time.Second
	}
	idleTimer := time.NewTimer(idleDuration)
	maximumTimer := time.NewTimer(max(time.Until(session.MaximumDeadline), time.Millisecond))
	reviewInterval := s.reviewInterval
	if reviewInterval <= 0 {
		reviewInterval = terminalReviewInterval
	}
	reviewTicker := time.NewTicker(reviewInterval)
	var revocationTimer *time.Timer
	var revocationDeadline <-chan time.Time
	defer idleTimer.Stop()
	defer maximumTimer.Stop()
	defer reviewTicker.Stop()
	defer func() {
		if revocationTimer != nil {
			revocationTimer.Stop()
		}
	}()
	for {
		select {
		case <-activity:
			if !idleTimer.Stop() {
				select {
				case <-idleTimer.C:
				default:
				}
			}
			idleTimer.Reset(idleDuration)
		case result := <-results:
			if result.client && errors.Is(result.err, errTerminalClientClosed) {
				return biz.CloseReasonUserRequested, "", websocket.StatusNormalClosure
			}
			switch result.safeCode {
			case "terminal_message_too_large":
				return biz.CloseReasonConnectionFailed, result.safeCode, websocket.StatusMessageTooBig
			case "terminal_rate_limit_exceeded", "terminal_protocol_violation":
				return biz.CloseReasonConnectionFailed, result.safeCode, websocket.StatusPolicyViolation
			}
			return biz.CloseReasonConnectionFailed, "terminal_connection_failed", websocket.StatusInternalError
		case <-idleTimer.C:
			return biz.CloseReasonIdleTimeout, "", websocket.StatusNormalClosure
		case <-maximumTimer.C:
			return biz.CloseReasonMaximumDuration, "", websocket.StatusNormalClosure
		case <-reviewTicker.C:
			review, err := s.reviewConnection(ctx, session)
			if err != nil {
				return biz.CloseReasonConnectionFailed, "terminal_connection_failed", websocket.StatusInternalError
			}
			if !review.Terminate {
				if revocationTimer != nil {
					if !revocationTimer.Stop() {
						select {
						case <-revocationTimer.C:
						default:
						}
					}
					revocationTimer, revocationDeadline = nil, nil
				}
				continue
			}
			if review.Reason != biz.CloseReasonPermissionRevoked {
				return terminalReviewOutcome(review)
			}
			if revocationTimer == nil {
				if err := s.writePermissionRevoked(
					ctx,
					connection,
					&serverSequence,
				); err != nil {
					return biz.CloseReasonConnectionFailed, "terminal_connection_failed", websocket.StatusInternalError
				}
				if review.GracePeriod <= 0 {
					return terminalReviewOutcome(review)
				}
				revocationTimer = time.NewTimer(review.GracePeriod)
				revocationDeadline = revocationTimer.C
			}
		case <-revocationDeadline:
			return biz.CloseReasonPermissionRevoked, "", websocket.StatusPolicyViolation
		case <-ctx.Done():
			return biz.CloseReasonServerShutdown, "terminal_connection_failed", websocket.StatusGoingAway
		}
	}
}

func (s *TerminalWSS) reviewConnection(
	ctx context.Context,
	session biz.TerminalSession,
) (biz.ConnectionReview, error) {
	timeout := s.reviewTimeout
	if timeout <= 0 {
		timeout = terminalReviewTimeout
	}
	reviewContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return s.connector.ReviewConnectedSession(reviewContext, session)
}

func (s *TerminalWSS) writePermissionRevoked(
	ctx context.Context,
	connection *websocket.Conn,
	sequence *atomic.Uint64,
) error {
	payload, err := terminalprotocol.EncodeControl(terminalprotocol.Control{
		Version: terminalprotocol.Version,
		Type:    terminalprotocol.TypeError, Sequence: sequence.Add(1),
		Code: "terminal_permission_revoked",
	}, terminalprotocol.DirectionServerToClient)
	if err != nil {
		return err
	}
	writeContext, cancel := context.WithTimeout(ctx, terminalWriteTimeout)
	defer cancel()
	return connection.Write(writeContext, websocket.MessageText, payload)
}

func terminalReviewOutcome(
	review biz.ConnectionReview,
) (biz.CloseReason, string, websocket.StatusCode) {
	switch review.Reason {
	case biz.CloseReasonUserRequested,
		biz.CloseReasonAdministratorTerminated:
		return review.Reason, "", websocket.StatusNormalClosure
	case biz.CloseReasonPermissionRevoked:
		return review.Reason, "", websocket.StatusPolicyViolation
	case biz.CloseReasonTargetUnavailable:
		return review.Reason, "terminal_target_unavailable", websocket.StatusTryAgainLater
	default:
		return biz.CloseReasonConnectionFailed,
			"terminal_connection_failed",
			websocket.StatusInternalError
	}
}

func (s *TerminalWSS) readClient(
	ctx context.Context,
	connection *websocket.Conn,
	stream biz.TerminalStream,
	lastSequence uint64,
	serverSequence *atomic.Uint64,
	activity chan<- struct{},
) terminalBridgeResult {
	windowStarted, messageCount := s.now(), 0
	for {
		messageType, payload, err := connection.Read(ctx)
		if err != nil {
			if errors.Is(err, websocket.ErrMessageTooBig) ||
				websocket.CloseStatus(err) == websocket.StatusMessageTooBig {
				return terminalBridgeResult{
					err: err, client: true, safeCode: "terminal_message_too_large",
				}
			}
			if websocket.CloseStatus(err) == websocket.StatusNormalClosure {
				return terminalBridgeResult{err: errTerminalClientClosed, client: true}
			}
			return terminalBridgeResult{err: err, client: true}
		}
		now := s.now()
		if now.Sub(windowStarted) >= time.Second {
			windowStarted, messageCount = now, 0
		}
		messageCount++
		if messageCount > terminalprotocol.MaximumInputMessagesPerSecond {
			return terminalBridgeResult{
				err: errors.New("input rate exceeded"), client: true,
				safeCode: "terminal_rate_limit_exceeded",
			}
		}
		signalTerminalActivity(activity)
		switch messageType {
		case websocket.MessageBinary:
			if err := terminalprotocol.ValidateData(payload); err != nil {
				return terminalBridgeResult{
					err: err, client: true, safeCode: "terminal_message_too_large",
				}
			}
			if err := writeAll(stream, payload); err != nil {
				return terminalBridgeResult{err: err, client: true}
			}
		case websocket.MessageText:
			control, err := terminalprotocol.DecodeControl(
				payload,
				terminalprotocol.DirectionClientToServer,
			)
			if err != nil || control.Sequence != lastSequence+1 || control.Type == terminalprotocol.TypeOpen {
				return terminalBridgeResult{
					err: terminalprotocol.ErrInvalidControlMessage, client: true,
					safeCode: "terminal_protocol_violation",
				}
			}
			lastSequence = control.Sequence
			switch control.Type {
			case terminalprotocol.TypeResize:
				if err := stream.Resize(ctx, biz.TerminalSize{
					Columns: control.Columns, Rows: control.Rows,
				}); err != nil {
					return terminalBridgeResult{err: err, client: true}
				}
			case terminalprotocol.TypePing:
				pong, _ := terminalprotocol.EncodeControl(terminalprotocol.Control{
					Version: terminalprotocol.Version, Type: terminalprotocol.TypePong,
					Sequence: serverSequence.Add(1),
				}, terminalprotocol.DirectionServerToClient)
				writeContext, cancel := context.WithTimeout(ctx, terminalWriteTimeout)
				err := connection.Write(writeContext, websocket.MessageText, pong)
				cancel()
				if err != nil {
					return terminalBridgeResult{err: err, client: true}
				}
			case terminalprotocol.TypeClose:
				return terminalBridgeResult{err: errTerminalClientClosed, client: true}
			}
		default:
			return terminalBridgeResult{err: terminalprotocol.ErrInvalidControlMessage, client: true}
		}
	}
}

func (s *TerminalWSS) writeOutput(
	ctx context.Context,
	connection *websocket.Conn,
	stream biz.TerminalStream,
	activity chan<- struct{},
) terminalBridgeResult {
	buffer := make([]byte, terminalprotocol.MaximumDataMessageBytes)
	for {
		read, err := stream.Read(buffer)
		if read > 0 {
			signalTerminalActivity(activity)
			writeContext, cancel := context.WithTimeout(ctx, terminalWriteTimeout)
			writeErr := connection.Write(writeContext, websocket.MessageBinary, buffer[:read])
			cancel()
			if writeErr != nil {
				return terminalBridgeResult{err: writeErr}
			}
		}
		if err != nil {
			return terminalBridgeResult{err: err}
		}
	}
}

func (s *TerminalWSS) closeSession(
	session biz.TerminalSession,
	reason biz.CloseReason,
	safeCode string,
	r *http.Request,
) {
	ctx, cancel := context.WithTimeout(context.Background(), terminalCloseTimeout)
	defer cancel()
	_, _ = s.connector.CloseConnectedSession(
		ctx,
		session,
		reason,
		safeCode,
		httpx.RequestIDFromContext(r.Context()),
	)
}

func validTerminalOrigin(r *http.Request) bool {
	values := r.Header.Values("Origin")
	if len(values) != 1 {
		return false
	}
	origin, err := url.Parse(strings.TrimSpace(values[0]))
	if err != nil || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" ||
		(origin.Path != "" && origin.Path != "/") || !strings.EqualFold(origin.Host, r.Host) {
		return false
	}
	if origin.Scheme == "https" {
		return true
	}
	return origin.Scheme == "http" && loopbackTerminalHost(origin.Hostname())
}

func loopbackTerminalHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func writeAll(writer io.Writer, payload []byte) error {
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

func signalTerminalActivity(activity chan<- struct{}) {
	select {
	case activity <- struct{}{}:
	default:
	}
}

func statusForTerminalError(err error) websocket.StatusCode {
	if errors.Is(err, biz.ErrInvalidTicket) {
		return websocket.StatusPolicyViolation
	}
	if errors.Is(err, biz.ErrTargetUnavailable) || errors.Is(err, biz.ErrStreamUnavailable) {
		return websocket.StatusTryAgainLater
	}
	return websocket.StatusInternalError
}

func safeTerminalErrorCode(err error) string {
	if errors.Is(err, biz.ErrInvalidTicket) {
		return "terminal_ticket_invalid"
	}
	if errors.Is(err, biz.ErrTargetUnavailable) {
		return "terminal_target_unavailable"
	}
	return "terminal_connection_failed"
}
