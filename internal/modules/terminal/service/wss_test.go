package service

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/owndock/owndock/internal/modules/terminal/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/terminalprotocol"
)

type wssConnectorStub struct {
	mu               sync.Mutex
	stream           *wssStreamStub
	connected        int
	closed           int
	sessionID        string
	ticket           string
	size             biz.TerminalSize
	reason           biz.CloseReason
	safeCode         string
	closeDone        chan struct{}
	review           biz.ConnectionReview
	reviewErr        error
	reviews          int
	connectedSession biz.TerminalSession
}

type wssObserverStub struct {
	mu       sync.Mutex
	opened   int
	closed   int
	kind     string
	mode     string
	reason   string
	duration time.Duration
}

func (o *wssObserverStub) TerminalConnectionOpened(kind, connectionMode string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.opened++
	o.kind, o.mode = kind, connectionMode
}

func (o *wssObserverStub) TerminalConnectionClosed(
	kind, connectionMode, reason string,
	duration time.Duration,
) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closed++
	o.kind, o.mode, o.reason, o.duration = kind, connectionMode, reason, duration
}

func (c *wssConnectorStub) ReviewConnectedSession(
	_ context.Context,
	_ biz.TerminalSession,
) (biz.ConnectionReview, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reviews++
	return c.review, c.reviewErr
}

func (c *wssConnectorStub) ConnectWithTicket(
	_ context.Context,
	sessionID, ticket, _ string,
	size biz.TerminalSize,
) (biz.TerminalSession, biz.TerminalStream, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connected++
	c.sessionID, c.ticket, c.size = sessionID, ticket, size
	now := time.Now().UTC()
	connected := c.connectedSession
	if connected.ID == "" {
		connected = biz.TerminalSession{
			ID: sessionID, OrganizationID: "organization-1", ProjectID: "project-1",
			Kind: biz.KindContainer, ActorID: "user-1", ManagedHostID: "host-1",
			RuntimeTargetID: "target-1", DeploymentID: "deployment-1",
			RunningInstanceID: "deployment-1:1", InstanceGeneration: 1,
			Status: biz.StatusOpen, ConnectionMode: runtimeaccess.ModeDirectDocker,
			CreatedAt: now.Add(-time.Minute), ConnectedAt: now, LastActivityAt: now,
			IdleDeadline: now.Add(time.Minute), MaximumDeadline: now.Add(time.Hour),
		}
	}
	return connected, c.stream, nil
}

func (c *wssConnectorStub) CloseConnectedSession(
	_ context.Context,
	session biz.TerminalSession,
	reason biz.CloseReason,
	safeCode, _ string,
) (biz.TerminalSession, error) {
	c.mu.Lock()
	c.closed++
	c.reason, c.safeCode = reason, safeCode
	if c.closeDone != nil {
		close(c.closeDone)
		c.closeDone = nil
	}
	c.mu.Unlock()
	return session, nil
}

type wssStreamStub struct {
	inputMu sync.Mutex
	input   bytes.Buffer
	reader  *io.PipeReader
	output  *io.PipeWriter
	closed  sync.Once
	resize  chan biz.TerminalSize
}

func newWSSStreamStub() *wssStreamStub {
	reader, writer := io.Pipe()
	return &wssStreamStub{
		reader: reader, output: writer, resize: make(chan biz.TerminalSize, 1),
	}
}

func (s *wssStreamStub) Read(payload []byte) (int, error) { return s.reader.Read(payload) }
func (s *wssStreamStub) Write(payload []byte) (int, error) {
	s.inputMu.Lock()
	defer s.inputMu.Unlock()
	return s.input.Write(payload)
}
func (s *wssStreamStub) Close() error {
	s.closed.Do(func() {
		_ = s.reader.Close()
		_ = s.output.Close()
	})
	return nil
}
func (s *wssStreamStub) Resize(_ context.Context, size biz.TerminalSize) error {
	s.resize <- size
	return nil
}

func TestContainerWSSBridgesBinaryDataAndControlMessages(t *testing.T) {
	stream := newWSSStreamStub()
	closeDone := make(chan struct{})
	connector := &wssConnectorStub{
		stream: stream, closeDone: closeDone,
	}
	observer := &wssObserverStub{}
	handler := NewTerminalWSS(connector, observer)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r, "terminal-session-1")
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, _, err := websocket.Dial(
		ctx,
		"ws"+strings.TrimPrefix(server.URL, "http"),
		&websocket.DialOptions{
			Subprotocols: []string{terminalSubprotocol},
			HTTPHeader: http.Header{
				"Origin": []string{server.URL},
				"Cookie": []string{ticketCookieName + "=one-time-ticket"},
			},
		},
	)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer connection.CloseNow()
	writeControl(t, ctx, connection, terminalprotocol.Control{
		Version: terminalprotocol.Version, Type: terminalprotocol.TypeOpen,
		Sequence: 1, Columns: 100, Rows: 40,
	})
	messageType, payload, err := connection.Read(ctx)
	if err != nil || messageType != websocket.MessageText {
		t.Fatalf("read ready type = %v, payload = %q, error = %v", messageType, payload, err)
	}
	ready, err := terminalprotocol.DecodeControl(payload, terminalprotocol.DirectionServerToClient)
	if err != nil || ready.Type != terminalprotocol.TypeReady {
		t.Fatalf("ready = %+v, error = %v", ready, err)
	}
	if err := connection.Write(ctx, websocket.MessageBinary, []byte("pwd")); err != nil {
		t.Fatalf("write stdin error = %v", err)
	}
	writeControl(t, ctx, connection, terminalprotocol.Control{
		Version: terminalprotocol.Version, Type: terminalprotocol.TypeResize,
		Sequence: 2, Columns: 132, Rows: 43,
	})
	select {
	case size := <-stream.resize:
		if size.Columns != 132 || size.Rows != 43 {
			t.Fatalf("resize = %+v", size)
		}
	case <-ctx.Done():
		t.Fatal("resize was not forwarded")
	}
	deadline := time.Now().Add(time.Second)
	for {
		stream.inputMu.Lock()
		stdin := stream.input.String()
		stream.inputMu.Unlock()
		if stdin == "pwd" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("stdin = %q, want pwd", stdin)
		}
		time.Sleep(time.Millisecond)
	}
	go func() { _, _ = stream.output.Write([]byte("ready\r\n")) }()
	messageType, payload, err = connection.Read(ctx)
	if err != nil || messageType != websocket.MessageBinary || string(payload) != "ready\r\n" {
		t.Fatalf("stdout type = %v, payload = %q, error = %v", messageType, payload, err)
	}
	writeControl(t, ctx, connection, terminalprotocol.Control{
		Version: terminalprotocol.Version, Type: terminalprotocol.TypeClose, Sequence: 3,
	})
	_, _, _ = connection.Read(ctx)
	select {
	case <-closeDone:
	case <-ctx.Done():
		t.Fatal("terminal session close was not persisted")
	}
	connector.mu.Lock()
	defer connector.mu.Unlock()
	if connector.connected != 1 || connector.closed != 1 ||
		connector.sessionID != "terminal-session-1" || connector.ticket != "one-time-ticket" ||
		connector.size.Columns != 100 || connector.size.Rows != 40 ||
		connector.reason != biz.CloseReasonUserRequested || connector.safeCode != "" {
		t.Fatalf("connector state = %+v", connector)
	}
	observer.mu.Lock()
	defer observer.mu.Unlock()
	if observer.opened != 1 || observer.closed != 1 ||
		observer.kind != "container" || observer.mode != "direct" ||
		observer.reason != "user_requested" || observer.duration < 0 {
		t.Fatalf("observer state = %+v", observer)
	}
}

func TestTerminalWSSBridgesHostSessionWithoutChangingBrowserProtocol(t *testing.T) {
	stream := newWSSStreamStub()
	closeDone := make(chan struct{})
	now := time.Now().UTC()
	connector := &wssConnectorStub{
		stream: stream, closeDone: closeDone,
		connectedSession: biz.TerminalSession{
			ID: "host-terminal-1", OrganizationID: "organization-1",
			Kind: biz.KindHost, ActorID: "owner-1", ManagedHostID: "host-1",
			Status: biz.StatusOpen, ConnectionMode: runtimeaccess.ModeAgent,
			CreatedAt: now.Add(-time.Minute), ConnectedAt: now,
			LastActivityAt: now, IdleDeadline: now.Add(time.Minute),
			MaximumDeadline: now.Add(time.Hour),
		},
	}
	observer := &wssObserverStub{}
	handler := NewTerminalWSS(connector, observer)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r, "host-terminal-1")
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, _, err := websocket.Dial(
		ctx,
		"ws"+strings.TrimPrefix(server.URL, "http"),
		&websocket.DialOptions{
			Subprotocols: []string{terminalSubprotocol},
			HTTPHeader: http.Header{
				"Origin": []string{server.URL},
				"Cookie": []string{ticketCookieName + "=one-time-ticket"},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseNow()
	writeControl(t, ctx, connection, terminalprotocol.Control{
		Version: terminalprotocol.Version, Type: terminalprotocol.TypeOpen,
		Sequence: 1, Columns: 100, Rows: 40,
	})
	if _, _, err := connection.Read(ctx); err != nil {
		t.Fatalf("read host ready: %v", err)
	}
	writeControl(t, ctx, connection, terminalprotocol.Control{
		Version: terminalprotocol.Version, Type: terminalprotocol.TypeClose,
		Sequence: 2,
	})
	_, _, _ = connection.Read(ctx)
	select {
	case <-closeDone:
	case <-ctx.Done():
		t.Fatal("host terminal close was not persisted")
	}
	observer.mu.Lock()
	defer observer.mu.Unlock()
	if observer.opened != 1 || observer.closed != 1 ||
		observer.kind != "host" || observer.mode != "agent" ||
		observer.reason != "user_requested" {
		t.Fatalf("host observer state = %+v", observer)
	}
}

func TestContainerWSSRejectsMissingOrCrossSiteOriginBeforeConnect(t *testing.T) {
	connector := &wssConnectorStub{stream: newWSSStreamStub()}
	defer connector.stream.Close()
	handler := NewTerminalWSS(connector)
	for _, origin := range []string{"", "https://attacker.example"} {
		request := httptest.NewRequest(http.MethodGet, "http://owndock.test/api/v1/terminal-sessions/session-1:connect", nil)
		request.Host = "owndock.test"
		request.Header.Set("Cookie", ticketCookieName+"=ticket")
		if origin != "" {
			request.Header.Set("Origin", origin)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request, "session-1")
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("origin %q status = %d, want 403", origin, recorder.Code)
		}
	}
	connector.mu.Lock()
	defer connector.mu.Unlock()
	if connector.connected != 0 {
		t.Fatal("untrusted Origin reached terminal connector")
	}
}

func TestContainerWSSClosesAfterAdministratorTerminationReview(t *testing.T) {
	stream := newWSSStreamStub()
	closeDone := make(chan struct{})
	connector := &wssConnectorStub{stream: stream, closeDone: closeDone}
	handler := NewTerminalWSS(connector)
	handler.reviewInterval = 10 * time.Millisecond
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r, "terminal-session-1")
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, _, err := websocket.Dial(
		ctx,
		"ws"+strings.TrimPrefix(server.URL, "http"),
		&websocket.DialOptions{
			Subprotocols: []string{terminalSubprotocol},
			HTTPHeader: http.Header{
				"Origin": []string{server.URL},
				"Cookie": []string{ticketCookieName + "=one-time-ticket"},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseNow()
	writeControl(t, ctx, connection, terminalprotocol.Control{
		Version: terminalprotocol.Version, Type: terminalprotocol.TypeOpen,
		Sequence: 1, Columns: 120, Rows: 30,
	})
	if _, _, err := connection.Read(ctx); err != nil {
		t.Fatalf("read ready: %v", err)
	}
	connector.mu.Lock()
	connector.review = biz.ConnectionReview{
		Terminate: true,
		Reason:    biz.CloseReasonAdministratorTerminated,
	}
	connector.mu.Unlock()
	_, _, err = connection.Read(ctx)
	if websocket.CloseStatus(err) != websocket.StatusNormalClosure {
		t.Fatalf("terminal close error = %v", err)
	}
	select {
	case <-closeDone:
	case <-ctx.Done():
		t.Fatal("terminated session close was not persisted")
	}
	connector.mu.Lock()
	defer connector.mu.Unlock()
	if connector.reason != biz.CloseReasonAdministratorTerminated ||
		connector.safeCode != "" {
		t.Fatalf("connector close = %s/%q", connector.reason, connector.safeCode)
	}
}

func TestContainerWSSNotifiesAndHonorsPermissionRevocationGrace(t *testing.T) {
	stream := newWSSStreamStub()
	closeDone := make(chan struct{})
	connector := &wssConnectorStub{
		stream: stream, closeDone: closeDone,
		review: biz.ConnectionReview{
			Terminate: true, Reason: biz.CloseReasonPermissionRevoked,
			GracePeriod: 60 * time.Millisecond,
		},
	}
	handler := NewTerminalWSS(connector)
	handler.reviewInterval = 10 * time.Millisecond
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r, "terminal-session-1")
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, _, err := websocket.Dial(
		ctx,
		"ws"+strings.TrimPrefix(server.URL, "http"),
		&websocket.DialOptions{
			Subprotocols: []string{terminalSubprotocol},
			HTTPHeader: http.Header{
				"Origin": []string{server.URL},
				"Cookie": []string{ticketCookieName + "=one-time-ticket"},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseNow()
	writeControl(t, ctx, connection, terminalprotocol.Control{
		Version: terminalprotocol.Version, Type: terminalprotocol.TypeOpen,
		Sequence: 1, Columns: 120, Rows: 30,
	})
	if _, _, err := connection.Read(ctx); err != nil {
		t.Fatalf("read ready: %v", err)
	}
	messageType, payload, err := connection.Read(ctx)
	if err != nil || messageType != websocket.MessageText {
		t.Fatalf("read revocation notice type = %v, payload = %q, error = %v", messageType, payload, err)
	}
	notice, err := terminalprotocol.DecodeControl(
		payload,
		terminalprotocol.DirectionServerToClient,
	)
	if err != nil || notice.Type != terminalprotocol.TypeError ||
		notice.Code != "terminal_permission_revoked" {
		t.Fatalf("revocation notice = %+v, error = %v", notice, err)
	}
	select {
	case <-closeDone:
		t.Fatal("permission grace period was skipped")
	case <-time.After(20 * time.Millisecond):
	}
	_, _, err = connection.Read(ctx)
	if websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatalf("revoked terminal close error = %v", err)
	}
	select {
	case <-closeDone:
	case <-ctx.Done():
		t.Fatal("revoked session close was not persisted")
	}
	connector.mu.Lock()
	defer connector.mu.Unlock()
	if connector.reason != biz.CloseReasonPermissionRevoked ||
		connector.safeCode != "" || connector.reviews < 1 {
		t.Fatalf("connector state = %+v", connector)
	}
}

func TestContainerWSSCancelsRevocationWhenPermissionRecovers(t *testing.T) {
	stream := newWSSStreamStub()
	connector := &wssConnectorStub{
		stream: stream,
		review: biz.ConnectionReview{
			Terminate: true, Reason: biz.CloseReasonPermissionRevoked,
			GracePeriod: 60 * time.Millisecond,
		},
	}
	handler := NewTerminalWSS(connector)
	handler.reviewInterval = 10 * time.Millisecond
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r, "terminal-session-1")
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, _, err := websocket.Dial(
		ctx,
		"ws"+strings.TrimPrefix(server.URL, "http"),
		&websocket.DialOptions{
			Subprotocols: []string{terminalSubprotocol},
			HTTPHeader: http.Header{
				"Origin": []string{server.URL},
				"Cookie": []string{ticketCookieName + "=one-time-ticket"},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseNow()
	writeControl(t, ctx, connection, terminalprotocol.Control{
		Version: terminalprotocol.Version, Type: terminalprotocol.TypeOpen,
		Sequence: 1, Columns: 120, Rows: 30,
	})
	if _, _, err := connection.Read(ctx); err != nil {
		t.Fatalf("read ready: %v", err)
	}
	if _, _, err := connection.Read(ctx); err != nil {
		t.Fatalf("read revocation notice: %v", err)
	}
	connector.mu.Lock()
	connector.review = biz.ConnectionReview{}
	connector.mu.Unlock()
	time.Sleep(90 * time.Millisecond)
	writeControl(t, ctx, connection, terminalprotocol.Control{
		Version: terminalprotocol.Version, Type: terminalprotocol.TypePing,
		Sequence: 2,
	})
	messageType, payload, err := connection.Read(ctx)
	if err != nil || messageType != websocket.MessageText {
		t.Fatalf("read pong type = %v, payload = %q, error = %v", messageType, payload, err)
	}
	pong, err := terminalprotocol.DecodeControl(
		payload,
		terminalprotocol.DirectionServerToClient,
	)
	if err != nil || pong.Type != terminalprotocol.TypePong {
		t.Fatalf("pong = %+v, error = %v", pong, err)
	}
}

func TestContainerWSSFailsClosedWhenReviewUnavailable(t *testing.T) {
	stream := newWSSStreamStub()
	closeDone := make(chan struct{})
	connector := &wssConnectorStub{
		stream: stream, closeDone: closeDone,
		reviewErr: errors.New("identity store unavailable"),
	}
	handler := NewTerminalWSS(connector)
	handler.reviewInterval = 10 * time.Millisecond
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r, "terminal-session-1")
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, _, err := websocket.Dial(
		ctx,
		"ws"+strings.TrimPrefix(server.URL, "http"),
		&websocket.DialOptions{
			Subprotocols: []string{terminalSubprotocol},
			HTTPHeader: http.Header{
				"Origin": []string{server.URL},
				"Cookie": []string{ticketCookieName + "=one-time-ticket"},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseNow()
	writeControl(t, ctx, connection, terminalprotocol.Control{
		Version: terminalprotocol.Version, Type: terminalprotocol.TypeOpen,
		Sequence: 1, Columns: 120, Rows: 30,
	})
	if _, _, err := connection.Read(ctx); err != nil {
		t.Fatalf("read ready: %v", err)
	}
	_, _, err = connection.Read(ctx)
	if websocket.CloseStatus(err) != websocket.StatusInternalError {
		t.Fatalf("review failure close error = %v", err)
	}
	select {
	case <-closeDone:
	case <-ctx.Done():
		t.Fatal("review failure close was not persisted")
	}
	connector.mu.Lock()
	defer connector.mu.Unlock()
	if connector.reason != biz.CloseReasonConnectionFailed ||
		connector.safeCode != "terminal_connection_failed" {
		t.Fatalf("connector close = %s/%q", connector.reason, connector.safeCode)
	}
}

func TestContainerWSSRejectsOversizedPayloadWithSafeMetadata(t *testing.T) {
	stream := newWSSStreamStub()
	closeDone := make(chan struct{})
	connector := &wssConnectorStub{stream: stream, closeDone: closeDone}
	handler := NewTerminalWSS(connector)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r, "terminal-session-1")
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, _, err := websocket.Dial(
		ctx,
		"ws"+strings.TrimPrefix(server.URL, "http"),
		&websocket.DialOptions{
			Subprotocols: []string{terminalSubprotocol},
			HTTPHeader: http.Header{
				"Origin": []string{server.URL},
				"Cookie": []string{ticketCookieName + "=one-time-ticket"},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseNow()
	writeControl(t, ctx, connection, terminalprotocol.Control{
		Version: terminalprotocol.Version, Type: terminalprotocol.TypeOpen,
		Sequence: 1, Columns: 120, Rows: 30,
	})
	if _, _, err := connection.Read(ctx); err != nil {
		t.Fatalf("read ready: %v", err)
	}
	secret := bytes.Repeat([]byte("terminal-secret"),
		terminalprotocol.MaximumDataMessageBytes/len("terminal-secret")+1)
	if err := connection.Write(ctx, websocket.MessageBinary, secret); err != nil &&
		websocket.CloseStatus(err) != websocket.StatusMessageTooBig {
		t.Fatalf("write oversized payload: %v", err)
	}
	_, _, err = connection.Read(ctx)
	if websocket.CloseStatus(err) != websocket.StatusMessageTooBig {
		t.Fatalf("oversized close error = %v", err)
	}
	select {
	case <-closeDone:
	case <-ctx.Done():
		t.Fatal("oversized payload close was not persisted")
	}
	connector.mu.Lock()
	defer connector.mu.Unlock()
	if connector.reason != biz.CloseReasonConnectionFailed ||
		connector.safeCode != "terminal_message_too_large" {
		t.Fatalf("connector close = %s/%q", connector.reason, connector.safeCode)
	}
	stream.inputMu.Lock()
	defer stream.inputMu.Unlock()
	if stream.input.Len() != 0 || strings.Contains(connector.safeCode, "terminal-secret") {
		t.Fatal("oversized terminal payload crossed the safe metadata boundary")
	}
}

func TestContainerWSSRejectsInvalidControlSequenceWithStableCode(t *testing.T) {
	stream := newWSSStreamStub()
	closeDone := make(chan struct{})
	connector := &wssConnectorStub{stream: stream, closeDone: closeDone}
	handler := NewTerminalWSS(connector)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r, "terminal-session-1")
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, _, err := websocket.Dial(
		ctx,
		"ws"+strings.TrimPrefix(server.URL, "http"),
		&websocket.DialOptions{
			Subprotocols: []string{terminalSubprotocol},
			HTTPHeader: http.Header{
				"Origin": []string{server.URL},
				"Cookie": []string{ticketCookieName + "=one-time-ticket"},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseNow()
	writeControl(t, ctx, connection, terminalprotocol.Control{
		Version: terminalprotocol.Version, Type: terminalprotocol.TypeOpen,
		Sequence: 1, Columns: 120, Rows: 30,
	})
	if _, _, err := connection.Read(ctx); err != nil {
		t.Fatalf("read ready: %v", err)
	}
	writeControl(t, ctx, connection, terminalprotocol.Control{
		Version: terminalprotocol.Version, Type: terminalprotocol.TypePing,
		Sequence: 9,
	})
	_, _, err = connection.Read(ctx)
	if websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatalf("invalid sequence close error = %v", err)
	}
	select {
	case <-closeDone:
	case <-ctx.Done():
		t.Fatal("protocol violation close was not persisted")
	}
	connector.mu.Lock()
	defer connector.mu.Unlock()
	if connector.safeCode != "terminal_protocol_violation" {
		t.Fatalf("safe code = %q", connector.safeCode)
	}
}

func writeControl(
	t *testing.T,
	ctx context.Context,
	connection *websocket.Conn,
	control terminalprotocol.Control,
) {
	t.Helper()
	payload, err := terminalprotocol.EncodeControl(control, terminalprotocol.DirectionClientToServer)
	if err != nil {
		t.Fatalf("EncodeControl() error = %v", err)
	}
	if err := connection.Write(ctx, websocket.MessageText, payload); err != nil {
		t.Fatalf("write control error = %v", err)
	}
}
