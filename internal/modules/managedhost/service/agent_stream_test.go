package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/managedhost/biz"
	managedhostdata "github.com/owndock/owndock/internal/modules/managedhost/data"
	"github.com/owndock/owndock/internal/shared/agentprotocol"
	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/transaction"
)

type agentControlRepositoryStub struct {
	identity   biz.AgentIdentity
	host       biz.ManagedHost
	heartbeats int
}

func (r *agentControlRepositoryStub) List(context.Context, string) ([]biz.ManagedHost, error) {
	return []biz.ManagedHost{r.host}, nil
}
func (r *agentControlRepositoryStub) Get(context.Context, string, string) (biz.ManagedHost, error) {
	return r.host, nil
}
func (r *agentControlRepositoryStub) Create(
	context.Context, biz.ManagedHost,
) (biz.ManagedHost, error) {
	return biz.ManagedHost{}, nil
}
func (r *agentControlRepositoryStub) Disable(
	context.Context, string, string, time.Time,
) (biz.ManagedHost, error) {
	return biz.ManagedHost{}, nil
}
func (r *agentControlRepositoryStub) ConnectionMode(
	context.Context, string, string,
) (runtimeaccess.Mode, bool, error) {
	return runtimeaccess.ModeAgent, true, nil
}
func (r *agentControlRepositoryStub) AuthenticateAgent(
	_ context.Context,
	certificate biz.AgentCertificateIdentity,
	now time.Time,
) (biz.AgentIdentity, error) {
	if certificate.IdentityID != r.identity.ID ||
		certificate.CertificateSerial != r.identity.CertificateSerial ||
		certificate.CertificateSHA256 != r.identity.CertificateSHA256 ||
		!r.identity.CertificateExpires.After(now) {
		return biz.AgentIdentity{}, biz.ErrInvalidAgentIdentity
	}
	return r.identity, nil
}
func (r *agentControlRepositoryStub) ConnectAgent(
	_ context.Context,
	session biz.AgentSession,
	now time.Time,
) error {
	r.host.Status = biz.StatusOnline
	r.host.AgentSessionID = session.ID
	r.host.LastSeenAt = now
	return nil
}
func (r *agentControlRepositoryStub) HeartbeatAgent(
	_ context.Context,
	session biz.AgentSession,
	now time.Time,
) error {
	if r.host.AgentSessionID != session.ID {
		return biz.ErrInvalidAgentIdentity
	}
	r.heartbeats++
	r.host.LastSeenAt = now
	return nil
}
func (r *agentControlRepositoryStub) DisconnectAgent(
	_ context.Context,
	session biz.AgentSession,
	_ time.Time,
) (bool, error) {
	if r.host.AgentSessionID != session.ID {
		return false, nil
	}
	r.host.Status = biz.StatusOffline
	r.host.AgentSessionID = ""
	return true, nil
}

type agentAuditStub struct {
	events []sharedaudit.Event
}

func (a *agentAuditStub) Record(_ context.Context, event sharedaudit.Event) error {
	a.events = append(a.events, event)
	return nil
}

type agentRegistryStub struct {
	hostID, sessionID string
	capabilities      []string
	cancel            context.CancelFunc
	commands          chan biz.AgentCommand
	results           []biz.AgentCommandResult
}

func (r *agentRegistryStub) Register(
	hostID, sessionID string,
	capabilities []string,
	cancel context.CancelFunc,
) <-chan biz.AgentCommand {
	r.hostID, r.sessionID, r.cancel = hostID, sessionID, cancel
	r.capabilities = append([]string(nil), capabilities...)
	if r.commands == nil {
		r.commands = make(chan biz.AgentCommand)
	}
	return r.commands
}
func (r *agentRegistryStub) Unregister(hostID, sessionID string) {
	if r.hostID == hostID && r.sessionID == sessionID {
		r.hostID, r.sessionID = "", ""
	}
}
func (r *agentRegistryStub) DisconnectHost(hostID string) {
	if r.hostID == hostID && r.cancel != nil {
		r.cancel()
	}
}
func (r *agentRegistryStub) Complete(
	hostID, sessionID string,
	result biz.AgentCommandResult,
) error {
	if r.hostID != hostID || r.sessionID != sessionID {
		return biz.ErrAgentDisconnected
	}
	r.results = append(r.results, result)
	return nil
}

type fullDuplexRecorder struct {
	*httptest.ResponseRecorder
}

func (fullDuplexRecorder) EnableFullDuplex() error          { return nil }
func (fullDuplexRecorder) SetReadDeadline(time.Time) error  { return nil }
func (fullDuplexRecorder) SetWriteDeadline(time.Time) error { return nil }

type streamingFullDuplexRecorder struct {
	mu     sync.Mutex
	header http.Header
	code   int
	body   bytes.Buffer
	wrote  chan struct{}
}

func newStreamingFullDuplexRecorder() *streamingFullDuplexRecorder {
	return &streamingFullDuplexRecorder{
		header: make(http.Header),
		wrote:  make(chan struct{}, 1),
	}
}

func (r *streamingFullDuplexRecorder) Header() http.Header {
	return r.header
}

func (r *streamingFullDuplexRecorder) WriteHeader(code int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.code == 0 {
		r.code = code
	}
}

func (r *streamingFullDuplexRecorder) Write(value []byte) (int, error) {
	r.mu.Lock()
	if r.code == 0 {
		r.code = http.StatusOK
	}
	written, err := r.body.Write(value)
	r.mu.Unlock()
	select {
	case r.wrote <- struct{}{}:
	default:
	}
	return written, err
}

func (*streamingFullDuplexRecorder) EnableFullDuplex() error {
	return nil
}
func (*streamingFullDuplexRecorder) SetReadDeadline(time.Time) error {
	return nil
}
func (*streamingFullDuplexRecorder) SetWriteDeadline(time.Time) error {
	return nil
}
func (*streamingFullDuplexRecorder) Flush() {}

func (r *streamingFullDuplexRecorder) waitContains(
	t *testing.T,
	value string,
) {
	t.Helper()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for {
		r.mu.Lock()
		found := strings.Contains(r.body.String(), value)
		r.mu.Unlock()
		if found {
			return
		}
		select {
		case <-r.wrote:
		case <-timer.C:
			r.mu.Lock()
			body := r.body.String()
			r.mu.Unlock()
			t.Fatalf("response did not contain %q: %s", value, body)
		}
	}
}

func TestAgentStreamNegotiatesAndAcknowledgesHeartbeat(t *testing.T) {
	now := time.Unix(500, 0).UTC()
	rawCertificate := []byte("agent-certificate")
	fingerprint := sha256.Sum256(rawCertificate)
	repository := &agentControlRepositoryStub{
		identity: biz.AgentIdentity{
			ID: "identity-1", OrganizationID: "organization-1",
			ManagedHostID: "host-1", InstanceID: "instance-1",
			CertificateSerial:  "2a",
			CertificateSHA256:  hex.EncodeToString(fingerprint[:]),
			CertificateExpires: now.Add(time.Hour),
			Capabilities: []string{
				agentprotocol.CapabilityRuntimeProbe,
			},
		},
		host: biz.ManagedHost{
			ID: "host-1", OrganizationID: "organization-1",
			Status: biz.StatusOffline, ConnectionMode: runtimeaccess.ModeAgent,
			AgentIdentityID: "identity-1", AgentInstanceID: "instance-1",
		},
	}
	audits := &agentAuditStub{}
	ids := []string{"session-1", "audit-connect", "audit-disconnect"}
	useCase := biz.NewUseCase(
		repository, transaction.Passthrough{}, audits,
		func() (string, error) {
			value := ids[0]
			ids = ids[1:]
			return value, nil
		},
		func() time.Time { return now },
	).WithAgentControl(repository, nil, []string{"v1"})
	registry := &agentRegistryStub{}
	stream, err := NewAgentStream(
		useCase, registry, time.Second, 2*time.Second, 5*time.Second, 4096,
	)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Join([]string{
		`{"type":"hello","sequence":1,"hello":{"organization_id":"organization-1","managed_host_id":"host-1","agent_identity_id":"identity-1","instance_id":"instance-1","boot_id":"boot-1","agent_version":"1.0.0","protocol_version":"v1","capabilities":["runtime.probe"]}}`,
		`{"type":"heartbeat","sequence":2}`,
		"",
	}, "\n")
	request := httptest.NewRequest(
		http.MethodPost, "/api/v1/agent/connect", strings.NewReader(body),
	)
	request.Header.Set("Content-Type", agentStreamContentType)
	request.TLS = testAgentTLSState(t, rawCertificate)
	recorder := fullDuplexRecorder{httptest.NewRecorder()}
	stream.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK ||
		!strings.Contains(recorder.Body.String(), `"type":"hello_ack"`) ||
		!strings.Contains(recorder.Body.String(), `"type":"heartbeat_ack"`) {
		t.Fatalf("response = %d %s", recorder.Code, recorder.Body.String())
	}
	if repository.heartbeats != 1 ||
		repository.host.Status != biz.StatusOffline ||
		len(audits.events) != 2 ||
		len(registry.capabilities) != 1 ||
		registry.capabilities[0] != "runtime.probe" {
		t.Fatalf(
			"repository = %+v, audits = %+v",
			repository, audits.events,
		)
	}
}

func TestAgentStreamRejectsMissingMutualTLSIdentity(t *testing.T) {
	stream, err := NewAgentStream(
		biz.NewUseCase(
			&agentControlRepositoryStub{},
			transaction.Passthrough{},
			&agentAuditStub{},
			func() (string, error) { return "id", nil },
			time.Now,
		),
		&agentRegistryStub{},
		time.Second,
		2*time.Second,
		5*time.Second,
		4096,
	)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodPost, "/api/v1/agent/connect", strings.NewReader("{}\n"),
	)
	request.Header.Set("Content-Type", agentStreamContentType)
	recorder := httptest.NewRecorder()
	stream.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
}

func TestAgentStreamDeliversAndCompletesRuntimeProbe(t *testing.T) {
	now := time.Unix(600, 0).UTC()
	rawCertificate := []byte("agent-command-certificate")
	fingerprint := sha256.Sum256(rawCertificate)
	repository := &agentControlRepositoryStub{
		identity: biz.AgentIdentity{
			ID: "identity-1", OrganizationID: "organization-1",
			ManagedHostID: "host-1", InstanceID: "instance-1",
			CertificateSerial:  "2a",
			CertificateSHA256:  hex.EncodeToString(fingerprint[:]),
			CertificateExpires: now.Add(time.Hour),
			Capabilities: []string{
				agentprotocol.CapabilityRuntimeProbe,
			},
		},
		host: biz.ManagedHost{
			ID: "host-1", OrganizationID: "organization-1",
			Status: biz.StatusOffline, ConnectionMode: runtimeaccess.ModeAgent,
			AgentIdentityID: "identity-1", AgentInstanceID: "instance-1",
		},
	}
	registry, err := managedhostdata.NewConnectionRegistry(2, 4)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{"session-1", "audit-connect", "audit-disconnect"}
	useCase := biz.NewUseCase(
		repository, transaction.Passthrough{}, &agentAuditStub{},
		func() (string, error) {
			value := ids[0]
			ids = ids[1:]
			return value, nil
		},
		func() time.Time { return now },
	).WithAgentControl(repository, registry, []string{"v1"})
	stream, err := NewAgentStream(
		useCase, registry, time.Second, 2*time.Second, 5*time.Second, 4096,
	)
	if err != nil {
		t.Fatal(err)
	}

	reader, writer := io.Pipe()
	request := httptest.NewRequest(
		http.MethodPost, "/api/v1/agent/connect", reader,
	)
	request.Header.Set("Content-Type", agentStreamContentType)
	request.TLS = testAgentTLSState(t, rawCertificate)
	recorder := newStreamingFullDuplexRecorder()
	handlerDone := make(chan struct{})
	go func() {
		stream.ServeHTTP(recorder, request)
		close(handlerDone)
	}()

	if _, err := fmt.Fprintln(
		writer,
		`{"type":"hello","sequence":1,"hello":{`+
			`"organization_id":"organization-1","managed_host_id":"host-1",`+
			`"agent_identity_id":"identity-1","instance_id":"instance-1",`+
			`"boot_id":"boot-1","agent_version":"1.0.0",`+
			`"protocol_version":"v1","capabilities":["runtime.probe"]}}`,
	); err != nil {
		t.Fatal(err)
	}
	recorder.waitContains(t, `"type":"hello_ack"`)

	command := biz.AgentCommand{
		ID: "command-1", Kind: biz.AgentCommandRuntimeProbe,
		Deadline:     time.Now().Add(time.Minute).UTC(),
		RuntimeProbe: &biz.RuntimeProbeCommand{RuntimeTargetID: "target-1"},
	}
	resultChannel := make(chan biz.AgentCommandResult, 1)
	errorChannel := make(chan error, 1)
	go func() {
		result, dispatchErr := registry.Dispatch(
			t.Context(), "host-1", command,
		)
		resultChannel <- result
		errorChannel <- dispatchErr
	}()
	recorder.waitContains(t, `"command_id":"command-1"`)

	if _, err := fmt.Fprintln(
		writer,
		`{"type":"command_result","sequence":2,"command_result":{`+
			`"command_id":"command-1","status":"succeeded",`+
			`"runtime_probe":{"status":"ready"}}}`,
	); err != nil {
		t.Fatal(err)
	}
	recorder.waitContains(t, `"type":"command_result_ack"`)
	if err := <-errorChannel; err != nil {
		t.Fatal(err)
	}
	result := <-resultChannel
	if result.RuntimeProbe == nil ||
		result.RuntimeProbe.Status != biz.RuntimeProbeReady {
		t.Fatalf("result = %+v", result)
	}

	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("Agent stream did not close after request EOF")
	}
}

func TestAgentCommandWireTypesRemainNarrow(t *testing.T) {
	deadline := time.Unix(700, 0).UTC()
	command := newServerCommand(biz.AgentCommand{
		ID: "command-1", Kind: biz.AgentCommandRuntimeProbe,
		Deadline:     deadline,
		RuntimeProbe: &biz.RuntimeProbeCommand{RuntimeTargetID: "target-1"},
	})
	if command.CommandID != "command-1" ||
		command.Kind != biz.AgentCommandRuntimeProbe ||
		!command.Deadline.Equal(deadline) ||
		command.RuntimeProbe == nil ||
		command.RuntimeProbe.RuntimeTargetID != "target-1" {
		t.Fatalf("server command = %+v", command)
	}

	var frame agentFrame
	err := decodeAgentFrame([]byte(
		`{"type":"command_result","sequence":3,`+
			`"command_result":{"command_id":"command-1","status":"succeeded",`+
			`"runtime_probe":{"status":"ready"}}}`,
	), &frame)
	if err != nil {
		t.Fatal(err)
	}
	result := frame.CommandResult.domain()
	if result.CommandID != "command-1" ||
		result.Status != biz.AgentCommandSucceeded ||
		result.RuntimeProbe == nil ||
		result.RuntimeProbe.Status != biz.RuntimeProbeReady {
		t.Fatalf("Agent result = %+v", result)
	}

	var inventoryFrame agentFrame
	err = decodeAgentFrame([]byte(
		`{"type":"command_result","sequence":4,`+
			`"command_result":{"command_id":"inventory-events-1",`+
			`"status":"succeeded","runtime_inventory":{"events":{"events":[`+
			`{"kind":"container","runtime_id":"container-1","action":"start",`+
			`"occurred_at":"2026-07-30T10:00:00Z"}]}}}}`,
	), &inventoryFrame)
	if err != nil {
		t.Fatal(err)
	}
	inventoryResult := inventoryFrame.CommandResult.domain()
	if inventoryResult.Inventory == nil || inventoryResult.Inventory.Events == nil ||
		len(inventoryResult.Inventory.Events.Events) != 1 ||
		inventoryResult.Inventory.Events.Events[0].RuntimeID != "container-1" {
		t.Fatalf("Agent inventory event result = %+v", inventoryResult)
	}
}

func testAgentTLSState(t *testing.T, rawCertificate []byte) *tls.ConnectionState {
	t.Helper()
	identityURI, err := url.Parse(
		"spiffe://owndock/organizations/organization-1/managed-hosts/host-1/" +
			"agents/identity-1/instances/instance-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{
		Raw: rawCertificate, SerialNumber: big.NewInt(42),
		URIs: []*url.URL{identityURI},
	}
	return &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{certificate},
		VerifiedChains:   [][]*x509.Certificate{{certificate}},
	}
}
