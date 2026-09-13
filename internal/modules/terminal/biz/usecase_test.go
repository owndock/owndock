package biz

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/security"
	"github.com/owndock/owndock/internal/shared/transaction"
)

func TestUseCaseCreatesAuditsAndTerminatesContainerSession(t *testing.T) {
	useCase, sessions, audits := newTestUseCase(t)
	principal := terminalPrincipal(security.RoleMaintainer, "maintainer-1")
	credential, err := useCase.CreateContainerSession(
		context.Background(), principal, "project-1", "deployment-1",
		"192.0.2.10", "Browser/1.0", "request-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	if credential.Ticket != "raw-ticket" || credential.Session.TicketHash != "" ||
		credential.Session.Status != StatusPending || len(audits.events) != 1 ||
		audits.events[0].Action != "terminal_session.create" {
		t.Fatalf("credential = %+v, audits = %+v", credential, audits.events)
	}
	terminated, err := useCase.TerminateSession(
		context.Background(), principal, credential.Session.ID, "request-2",
	)
	if err != nil || terminated.Status != StatusClosed || terminated.Active ||
		len(audits.events) != 2 || audits.events[1].Action != "terminal_session.terminate" {
		t.Fatalf("terminated = %+v, error = %v, audits = %+v", terminated, err, audits.events)
	}
	version := terminated.Version
	terminated, err = useCase.TerminateSession(
		context.Background(), principal, credential.Session.ID, "request-3",
	)
	if err != nil || terminated.Version != version || len(audits.events) != 2 {
		t.Fatalf("idempotent termination = %+v, error = %v", terminated, err)
	}
	if sessions.items[credential.Session.ID].TicketHash != "" {
		t.Fatal("pending termination must invalidate the stored ticket")
	}
}

func TestConvergeRuntimeTargetClosesTicketsAndDrainsConnectedSessions(t *testing.T) {
	useCase, sessions, audits := newTestUseCase(t)
	principal := terminalPrincipal(security.RoleMaintainer, "maintainer-1")
	useCase.WithPrincipalResolver(&terminalPrincipalResolverStub{principal: principal})
	pending, err := useCase.CreateContainerSession(
		t.Context(), principal, "project-1", "deployment-1",
		"192.0.2.10", "Browser/1.0", "request-pending",
	)
	if err != nil {
		t.Fatal(err)
	}
	connected, err := useCase.CreateContainerSession(
		t.Context(), principal, "project-1", "deployment-1",
		"192.0.2.10", "Browser/1.0", "request-connected",
	)
	if err != nil {
		t.Fatal(err)
	}
	open, err := sessions.items[connected.Session.ID].MarkOpen(time.Unix(101, 0))
	if err != nil {
		t.Fatal(err)
	}
	sessions.items[open.ID] = open

	waiting, err := useCase.ConvergeRuntimeTarget(
		t.Context(), "organization-1", "project-1", "target-1",
		"owner-1", "target-delete-request",
	)
	if err != nil || waiting {
		t.Fatalf("first convergence = %t/%v", waiting, err)
	}
	closedTicket := sessions.items[pending.Session.ID]
	closingStream := sessions.items[connected.Session.ID]
	if closedTicket.Status != StatusClosed || closedTicket.Active ||
		closedTicket.TicketHash != "" ||
		closedTicket.CloseReason != CloseReasonTargetUnavailable ||
		closingStream.Status != StatusClosed || closingStream.Active ||
		closingStream.CloseReason != CloseReasonTargetUnavailable {
		t.Fatalf("pending = %+v, connected = %+v", closedTicket, closingStream)
	}
	if len(audits.events) != 4 ||
		audits.events[2].Action != "terminal_session.close_for_runtime_target_retirement" ||
		audits.events[3].Action != "terminal_session.close_for_runtime_target_retirement" {
		t.Fatalf("audit events = %+v", audits.events)
	}
	review, err := useCase.ReviewConnectedSession(t.Context(), open)
	if err != nil || !review.Terminate ||
		review.Reason != CloseReasonTargetUnavailable {
		t.Fatalf("connected stream review = %+v/%v", review, err)
	}
	waiting, err = useCase.ConvergeRuntimeTarget(
		t.Context(), "organization-1", "project-1", "target-1",
		"owner-1", "target-delete-request",
	)
	if err != nil || waiting {
		t.Fatalf("completed convergence = %t/%v", waiting, err)
	}
}

func TestConvergeRuntimeTargetHandlesRepositoryFailuresAndConflicts(t *testing.T) {
	useCase, sessions, _ := newTestUseCase(t)
	if _, err := useCase.ConvergeRuntimeTarget(
		t.Context(), "", "", "", "", "",
	); !errors.Is(err, ErrTerminalUnavailable) {
		t.Fatalf("invalid scope error = %v", err)
	}
	probe := errors.New("list failed")
	sessions.listErr = probe
	if _, err := useCase.ConvergeRuntimeTarget(
		t.Context(), "organization-1", "project-1", "target-1",
		"owner-1", "request-1",
	); !errors.Is(err, probe) {
		t.Fatalf("list failure = %v", err)
	}
	sessions.listErr = nil
	principal := terminalPrincipal(security.RoleMaintainer, "maintainer-1")
	if _, err := useCase.CreateContainerSession(
		t.Context(), principal, "project-1", "deployment-1",
		"192.0.2.10", "Browser/1.0", "request-create",
	); err != nil {
		t.Fatal(err)
	}
	sessions.saveErr = ErrSessionConflict
	pending, err := useCase.ConvergeRuntimeTarget(
		t.Context(), "organization-1", "project-1", "target-1",
		"owner-1", "request-1",
	)
	if err != nil || !pending {
		t.Fatalf("conflict convergence = %t/%v", pending, err)
	}
}

func TestUseCaseEnforcesDefaultRoleAndDistributedConcurrencyPolicy(t *testing.T) {
	useCase, _, _ := newTestUseCase(t)
	developer := terminalPrincipal(security.RoleDeveloper, "developer-1")
	_, err := useCase.CreateContainerSession(
		context.Background(), developer, "project-1", "deployment-1",
		"192.0.2.11", "Browser/1.0", "request-dev",
	)
	if !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("developer default policy error = %v", err)
	}
	maintainer := terminalPrincipal(security.RoleMaintainer, "maintainer-1")
	for index := 0; index < DefaultContainerSessionsPerUser; index++ {
		_, err = useCase.CreateContainerSession(
			context.Background(), maintainer, "project-1", "deployment-1",
			"192.0.2.12", "Browser/1.0", fmt.Sprintf("request-%d", index),
		)
		if err != nil {
			t.Fatalf("create session %d: %v", index, err)
		}
	}
	_, err = useCase.CreateContainerSession(
		context.Background(), maintainer, "project-1", "deployment-1",
		"192.0.2.12", "Browser/1.0", "request-limit",
	)
	if !errors.Is(err, ErrSessionLimit) {
		t.Fatalf("limit error = %v", err)
	}
}

func TestUseCaseHostShellDefaultsToOwnerOnly(t *testing.T) {
	useCase, _, _ := newTestUseCase(t)
	_, err := useCase.CreateHostSession(
		context.Background(), terminalPrincipal(security.RoleMaintainer, "maintainer-1"),
		"host-1", "192.0.2.10", "Browser/1.0", "request-1",
	)
	if !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("maintainer host access error = %v", err)
	}
	_, err = useCase.CreateHostSession(
		context.Background(), terminalPrincipal(security.RoleOwner, "owner-1"),
		"host-1", "192.0.2.10", "Browser/1.0", "request-2",
	)
	if err != nil {
		t.Fatalf("owner host access: %v", err)
	}
}

func TestUseCaseConsumesTerminalTicketExactlyOnce(t *testing.T) {
	useCase, _, audits := newTestUseCase(t)
	principal := terminalPrincipal(security.RoleOwner, "owner-1")
	credential, err := useCase.CreateHostSession(
		context.Background(), principal, "host-1", "192.0.2.10", "Browser/1.0", "request-create",
	)
	if err != nil {
		t.Fatal(err)
	}
	connected, err := useCase.ConnectSession(
		context.Background(), principal, credential.Session.ID, credential.Ticket, "request-connect",
	)
	if err != nil || connected.Status != StatusOpen || connected.TicketHash != "" ||
		len(audits.events) != 2 || audits.events[1].Action != "terminal_session.connect" {
		t.Fatalf("connected = %+v, error = %v, audits = %+v", connected, err, audits.events)
	}
	_, err = useCase.ConnectSession(
		context.Background(), principal, credential.Session.ID, credential.Ticket, "request-replay",
	)
	if !errors.Is(err, ErrInvalidTicket) || len(audits.events) != 2 {
		t.Fatalf("replay error = %v, audits = %+v", err, audits.events)
	}
}

func TestUseCaseConnectContainerConsumesTicketBeforeOpeningStream(t *testing.T) {
	useCase, sessions, audits := newTestUseCase(t)
	gateway := &terminalContainerGatewayStub{stream: &terminalStreamStub{}}
	useCase.WithContainerGateway(gateway)
	principal := terminalPrincipal(security.RoleMaintainer, "maintainer-1")
	credential, err := useCase.CreateContainerSession(
		context.Background(), principal, "project-1", "deployment-1",
		"192.0.2.10", "Browser/1.0", "request-create",
	)
	if err != nil {
		t.Fatal(err)
	}
	connected, stream, err := useCase.ConnectContainer(
		context.Background(), principal, credential.Session.ID, credential.Ticket,
		"request-connect", TerminalSize{Columns: 100, Rows: 40},
	)
	if err != nil || stream == nil || connected.Status != StatusOpen || gateway.opens != 1 {
		t.Fatalf("connected = %+v, stream = %v, opens = %d, error = %v", connected, stream, gateway.opens, err)
	}
	stored := sessions.items[credential.Session.ID]
	if stored.Status != StatusOpen || stored.TicketHash != "" || len(audits.events) != 2 ||
		audits.events[1].Action != "terminal_session.connect" {
		t.Fatalf("stored = %+v, audits = %+v", stored, audits.events)
	}
}

func TestUseCaseConnectContainerPersistsSafeFailure(t *testing.T) {
	useCase, sessions, audits := newTestUseCase(t)
	useCase.WithContainerGateway(&terminalContainerGatewayStub{err: ErrStreamUnavailable})
	principal := terminalPrincipal(security.RoleMaintainer, "maintainer-1")
	credential, err := useCase.CreateContainerSession(
		context.Background(), principal, "project-1", "deployment-1",
		"192.0.2.10", "Browser/1.0", "request-create",
	)
	if err != nil {
		t.Fatal(err)
	}
	_, stream, err := useCase.ConnectContainer(
		context.Background(), principal, credential.Session.ID, credential.Ticket,
		"request-connect", DefaultTerminalSize(),
	)
	if !errors.Is(err, ErrStreamUnavailable) || stream != nil {
		t.Fatalf("stream = %v, error = %v", stream, err)
	}
	stored := sessions.items[credential.Session.ID]
	if stored.Status != StatusFailed || stored.Active ||
		stored.CloseReason != CloseReasonConnectionFailed ||
		stored.SafeErrorCode != "terminal_connection_failed" || len(audits.events) != 3 ||
		audits.events[2].Action != "terminal_session.fail" {
		t.Fatalf("stored = %+v, audits = %+v", stored, audits.events)
	}
}

func TestUseCaseConnectContainerWithTicketRevalidatesBoundLoginSession(t *testing.T) {
	useCase, _, _ := newTestUseCase(t)
	useCase.WithContainerGateway(&terminalContainerGatewayStub{stream: &terminalStreamStub{}})
	resolver := &terminalPrincipalResolverStub{principal: terminalPrincipal(
		security.RoleMaintainer,
		"maintainer-1",
	)}
	useCase.WithPrincipalResolver(resolver)
	credential, err := useCase.CreateContainerSession(
		context.Background(), resolver.principal, "project-1", "deployment-1",
		"192.0.2.10", "Browser/1.0", "request-create",
	)
	if err != nil {
		t.Fatal(err)
	}
	connected, stream, err := useCase.ConnectContainerWithTicket(
		context.Background(), credential.Session.ID, credential.Ticket,
		"request-connect", DefaultTerminalSize(),
	)
	if err != nil || connected.Status != StatusOpen || stream == nil || resolver.calls != 1 {
		t.Fatalf("connected = %+v, stream = %v, calls = %d, error = %v", connected, stream, resolver.calls, err)
	}
	if resolver.organizationID != resolver.principal.OrganizationID ||
		resolver.userID != resolver.principal.UserID ||
		resolver.sessionID != resolver.principal.SessionID {
		t.Fatalf("resolver scope = %q/%q/%q", resolver.organizationID, resolver.userID, resolver.sessionID)
	}
}

func TestUseCaseConnectsHostTicketThroughFixedHostGateway(t *testing.T) {
	useCase, sessions, audits := newTestUseCase(t)
	gateway := &terminalHostGatewayStub{stream: &terminalStreamStub{}}
	useCase.WithHostGateway(gateway)
	resolver := &terminalPrincipalResolverStub{principal: terminalPrincipal(
		security.RoleOwner,
		"owner-1",
	)}
	useCase.WithPrincipalResolver(resolver)
	credential, err := useCase.CreateHostSession(
		t.Context(), resolver.principal, "host-1",
		"192.0.2.10", "Browser/1.0", "request-create",
	)
	if err != nil {
		t.Fatal(err)
	}
	connected, stream, err := useCase.ConnectWithTicket(
		t.Context(), credential.Session.ID, credential.Ticket,
		"request-connect", TerminalSize{Columns: 100, Rows: 40},
	)
	if err != nil || stream == nil || connected.Kind != KindHost ||
		gateway.opens != 1 || gateway.target.Kind != KindHost ||
		gateway.target.ManagedHostID != "host-1" {
		t.Fatalf(
			"connected = %+v, gateway = %+v, stream = %v, error = %v",
			connected, gateway, stream, err,
		)
	}
	stored := sessions.items[credential.Session.ID]
	if stored.Status != StatusOpen || stored.TicketHash != "" ||
		len(audits.events) != 2 || audits.events[1].Action != "terminal_session.connect" {
		t.Fatalf("stored = %+v, audits = %+v", stored, audits.events)
	}
}

func TestUseCaseReviewsExplicitlyTerminatedConnectedSession(t *testing.T) {
	useCase, _, _ := newTestUseCase(t)
	useCase.WithContainerGateway(&terminalContainerGatewayStub{
		stream: &terminalStreamStub{},
	})
	resolver := &terminalPrincipalResolverStub{principal: terminalPrincipal(
		security.RoleMaintainer,
		"maintainer-1",
	)}
	useCase.WithPrincipalResolver(resolver)
	credential, err := useCase.CreateContainerSession(
		t.Context(), resolver.principal, "project-1", "deployment-1",
		"192.0.2.10", "Browser/1.0", "request-create",
	)
	if err != nil {
		t.Fatal(err)
	}
	connected, _, err := useCase.ConnectContainerWithTicket(
		t.Context(), credential.Session.ID, credential.Ticket,
		"request-connect", DefaultTerminalSize(),
	)
	if err != nil {
		t.Fatal(err)
	}
	review, err := useCase.ReviewConnectedSession(t.Context(), connected)
	if err != nil || review.Terminate {
		t.Fatalf("initial review = %+v, error = %v", review, err)
	}
	if _, err := useCase.TerminateSession(
		t.Context(), resolver.principal, connected.ID, "request-terminate",
	); err != nil {
		t.Fatal(err)
	}
	review, err = useCase.ReviewConnectedSession(t.Context(), connected)
	if err != nil || !review.Terminate ||
		review.Reason != CloseReasonUserRequested || review.GracePeriod != 0 {
		t.Fatalf("terminated review = %+v, error = %v", review, err)
	}
}

func TestUseCaseReviewsRevokedLoginWithPolicyGrace(t *testing.T) {
	useCase, _, _ := newTestUseCase(t)
	useCase.WithContainerGateway(&terminalContainerGatewayStub{
		stream: &terminalStreamStub{},
	})
	resolver := &terminalPrincipalResolverStub{principal: terminalPrincipal(
		security.RoleMaintainer,
		"maintainer-1",
	)}
	useCase.WithPrincipalResolver(resolver)
	credential, err := useCase.CreateContainerSession(
		t.Context(), resolver.principal, "project-1", "deployment-1",
		"192.0.2.10", "Browser/1.0", "request-create",
	)
	if err != nil {
		t.Fatal(err)
	}
	connected, _, err := useCase.ConnectContainerWithTicket(
		t.Context(), credential.Session.ID, credential.Ticket,
		"request-connect", DefaultTerminalSize(),
	)
	if err != nil {
		t.Fatal(err)
	}
	resolver.err = security.ErrUnauthenticated
	review, err := useCase.ReviewConnectedSession(t.Context(), connected)
	if err != nil || !review.Terminate ||
		review.Reason != CloseReasonPermissionRevoked ||
		review.GracePeriod != DefaultRevocationGrace {
		t.Fatalf("revoked review = %+v, error = %v", review, err)
	}
}

func newTestUseCase(t *testing.T) (*UseCase, *terminalSessionStore, *terminalAuditStore) {
	t.Helper()
	sequence := 0
	newID := func() (string, error) {
		sequence++
		return fmt.Sprintf("id-%d", sequence), nil
	}
	sessions := &terminalSessionStore{items: map[string]TerminalSession{}}
	audits := &terminalAuditStore{}
	useCase, err := NewUseCase(
		terminalPolicyStore{}, sessions, terminalTargets{}, terminalRoles{},
		transaction.Passthrough{}, audits, terminalTickets{}, newID,
		func() time.Time { return time.Unix(100, 0).UTC() },
	)
	if err != nil {
		t.Fatal(err)
	}
	return useCase, sessions, audits
}

func terminalPrincipal(role security.Role, userID string) security.Principal {
	return security.Principal{
		UserID: userID, OrganizationID: "organization-1", Role: role, SessionID: "login-session-1",
	}
}

type terminalPolicyStore struct{}

func (terminalPolicyStore) GetProjectPolicy(context.Context, string, string) (AccessPolicy, error) {
	return AccessPolicy{}, ErrPolicyNotFound
}
func (terminalPolicyStore) GetOrganizationPolicy(context.Context, string) (AccessPolicy, error) {
	return AccessPolicy{}, ErrPolicyNotFound
}
func (terminalPolicyStore) SavePolicy(_ context.Context, policy AccessPolicy, _ uint64) (AccessPolicy, error) {
	return policy, nil
}

type terminalSessionStore struct {
	items   map[string]TerminalSession
	listErr error
	saveErr error
}

func (s *terminalSessionStore) GetSession(_ context.Context, organizationID, sessionID string) (TerminalSession, error) {
	item, ok := s.items[sessionID]
	if !ok || item.OrganizationID != organizationID {
		return TerminalSession{}, ErrSessionNotFound
	}
	return item, nil
}
func (s *terminalSessionStore) GetSessionForConnect(_ context.Context, sessionID string) (TerminalSession, error) {
	item, ok := s.items[sessionID]
	if !ok || item.Status != StatusPending || !item.Active {
		return TerminalSession{}, ErrSessionNotFound
	}
	return item, nil
}
func (s *terminalSessionStore) ListActiveSessionsForRuntimeTarget(
	_ context.Context,
	organizationID, projectID, runtimeTargetID string,
	limit int64,
) ([]TerminalSession, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	result := make([]TerminalSession, 0, limit)
	for _, item := range s.items {
		if item.OrganizationID == organizationID && item.ProjectID == projectID &&
			item.RuntimeTargetID == runtimeTargetID && item.Active {
			result = append(result, item)
			if int64(len(result)) == limit {
				break
			}
		}
	}
	return result, nil
}
func (s *terminalSessionStore) CreateSession(_ context.Context, candidate TerminalSession) (TerminalSession, error) {
	for _, item := range s.items {
		if !item.Active || item.OrganizationID != candidate.OrganizationID {
			continue
		}
		if item.ActorID == candidate.ActorID && item.UserConcurrencySlot == candidate.UserConcurrencySlot ||
			item.TargetScope() == candidate.TargetScope() && item.TargetConcurrencySlot == candidate.TargetConcurrencySlot {
			return TerminalSession{}, ErrSessionSlotConflict
		}
	}
	s.items[candidate.ID] = candidate
	return candidate, nil
}
func (s *terminalSessionStore) SaveSession(_ context.Context, item TerminalSession, expectedVersion uint64) (TerminalSession, error) {
	if s.saveErr != nil {
		return TerminalSession{}, s.saveErr
	}
	current, ok := s.items[item.ID]
	if !ok {
		return TerminalSession{}, ErrSessionNotFound
	}
	if current.Version != expectedVersion {
		return TerminalSession{}, ErrSessionConflict
	}
	s.items[item.ID] = item
	return item, nil
}
func (s *terminalSessionStore) ConsumeTicket(_ context.Context, organizationID, sessionID, ticketHash string, now time.Time) (TerminalSession, error) {
	item, ok := s.items[sessionID]
	if !ok || item.OrganizationID != organizationID || item.Status != StatusPending ||
		item.TicketHash != ticketHash || !now.Before(item.TicketExpiresAt) || !now.Before(item.MaximumDeadline) {
		return TerminalSession{}, ErrInvalidTicket
	}
	connected, err := item.MarkOpen(now)
	if err != nil {
		return TerminalSession{}, ErrInvalidTicket
	}
	s.items[sessionID] = connected
	return connected, nil
}

type terminalTargets struct{}

func (terminalTargets) ProjectExists(context.Context, string, string) (bool, error) { return true, nil }
func (terminalTargets) ResolveContainer(_ context.Context, organizationID, projectID, deploymentID string) (Target, error) {
	return Target{
		Kind: KindContainer, OrganizationID: organizationID, ProjectID: projectID,
		ManagedHostID: "host-1", RuntimeTargetID: "target-1", DeploymentID: deploymentID,
		RunningInstanceID: deploymentID + ":1", InstanceGeneration: 1,
		EnvironmentStage: "development", ConnectionMode: runtimeaccess.ModeAgent,
	}, nil
}
func (terminalTargets) ResolveHost(_ context.Context, organizationID, managedHostID string) (Target, error) {
	return Target{Kind: KindHost, OrganizationID: organizationID, ManagedHostID: managedHostID, ConnectionMode: runtimeaccess.ModeAgent}, nil
}

type terminalRoles struct{}

func (terminalRoles) ResolveTerminalProjectRole(_ context.Context, _, _, _ string) (security.Role, error) {
	return security.RoleMaintainer, nil
}

type terminalTickets struct{}

func (terminalTickets) New() (string, string, error) {
	return "raw-ticket", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil
}
func (terminalTickets) Hash(string) string {
	return "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}

type terminalAuditStore struct{ events []sharedaudit.Event }

func (s *terminalAuditStore) Record(_ context.Context, event sharedaudit.Event) error {
	s.events = append(s.events, event)
	return nil
}

type terminalContainerGatewayStub struct {
	stream TerminalStream
	err    error
	opens  int
}

type terminalHostGatewayStub struct {
	stream TerminalStream
	err    error
	opens  int
	target Target
}

func (g *terminalHostGatewayStub) OpenHost(
	_ context.Context,
	_ string,
	target Target,
	_ TerminalSize,
) (TerminalStream, error) {
	g.opens++
	g.target = target
	return g.stream, g.err
}

func (g *terminalContainerGatewayStub) OpenContainer(
	context.Context,
	string,
	Target,
	TerminalSize,
) (TerminalStream, error) {
	g.opens++
	return g.stream, g.err
}

type terminalStreamStub struct{ bytes.Buffer }

func (*terminalStreamStub) Close() error { return nil }
func (*terminalStreamStub) Resize(context.Context, TerminalSize) error {
	return nil
}

type terminalPrincipalResolverStub struct {
	principal      security.Principal
	err            error
	calls          int
	organizationID string
	userID         string
	sessionID      string
}

func (r *terminalPrincipalResolverStub) ResolveTerminalPrincipal(
	_ context.Context,
	organizationID, userID, sessionID string,
) (security.Principal, error) {
	r.calls++
	r.organizationID, r.userID, r.sessionID = organizationID, userID, sessionID
	return r.principal, r.err
}
