package biz

import (
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

type terminalSessionStore struct{ items map[string]TerminalSession }

func (s *terminalSessionStore) GetSession(_ context.Context, organizationID, sessionID string) (TerminalSession, error) {
	item, ok := s.items[sessionID]
	if !ok || item.OrganizationID != organizationID {
		return TerminalSession{}, ErrSessionNotFound
	}
	return item, nil
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
