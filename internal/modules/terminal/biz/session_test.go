package biz

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/shared/runtimeaccess"
)

func TestTerminalSessionLifecycleAndTicketRedaction(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	policy := DefaultProjectPolicy("organization-1", "project-1")
	session, err := NewTerminalSession(
		"session-1", "user-1", strings.Repeat("a", 64), "192.0.2.10",
		"OwnDock-Web/1.0", "request-1",
		Target{
			Kind: KindContainer, OrganizationID: "organization-1", ProjectID: "project-1",
			ManagedHostID: "host-1", RuntimeTargetID: "target-1",
			DeploymentID: "deployment-1", RunningInstanceID: "instance-1",
			InstanceGeneration: 3, EnvironmentStage: "development",
			ConnectionMode: runtimeaccess.ModeAgent,
		},
		policy, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if session.Redacted().TicketHash != "" || !session.Active {
		t.Fatalf("new session = %+v", session)
	}
	opened, err := session.MarkOpen(now.Add(10 * time.Second))
	if err != nil || opened.Status != StatusOpen || opened.TicketHash != "" ||
		opened.TicketConsumedAt.IsZero() {
		t.Fatalf("opened = %+v, error = %v", opened, err)
	}
	closing, err := opened.RequestTermination(CloseReasonUserRequested, now.Add(20*time.Second))
	if err != nil || closing.Status != StatusClosing || !closing.Active {
		t.Fatalf("closing = %+v, error = %v", closing, err)
	}
	closed, err := closing.Close(CloseReasonUserRequested, "", now.Add(30*time.Second))
	if err != nil || closed.Status != StatusClosed || closed.Active || closed.EndedAt.IsZero() {
		t.Fatalf("closed = %+v, error = %v", closed, err)
	}
	idempotent, err := closed.Close(CloseReasonUserRequested, "", now.Add(time.Minute))
	if err != nil || idempotent.Version != closed.Version {
		t.Fatalf("idempotent close = %+v, error = %v", idempotent, err)
	}
}

func TestPendingTerminalSessionTerminationInvalidatesTicket(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	session, err := NewTerminalSession(
		"session-1", "owner-1", strings.Repeat("b", 64), "192.0.2.10",
		"Browser/1.0", "request-1",
		Target{Kind: KindHost, OrganizationID: "organization-1", ManagedHostID: "host-1", ConnectionMode: runtimeaccess.ModeAgent},
		DefaultOrganizationPolicy("organization-1"), now,
	)
	if err != nil {
		t.Fatal(err)
	}
	closed, err := session.RequestTermination(CloseReasonUserRequested, now.Add(time.Second))
	if err != nil || closed.Status != StatusClosed || closed.TicketHash != "" || closed.Active {
		t.Fatalf("closed = %+v, error = %v", closed, err)
	}
	if _, err := session.MarkOpen(now.Add(2 * time.Minute)); !errors.Is(err, ErrSessionConflict) {
		t.Fatalf("expired ticket error = %v", err)
	}
}

func TestTerminalSessionRejectsUnsafeClientMetadata(t *testing.T) {
	baseTarget := Target{Kind: KindHost, OrganizationID: "organization-1", ManagedHostID: "host-1", ConnectionMode: runtimeaccess.ModeAgent}
	for _, test := range []struct {
		name, clientIP, userAgent, requestID string
	}{
		{name: "invalid IP", clientIP: "not-an-ip", userAgent: "Browser", requestID: "request-1"},
		{name: "control user agent", clientIP: "192.0.2.1", userAgent: "Browser\nsecret", requestID: "request-1"},
		{name: "missing request ID", clientIP: "192.0.2.1", userAgent: "Browser"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewTerminalSession(
				"session-1", "owner-1", strings.Repeat("c", 64), test.clientIP,
				test.userAgent, test.requestID, baseTarget,
				DefaultOrganizationPolicy("organization-1"), time.Now(),
			)
			if !errors.Is(err, ErrInvalidSession) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}
