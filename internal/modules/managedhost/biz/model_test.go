package biz

import (
	"testing"
	"time"

	"github.com/owndock/owndock/internal/shared/runtimeaccess"
)

func TestNewManagedHostEnforcesMutuallyExclusiveConnectionFields(t *testing.T) {
	direct, err := NewManagedHost(
		"host-1", "organization-1", "Production Host",
		runtimeaccess.ModeDirectDocker, "secret://production-ssh",
		"owner-1", time.Unix(1, 0),
	)
	if err != nil || direct.Status != StatusOffline {
		t.Fatalf("direct host = %+v, error = %v", direct, err)
	}
	agent, err := NewManagedHost(
		"host-2", "organization-1", "Private Host",
		runtimeaccess.ModeAgent, "", "owner-1", time.Unix(1, 0),
	)
	if err != nil || agent.Status != StatusEnrolling {
		t.Fatalf("agent host = %+v, error = %v", agent, err)
	}
	if _, err := NewManagedHost(
		"host-3", "organization-1", "Invalid Host",
		runtimeaccess.ModeAgent, "secret://ssh", "owner-1", time.Now(),
	); err != ErrInvalidHost {
		t.Fatalf("agent host with direct SSH error = %v", err)
	}
}
