package runtimeaccess

import (
	"errors"
	"testing"
)

func TestConnectionValidation(t *testing.T) {
	direct, err := NewDirectDocker(
		"", "tcp://docker.example.com:2376", "docker.example.com", "secret://runtime",
	)
	if err != nil || direct.Mode != ModeDirectDocker || direct.DirectDocker == nil {
		t.Fatalf("direct connection = %+v, error = %v", direct, err)
	}
	agent, err := NewAgent("host-1")
	if err != nil || agent.Mode != ModeAgent || agent.ManagedHostID != "host-1" {
		t.Fatalf("agent connection = %+v, error = %v", agent, err)
	}
	if _, err := NewAgent(""); !errors.Is(err, ErrInvalidConnection) {
		t.Fatalf("empty agent host error = %v", err)
	}
	if err := (Connection{Mode: "unknown"}).Validate(); !errors.Is(err, ErrUnsupportedMode) {
		t.Fatalf("unknown mode error = %v", err)
	}
}
