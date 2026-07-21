package config

import (
	"testing"
	"time"
)

func TestConfigValidate(t *testing.T) {
	cfg := Config{Server: Server{HTTP: HTTP{
		Address:         "127.0.0.1:8000",
		Timeout:         "5s",
		ShutdownTimeout: "10s",
	}}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	timeout, err := cfg.Server.HTTP.TimeoutDuration()
	if err != nil {
		t.Fatalf("TimeoutDuration() error = %v", err)
	}
	if timeout != 5*time.Second {
		t.Fatalf("TimeoutDuration() = %v, want %v", timeout, 5*time.Second)
	}
}

func TestConfigRejectsInvalidDuration(t *testing.T) {
	cfg := Config{Server: Server{HTTP: HTTP{
		Address: "127.0.0.1:8000",
		Timeout: "not-a-duration",
	}}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want an error")
	}
}
