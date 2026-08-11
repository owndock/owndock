package agentruntime

import (
	"bytes"
	"context"
	"os/user"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/shared/agentprotocol"
)

func TestHostTerminalRequiresFixedEffectiveUser(t *testing.T) {
	_, err := newHostTerminalExecutor(
		HostTerminalConfig{
			User: "configured-user", Shell: "/bin/sh",
			TerminationGrace: time.Second,
		},
		func() (*user.User, error) {
			return &user.User{
				Uid: "1000", Username: "different-user", HomeDir: "/tmp",
			}, nil
		},
	)
	if err != ErrHostTerminalConfiguration {
		t.Fatalf("identity mismatch error = %v", err)
	}
}

func TestHostTerminalRejectsContainerSelector(t *testing.T) {
	account, err := user.Current()
	if err != nil {
		t.Skipf("current user unavailable: %v", err)
	}
	executor, err := NewHostTerminalExecutor(HostTerminalConfig{
		User: account.Username, Shell: "/bin/sh", TerminationGrace: time.Second,
	})
	if err != nil {
		t.Skipf("host terminal unavailable: %v", err)
	}
	_, err = executor.OpenHostTerminal(t.Context(), agentprotocol.TerminalOpen{
		Kind:         agentprotocol.TerminalKindContainer,
		DeploymentID: "deployment-1", ProjectID: "project-1",
		ApplicationID: "application-1", EnvironmentID: "environment-1",
		RuntimeTargetID: "target-1", ContainerName: "owndock-container-1",
		CutoverSequence: 1, Columns: 120, Rows: 30,
	})
	if err != ErrTerminalTargetUnavailable {
		t.Fatalf("container selector error = %v", err)
	}
}

func TestHostTerminalRunsPTYWithSanitizedEnvironmentAndReapsGroup(t *testing.T) {
	account, err := user.Current()
	if err != nil {
		t.Skipf("current user unavailable: %v", err)
	}
	t.Setenv("OWNDOCK_HOST_TERMINAL_SECRET", "must-not-enter-pty")
	executor, err := NewHostTerminalExecutor(HostTerminalConfig{
		User: account.Username, Shell: "/bin/sh",
		TerminationGrace: 100 * time.Millisecond,
	})
	if err != nil {
		t.Skipf("host terminal unavailable: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	raw, err := executor.OpenHostTerminal(ctx, agentprotocol.TerminalOpen{
		Kind: agentprotocol.TerminalKindHost, Columns: 80, Rows: 24,
	})
	if err != nil {
		t.Fatal(err)
	}
	stream := raw.(*hostTerminalStream)
	if err := stream.Resize(ctx, 132, 43); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte("printf 'host-pty-ok:%s\\n' \"${OWNDOCK_HOST_TERMINAL_SECRET-unset}\"\nsleep 30\n")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 4096)
	output := make([]byte, 0, 4096)
	for !bytes.Contains(output, []byte("host-pty-ok:unset")) {
		read, readErr := stream.Read(buffer)
		output = append(output, buffer[:read]...)
		if readErr != nil {
			t.Fatalf("read PTY before marker: %v, output=%q", readErr, output)
		}
	}
	if bytes.Contains(output, []byte("must-not-enter-pty")) {
		t.Fatal("Agent environment secret leaked into host PTY")
	}
	started := time.Now()
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("process group cleanup took %s", elapsed)
	}
	select {
	case <-stream.exited:
	case <-ctx.Done():
		t.Fatal("host shell process was not reaped")
	}
}
