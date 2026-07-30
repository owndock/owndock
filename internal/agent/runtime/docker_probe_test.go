package agentruntime

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/moby/moby/client"

	"github.com/owndock/owndock/internal/shared/agentprotocol"
)

type dockerProbeEngineStub struct {
	ping func(context.Context) error
}

type noopCutoverStore struct{}

func (noopCutoverStore) Observe(string, string, uint64) (bool, error) {
	return false, nil
}

func (e dockerProbeEngineStub) Ping(
	ctx context.Context,
	_ client.PingOptions,
) (client.PingResult, error) {
	if e.ping == nil {
		return client.PingResult{}, nil
	}
	return client.PingResult{}, e.ping(ctx)
}

func (dockerProbeEngineStub) Close() error { return nil }

func TestDockerExecutorReturnsAndCachesReady(t *testing.T) {
	cache, err := NewFileResultCache(
		filepath.Join(t.TempDir(), "state"),
		4,
	)
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewDockerExecutor(
		"/var/run/docker.sock",
		cache,
		noopCutoverStore{},
	)
	if err != nil {
		t.Fatal(err)
	}
	engineCalls := 0
	executor.newEngine = func(string) (dockerProbeEngine, error) {
		engineCalls++
		return dockerProbeEngineStub{}, nil
	}
	command := runtimeProbeCommand("command-1", "target-1")
	first, err := executor.Execute(t.Context(), command)
	if err != nil {
		t.Fatal(err)
	}
	second, err := executor.Execute(t.Context(), command)
	if err != nil {
		t.Fatal(err)
	}
	if first.RuntimeProbe == nil ||
		first.RuntimeProbe.Status != agentprotocol.RuntimeProbeReady ||
		!first.Equivalent(second) || engineCalls != 1 {
		t.Fatalf(
			"first = %+v, second = %+v, engine calls = %d",
			first, second, engineCalls,
		)
	}
}

func TestDockerExecutorSharesConcurrentCommandExecution(t *testing.T) {
	cache, err := NewFileResultCache(
		filepath.Join(t.TempDir(), "state"),
		4,
	)
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewDockerExecutor(
		"/var/run/docker.sock",
		cache,
		noopCutoverStore{},
	)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	engineCalls := 0
	executor.newEngine = func(string) (dockerProbeEngine, error) {
		engineCalls++
		return dockerProbeEngineStub{
			ping: func(context.Context) error {
				close(started)
				<-release
				return nil
			},
		}, nil
	}
	command := runtimeProbeCommand("command-1", "target-1")
	first := make(chan agentprotocol.AgentCommandResult, 1)
	second := make(chan agentprotocol.AgentCommandResult, 1)
	go func() {
		result, _ := executor.Execute(t.Context(), command)
		first <- result
	}()
	<-started
	go func() {
		result, _ := executor.Execute(t.Context(), command)
		second <- result
	}()
	close(release)
	firstResult := <-first
	secondResult := <-second
	if !firstResult.Equivalent(secondResult) || engineCalls != 1 {
		t.Fatalf(
			"first = %+v, second = %+v, engine calls = %d",
			firstResult, secondResult, engineCalls,
		)
	}
}

func TestDockerExecutorClassifiesRuntimeSafely(t *testing.T) {
	tests := []struct {
		name       string
		engineErr  error
		ping       func(context.Context) error
		wantStatus agentprotocol.AgentCommandStatus
		wantProbe  agentprotocol.RuntimeProbeStatus
		wantCode   string
	}{
		{
			name:       "unreachable",
			ping:       func(context.Context) error { return errors.New("dial details") },
			wantStatus: agentprotocol.AgentCommandSucceeded,
			wantProbe:  agentprotocol.RuntimeProbeUnreachable,
		},
		{
			name:       "invalid local runtime configuration",
			engineErr:  errors.New("configuration details"),
			wantStatus: agentprotocol.AgentCommandFailed,
			wantCode:   "runtime_configuration",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cache, err := NewFileResultCache(
				filepath.Join(t.TempDir(), "state"),
				2,
			)
			if err != nil {
				t.Fatal(err)
			}
			executor, err := NewDockerExecutor(
				"/var/run/docker.sock",
				cache,
				noopCutoverStore{},
			)
			if err != nil {
				t.Fatal(err)
			}
			executor.newEngine = func(string) (dockerProbeEngine, error) {
				return dockerProbeEngineStub{ping: test.ping}, test.engineErr
			}
			command := runtimeProbeCommand("command-1", "target-1")
			result, err := executor.Execute(t.Context(), command)
			if err != nil {
				t.Fatal(err)
			}
			if result.Status != test.wantStatus ||
				result.ErrorCode != test.wantCode {
				t.Fatalf("result = %+v", result)
			}
			if test.wantProbe == "" {
				if result.RuntimeProbe != nil {
					t.Fatalf("unexpected runtime result = %+v", result)
				}
			} else if result.RuntimeProbe == nil ||
				result.RuntimeProbe.Status != test.wantProbe {
				t.Fatalf("runtime result = %+v", result.RuntimeProbe)
			}
		})
	}
}

func TestDockerExecutorHonorsDeadlineAndShutdown(t *testing.T) {
	cache, err := NewFileResultCache(
		filepath.Join(t.TempDir(), "state"),
		4,
	)
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewDockerExecutor(
		"/var/run/docker.sock",
		cache,
		noopCutoverStore{},
	)
	if err != nil {
		t.Fatal(err)
	}
	executor.newEngine = func(string) (dockerProbeEngine, error) {
		return dockerProbeEngineStub{
			ping: func(ctx context.Context) error {
				<-ctx.Done()
				return ctx.Err()
			},
		}, nil
	}

	expired := runtimeProbeCommand("expired", "target-1")
	expired.Deadline = time.Now().Add(-time.Second)
	result, err := executor.Execute(t.Context(), expired)
	if err != nil || result.ErrorCode != "command_expired" {
		t.Fatalf("expired result = %+v, error = %v", result, err)
	}

	command := runtimeProbeCommand("canceled", "target-1")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := executor.Execute(ctx, command); !errors.Is(
		err, context.Canceled,
	) {
		t.Fatalf("shutdown error = %v", err)
	}
	if _, exists, err := cache.Lookup(command); err != nil || exists {
		t.Fatalf("canceled command cached = %v, error = %v", exists, err)
	}
}

func TestDockerExecutorAcceptsOnlyAbsoluteUnixSocketPath(t *testing.T) {
	cache, err := NewFileResultCache(
		filepath.Join(t.TempDir(), "state"),
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{
		"", "var/run/docker.sock", "tcp://docker.example.com:2376",
		"/var/run/../run/docker.sock",
	} {
		if _, err := NewDockerExecutor(
			value,
			cache,
			noopCutoverStore{},
		); !errors.Is(
			err, ErrInvalidDockerSocket,
		) {
			t.Fatalf("socket %q error = %v", value, err)
		}
	}
	if _, err := NewDockerExecutor(
		"/var/run/docker.sock",
		cache,
		noopCutoverStore{},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDockerExecutor(
		"/var/run/docker.sock",
		cache,
		nil,
	); !errors.Is(err, ErrRuntimeExecutorMissing) {
		t.Fatalf("missing cutover store error = %v", err)
	}
}
