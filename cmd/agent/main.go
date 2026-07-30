package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	agentconfig "github.com/owndock/owndock/internal/agent/config"
	agentcontrol "github.com/owndock/owndock/internal/agent/control"
	agentruntime "github.com/owndock/owndock/internal/agent/runtime"
)

const serviceName = "owndock-agent"

var (
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
)

func main() {
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string) error {
	flags := flag.NewFlagSet(serviceName, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var configPath string
	var showVersion bool
	flags.StringVar(
		&configPath,
		"conf",
		"/etc/owndock/agent.yaml",
		"Agent configuration file or directory",
	)
	flags.BoolVar(&showVersion, "version", false, "print version and exit")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if showVersion {
		_, err := fmt.Fprintf(
			os.Stdout,
			"%s %s (%s, %s)\n",
			serviceName,
			version,
			commit,
			buildTime,
		)
		return err
	}

	config, err := agentconfig.Load(configPath)
	if err != nil {
		return err
	}
	bootID, err := agentconfig.ReadBootID(config.Control.BootIDFile)
	if err != nil {
		return err
	}
	handshakeTimeout, _ := config.Control.HandshakeTimeoutDuration()
	serverSilenceTimeout, _ :=
		config.Control.ServerSilenceTimeoutDuration()
	reconnectMinimum, _ := config.Control.ReconnectMinimumDuration()
	reconnectMaximum, _ := config.Control.ReconnectMaximumDuration()
	reconnectStableAfter, _ :=
		config.Control.ReconnectStableAfterDuration()

	cache, err := agentruntime.NewFileResultCache(
		config.Runtime.StateDirectory,
		config.Runtime.ResultCacheSize,
	)
	if err != nil {
		return fmt.Errorf("create Agent result cache: %w", err)
	}
	cutovers, err := agentruntime.NewFileCutoverStore(
		config.Runtime.StateDirectory,
		config.Runtime.CutoverWatermarkSize,
	)
	if err != nil {
		return fmt.Errorf("create Agent cutover store: %w", err)
	}
	executor, err := agentruntime.NewDockerExecutor(
		config.Runtime.DockerSocket,
		cache,
		cutovers,
	)
	if err != nil {
		return fmt.Errorf("create Agent Docker runtime: %w", err)
	}
	httpClient, err := agentcontrol.NewHTTPClient(
		agentcontrol.TLSFiles{
			CACertificateFile:     config.Control.CACertificateFile,
			ClientCertificateFile: config.Control.ClientCertificateFile,
			ClientPrivateKeyFile:  config.Control.ClientPrivateKeyFile,
		},
		handshakeTimeout,
	)
	if err != nil {
		return fmt.Errorf("create Agent control TLS client: %w", err)
	}
	client, err := agentcontrol.NewClient(
		httpClient,
		executor,
		agentcontrol.ClientConfig{
			Endpoint: config.Control.Endpoint,
			Identity: agentcontrol.Identity{
				OrganizationID: config.Control.OrganizationID,
				ManagedHostID:  config.Control.ManagedHostID,
				IdentityID:     config.Control.IdentityID,
				InstanceID:     config.Control.InstanceID,
				BootID:         bootID,
				AgentVersion:   version,
			},
			HandshakeTimeout:     handshakeTimeout,
			ServerSilenceTimeout: serverSilenceTimeout,
			MaxFrameBytes:        config.Control.MaxFrameBytes,
			MaxConcurrentCommands: config.Control.
				MaxConcurrentCommands,
			Capabilities: append(
				[]string(nil),
				config.Control.Capabilities...,
			),
		},
	)
	if err != nil {
		httpClient.CloseIdleConnections()
		return fmt.Errorf("create Agent control client: %w", err)
	}
	defer client.CloseIdleConnections()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With(
		"service.name", serviceName,
		"service.version", version,
		"agent.managed_host_id", config.Control.ManagedHostID,
	)
	runner, err := agentcontrol.NewRunner(
		client,
		agentcontrol.RunnerConfig{
			MinimumDelay: reconnectMinimum,
			MaximumDelay: reconnectMaximum,
			StableAfter:  reconnectStableAfter,
		},
		func(event agentcontrol.ReconnectEvent) {
			logger.Warn(
				"Agent control reconnect scheduled",
				"error.category", event.Code,
				"attempt", event.Attempt,
				"delay", event.Delay.String(),
			)
		},
	)
	if err != nil {
		return fmt.Errorf("create Agent control runner: %w", err)
	}
	logger.Info(
		"Agent started",
		"runtime", "docker",
		"protocol.version", "v1",
	)
	err = runner.Run(ctx)
	if err != nil {
		return err
	}
	logger.Info("Agent stopped")
	return nil
}
