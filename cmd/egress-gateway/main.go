package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	platformconfig "github.com/owndock/owndock/internal/platform/config"
	"github.com/owndock/owndock/internal/shared/egressproxy"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
)

func main() {
	var configPath string
	var scope string
	var healthcheck bool
	flag.StringVar(&configPath, "conf", "configs/config.yaml", "configuration file or directory")
	flag.StringVar(&scope, "scope", "", "isolated gateway scope: build, evidence, or vulnerability-db")
	flag.BoolVar(&healthcheck, "healthcheck", false, "check the configured local gateway listener")
	flag.Parse()
	if healthcheck {
		if err := check(configPath, scope); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, configPath, scope); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func check(configPath, scope string) error {
	cfg, err := platformconfig.Load(configPath)
	if err != nil {
		return errors.New("egress gateway configuration is unavailable")
	}
	gatewayConfig, err := selectGatewayConfig(cfg, scope)
	if err != nil || !gatewayConfig.Enabled {
		return errors.New("egress gateway configuration is unavailable")
	}
	host, port, err := net.SplitHostPort(gatewayConfig.AddressValue())
	if err != nil {
		return errors.New("egress gateway address is invalid")
	}
	if net.ParseIP(host).IsUnspecified() {
		host = "127.0.0.1"
	}
	connection, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 2*time.Second)
	if err != nil {
		return errors.New("egress gateway is unavailable")
	}
	return connection.Close()
}

func run(ctx context.Context, configPath, scope string) error {
	cfg, err := platformconfig.Load(configPath)
	if err != nil {
		return err
	}
	gatewayConfig, err := selectGatewayConfig(cfg, scope)
	if err != nil {
		return err
	}
	if !gatewayConfig.Enabled {
		return errors.New("egress gateway is disabled")
	}
	dialTimeout, err := gatewayConfig.DialTimeoutDuration()
	if err != nil {
		return err
	}
	idleTimeout, err := gatewayConfig.IdleTimeoutDuration()
	if err != nil {
		return err
	}
	destinations := make([]egressproxy.Destination, 0, len(gatewayConfig.AllowedDestinations))
	for _, destination := range gatewayConfig.AllowedDestinations {
		destinations = append(destinations, egressproxy.Destination{
			Authority: destination.Authority, AllowPrivate: destination.AllowPrivate,
		})
	}
	gateway, err := egressproxy.New(egressproxy.Options{
		Destinations: destinations, DialTimeout: dialTimeout, IdleTimeout: idleTimeout,
		MaximumConnections: gatewayConfig.MaximumConnectionsValue(),
	})
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", gatewayConfig.AddressValue())
	if err != nil {
		return errors.New("listen for egress gateway failed")
	}
	server := &http.Server{
		Handler: gateway, ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: idleTimeout, WriteTimeout: idleTimeout,
		IdleTimeout: idleTimeout, MaxHeaderBytes: 64 * 1024,
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.New("serve egress gateway failed")
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return errors.New("stop egress gateway failed")
		}
		return nil
	}
}

func selectGatewayConfig(cfg platformconfig.Config, scope string) (platformconfig.EgressGateway, error) {
	switch scope {
	case "build":
		return cfg.Runtime.BuildEgress, nil
	case "evidence":
		return cfg.Runtime.EvidenceEgress, nil
	case "vulnerability-db":
		return cfg.Runtime.VulnerabilityDBEgress, nil
	default:
		return platformconfig.EgressGateway{}, errors.New(
			"egress gateway scope must be build, evidence, or vulnerability-db",
		)
	}
}
