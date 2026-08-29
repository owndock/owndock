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

	"github.com/owndock/owndock/internal/modules/build/egressproxy"
	platformconfig "github.com/owndock/owndock/internal/platform/config"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
)

func main() {
	var configPath string
	var healthcheck bool
	flag.StringVar(&configPath, "conf", "configs/config.yaml", "configuration file or directory")
	flag.BoolVar(&healthcheck, "healthcheck", false, "check the configured local gateway listener")
	flag.Parse()
	if healthcheck {
		if err := check(configPath); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, configPath); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func check(configPath string) error {
	cfg, err := platformconfig.Load(configPath)
	if err != nil || !cfg.Runtime.BuildEgress.Enabled {
		return errors.New("build egress gateway configuration is unavailable")
	}
	host, port, err := net.SplitHostPort(cfg.Runtime.BuildEgress.AddressValue())
	if err != nil {
		return errors.New("build egress gateway address is invalid")
	}
	if net.ParseIP(host).IsUnspecified() {
		host = "127.0.0.1"
	}
	connection, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 2*time.Second)
	if err != nil {
		return errors.New("build egress gateway is unavailable")
	}
	return connection.Close()
}

func run(ctx context.Context, configPath string) error {
	cfg, err := platformconfig.Load(configPath)
	if err != nil {
		return err
	}
	gatewayConfig := cfg.Runtime.BuildEgress
	if !gatewayConfig.Enabled {
		return errors.New("build egress gateway is disabled")
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
		return errors.New("listen for build egress gateway failed")
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
		return errors.New("serve build egress gateway failed")
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return errors.New("stop build egress gateway failed")
		}
		return nil
	}
}
