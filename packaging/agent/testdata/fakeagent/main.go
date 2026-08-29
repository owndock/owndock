package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

func main() {
	showVersion := flag.Bool("version", false, "print version")
	flag.String("conf", "", "ignored test configuration")
	flag.Parse()
	version, err := installedVersion()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *showVersion {
		_, _ = fmt.Printf("owndock-agent %s (systemd-fixture, test)\n", version)
		return
	}
	if os.Geteuid() == 0 {
		_, _ = fmt.Fprintln(os.Stderr, "fixture must not run as root")
		os.Exit(3)
	}
	if version == "9.9.9" {
		_, _ = fmt.Fprintln(os.Stderr, "intentional startup failure")
		os.Exit(23)
	}
	if err := os.WriteFile("/etc/owndock-agent-systemd-escape", []byte("unsafe"), 0o600); err == nil {
		_ = os.Remove("/etc/owndock-agent-systemd-escape")
		_, _ = fmt.Fprintln(os.Stderr, "ProtectSystem did not prevent an /etc write")
		os.Exit(4)
	}
	if err := os.WriteFile(
		"/var/lib/owndock-agent/systemd-running-version",
		[]byte(version+"\n"),
		0o600,
	); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(5)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
}

func installedVersion() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	value, err := os.ReadFile(filepath.Join(filepath.Dir(executable), "VERSION"))
	if err != nil {
		return "", err
	}
	version := strings.TrimSpace(string(value))
	if version == "" || strings.ContainsAny(version, "/\\ \t\r\n") {
		return "", errors.New("invalid fixture version")
	}
	return version, nil
}
