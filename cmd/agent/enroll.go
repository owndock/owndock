package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	agentenrollment "github.com/owndock/owndock/internal/agent/enrollment"
)

const maximumEnrollmentTokenFileBytes = 257

var productionEnrollmentPaths = agentenrollment.Paths{
	Config:         "/etc/owndock/agent.yaml",
	CACertificate:  "/etc/owndock/agent-ca.pem",
	IdentityBundle: "/var/lib/owndock-agent/identity/agent-identity.pem",
	StateDirectory: "/var/lib/owndock-agent",
}

func runEnrollment(ctx context.Context, arguments []string) error {
	flags := flag.NewFlagSet(serviceName+" enroll", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var enrollmentEndpoint string
	var controlEndpoint string
	var tokenFile string
	var serverCAFile string
	var instanceID string
	var recoverPending bool
	var enableHostTerminal bool
	var requestTimeout time.Duration
	flags.StringVar(
		&enrollmentEndpoint, "enrollment-endpoint", "",
		"HTTPS bootstrap endpoint ending in /api/v1/agent/enrollments:exchange",
	)
	flags.StringVar(
		&controlEndpoint, "control-endpoint", "",
		"HTTPS Agent control endpoint ending in /api/v1/agent/connect",
	)
	flags.StringVar(
		&tokenFile, "token-file", "",
		"absolute path to a private regular file containing the one-time token",
	)
	flags.StringVar(
		&serverCAFile, "server-ca-file", "",
		"optional private CA used only to authenticate the bootstrap HTTPS server",
	)
	flags.StringVar(
		&instanceID, "instance-id", "",
		"optional stable installation instance identifier; generated when omitted",
	)
	flags.BoolVar(
		&enableHostTerminal, "enable-host-terminal", false,
		"grant and enable audited host terminal support for this Agent identity",
	)
	flags.BoolVar(
		&recoverPending, "recover", false,
		"finish installing a locally persisted enrollment response without a token",
	)
	flags.DurationVar(&requestTimeout, "timeout", 30*time.Second, "bootstrap request timeout")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return agentenrollment.ErrInvalidEnrollment
	}
	if os.Geteuid() != 0 {
		return errors.New("Agent enrollment must run as root through owndock-agentctl")
	}
	if recoverPending {
		if enrollmentEndpoint != "" || controlEndpoint != "" || tokenFile != "" ||
			serverCAFile != "" || instanceID != "" || enableHostTerminal {
			return errors.New("--recover does not accept enrollment inputs")
		}
		result, err := agentenrollment.Recover(productionEnrollmentPaths, time.Now())
		if err != nil {
			return err
		}
		return printEnrollmentResult(result)
	}
	token, err := readEnrollmentTokenFile(tokenFile)
	if err != nil {
		return err
	}
	defer clearEnrollmentSecret(token)
	result, err := agentenrollment.Provision(ctx, agentenrollment.Options{
		EnrollmentEndpoint: enrollmentEndpoint,
		ControlEndpoint:    controlEndpoint,
		ServerCAFile:       serverCAFile,
		InstanceID:         instanceID,
		AgentVersion:       version,
		Capabilities:       agentenrollment.StandardCapabilities(enableHostTerminal),
		HostTerminal:       enableHostTerminal,
		RequestTimeout:     requestTimeout,
		Paths:              productionEnrollmentPaths,
	}, token)
	if err != nil {
		if errors.Is(err, agentenrollment.ErrPendingEnrollment) {
			return fmt.Errorf("%w; rerun with --recover", err)
		}
		return err
	}
	return printEnrollmentResult(result)
}

func readEnrollmentTokenFile(value string) ([]byte, error) {
	path := filepath.Clean(strings.TrimSpace(value))
	if !filepath.IsAbs(path) || path != value {
		return nil, errors.New("enrollment token file path must be absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect enrollment token file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 || info.Size() > maximumEnrollmentTokenFileBytes {
		return nil, errors.New("enrollment token file must be a private regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open enrollment token file: %w", err)
	}
	defer file.Close()
	token, err := io.ReadAll(io.LimitReader(file, maximumEnrollmentTokenFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read enrollment token file: %w", err)
	}
	if len(token) > maximumEnrollmentTokenFileBytes {
		clearEnrollmentSecret(token)
		return nil, errors.New("enrollment token file is too large")
	}
	return token, nil
}

func printEnrollmentResult(result agentenrollment.Result) error {
	_, err := fmt.Fprintf(
		os.Stdout,
		"enrolled OwnDock Agent identity %s for managed host %s; certificate expires %s\n",
		result.IdentityID,
		result.ManagedHostID,
		result.ExpiresAt.UTC().Format(time.RFC3339),
	)
	return err
}

func clearEnrollmentSecret(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
