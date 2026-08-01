package agentconfig

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	kratosconfig "github.com/go-kratos/kratos/v2/config"
	"github.com/go-kratos/kratos/v2/config/file"

	"github.com/owndock/owndock/internal/shared/agentprotocol"
)

const (
	defaultHandshakeTimeout      = 10 * time.Second
	defaultServerSilenceTimeout  = 45 * time.Second
	defaultReconnectMinimum      = time.Second
	defaultReconnectMaximum      = 30 * time.Second
	defaultReconnectStableAfter  = time.Minute
	defaultMaxFrameBytes         = 64 * 1024
	defaultMaxConcurrentCommands = 4
	defaultResultCacheSize       = 256
	defaultCutoverWatermarkSize  = 16384
	defaultBootIDFile            = "/proc/sys/kernel/random/boot_id"
	defaultDockerSocket          = "/var/run/docker.sock"
	defaultStateDirectory        = "/var/lib/owndock-agent"
)

var ErrInvalidConfig = errors.New("Agent configuration is invalid")

type Config struct {
	Control Control `json:"control"`
	Runtime Runtime `json:"runtime"`
}

type Control struct {
	Endpoint              string   `json:"endpoint"`
	OrganizationID        string   `json:"organization_id"`
	ManagedHostID         string   `json:"managed_host_id"`
	IdentityID            string   `json:"identity_id"`
	InstanceID            string   `json:"instance_id"`
	BootIDFile            string   `json:"boot_id_file"`
	CACertificateFile     string   `json:"ca_certificate_file"`
	ClientCertificateFile string   `json:"client_certificate_file"`
	ClientPrivateKeyFile  string   `json:"client_private_key_file"`
	HandshakeTimeout      string   `json:"handshake_timeout"`
	ServerSilenceTimeout  string   `json:"server_silence_timeout"`
	ReconnectMinimum      string   `json:"reconnect_minimum"`
	ReconnectMaximum      string   `json:"reconnect_maximum"`
	ReconnectStableAfter  string   `json:"reconnect_stable_after"`
	MaxFrameBytes         int      `json:"max_frame_bytes"`
	MaxConcurrentCommands int      `json:"max_concurrent_commands"`
	Capabilities          []string `json:"capabilities"`
}

type Runtime struct {
	DockerSocket         string `json:"docker_socket"`
	StateDirectory       string `json:"state_directory"`
	ResultCacheSize      int    `json:"result_cache_size"`
	CutoverWatermarkSize int    `json:"cutover_watermark_size"`
}

func Load(path string) (Config, error) {
	sourcePath := strings.TrimSpace(path)
	if sourcePath == "" {
		return Config{}, ErrInvalidConfig
	}
	loader := kratosconfig.New(
		kratosconfig.WithSource(file.NewSource(sourcePath)),
	)
	defer func() { _ = loader.Close() }()
	if err := loader.Load(); err != nil {
		return Config{}, fmt.Errorf("load Agent config: %w", err)
	}
	config := Config{
		Control: Control{
			BootIDFile:            defaultBootIDFile,
			HandshakeTimeout:      defaultHandshakeTimeout.String(),
			ServerSilenceTimeout:  defaultServerSilenceTimeout.String(),
			ReconnectMinimum:      defaultReconnectMinimum.String(),
			ReconnectMaximum:      defaultReconnectMaximum.String(),
			ReconnectStableAfter:  defaultReconnectStableAfter.String(),
			MaxFrameBytes:         defaultMaxFrameBytes,
			MaxConcurrentCommands: defaultMaxConcurrentCommands,
			Capabilities:          baselineCapabilities(),
		},
		Runtime: Runtime{
			DockerSocket:         defaultDockerSocket,
			StateDirectory:       defaultStateDirectory,
			ResultCacheSize:      defaultResultCacheSize,
			CutoverWatermarkSize: defaultCutoverWatermarkSize,
		},
	}
	if err := loader.Scan(&config); err != nil {
		return Config{}, fmt.Errorf("scan Agent config: %w", err)
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (c Config) Validate() error {
	endpoint, err := url.Parse(strings.TrimSpace(c.Control.Endpoint))
	if err != nil || endpoint.Scheme != "https" ||
		endpoint.Host == "" || endpoint.User != nil ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" ||
		endpoint.Path != "/api/v1/agent/connect" {
		return fmt.Errorf("%w: control.endpoint", ErrInvalidConfig)
	}
	for name, value := range map[string]string{
		"control.organization_id": c.Control.OrganizationID,
		"control.managed_host_id": c.Control.ManagedHostID,
		"control.identity_id":     c.Control.IdentityID,
		"control.instance_id":     c.Control.InstanceID,
	} {
		if !validIdentifier(value) {
			return fmt.Errorf("%w: %s", ErrInvalidConfig, name)
		}
	}
	for name, value := range map[string]string{
		"control.boot_id_file":            c.Control.BootIDFile,
		"control.ca_certificate_file":     c.Control.CACertificateFile,
		"control.client_certificate_file": c.Control.ClientCertificateFile,
		"control.client_private_key_file": c.Control.ClientPrivateKeyFile,
		"runtime.docker_socket":           c.Runtime.DockerSocket,
		"runtime.state_directory":         c.Runtime.StateDirectory,
	} {
		if !cleanAbsolutePath(value) {
			return fmt.Errorf("%w: %s", ErrInvalidConfig, name)
		}
	}
	handshake, err := c.Control.HandshakeTimeoutDuration()
	if err != nil {
		return fmt.Errorf("%w: control.handshake_timeout", ErrInvalidConfig)
	}
	silence, err := c.Control.ServerSilenceTimeoutDuration()
	if err != nil || silence <= handshake {
		return fmt.Errorf("%w: control.server_silence_timeout", ErrInvalidConfig)
	}
	minimum, err := c.Control.ReconnectMinimumDuration()
	if err != nil {
		return fmt.Errorf("%w: control.reconnect_minimum", ErrInvalidConfig)
	}
	maximum, err := c.Control.ReconnectMaximumDuration()
	if err != nil || maximum < minimum || maximum > 10*time.Minute {
		return fmt.Errorf("%w: control.reconnect_maximum", ErrInvalidConfig)
	}
	if _, err := c.Control.ReconnectStableAfterDuration(); err != nil {
		return fmt.Errorf("%w: control.reconnect_stable_after", ErrInvalidConfig)
	}
	if c.Control.MaxFrameBytes < 1024 ||
		c.Control.MaxFrameBytes > 1024*1024 {
		return fmt.Errorf("%w: control.max_frame_bytes", ErrInvalidConfig)
	}
	if c.Control.MaxConcurrentCommands < 1 ||
		c.Control.MaxConcurrentCommands > 64 {
		return fmt.Errorf(
			"%w: control.max_concurrent_commands",
			ErrInvalidConfig,
		)
	}
	if !validCapabilities(c.Control.Capabilities) {
		return fmt.Errorf("%w: control.capabilities", ErrInvalidConfig)
	}
	if inventoryCapabilitiesEnabled(c.Control.Capabilities) &&
		c.Control.MaxFrameBytes < 64*1024 {
		return fmt.Errorf(
			"%w: control.max_frame_bytes requires 65536 for inventory",
			ErrInvalidConfig,
		)
	}
	if c.Runtime.ResultCacheSize < 1 ||
		c.Runtime.ResultCacheSize > 4096 {
		return fmt.Errorf("%w: runtime.result_cache_size", ErrInvalidConfig)
	}
	if c.Runtime.CutoverWatermarkSize < 1 ||
		c.Runtime.CutoverWatermarkSize > 65536 {
		return fmt.Errorf(
			"%w: runtime.cutover_watermark_size",
			ErrInvalidConfig,
		)
	}
	return nil
}

func baselineCapabilities() []string {
	return []string{
		agentprotocol.CapabilityRuntimeProbe,
		agentprotocol.CapabilityDeploymentPrepare,
		agentprotocol.CapabilityDeploymentStage,
		agentprotocol.CapabilityDeploymentActivate,
		agentprotocol.CapabilityDeploymentCancel,
	}
}

func validCapabilities(values []string) bool {
	if len(values) == 0 || len(values) > 64 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	inventoryCount := 0
	for _, value := range values {
		if !agentprotocol.SupportsCapability(value) {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
		switch value {
		case agentprotocol.CapabilityInventoryPrepare,
			agentprotocol.CapabilityInventoryChunk,
			agentprotocol.CapabilityInventoryRelease,
			agentprotocol.CapabilityInventoryEvents:
			inventoryCount++
		}
	}
	return inventoryCount == 0 || inventoryCount == 4
}

func inventoryCapabilitiesEnabled(values []string) bool {
	for _, value := range values {
		if value == agentprotocol.CapabilityInventoryPrepare {
			return true
		}
	}
	return false
}

func (c Control) HandshakeTimeoutDuration() (time.Duration, error) {
	return parseDuration(c.HandshakeTimeout, defaultHandshakeTimeout)
}

func (c Control) ServerSilenceTimeoutDuration() (time.Duration, error) {
	return parseDuration(
		c.ServerSilenceTimeout,
		defaultServerSilenceTimeout,
	)
}

func (c Control) ReconnectMinimumDuration() (time.Duration, error) {
	return parseDuration(c.ReconnectMinimum, defaultReconnectMinimum)
}

func (c Control) ReconnectMaximumDuration() (time.Duration, error) {
	return parseDuration(c.ReconnectMaximum, defaultReconnectMaximum)
}

func (c Control) ReconnectStableAfterDuration() (time.Duration, error) {
	return parseDuration(
		c.ReconnectStableAfter,
		defaultReconnectStableAfter,
	)
}

func ReadBootID(path string) (string, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if !filepath.IsAbs(path) {
		return "", ErrInvalidConfig
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("inspect Agent boot ID: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%w: control.boot_id_file", ErrInvalidConfig)
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("read Agent boot ID: %w", err)
	}
	defer func() { _ = file.Close() }()
	value, err := io.ReadAll(io.LimitReader(file, 257))
	if err != nil {
		return "", fmt.Errorf("read Agent boot ID: %w", err)
	}
	if len(value) > 256 {
		return "", fmt.Errorf("%w: control.boot_id_file", ErrInvalidConfig)
	}
	bootID := strings.TrimSpace(string(value))
	if !validIdentifier(bootID) {
		return "", fmt.Errorf("%w: control.boot_id_file", ErrInvalidConfig)
	}
	return bootID, nil
}

func parseDuration(value string, fallback time.Duration) (time.Duration, error) {
	if strings.TrimSpace(value) == "" {
		return fallback, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return 0, ErrInvalidConfig
	}
	return duration, nil
}

func cleanAbsolutePath(value string) bool {
	trimmed := strings.TrimSpace(value)
	return trimmed != "" &&
		filepath.IsAbs(trimmed) &&
		filepath.Clean(trimmed) == trimmed &&
		!strings.ContainsRune(trimmed, '\x00')
}

func validIdentifier(value string) bool {
	if value == "" || len(value) > 128 ||
		value == "." || value == ".." || value[0] == '.' {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}
