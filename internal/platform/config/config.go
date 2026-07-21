package config

import (
	"fmt"
	"strings"
	"time"

	kratosconfig "github.com/go-kratos/kratos/v2/config"
	"github.com/go-kratos/kratos/v2/config/file"
)

const (
	defaultHTTPTimeout     = 30 * time.Second
	defaultShutdownTimeout = 15 * time.Second
)

// Config is the process configuration root. Keep transport and infrastructure
// configuration here; domain rules belong to their owning module.
type Config struct {
	Server Server `json:"server"`
}

type Server struct {
	HTTP HTTP `json:"http"`
}

type HTTP struct {
	Address         string `json:"address"`
	Timeout         string `json:"timeout"`
	ShutdownTimeout string `json:"shutdown_timeout"`
}

func Load(path string) (Config, error) {
	c := kratosconfig.New(kratosconfig.WithSource(file.NewSource(path)))
	defer func() { _ = c.Close() }()

	if err := c.Load(); err != nil {
		return Config{}, fmt.Errorf("load config: %w", err)
	}

	var cfg Config
	if err := c.Scan(&cfg); err != nil {
		return Config{}, fmt.Errorf("scan config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.Server.HTTP.Address) == "" {
		return fmt.Errorf("server.http.address is required")
	}
	if _, err := c.Server.HTTP.TimeoutDuration(); err != nil {
		return fmt.Errorf("server.http.timeout: %w", err)
	}
	if _, err := c.Server.HTTP.ShutdownTimeoutDuration(); err != nil {
		return fmt.Errorf("server.http.shutdown_timeout: %w", err)
	}
	return nil
}

func (h HTTP) TimeoutDuration() (time.Duration, error) {
	return parseDuration(h.Timeout, defaultHTTPTimeout)
}

func (h HTTP) ShutdownTimeoutDuration() (time.Duration, error) {
	return parseDuration(h.ShutdownTimeout, defaultShutdownTimeout)
}

func parseDuration(value string, fallback time.Duration) (time.Duration, error) {
	if strings.TrimSpace(value) == "" {
		return fallback, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, err
	}
	if duration <= 0 {
		return 0, fmt.Errorf("must be greater than zero")
	}
	return duration, nil
}
