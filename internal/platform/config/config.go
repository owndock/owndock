package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	kratosconfig "github.com/go-kratos/kratos/v2/config"
	"github.com/go-kratos/kratos/v2/config/file"
)

const (
	defaultHTTPTimeout      = 30 * time.Second
	defaultShutdownTimeout  = 15 * time.Second
	defaultTraceSampleRatio = 1.0
	defaultMongoURIEnv      = "OWNDOCK_MONGODB_URI"
	defaultMongoDatabase    = "owndock"
	defaultMongoConnect     = 10 * time.Second
	defaultMongoOperation   = 5 * time.Second
	defaultMongoMaxIdle     = 5 * time.Minute
	defaultMongoMaxPoolSize = 100
)

// Config is the process configuration root. Keep transport and infrastructure
// configuration here; domain rules belong to their owning module.
type Config struct {
	Server        Server        `json:"server"`
	Observability Observability `json:"observability"`
	Development   Development   `json:"development"`
	Database      Database      `json:"database"`
}

type Server struct {
	HTTP HTTP `json:"http"`
}

type HTTP struct {
	Address         string `json:"address"`
	Timeout         string `json:"timeout"`
	ShutdownTimeout string `json:"shutdown_timeout"`
}

type Observability struct {
	Tracing Tracing `json:"tracing"`
}

type Tracing struct {
	Enabled     bool    `json:"enabled"`
	Endpoint    string  `json:"endpoint"`
	Insecure    bool    `json:"insecure"`
	SampleRatio float64 `json:"sample_ratio"`
}

// Development contains explicitly non-production switches. Features in this
// section must remain disabled in the checked-in default configuration.
type Development struct {
	EnableEngineeringSamples bool `json:"enable_engineering_samples"`
}

type Database struct {
	Mongo Mongo `json:"mongo"`
}

type Mongo struct {
	Enabled          bool   `json:"enabled"`
	URIEnv           string `json:"uri_env"`
	Database         string `json:"database"`
	ConnectTimeout   string `json:"connect_timeout"`
	OperationTimeout string `json:"operation_timeout"`
	MaxIdleTime      string `json:"max_idle_time"`
	MinPoolSize      uint64 `json:"min_pool_size"`
	MaxPoolSize      uint64 `json:"max_pool_size"`
}

func Load(path string) (Config, error) {
	c := kratosconfig.New(kratosconfig.WithSource(file.NewSource(path)))
	defer func() { _ = c.Close() }()

	if err := c.Load(); err != nil {
		return Config{}, fmt.Errorf("load config: %w", err)
	}

	cfg := Config{
		Observability: Observability{
			Tracing: Tracing{SampleRatio: defaultTraceSampleRatio},
		},
		Database: Database{
			Mongo: Mongo{
				URIEnv:           defaultMongoURIEnv,
				Database:         defaultMongoDatabase,
				ConnectTimeout:   defaultMongoConnect.String(),
				OperationTimeout: defaultMongoOperation.String(),
				MaxIdleTime:      defaultMongoMaxIdle.String(),
				MaxPoolSize:      defaultMongoMaxPoolSize,
			},
		},
	}
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
	if err := c.Observability.Tracing.Validate(); err != nil {
		return fmt.Errorf("observability.tracing: %w", err)
	}
	if err := c.Database.Mongo.Validate(); err != nil {
		return fmt.Errorf("database.mongo: %w", err)
	}
	return nil
}

func (m Mongo) Validate() error {
	if !m.Enabled {
		return nil
	}
	if strings.TrimSpace(m.URIEnv) == "" {
		return fmt.Errorf("uri_env is required when enabled")
	}
	if strings.TrimSpace(m.Database) == "" {
		return fmt.Errorf("database is required when enabled")
	}
	if _, err := m.ConnectTimeoutDuration(); err != nil {
		return fmt.Errorf("connect_timeout: %w", err)
	}
	if _, err := m.OperationTimeoutDuration(); err != nil {
		return fmt.Errorf("operation_timeout: %w", err)
	}
	if _, err := m.MaxIdleTimeDuration(); err != nil {
		return fmt.Errorf("max_idle_time: %w", err)
	}
	if m.MaxPoolSize == 0 {
		return fmt.Errorf("max_pool_size must be greater than zero")
	}
	if m.MinPoolSize > m.MaxPoolSize {
		return fmt.Errorf("min_pool_size must not exceed max_pool_size")
	}
	return nil
}

func (m Mongo) URI() (string, error) {
	name := strings.TrimSpace(m.URIEnv)
	if name == "" {
		return "", fmt.Errorf("uri_env is required")
	}
	value, ok := os.LookupEnv(name)
	if !ok || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("environment variable %s is required", name)
	}
	return strings.TrimSpace(value), nil
}

func (m Mongo) ConnectTimeoutDuration() (time.Duration, error) {
	return parseDuration(m.ConnectTimeout, defaultMongoConnect)
}

func (m Mongo) OperationTimeoutDuration() (time.Duration, error) {
	return parseDuration(m.OperationTimeout, defaultMongoOperation)
}

func (m Mongo) MaxIdleTimeDuration() (time.Duration, error) {
	return parseDuration(m.MaxIdleTime, defaultMongoMaxIdle)
}

func (t Tracing) Validate() error {
	if !t.Enabled {
		return nil
	}

	endpoint := strings.TrimSpace(t.Endpoint)
	if endpoint == "" {
		return fmt.Errorf("endpoint is required when enabled")
	}
	if strings.Contains(endpoint, "://") {
		return fmt.Errorf("endpoint must use host:port format")
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || strings.TrimSpace(host) == "" {
		return fmt.Errorf("endpoint must use host:port format")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return fmt.Errorf("endpoint port must be between 1 and 65535")
	}
	if t.SampleRatio < 0 || t.SampleRatio > 1 {
		return fmt.Errorf("sample_ratio must be between 0 and 1")
	}
	return nil
}

func (t Tracing) EffectiveSampleRatio() float64 {
	return t.SampleRatio
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
