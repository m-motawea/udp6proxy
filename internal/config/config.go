// Package config loads the udp6proxy daemon configuration (TOML).
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/m-motawea/udp6proxy/internal/endpoint"
)

// Server configures the management API / web UI.
type Server struct {
	// Listen is the API/UI address. Empty string disables the API.
	// Default "127.0.0.1:8080".
	Listen  *string
	TLSCert string
	TLSKey  string
	// SessionHours is the web UI login lifetime (default 12).
	SessionHours int
	// SecureCookies forces the Secure cookie flag (set this when serving
	// plain HTTP behind a TLS-terminating reverse proxy).
	SecureCookies bool
}

// Storage selects where endpoints are persisted.
type Storage struct {
	// Backend is "file" or "redis". If empty: "redis" when [Redis] has an
	// Address (v1 compatibility), else "file".
	Backend string
	// StateDir holds endpoints.json (file backend) and auth.json.
	// Relative paths are resolved against the config file directory.
	StateDir string
	// ReloadInterval (seconds) is how often the backend is polled for
	// external changes. Default 10 (or [Redis].Update if set).
	ReloadInterval int
}

// Redis is the v1-compatible Redis section.
type Redis struct {
	Address  string
	Port     int
	Password string
	Username string
	DB       int
	Prefix   string
	Update   int // v1: reload interval in seconds
	TLS      bool
}

// Config is the whole daemon configuration.
type Config struct {
	Server   Server
	Storage  Storage
	Redis    Redis
	LogLevel string
	Endpoint []endpoint.Endpoint

	path string
}

// Load reads and validates a config file. A missing file is allowed and
// yields defaults (useful for "udp6proxy serve" with no config at all).
func Load(path string) (*Config, error) {
	c := &Config{path: path}
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		md, err := toml.Decode(string(data), c)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if und := md.Undecoded(); len(und) > 0 {
			keys := make([]string, len(und))
			for i, k := range und {
				keys[i] = k.String()
			}
			return nil, fmt.Errorf("%s: unknown keys: %s", path, strings.Join(keys, ", "))
		}
	case os.IsNotExist(err):
	default:
		return nil, err
	}
	if err := c.applyDefaults(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) applyDefaults() error {
	if c.Server.Listen == nil {
		def := "127.0.0.1:8080"
		c.Server.Listen = &def
	}
	if c.Server.SessionHours <= 0 {
		c.Server.SessionHours = 12
	}
	if (c.Server.TLSCert == "") != (c.Server.TLSKey == "") {
		return fmt.Errorf("Server.TLSCert and Server.TLSKey must be set together")
	}
	b := strings.ToLower(c.Storage.Backend)
	if b == "" {
		if c.Redis.Address != "" {
			b = "redis"
		} else {
			b = "file"
		}
	}
	if b != "file" && b != "redis" {
		return fmt.Errorf("Storage.Backend must be \"file\" or \"redis\", got %q", c.Storage.Backend)
	}
	c.Storage.Backend = b
	if c.Redis.Port == 0 {
		c.Redis.Port = 6379
	}
	if b == "redis" && c.Redis.Address == "" {
		c.Redis.Address = "127.0.0.1"
	}
	if c.Storage.ReloadInterval <= 0 {
		c.Storage.ReloadInterval = 10
		if c.Redis.Update > 0 {
			c.Storage.ReloadInterval = c.Redis.Update
		}
	}
	dir := c.Storage.StateDir
	if dir == "" {
		dir = "."
	}
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(filepath.Dir(c.path), dir)
	}
	c.Storage.StateDir = dir

	seen := map[string]bool{}
	for i := range c.Endpoint {
		e := &c.Endpoint[i]
		e.Normalize()
		if err := e.Validate(); err != nil {
			return fmt.Errorf("Endpoint %q: %w", e.Name, err)
		}
		if seen[e.Name] {
			return fmt.Errorf("Endpoint %q defined twice", e.Name)
		}
		seen[e.Name] = true
		if err := endpoint.CheckConflicts(*e, c.Endpoint[:i]); err != nil {
			return fmt.Errorf("Endpoint %q: %w", e.Name, err)
		}
	}
	return nil
}

// ReloadInterval as a duration.
func (c *Config) ReloadInterval() time.Duration {
	return time.Duration(c.Storage.ReloadInterval) * time.Second
}

// Path returns the file the config was loaded from.
func (c *Config) Path() string { return c.path }
