// Package config centralises every environment-derived setting so the rest of the
// program never reads os.Getenv directly. One place to look, one place to test.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
)

// Config is the immutable runtime configuration of the server.
type Config struct {
	// Addr is the listen address, e.g. ":8080".
	Addr string
	// Port is kept separately because the healthcheck subcommand needs it.
	Port int
	// RulesDir, when set, replaces the embedded rule set with a directory of
	// YAML files (normally a read-only bind mount).
	RulesDir string
	// MaxBatch bounds how many observations one request may carry.
	MaxBatch int
	// MaxBodyBytes bounds the request body.
	MaxBodyBytes int64
	// Workers bounds the identification worker pool; 0 means GOMAXPROCS.
	Workers int
	// LogLevel is the slog threshold.
	LogLevel slog.Level
}

// Defaults. They are exported so tests and documentation share one definition.
const (
	DefaultPort         = 8080
	DefaultMaxBatch     = 5000
	DefaultMaxBodyBytes = 8 << 20 // 8 MiB
)

// Load reads the configuration from the environment, applying defaults.
// Invalid values are a startup error rather than a silent fallback: a typo in an
// orchestration file should fail the container, not change behaviour quietly.
func Load() (Config, error) {
	cfg := Config{
		Port:         DefaultPort,
		MaxBatch:     DefaultMaxBatch,
		MaxBodyBytes: DefaultMaxBodyBytes,
	}

	if v := strings.TrimSpace(os.Getenv("PORT")); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p <= 0 || p > 65535 {
			return cfg, fmt.Errorf("PORT must be 1..65535, got %q", v)
		}
		cfg.Port = p
	}
	cfg.Addr = fmt.Sprintf(":%d", cfg.Port)

	cfg.RulesDir = strings.TrimSpace(os.Getenv("RULES_DIR"))

	if v := strings.TrimSpace(os.Getenv("MAX_BATCH")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return cfg, fmt.Errorf("MAX_BATCH must be a positive integer, got %q", v)
		}
		cfg.MaxBatch = n
	}
	if v := strings.TrimSpace(os.Getenv("MAX_BODY_BYTES")); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			return cfg, fmt.Errorf("MAX_BODY_BYTES must be a positive integer, got %q", v)
		}
		cfg.MaxBodyBytes = n
	}
	if v := strings.TrimSpace(os.Getenv("WORKERS")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return cfg, fmt.Errorf("WORKERS must be >= 0, got %q", v)
		}
		cfg.Workers = n
	}
	level := strings.ToLower(strings.TrimSpace(os.Getenv("LOG_LEVEL")))
	switch level {
	case "", "info":
		cfg.LogLevel = slog.LevelInfo
	case "debug":
		cfg.LogLevel = slog.LevelDebug
	case "warn", "warning":
		cfg.LogLevel = slog.LevelWarn
	case "error":
		cfg.LogLevel = slog.LevelError
	default:
		return cfg, fmt.Errorf("LOG_LEVEL must be debug|info|warn|error, got %q", level)
	}
	return cfg, nil
}
