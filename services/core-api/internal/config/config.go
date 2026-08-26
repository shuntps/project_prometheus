// Package config loads and validates every setting the service needs at startup.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence"
	"github.com/shuntps/project_prometheus/services/core-api/internal/ratelimit"
)

type Environment string

const (
	EnvDevelopment Environment = "development"
	EnvStaging     Environment = "staging"
	EnvProduction  Environment = "production"
)

type Config struct {
	Environment     Environment
	LogLevel        string
	HTTPAddress     string
	RateLimit       ratelimit.Policy
	DatabaseURL     persistence.DSN
	Database        persistence.Settings
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
}

// ErrInvalid reports a configuration the service refuses to start with.
var ErrInvalid = errors.New("invalid configuration")

type Lookup func(key string) (string, bool)

// Load reads configuration from lookup and refuses to return a Config that
// would let the service start in an undefined state.
func Load(lookup Lookup) (Config, error) {
	if lookup == nil {
		lookup = os.LookupEnv
	}

	cfg := Config{
		LogLevel:        stringValue(lookup, "LOG_LEVEL", "info"),
		HTTPAddress:     stringValue(lookup, "HTTP_ADDRESS", ":8080"),
		ReadTimeout:     0,
		WriteTimeout:    0,
		IdleTimeout:     0,
		ShutdownTimeout: 0,
	}

	var problems []string

	rawEnv, ok := lookup("APP_ENV")
	if !ok || strings.TrimSpace(rawEnv) == "" {
		problems = append(problems, "APP_ENV is required")
	} else {
		env := Environment(strings.ToLower(strings.TrimSpace(rawEnv)))
		switch env {
		case EnvDevelopment, EnvStaging, EnvProduction:
			cfg.Environment = env
		default:
			problems = append(problems, fmt.Sprintf("APP_ENV %q is not one of development, staging, production", rawEnv))
		}
	}

	if !isKnownLogLevel(cfg.LogLevel) {
		problems = append(problems, fmt.Sprintf("LOG_LEVEL %q is not one of debug, info, warn, error", cfg.LogLevel))
	}

	if err := validateAddress(cfg.HTTPAddress); err != nil {
		problems = append(problems, err.Error())
	}

	durations := []struct {
		key    string
		target *time.Duration
		def    time.Duration
	}{
		{"HTTP_READ_TIMEOUT", &cfg.ReadTimeout, 10 * time.Second},
		{"HTTP_WRITE_TIMEOUT", &cfg.WriteTimeout, 15 * time.Second},
		{"HTTP_IDLE_TIMEOUT", &cfg.IdleTimeout, 60 * time.Second},
		{"SHUTDOWN_TIMEOUT", &cfg.ShutdownTimeout, 15 * time.Second},
	}
	for _, d := range durations {
		value, err := durationValue(lookup, d.key, d.def)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		*d.target = value
	}

	policy, rateProblems := loadRateLimit(lookup, cfg.Environment)
	cfg.RateLimit = policy
	problems = append(problems, rateProblems...)

	dsn, database, storeProblems := loadPersistence(lookup, cfg.Environment)
	cfg.DatabaseURL = dsn
	cfg.Database = database
	problems = append(problems, storeProblems...)

	if len(problems) > 0 {
		return Config{}, fmt.Errorf("%w: %s", ErrInvalid, strings.Join(problems, "; "))
	}
	return cfg, nil
}

func stringValue(lookup Lookup, key, fallback string) string {
	if raw, ok := lookup(key); ok && strings.TrimSpace(raw) != "" {
		return strings.TrimSpace(raw)
	}
	return fallback
}

func durationValue(lookup Lookup, key string, fallback time.Duration) (time.Duration, error) {
	raw, ok := lookup(key)
	if !ok || strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("%s %q is not a valid duration", key, raw)
	}
	if parsed <= 0 {
		return 0, fmt.Errorf("%s must be greater than zero", key)
	}
	return parsed, nil
}

func isKnownLogLevel(level string) bool {
	switch strings.ToLower(level) {
	case "debug", "info", "warn", "error":
		return true
	default:
		return false
	}
}

func validateAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("HTTP_ADDRESS %q is not a valid host:port", address)
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return fmt.Errorf("HTTP_ADDRESS %q does not carry a port between 1 and 65535", address)
	}
	if host != "" && net.ParseIP(host) == nil && !isHostname(host) {
		return fmt.Errorf("HTTP_ADDRESS %q does not carry a valid host", address)
	}
	return nil
}

func isHostname(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			return false
		}
	}
	return true
}
