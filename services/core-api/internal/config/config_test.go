package config_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/config"
)

var ratePolicy = map[string]string{
	"RATE_LIMIT_MAX":       "100",
	"RATE_LIMIT_WINDOW":    "1m",
	"RATE_LIMIT_ALGORITHM": "fixed_window",
	"NETWORK_MODE":         "direct",
}

func merge(base map[string]string, key, value string) map[string]string {
	out := map[string]string{key: value}
	for k, v := range base {
		out[k] = v
	}
	return out
}

func lookupFrom(values map[string]string) config.Lookup {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}

func TestLoadAppliesDefaultsForOptionalSettings(t *testing.T) {
	cfg, err := config.Load(lookupFrom(withEnv("production", ratePolicy)))
	if err != nil {
		t.Fatalf("expected a valid configuration, got error: %v", err)
	}
	if cfg.Environment != config.EnvProduction {
		t.Errorf("environment = %q, want production", cfg.Environment)
	}
	if cfg.HTTPAddress != ":8080" {
		t.Errorf("address = %q, want :8080", cfg.HTTPAddress)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("log level = %q, want info", cfg.LogLevel)
	}
	if cfg.ShutdownTimeout != 15*time.Second {
		t.Errorf("shutdown timeout = %s, want 15s", cfg.ShutdownTimeout)
	}
}

func TestLoadAcceptsExplicitValues(t *testing.T) {
	cfg, err := config.Load(lookupFrom(withEnv("staging", map[string]string{
		"RATE_LIMIT_MAX":       ratePolicy["RATE_LIMIT_MAX"],
		"RATE_LIMIT_WINDOW":    ratePolicy["RATE_LIMIT_WINDOW"],
		"RATE_LIMIT_ALGORITHM": ratePolicy["RATE_LIMIT_ALGORITHM"],
		"NETWORK_MODE":         ratePolicy["NETWORK_MODE"],
		"LOG_LEVEL":            "debug",
		"HTTP_ADDRESS":         "127.0.0.1:9000",
		"HTTP_READ_TIMEOUT":    "5s",
		"HTTP_WRITE_TIMEOUT":   "6s",
		"HTTP_IDLE_TIMEOUT":    "7s",
		"SHUTDOWN_TIMEOUT":     "8s",
	})))
	if err != nil {
		t.Fatalf("expected a valid configuration, got error: %v", err)
	}
	if cfg.HTTPAddress != "127.0.0.1:9000" || cfg.ReadTimeout != 5*time.Second || cfg.IdleTimeout != 7*time.Second {
		t.Errorf("explicit values were not applied: %+v", cfg)
	}
}

func TestLoadRefusesInvalidConfiguration(t *testing.T) {
	cases := map[string]map[string]string{
		"missing environment":   {},
		"blank environment":     {"APP_ENV": "  "},
		"unknown environment":   {"APP_ENV": "prod"},
		"unknown log level":     {"APP_ENV": "production", "LOG_LEVEL": "verbose"},
		"address without port":  {"APP_ENV": "production", "HTTP_ADDRESS": "localhost"},
		"port out of range":     {"APP_ENV": "production", "HTTP_ADDRESS": ":70000"},
		"unparsable duration":   {"APP_ENV": "production", "SHUTDOWN_TIMEOUT": "soon"},
		"non positive duration": {"APP_ENV": "production", "HTTP_READ_TIMEOUT": "0s"},
		"negative duration":     {"APP_ENV": "production", "HTTP_WRITE_TIMEOUT": "-1s"},
	}
	for name, values := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, err := config.Load(lookupFrom(values))
			if err == nil {
				t.Fatalf("expected startup to be refused, got configuration %+v", cfg)
			}
			if !errors.Is(err, config.ErrInvalid) {
				t.Errorf("error = %v, want it to wrap ErrInvalid", err)
			}
			if !reflect.DeepEqual(cfg, config.Config{}) {
				t.Errorf("expected the zero configuration on refusal, got %+v", cfg)
			}
		})
	}
}

func TestLoadReportsEveryProblemAtOnce(t *testing.T) {
	_, err := config.Load(lookupFrom(map[string]string{"LOG_LEVEL": "verbose", "HTTP_ADDRESS": "nope"}))
	if err == nil {
		t.Fatal("expected startup to be refused")
	}
	message := err.Error()
	for _, want := range []string{"APP_ENV", "LOG_LEVEL", "HTTP_ADDRESS"} {
		if !strings.Contains(message, want) {
			t.Errorf("error %q does not mention %s", message, want)
		}
	}
}
