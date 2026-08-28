package config_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/config"
	"github.com/shuntps/project_prometheus/services/core-api/internal/ratelimit"
)

// withEnv supplies the store settings every environment requires, so a test about
// another subject is not refused for an unrelated reason. An explicit value wins.
func withEnv(env string, extra map[string]string) map[string]string {
	values := map[string]string{
		"APP_ENV":                           env,
		"DATABASE_URL":                      "postgres://core_api_test:fixture-only-not-a-secret@db.invalid:5432/core_api_test",
		"DATABASE_TLS_MODE":                 "verify-full",
		"DATABASE_TLS_ROOT_CERT":            "/etc/core-api/root.crt",
		"PASSWORD_ARGON2_MEMORY_KIB":        "19456",
		"PASSWORD_ARGON2_ITERATIONS":        "2",
		"PASSWORD_ARGON2_LANES":             "1",
		"PASSWORD_MIN_LENGTH":               "15",
		"SESSION_ABSOLUTE_LIFETIME":         "12h",
		"SESSION_IDLE_LIFETIME":             "30m",
		"PUBLIC_ORIGIN":                     "https://app.example.com",
		"AUTH_RATE_LIMIT_CLIENT_ATTEMPTS":   "10",
		"AUTH_RATE_LIMIT_IDENTITY_ATTEMPTS": "5",
		"AUTH_RATE_LIMIT_WINDOW":            "15m",
		"AUTH_RATE_LIMIT_CAPACITY":          "65536",
	}
	for k, v := range extra {
		values[k] = v
	}
	return values
}

func TestRateLimitPolicyIsRequiredInStagingAndProduction(t *testing.T) {
	for _, env := range []string{"staging", "production"} {
		t.Run(env, func(t *testing.T) {
			_, err := config.Load(lookupFrom(withEnv(env, nil)))
			if err == nil {
				t.Fatal("expected startup to be refused without a rate-limit policy")
			}
			for _, key := range []string{"RATE_LIMIT_MAX", "RATE_LIMIT_WINDOW", "RATE_LIMIT_ALGORITHM"} {
				if !strings.Contains(err.Error(), key) {
					t.Errorf("refusal does not mention %s: %v", key, err)
				}
			}
		})
	}
}

func TestRateLimitPolicyIsRefusedWhenNullOrDisabled(t *testing.T) {
	cases := map[string]map[string]string{
		"zero maximum":       {"RATE_LIMIT_MAX": "0", "RATE_LIMIT_WINDOW": "1m", "RATE_LIMIT_ALGORITHM": "fixed_window"},
		"negative maximum":   {"RATE_LIMIT_MAX": "-1", "RATE_LIMIT_WINDOW": "1m", "RATE_LIMIT_ALGORITHM": "fixed_window"},
		"zero window":        {"RATE_LIMIT_MAX": "10", "RATE_LIMIT_WINDOW": "0s", "RATE_LIMIT_ALGORITHM": "fixed_window"},
		"unrealistic max":    {"RATE_LIMIT_MAX": "100000000", "RATE_LIMIT_WINDOW": "1m", "RATE_LIMIT_ALGORITHM": "fixed_window"},
		"unrealistic window": {"RATE_LIMIT_MAX": "10", "RATE_LIMIT_WINDOW": "72h", "RATE_LIMIT_ALGORITHM": "fixed_window"},
		"unknown algorithm":  {"RATE_LIMIT_MAX": "10", "RATE_LIMIT_WINDOW": "1m", "RATE_LIMIT_ALGORITHM": "token_bucket", "NETWORK_MODE": "direct"},
		"unparsable max":     {"RATE_LIMIT_MAX": "many", "RATE_LIMIT_WINDOW": "1m", "RATE_LIMIT_ALGORITHM": "fixed_window"},
		"bad proxy entry":    {"RATE_LIMIT_MAX": "10", "RATE_LIMIT_WINDOW": "1m", "RATE_LIMIT_ALGORITHM": "fixed_window", "RATE_LIMIT_TRUSTED_PROXIES": "not-an-address"},
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, err := config.Load(lookupFrom(withEnv("production", extra)))
			if err == nil {
				t.Fatalf("expected startup to be refused, got %+v", cfg)
			}
			if !errors.Is(err, config.ErrInvalid) {
				t.Errorf("error = %v, want it to wrap ErrInvalid", err)
			}
		})
	}
}

func TestRateLimitPolicyIsAcceptedWhenComplete(t *testing.T) {
	cfg, err := config.Load(lookupFrom(withEnv("production", map[string]string{
		"RATE_LIMIT_MAX":             "120",
		"RATE_LIMIT_WINDOW":          "1m",
		"RATE_LIMIT_ALGORITHM":       "sliding_window",
		"NETWORK_MODE":               "behind_proxy",
		"RATE_LIMIT_PROXY_HEADER":    "X-Forwarded-For",
		"RATE_LIMIT_TRUSTED_PROXIES": "10.0.0.0/8, 192.0.2.7",
	})))
	if err != nil {
		t.Fatalf("expected a valid configuration, got %v", err)
	}
	if cfg.RateLimit.Max != 120 || cfg.RateLimit.Window != time.Minute {
		t.Errorf("policy = %+v, want max 120 over 1m", cfg.RateLimit)
	}
	if cfg.RateLimit.Algorithm != ratelimit.SlidingWindow {
		t.Errorf("algorithm = %q, want sliding_window", cfg.RateLimit.Algorithm)
	}
	if len(cfg.RateLimit.TrustedProxies) != 2 {
		t.Fatalf("trusted proxies = %v, want two entries", cfg.RateLimit.TrustedProxies)
	}
	if got := cfg.RateLimit.TrustedProxies[1].String(); got != "192.0.2.7/32" {
		t.Errorf("bare address became %q, want a single-host prefix", got)
	}
}

func TestDevelopmentGetsAPolicyWithoutExplicitConfiguration(t *testing.T) {
	cfg, err := config.Load(lookupFrom(withEnv("development", nil)))
	if err != nil {
		t.Fatalf("development should start without an explicit policy: %v", err)
	}
	if cfg.RateLimit.Max <= 0 || cfg.RateLimit.Window <= 0 {
		t.Errorf("development policy is not usable: %+v", cfg.RateLimit)
	}
	if len(cfg.RateLimit.TrustedProxies) != 0 {
		t.Errorf("development trusts proxies by default: %v", cfg.RateLimit.TrustedProxies)
	}
}

func TestNetworkModeIsRequiredAndConstrainsProxySettings(t *testing.T) {
	base := map[string]string{"RATE_LIMIT_MAX": "10", "RATE_LIMIT_WINDOW": "1m", "RATE_LIMIT_ALGORITHM": "fixed_window"}
	refused := map[string]map[string]string{
		"mode absent in production":      base,
		"unknown mode":                   merge(base, "NETWORK_MODE", "edge"),
		"behind proxy without allowlist": merge(merge(base, "NETWORK_MODE", "behind_proxy"), "RATE_LIMIT_PROXY_HEADER", "X-Forwarded-For"),
		"behind proxy without header":    merge(merge(base, "NETWORK_MODE", "behind_proxy"), "RATE_LIMIT_TRUSTED_PROXIES", "10.0.0.0/8"),
		"direct with proxies":            merge(merge(base, "NETWORK_MODE", "direct"), "RATE_LIMIT_TRUSTED_PROXIES", "10.0.0.0/8"),
		"direct with header":             merge(merge(base, "NETWORK_MODE", "direct"), "RATE_LIMIT_PROXY_HEADER", "X-Forwarded-For"),
	}
	for name, values := range refused {
		t.Run(name, func(t *testing.T) {
			if cfg, err := config.Load(lookupFrom(withEnv("production", values))); err == nil {
				t.Fatalf("expected startup to be refused, got %+v", cfg.RateLimit)
			}
		})
	}
}

func TestBehindProxyModeIsAcceptedWhenComplete(t *testing.T) {
	cfg, err := config.Load(lookupFrom(withEnv("production", map[string]string{
		"RATE_LIMIT_MAX":             "10",
		"RATE_LIMIT_WINDOW":          "1m",
		"RATE_LIMIT_ALGORITHM":       "fixed_window",
		"NETWORK_MODE":               "behind_proxy",
		"RATE_LIMIT_TRUSTED_PROXIES": "10.0.0.0/8",
		"RATE_LIMIT_PROXY_HEADER":    "x-forwarded-for",
	})))
	if err != nil {
		t.Fatalf("complete behind-proxy configuration was refused: %v", err)
	}
	if cfg.RateLimit.NetworkMode != ratelimit.BehindProxy {
		t.Errorf("mode = %q, want behind_proxy", cfg.RateLimit.NetworkMode)
	}
	if cfg.RateLimit.ProxyHeader != "X-Forwarded-For" {
		t.Errorf("header = %q, want the canonical form", cfg.RateLimit.ProxyHeader)
	}
}
