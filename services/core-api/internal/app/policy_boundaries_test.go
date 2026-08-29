package app_test

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/app"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/browser"
	"github.com/shuntps/project_prometheus/services/core-api/internal/config"
	"github.com/shuntps/project_prometheus/services/core-api/internal/ratelimit"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi"
)

func loadWith(values map[string]string) (config.Config, error) {
	return config.Load(func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	})
}

func behindProxyEnv(header string) map[string]string {
	return map[string]string{
		"APP_ENV":                           "production",
		"RATE_LIMIT_MAX":                    "10",
		"RATE_LIMIT_WINDOW":                 "1m",
		"RATE_LIMIT_ALGORITHM":              "fixed_window",
		"NETWORK_MODE":                      "behind_proxy",
		"RATE_LIMIT_TRUSTED_PROXIES":        "10.0.0.0/8",
		"RATE_LIMIT_PROXY_HEADER":           header,
		"DATABASE_URL":                      "postgres://core_api_test:fixture-only-not-a-secret@127.0.0.1:5432/core_api_test",
		"DATABASE_TLS_MODE":                 "verify-full",
		"DATABASE_TLS_ROOT_CERT":            "/etc/core-api/root.crt",
		"PASSWORD_ARGON2_MEMORY_KIB":        "19456",
		"PASSWORD_ARGON2_ITERATIONS":        "2",
		"PASSWORD_ARGON2_LANES":             "1",
		"PASSWORD_MIN_LENGTH":               "15",
		"SESSION_ABSOLUTE_LIFETIME":         "12h",
		"SESSION_IDLE_LIFETIME":             "30m",
		"SESSION_ACTIVITY_INTERVAL":         "1m",
		"PUBLIC_ORIGIN":                     "https://app.example.com",
		"AUTH_RATE_LIMIT_CLIENT_ATTEMPTS":   "10",
		"AUTH_RATE_LIMIT_IDENTITY_ATTEMPTS": "5",
		"AUTH_RATE_LIMIT_WINDOW":            "15m",
		"AUTH_RATE_LIMIT_CAPACITY":          "65536",
	}
}

// TestLoaderCanonicalisesEverySupportedProxyHeader exercises the configuration
// loader, which must return a semantically valid policy on its own.
func TestLoaderCanonicalisesEverySupportedProxyHeader(t *testing.T) {
	for _, canonical := range ratelimit.SupportedProxyHeaders {
		for _, spelling := range []string{canonical, lower(canonical), "  " + canonical + "  "} {
			cfg, err := loadWith(behindProxyEnv(spelling))
			if err != nil {
				t.Fatalf("loader refused supported header %q: %v", spelling, err)
			}
			if cfg.RateLimit.ProxyHeader != canonical {
				t.Errorf("loader returned %q for %q, want the canonical %q", cfg.RateLimit.ProxyHeader, spelling, canonical)
			}
			if err := cfg.RateLimit.Validate(); err != nil {
				t.Errorf("loader returned a policy the domain rejects: %v", err)
			}
			opts := httpapi.Options{RateLimit: cfg.RateLimit, Persistence: availableStore{}, CheckTimeout: time.Second}
			if _, err := httpapi.New(opts); err != nil {
				t.Errorf("constructor refused a header the loader accepted: %v", err)
			}
		}
	}
}

func TestLoaderRefusesEveryUnsupportedProxyHeader(t *testing.T) {
	for _, unsupported := range []string{"X-Client-Ip", "Forwarded", "True-Client-Ip", "x_forwarded_for", "!"} {
		cfg, err := loadWith(behindProxyEnv(unsupported))
		if err == nil {
			t.Errorf("loader accepted unsupported header %q and returned %+v", unsupported, cfg.RateLimit)
			continue
		}
		policy := ratelimit.Policy{
			Max: 10, Window: time.Minute, Algorithm: ratelimit.FixedWindow,
			NetworkMode: ratelimit.BehindProxy, ProxyHeader: unsupported,
			TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		}
		if _, err := httpapi.New(httpapi.Options{RateLimit: policy}); err == nil {
			t.Errorf("constructor accepted unsupported header %q that the loader refused", unsupported)
		}
	}
}

func TestUnknownOrUnsetNetworkModeIsRefusedAtBothBoundaries(t *testing.T) {
	for _, mode := range []string{"edge", "none", " ", "DIRECT-ish"} {
		values := behindProxyEnv("X-Forwarded-For")
		values["NETWORK_MODE"] = mode
		if cfg, err := loadWith(values); err == nil {
			t.Errorf("loader accepted network mode %q and returned %+v", mode, cfg.RateLimit)
		}
	}

	for name, policy := range map[string]ratelimit.Policy{
		"unset mode":   {Max: 10, Window: time.Minute, Algorithm: ratelimit.FixedWindow},
		"unknown mode": {Max: 10, Window: time.Minute, Algorithm: ratelimit.FixedWindow, NetworkMode: "edge"},
	} {
		if err := policy.Validate(); err == nil {
			t.Errorf("%s: the domain accepted it", name)
		}
		if _, err := httpapi.New(httpapi.Options{RateLimit: policy}); err == nil {
			t.Errorf("%s: the constructor accepted it", name)
		}
	}
}

func TestProcessRefusesToStartWithAnInvalidPolicy(t *testing.T) {
	values := behindProxyEnv("X-Forwarded-For")
	delete(values, "RATE_LIMIT_TRUSTED_PROXIES")
	if _, err := loadWith(values); err == nil {
		t.Fatal("loader accepted behind_proxy without an allowlist")
	}

	// A caller bypassing the loader must still be refused by the service.
	invalid := ratelimit.Policy{
		Max: 10, Window: time.Minute, Algorithm: ratelimit.FixedWindow,
		NetworkMode: ratelimit.BehindProxy, ProxyHeader: "X-Forwarded-For",
		TrustedProxies: []netip.Prefix{{}},
	}
	// Everything but the policy is valid, so the refusal can only come from it.
	cfg := config.Config{
		Environment: config.EnvProduction, LogLevel: "error", HTTPAddress: "127.0.0.1:0",
		PublicOrigin: testPublicOrigin, Auth: testAuthSettings(),
		RateLimit: invalid, ReadTimeout: time.Second, WriteTimeout: time.Second,
		IdleTimeout: time.Second, ShutdownTimeout: time.Second,
	}
	service, err := app.New(context.Background(), cfg, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err == nil {
		t.Fatal("the service started with an invalid prefix in the allowlist")
	}
	if service != nil {
		t.Error("expected no service when the policy is refused")
	}
}

func lower(s string) string {
	out := []rune(s)
	for i, r := range out {
		if r >= 'A' && r <= 'Z' {
			out[i] = r + 32
		}
	}
	return string(out)
}

// testPublicOrigin and testAuthSettings supply the posture the service refuses to
// start without, so a test about another subject is not rejected for that reason.
var testPublicOrigin = func() browser.Origin {
	origin, err := browser.ParseOrigin("https://app.example.com")
	if err != nil {
		panic(err)
	}
	return origin
}()

func testAuthSettings() config.AuthSettings {
	return config.AuthSettings{
		Password: config.PasswordSettings{
			Params: password.Params{MemoryKiB: password.FloorMemoryKiB, Iterations: password.FloorIterations, Lanes: password.FloorLanes},
			Policy: password.Policy{MinCodePoints: password.SingleFactorMinimum},
		},
		Session:   session.Lifetimes{Absolute: time.Hour, Idle: 30 * time.Minute, ActivityInterval: time.Minute},
		RateLimit: ratelimit.AuthPolicy{ClientAttempts: 10, IdentityAttempts: 5, Window: 15 * time.Minute, Capacity: ratelimit.MinAuthCapacity},
	}
}
