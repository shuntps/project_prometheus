package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/config"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence"
)

const (
	probePassword = "s3cr3t-loader-probe"
	probeHost     = "db.internal.loader.example"
	validURL      = "postgres://core_api:" + probePassword + "@" + probeHost + ":6432/core_api"
)

func storeEnv(env string, extra map[string]string) map[string]string {
	values := map[string]string{
		"APP_ENV":                    env,
		"RATE_LIMIT_MAX":             "100",
		"RATE_LIMIT_WINDOW":          "1m",
		"RATE_LIMIT_ALGORITHM":       "fixed_window",
		"NETWORK_MODE":               "direct",
		"DATABASE_URL":               validURL,
		"DATABASE_TLS_MODE":          "verify-full",
		"DATABASE_TLS_ROOT_CERT":     "/etc/core-api/root.crt",
		"PASSWORD_ARGON2_MEMORY_KIB": "19456",
		"PASSWORD_ARGON2_ITERATIONS": "2",
		"PASSWORD_ARGON2_LANES":      "1",
		"PASSWORD_MIN_LENGTH":        "15",
		"SESSION_ABSOLUTE_LIFETIME":  "12h",
		"SESSION_IDLE_LIFETIME":      "30m",
	}
	for k, v := range extra {
		if v == "" {
			delete(values, k)
			continue
		}
		values[k] = v
	}
	return values
}

func TestConnectionStringIsRequiredInEveryEnvironment(t *testing.T) {
	for _, env := range []string{"development", "staging", "production"} {
		t.Run(env, func(t *testing.T) {
			for name, values := range map[string]map[string]string{
				"absent": storeEnv(env, map[string]string{"DATABASE_URL": ""}),
				"blank":  storeEnv(env, map[string]string{"DATABASE_URL": "   "}),
			} {
				if _, err := config.Load(lookupFrom(values)); err == nil {
					t.Errorf("%s connection string was accepted", name)
				}
			}
		})
	}
}

func TestMalformedConnectionStringsAreRefused(t *testing.T) {
	cases := map[string]string{
		"wrong scheme":       "mysql://core_api@" + probeHost + ":3306/core_api",
		"no scheme":          "core_api@" + probeHost + ":6432/core_api",
		"no host":            "postgres:///core_api",
		"not a URL":          "postgres://core api@ho st:99/db",
		"sslmode in the URL": validURL + "?sslmode=disable",
		"verify in the URL":  validURL + "?sslmode=verify-full",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := config.Load(lookupFrom(storeEnv("production", map[string]string{"DATABASE_URL": raw}))); err == nil {
				t.Fatal("the connection string was accepted")
			}
		})
	}
}

// TestNoProblemReportReproducesTheConnectionString is the loader-side half of
// the secret-handling rule: a refusal must name the variable, never its value.
func TestNoProblemReportReproducesTheConnectionString(t *testing.T) {
	cases := map[string]map[string]string{
		"unusable scheme":     {"DATABASE_URL": strings.Replace(validURL, "postgres://", "mysql://", 1)},
		"sslmode present":     {"DATABASE_URL": validURL + "?sslmode=disable"},
		"unparsable":          {"DATABASE_URL": "postgres://core api:" + probePassword + "@ho st:99/db"},
		"refused TLS posture": {"DATABASE_URL": validURL, "DATABASE_TLS_MODE": "disable"},
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := config.Load(lookupFrom(storeEnv("production", extra)))
			if err == nil {
				t.Fatal("expected a refusal")
			}
			for label, secret := range map[string]string{"password": probePassword, "host": probeHost} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("the report exposed the %s: %v", label, err)
				}
			}
			if !strings.Contains(err.Error(), "DATABASE_") {
				t.Errorf("the report does not name the variable: %v", err)
			}
		})
	}
}

func TestTLSPostureIsRequiredAndAuthenticatedAwayFromDevelopment(t *testing.T) {
	for _, env := range []string{"staging", "production"} {
		t.Run(env, func(t *testing.T) {
			if _, err := config.Load(lookupFrom(storeEnv(env, map[string]string{"DATABASE_TLS_MODE": ""}))); err == nil {
				t.Error("an absent TLS posture was accepted")
			}
			// disable encrypts nothing; allow, prefer and require leave the server
			// unauthenticated. None may govern a connection off the host.
			for _, refused := range []string{"disable", "allow", "prefer", "require", "", "yes"} {
				values := storeEnv(env, nil)
				values["DATABASE_TLS_MODE"] = refused
				if _, err := config.Load(lookupFrom(values)); err == nil {
					t.Errorf("TLS posture %q was accepted", refused)
				}
			}
			for _, accepted := range []string{"verify-ca", "verify-full", "  VERIFY-FULL "} {
				cfg, err := config.Load(lookupFrom(storeEnv(env, map[string]string{"DATABASE_TLS_MODE": accepted})))
				if err != nil {
					t.Errorf("TLS posture %q was refused: %v", accepted, err)
					continue
				}
				if !cfg.Database.TLSMode.AuthenticatesServer() {
					t.Errorf("TLS posture %q resolved to %q, which does not authenticate the server", accepted, cfg.Database.TLSMode)
				}
			}
		})
	}
}

func TestDevelopmentResolvesAUsableStoreWithoutExplicitSettings(t *testing.T) {
	values := storeEnv("development", map[string]string{"DATABASE_TLS_MODE": "", "DATABASE_TLS_ROOT_CERT": ""})
	cfg, err := config.Load(lookupFrom(values))
	if err != nil {
		t.Fatalf("development was refused: %v", err)
	}
	if cfg.Database.TLSMode != persistence.TLSDisable {
		t.Errorf("development resolved TLS posture %q, want %q", cfg.Database.TLSMode, persistence.TLSDisable)
	}
	if err := cfg.Database.Validate(); err != nil {
		t.Errorf("the loader returned settings the domain rejects: %v", err)
	}
	if cfg.DatabaseURL.Reveal() != validURL {
		t.Error("the loader did not carry the connection string through")
	}
}

func TestPoolSettingsAreCanonicalisedAndBounded(t *testing.T) {
	cfg, err := config.Load(lookupFrom(storeEnv("production", map[string]string{
		"DATABASE_MAX_CONNS":            "32",
		"DATABASE_MIN_CONNS":            "4",
		"DATABASE_MAX_CONN_LIFETIME":    "45m",
		"DATABASE_MAX_CONN_IDLE_TIME":   "5m",
		"DATABASE_CONNECT_TIMEOUT":      "3s",
		"DATABASE_HEALTH_CHECK_TIMEOUT": "1500ms",
	})))
	if err != nil {
		t.Fatalf("complete settings were refused: %v", err)
	}
	want := persistence.Settings{
		TLSMode: persistence.TLSVerifyFull, TLSRoot: "/etc/core-api/root.crt", MaxConns: 32, MinConns: 4,
		MaxConnLifetime: 45 * time.Minute, MaxConnIdleTime: 5 * time.Minute,
		ConnectTimeout: 3 * time.Second, CheckTimeout: 1500 * time.Millisecond,
	}
	if cfg.Database != want {
		t.Errorf("loader returned %+v, want %+v", cfg.Database, want)
	}

	refused := map[string]map[string]string{
		"maximum not an integer":  {"DATABASE_MAX_CONNS": "many"},
		"maximum zero":            {"DATABASE_MAX_CONNS": "0"},
		"maximum above ceiling":   {"DATABASE_MAX_CONNS": "100000"},
		"minimum above maximum":   {"DATABASE_MAX_CONNS": "4", "DATABASE_MIN_CONNS": "9"},
		"minimum negative":        {"DATABASE_MIN_CONNS": "-1"},
		"lifetime not a duration": {"DATABASE_MAX_CONN_LIFETIME": "45"},
		"lifetime too short":      {"DATABASE_MAX_CONN_LIFETIME": "1s"},
		"connect timeout too low": {"DATABASE_CONNECT_TIMEOUT": "1ms"},
		"check timeout too high":  {"DATABASE_HEALTH_CHECK_TIMEOUT": "10m"},
		"check timeout negative":  {"DATABASE_HEALTH_CHECK_TIMEOUT": "-1s"},
	}
	for name, extra := range refused {
		t.Run(name, func(t *testing.T) {
			if _, err := config.Load(lookupFrom(storeEnv("production", extra))); err == nil {
				t.Fatal("the settings were accepted")
			}
		})
	}
}

// TestRefusedStoreSettingsNeverReturnAUsableConfiguration keeps the loader from
// handing back a partially built store the caller might still open.
func TestRefusedStoreSettingsNeverReturnAUsableConfiguration(t *testing.T) {
	cfg, err := config.Load(lookupFrom(storeEnv("production", map[string]string{"DATABASE_TLS_MODE": "require"})))
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if !cfg.DatabaseURL.IsZero() || cfg.Database != (persistence.Settings{}) {
		t.Error("a refused configuration still carried store settings")
	}
}
