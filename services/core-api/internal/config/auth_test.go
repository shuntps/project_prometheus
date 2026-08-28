package config_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/config"
	"github.com/shuntps/project_prometheus/services/core-api/internal/ratelimit"
)

var authKeys = []string{
	"PASSWORD_ARGON2_MEMORY_KIB", "PASSWORD_ARGON2_ITERATIONS", "PASSWORD_ARGON2_LANES",
	"PASSWORD_MIN_LENGTH", "SESSION_ABSOLUTE_LIFETIME", "SESSION_IDLE_LIFETIME",
}

func TestEveryAuthenticationSettingIsRequiredAwayFromDevelopment(t *testing.T) {
	for _, env := range []string{"staging", "production"} {
		for _, key := range authKeys {
			t.Run(env+" without "+key, func(t *testing.T) {
				values := storeEnv(env, map[string]string{key: ""})
				cfg, err := config.Load(lookupFrom(values))
				if err == nil {
					t.Fatalf("%s was optional and resolved to %+v", key, cfg.Auth)
				}
				if !strings.Contains(err.Error(), key) {
					t.Errorf("the refusal does not name %s: %v", key, err)
				}
			})
		}
	}
}

// TestDevelopmentResolvesToTheAdoptedFloor keeps a developer machine on the same
// storage posture as a deployment, never a weaker one.
func TestDevelopmentResolvesToTheAdoptedFloor(t *testing.T) {
	values := storeEnv("development", nil)
	for _, key := range authKeys {
		delete(values, key)
	}
	cfg, err := config.Load(lookupFrom(values))
	if err != nil {
		t.Fatalf("development was refused: %v", err)
	}
	want := password.Params{
		MemoryKiB: password.FloorMemoryKiB, Iterations: password.FloorIterations, Lanes: password.FloorLanes,
	}
	if cfg.Auth.Password.Params != want {
		t.Errorf("resolved %+v, want the floor %+v", cfg.Auth.Password.Params, want)
	}
	if err := cfg.Auth.Validate(); err != nil {
		t.Errorf("the loader returned settings the domain rejects: %v", err)
	}
}

// TestNoConfigurationCanFallUnderTheAdoptedFloor is the rule that a deployment
// mistake must not weaken password storage silently.
func TestNoConfigurationCanFallUnderTheAdoptedFloor(t *testing.T) {
	refused := map[string]map[string]string{
		"memory below the OWASP minimum":      {"PASSWORD_ARGON2_MEMORY_KIB": "19455"},
		"memory at zero":                      {"PASSWORD_ARGON2_MEMORY_KIB": "0"},
		"one iteration":                       {"PASSWORD_ARGON2_ITERATIONS": "1"},
		"no iteration":                        {"PASSWORD_ARGON2_ITERATIONS": "0"},
		"no parallelism":                      {"PASSWORD_ARGON2_LANES": "0"},
		"memory not an integer":               {"PASSWORD_ARGON2_MEMORY_KIB": "lots"},
		"memory absurd":                       {"PASSWORD_ARGON2_MEMORY_KIB": "99999999"},
		"minimum length under the NIST floor": {"PASSWORD_MIN_LENGTH": "14"},
		"minimum length at eight":             {"PASSWORD_MIN_LENGTH": "8"},
		"minimum length at zero":              {"PASSWORD_MIN_LENGTH": "0"},
		"minimum length absurd":               {"PASSWORD_MIN_LENGTH": "100000"},
		"idle lifetime too short":             {"SESSION_IDLE_LIFETIME": "1s"},
		"absolute lifetime too short":         {"SESSION_ABSOLUTE_LIFETIME": "10s"},
		"absolute lifetime too long":          {"SESSION_ABSOLUTE_LIFETIME": "8760h"},
		"idle beyond absolute":                {"SESSION_IDLE_LIFETIME": "24h", "SESSION_ABSOLUTE_LIFETIME": "1h"},
		"lifetime not a duration":             {"SESSION_IDLE_LIFETIME": "30"},
		"negative lifetime":                   {"SESSION_IDLE_LIFETIME": "-30m"},
	}
	for name, extra := range refused {
		t.Run(name, func(t *testing.T) {
			cfg, err := config.Load(lookupFrom(storeEnv("production", extra)))
			if err == nil {
				t.Fatalf("the settings were accepted and resolved to %+v", cfg.Auth)
			}
			if cfg.Auth != (config.AuthSettings{}) {
				t.Error("a refused configuration still carried authentication settings")
			}
		})
	}
}

func TestStrongerThanTheFloorIsAccepted(t *testing.T) {
	cfg, err := config.Load(lookupFrom(storeEnv("production", map[string]string{
		"PASSWORD_ARGON2_MEMORY_KIB": "47104",
		"PASSWORD_ARGON2_ITERATIONS": "3",
		"PASSWORD_ARGON2_LANES":      "2",
		"PASSWORD_MIN_LENGTH":        "20",
		"SESSION_ABSOLUTE_LIFETIME":  "8h",
		"SESSION_IDLE_LIFETIME":      "15m",
	})))
	if err != nil {
		t.Fatalf("stronger settings were refused: %v", err)
	}
	want := config.AuthSettings{
		Password: config.PasswordSettings{
			Params: password.Params{MemoryKiB: 47104, Iterations: 3, Lanes: 2},
			Policy: password.Policy{MinCodePoints: 20},
		},
		Session:   session.Lifetimes{Absolute: 8 * time.Hour, Idle: 15 * time.Minute},
		RateLimit: ratelimit.AuthPolicy{ClientAttempts: 10, IdentityAttempts: 5, Window: 15 * time.Minute, Capacity: 65_536},
	}
	if cfg.Auth != want {
		t.Errorf("resolved %+v, want %+v", cfg.Auth, want)
	}
}

// TestTheSettingsCarryNoSecret keeps configuration free of material that would
// have to be redacted: every field is a bound, never a credential.
func TestTheSettingsCarryNoSecret(t *testing.T) {
	cfg, err := config.Load(lookupFrom(storeEnv("production", nil)))
	if err != nil {
		t.Fatalf("loading failed: %v", err)
	}
	rendered := fmt.Sprintf("%+v", cfg.Auth)
	for _, forbidden := range []string{probePassword, validURL, "argon2id$"} {
		if strings.Contains(rendered, forbidden) {
			t.Errorf("the settings render %q: %s", forbidden, rendered)
		}
	}
	if !strings.Contains(rendered, "MemoryKiB:19456") {
		t.Errorf("the settings do not render the adopted parameters: %s", rendered)
	}
}
