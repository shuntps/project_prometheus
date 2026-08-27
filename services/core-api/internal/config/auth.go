package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
)

// Development values sit exactly on the adopted floor. They are not a deployment
// posture: staging and production must calibrate and set every value explicitly.
const (
	devPasswordMemoryKiB  = int64(password.FloorMemoryKiB)
	devPasswordIterations = int64(password.FloorIterations)
	devPasswordLanes      = int64(password.FloorLanes)
	// ASVS v5.0.0-6.2.1 requires at least 8 and strongly recommends 15.
	devPasswordMinLength = 15
	devSessionAbsolute   = 12 * time.Hour
	devSessionIdle       = 30 * time.Minute
)

// PasswordSettings is the adopted password posture. The hashing parameters are
// versioned by being carried inside every stored representation.
type PasswordSettings struct {
	Params password.Params
	Policy password.Policy
}

// AuthSettings groups every authentication value the service is allowed to run
// with. No secret is represented here.
type AuthSettings struct {
	Password PasswordSettings
	Session  session.Lifetimes
}

// Validate delegates each floor to the package that owns it, so no configuration
// path can define its own weaker rule.
func (a AuthSettings) Validate() error {
	var problems []string
	if err := a.Password.Params.Validate(); err != nil {
		problems = append(problems, err.Error())
	}
	if err := a.Password.Policy.Validate(); err != nil {
		problems = append(problems, err.Error())
	}
	if err := a.Session.Validate(); err != nil {
		problems = append(problems, err.Error())
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalid, strings.Join(problems, "; "))
	}
	return nil
}

// loadAuth returns settings only when they are semantically valid; the domain
// packages are the single authority on what that means.
func loadAuth(lookup Lookup, env Environment) (AuthSettings, []string) {
	var problems []string
	explicit := env == EnvStaging || env == EnvProduction

	counts := []struct {
		key string
		def int64
		min int64
		max int64
		out *int64
	}{
		{"PASSWORD_ARGON2_MEMORY_KIB", devPasswordMemoryKiB, 1, 1 << 22, new(int64)},
		{"PASSWORD_ARGON2_ITERATIONS", devPasswordIterations, 1, 64, new(int64)},
		{"PASSWORD_ARGON2_LANES", devPasswordLanes, 1, 64, new(int64)},
		{"PASSWORD_MIN_LENGTH", devPasswordMinLength, 1, password.MaxBytes, new(int64)},
	}
	for _, c := range counts {
		raw, present := trimmed(lookup, c.key)
		switch {
		case present:
			var value int64
			if _, err := fmt.Sscanf(raw, "%d", &value); err != nil || raw != fmt.Sprintf("%d", value) {
				problems = append(problems, fmt.Sprintf("%s %q is not an integer", c.key, raw))
				continue
			}
			if value < c.min || value > c.max {
				problems = append(problems, fmt.Sprintf("%s must be between %d and %d", c.key, c.min, c.max))
				continue
			}
			*c.out = value
		case explicit:
			problems = append(problems, fmt.Sprintf("%s is required in staging and production", c.key))
		default:
			*c.out = c.def
		}
	}

	durations := []struct {
		key string
		def time.Duration
		out *time.Duration
	}{
		{"SESSION_ABSOLUTE_LIFETIME", devSessionAbsolute, new(time.Duration)},
		{"SESSION_IDLE_LIFETIME", devSessionIdle, new(time.Duration)},
	}
	for _, d := range durations {
		if _, present := trimmed(lookup, d.key); !present && explicit {
			problems = append(problems, fmt.Sprintf("%s is required in staging and production", d.key))
			continue
		}
		value, err := durationValue(lookup, d.key, d.def)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		*d.out = value
	}

	if len(problems) > 0 {
		return AuthSettings{}, problems
	}

	settings := AuthSettings{
		Password: PasswordSettings{
			Params: password.Params{
				MemoryKiB:  uint32(*counts[0].out),
				Iterations: uint32(*counts[1].out),
				Lanes:      uint8(*counts[2].out),
			},
			Policy: password.Policy{MinCodePoints: int(*counts[3].out)},
		},
		Session: session.Lifetimes{
			Absolute: *durations[0].out,
			Idle:     *durations[1].out,
		},
	}
	if err := settings.Validate(); err != nil {
		return AuthSettings{}, []string{err.Error()}
	}
	return settings, nil
}
