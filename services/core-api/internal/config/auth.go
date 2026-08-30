package config

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/ratelimit"
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
	// Activity is persisted at most once a minute per session, so a burst of user
	// events costs one write rather than one per event.
	devSessionActivityInterval = time.Minute
	// Attempt allowances start deliberately low: a legitimate sign-in rarely
	// needs several tries, and credential stuffing needs many.
	devAuthClientAttempts   = int64(10)
	devAuthIdentityAttempts = int64(5)
	devAuthWindow           = 15 * time.Minute
	devAuthCapacity         = int64(65_536)
)

// The configuration group each domain refusal belongs to. A domain error knows
// nothing of environment variable names, so the loader attaches the group.
const (
	memoryKey            = "PASSWORD_ARGON2_MEMORY_KIB"
	iterationsKey        = "PASSWORD_ARGON2_ITERATIONS"
	lanesKey             = "PASSWORD_ARGON2_LANES"
	minLengthKey         = "PASSWORD_MIN_LENGTH"
	absoluteLifetimeKey  = "SESSION_ABSOLUTE_LIFETIME"
	idleLifetimeKey      = "SESSION_IDLE_LIFETIME"
	activityIntervalKey  = "SESSION_ACTIVITY_INTERVAL"
	clientAttemptsKey    = "AUTH_RATE_LIMIT_CLIENT_ATTEMPTS"
	identityAttemptsKey  = "AUTH_RATE_LIMIT_IDENTITY_ATTEMPTS"
	rateLimitWindowKey   = "AUTH_RATE_LIMIT_WINDOW"
	rateLimitCapacityKey = "AUTH_RATE_LIMIT_CAPACITY"
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
	Password  PasswordSettings
	Session   session.Lifetimes
	RateLimit ratelimit.AuthPolicy
}

// domainCheck ties one configuration group to the domain that decides it. The
// domain remains the only authority on whether a value is acceptable.
type domainCheck struct {
	keys  []string
	check func() error
}

// domainChecks is the single inventory both validation boundaries consume, so an
// entry cannot be added to one boundary without reaching the other.
func (a AuthSettings) domainChecks() []domainCheck {
	return []domainCheck{
		{[]string{memoryKey, iterationsKey, lanesKey}, a.Password.Params.Validate},
		{[]string{minLengthKey}, a.Password.Policy.Validate},
		{[]string{absoluteLifetimeKey, idleLifetimeKey, activityIntervalKey}, a.Session.Validate},
		{[]string{clientAttemptsKey, identityAttemptsKey, rateLimitWindowKey, rateLimitCapacityKey}, a.RateLimit.Validate},
	}
}

// Validate delegates every authentication rule to the package that owns it, so no
// configuration path can define a weaker rule.
func (a AuthSettings) Validate() error {
	var problems []string
	for _, domain := range a.domainChecks() {
		if err := domain.check(); err != nil {
			problems = append(problems, err.Error())
		}
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
		// The bounds below are what the target type can hold, nothing more: the
		// password package owns every floor and ceiling and states them once.
		{memoryKey, devPasswordMemoryKiB, 0, math.MaxUint32, new(int64)},
		{iterationsKey, devPasswordIterations, 0, math.MaxUint32, new(int64)},
		{lanesKey, devPasswordLanes, 0, math.MaxUint8, new(int64)},
		{minLengthKey, devPasswordMinLength, 0, math.MaxInt, new(int64)},
		{"AUTH_RATE_LIMIT_CLIENT_ATTEMPTS", devAuthClientAttempts, ratelimit.MinAuthAttempts, ratelimit.MaxAuthAttempts, new(int64)},
		{"AUTH_RATE_LIMIT_IDENTITY_ATTEMPTS", devAuthIdentityAttempts, ratelimit.MinAuthAttempts, ratelimit.MaxAuthAttempts, new(int64)},
		{"AUTH_RATE_LIMIT_CAPACITY", devAuthCapacity, ratelimit.MinAuthCapacity, ratelimit.MaxAuthCapacity, new(int64)},
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
		{"SESSION_ACTIVITY_INTERVAL", devSessionActivityInterval, new(time.Duration)},
		{"AUTH_RATE_LIMIT_WINDOW", devAuthWindow, new(time.Duration)},
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
			Absolute:         *durations[0].out,
			Idle:             *durations[1].out,
			ActivityInterval: *durations[2].out,
		},
		RateLimit: ratelimit.AuthPolicy{
			ClientAttempts:   int(*counts[4].out),
			IdentityAttempts: int(*counts[5].out),
			Window:           *durations[3].out,
			Capacity:         int(*counts[6].out),
		},
	}
	// The same inventory the settings validate themselves with, asked once per
	// domain, with the configuration group added to whatever the domain decides.
	for _, domain := range settings.domainChecks() {
		if err := domain.check(); err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", strings.Join(domain.keys, ", "), err))
		}
	}
	if len(problems) > 0 {
		return AuthSettings{}, problems
	}
	return settings, nil
}
