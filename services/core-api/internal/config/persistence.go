package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence"
)

// Development values suit a store on loopback. They are not a deployment posture:
// the TLS default below is refused in staging and production.
const (
	devDatabaseTLSMode     = persistence.TLSDisable
	devDatabaseMaxConns    = int32(8)
	devDatabaseMinConns    = int32(0)
	devDatabaseLifetime    = time.Hour
	devDatabaseIdleTime    = 30 * time.Minute
	devDatabaseConnect     = 5 * time.Second
	devDatabaseHealthCheck = 2 * time.Second
)

// loadPersistence returns settings only when they are semantically valid; the
// domain package is the single authority on what that means.
func loadPersistence(lookup Lookup, env Environment) (persistence.DSN, persistence.Settings, []string) {
	var problems []string
	remote := env == EnvStaging || env == EnvProduction

	dsn := persistence.NewDSN(stringValue(lookup, "DATABASE_URL", ""))
	problems = append(problems, validateDatabaseURL(dsn)...)

	settings := persistence.Settings{}

	rawMode, hasMode := trimmed(lookup, "DATABASE_TLS_MODE")
	switch {
	case hasMode:
		mode, ok := persistence.ParseTLSMode(rawMode)
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf("DATABASE_TLS_MODE %q is not one of %s", rawMode, joinTLSModes()))
		case remote && !mode.AuthenticatesServer():
			// The rule keys on the declared environment, not on where the host
			// actually is: no topology is detected here.
			problems = append(problems, fmt.Sprintf("DATABASE_TLS_MODE %q does not authenticate the server and is refused in staging and production; use verify-ca or verify-full", rawMode))
		default:
			settings.TLSMode = mode
		}
	case remote:
		problems = append(problems, "DATABASE_TLS_MODE is required in staging and production, and must be verify-ca or verify-full")
	default:
		settings.TLSMode = devDatabaseTLSMode
	}

	rawRoot, hasRoot := trimmed(lookup, "DATABASE_TLS_ROOT_CERT")
	switch {
	case hasRoot:
		root, ok := persistence.ParseTLSRoot(rawRoot)
		if !ok {
			problems = append(problems, fmt.Sprintf("DATABASE_TLS_ROOT_CERT %q is not %q and is not an absolute path", rawRoot, persistence.TLSRootSystem))
		} else {
			settings.TLSRoot = root
		}
	case settings.TLSMode.AuthenticatesServer():
		// There is no implicit source: the driver would otherwise take one from
		// the account's home directory without reporting it.
		problems = append(problems, fmt.Sprintf("DATABASE_TLS_ROOT_CERT is required when DATABASE_TLS_MODE is %s; use %q or an absolute path", settings.TLSMode, persistence.TLSRootSystem))
	}

	counts := []struct {
		key    string
		target *int32
		def    int32
	}{
		{"DATABASE_MAX_CONNS", &settings.MaxConns, devDatabaseMaxConns},
		{"DATABASE_MIN_CONNS", &settings.MinConns, devDatabaseMinConns},
	}
	for _, c := range counts {
		value, err := int32Value(lookup, c.key, c.def)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		*c.target = value
	}

	durations := []struct {
		key    string
		target *time.Duration
		def    time.Duration
	}{
		{"DATABASE_MAX_CONN_LIFETIME", &settings.MaxConnLifetime, devDatabaseLifetime},
		{"DATABASE_MAX_CONN_IDLE_TIME", &settings.MaxConnIdleTime, devDatabaseIdleTime},
		{"DATABASE_CONNECT_TIMEOUT", &settings.ConnectTimeout, devDatabaseConnect},
		{"DATABASE_HEALTH_CHECK_TIMEOUT", &settings.CheckTimeout, devDatabaseHealthCheck},
	}
	for _, d := range durations {
		value, err := durationValue(lookup, d.key, d.def)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		*d.target = value
	}

	if len(problems) > 0 {
		return persistence.DSN{}, persistence.Settings{}, problems
	}
	if err := settings.Validate(); err != nil {
		return persistence.DSN{}, persistence.Settings{}, []string{err.Error()}
	}
	return dsn, settings, nil
}

// validateDatabaseURL delegates to the domain so the loader and the adapter
// cannot drift. The value is a secret, so no problem may reproduce any part.
func validateDatabaseURL(dsn persistence.DSN) []string {
	if _, err := persistence.ParseTarget(dsn); err != nil {
		return []string{"DATABASE_URL is unusable: " + strings.TrimPrefix(err.Error(), persistence.ErrConfiguration.Error()+": ")}
	}
	return nil
}

func int32Value(lookup Lookup, key string, fallback int32) (int32, error) {
	raw, ok := trimmed(lookup, key)
	if !ok {
		return fallback, nil
	}
	var value int32
	if _, err := fmt.Sscanf(raw, "%d", &value); err != nil || raw != fmt.Sprintf("%d", value) {
		return 0, fmt.Errorf("%s %q is not an integer", key, raw)
	}
	return value, nil
}

func joinTLSModes() string {
	names := make([]string, 0, len(persistence.SupportedTLSModes))
	for _, mode := range persistence.SupportedTLSModes {
		names = append(names, string(mode))
	}
	return strings.Join(names, ", ")
}
