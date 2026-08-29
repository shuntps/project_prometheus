package postgres

import (
	"crypto/tls"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence"
)

// The list may not widen past the keys the adapter writes. It bounds the rebuilt
// string only; a caller's own string is refused earlier for carrying any key.
func TestTheAllowListIsExactlyWhatTheAdapterWrites(t *testing.T) {
	written := map[string]struct{}{"host": {}, "port": {}, "user": {}, "password": {}, "database": {}}
	for key := range parsedQuery(t, connString(probeTarget(), probeSettings(persistence.TLSVerifyFull, WriteTestCA(t)))) {
		written[key] = struct{}{}
	}
	for key := range written {
		if !slices.Contains(allowedConnStringKeys, key) {
			t.Errorf("the adapter writes %q but the allow-list refuses it", key)
		}
	}
	for _, key := range allowedConnStringKeys {
		if _, ok := written[key]; !ok {
			t.Errorf("%q is allowed but the adapter never writes it", key)
		}
	}
	// service is what makes the driver read a service file; nothing writes it.
	for _, key := range []string{"service", "sslpassword", "options", "target_session_attrs"} {
		if slices.Contains(allowedConnStringKeys, key) {
			t.Errorf("%q is allowed in the connection string", key)
		}
	}
}

// TestTheDriverEnforcesTheAllowListBeforeReadingAnything exercises the driver's
// own guard, so the adapter does not merely assume the option is honoured.
func TestTheDriverEnforcesTheAllowListBeforeReadingAnything(t *testing.T) {
	options := pgx.ParseConfigOptions{
		ParseConfigOptions: pgconn.ParseConfigOptions{ConnStringAllowedKeys: allowedConnStringKeys},
	}
	base := "postgres://svc:pw@db.example:6432/store"

	if _, err := pgx.ParseConfigWithOptions(base+"?sslmode=verify-full", options); err != nil {
		t.Fatalf("an allowed key was rejected: %v", err)
	}
	for _, key := range []string{"service", "sslpassword", "options", "target_session_attrs", "connect_timeout"} {
		if _, err := pgx.ParseConfigWithOptions(base+"?"+key+"=probe", options); err == nil {
			t.Errorf("%q was accepted in the connection string", key)
		}
	}
}

// TestTheRebuiltStringNeutralisesEveryHomeDirectoryDefault pins the four keys the
// driver would otherwise resolve from the account's home directory.
func TestTheRebuiltStringNeutralisesEveryHomeDirectoryDefault(t *testing.T) {
	root := WriteTestCA(t)
	query := parsedQuery(t, connString(probeTarget(), probeSettings(persistence.TLSVerifyFull, root)))

	for _, key := range []string{"sslcert", "sslkey", "passfile", "servicefile"} {
		value, present := query[key]
		if !present || len(value) != 1 || value[0] != "" {
			t.Errorf("%q is %v, want it written empty so the home default cannot apply", key, value)
		}
	}
	if got := query.Get("sslmode"); got != "verify-full" {
		t.Errorf("sslmode is %q", got)
	}
	if got := query.Get("sslrootcert"); got != root {
		t.Errorf("sslrootcert is %q, want the configured trust source", got)
	}

	disabled := parsedQuery(t, connString(probeTarget(), probeSettings(persistence.TLSDisable, "")))
	if got := disabled.Get("sslrootcert"); got != "" {
		t.Errorf("sslrootcert is %q where the posture is disable", got)
	}
}

func TestTheResolvedConfigurationIsVerifiedAgainstTheConfiguredDestination(t *testing.T) {
	want := probeTarget()
	root := WriteTestCA(t)
	sound := func() *pgx.ConnConfig {
		cfg, err := pgx.ParseConfig(connString(want, probeSettings(persistence.TLSVerifyFull, root)))
		if err != nil {
			t.Fatalf("building a sound configuration failed: %v", err)
		}
		return cfg
	}

	if err := verifyResolved(sound(), want, probeSettings(persistence.TLSVerifyFull, root)); err != nil {
		t.Fatalf("a sound configuration was rejected: %v", err)
	}

	cases := map[string]func(*pgx.ConnConfig){
		"host moved":       func(c *pgx.ConnConfig) { c.Host = "elsewhere.example" },
		"port moved":       func(c *pgx.ConnConfig) { c.Port = 15432 },
		"user replaced":    func(c *pgx.ConnConfig) { c.User = "someone_else" },
		"database swapped": func(c *pgx.ConnConfig) { c.Database = "other_store" },
		"fallback present": func(c *pgx.ConnConfig) {
			c.Fallbacks = []*pgconn.FallbackConfig{{Host: want.Host.Reveal(), Port: want.Port}}
		},
		"encryption gone": func(c *pgx.ConnConfig) { c.TLSConfig = nil },
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := sound()
			tamper(cfg)
			if err := verifyResolved(cfg, want, probeSettings(persistence.TLSVerifyFull, root)); err == nil {
				t.Fatal("the tampered configuration was accepted")
			}
		})
	}

	plaintext := sound()
	plaintext.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if err := verifyResolved(plaintext, want, probeSettings(persistence.TLSDisable, "")); err == nil {
		t.Error("encryption was accepted where the posture is disable")
	}
}

// TestTheDestinationSurvivesRebuildingForEveryHostForm covers the three address
// forms. A bracketed IPv6 literal is the one concatenation gets wrong.
func TestTheDestinationSurvivesRebuildingForEveryHostForm(t *testing.T) {
	cases := map[string]struct {
		dsn  string
		host string
		port uint16
	}{
		"IPv4 with a port":      {"postgres://svc:pw@192.0.2.10:6432/store", "192.0.2.10", 6432},
		"IPv4 default port":     {"postgres://svc:pw@192.0.2.10/store", "192.0.2.10", persistence.DefaultPort},
		"DNS name with a port":  {"postgres://svc:pw@db.example:6432/store", "db.example", 6432},
		"DNS name default port": {"postgres://svc:pw@db.example/store", "db.example", persistence.DefaultPort},
		"IPv6 with a port":      {"postgres://svc:pw@[2001:db8::1]:6432/store", "2001:db8::1", 6432},
		"IPv6 default port":     {"postgres://svc:pw@[2001:db8::1]/store", "2001:db8::1", persistence.DefaultPort},
		"IPv6 loopback":         {"postgres://svc:pw@[::1]:6432/store", "::1", 6432},
		"IPv6 mapped IPv4":      {"postgres://svc:pw@[::ffff:192.0.2.10]:6432/store", "::ffff:192.0.2.10", 6432},
	}
	settings := probeSettings(persistence.TLSDisable, "")

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			target, err := persistence.ParseTarget(persistence.NewDSN(want.dsn))
			if err != nil {
				t.Fatalf("the connection string was refused: %v", err)
			}
			if target.Host.Reveal() != want.host || target.Port != want.port {
				t.Fatalf("validation resolved port %d, want %s:%d", target.Port, want.host, want.port)
			}

			resolved, err := pgx.ParseConfig(connString(target, settings))
			if err != nil {
				t.Fatalf("the rebuilt string was refused: %v", err)
			}
			if resolved.Host != want.host || resolved.Port != want.port {
				t.Errorf("the driver resolved %s:%d, want the validated %s:%d", resolved.Host, resolved.Port, want.host, want.port)
			}
			if err := verifyResolved(resolved, target, settings); err != nil {
				t.Errorf("the rebuilt destination failed verification: %v", err)
			}
		})
	}
}
