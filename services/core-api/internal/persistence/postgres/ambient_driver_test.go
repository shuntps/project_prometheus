package postgres

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence"
)

func TestEveryDriverEnvironmentVariableCarryingAValueIsRefused(t *testing.T) {
	if err := refuseAmbientSettings(func(string) (string, bool) { return "", false }); err != nil {
		t.Fatalf("a clean environment was refused: %v", err)
	}
	for _, name := range libpqEnvironment {
		err := refuseAmbientSettings(func(key string) (string, bool) {
			if key == name {
				return "a-value", true
			}
			return "", false
		})
		if err == nil {
			t.Errorf("%s was accepted while carrying a value", name)
			continue
		}
		if !strings.Contains(err.Error(), name) {
			t.Errorf("the refusal for %s does not name it: %v", name, err)
		}
	}
}

// This pins the set for the resolved driver version. The driver's table is
// unexported, so a later addition cannot be discovered: revisit on every upgrade.
func TestTheRefusedVariablesCoverThePinnedDriver(t *testing.T) {
	for _, name := range []string{"PGHOST", "PGPORT", "PGUSER", "PGPASSWORD", "PGDATABASE", "PGSERVICE", "PGSERVICEFILE", "PGPASSFILE", "PGSSLMODE", "PGSSLROOTCERT", "PGSSLCERT", "PGSSLKEY"} {
		if !slices.Contains(libpqEnvironment, name) {
			t.Errorf("%s is resolved by the driver but not refused", name)
		}
	}
	if len(libpqEnvironment) != 24 {
		t.Errorf("the list holds %d variables, want the 24 read by the resolved driver version", len(libpqEnvironment))
	}
}

// Real poisoned files in a directory of their own; the account's home is untouched.
// Defaults merge below the environment, so poisoning it is strictly stronger.
func TestPoisonedAccountDefaultsAreNeitherConsumedNorAbleToChangeTheConnection(t *testing.T) {
	poisoned := t.TempDir()
	passfile := filepath.Join(poisoned, ".pgpass")
	servicefile := filepath.Join(poisoned, ".pg_service.conf")
	if err := os.WriteFile(passfile, []byte("*:*:*:*:password-from-the-passfile\n"), 0o600); err != nil {
		t.Fatalf("writing the passfile failed: %v", err)
	}
	if err := os.WriteFile(servicefile, []byte("[probe]\nhost=elsewhere.example\nport=6543\nsslmode=disable\n"), 0o600); err != nil {
		t.Fatalf("writing the service file failed: %v", err)
	}
	poisonedCA := WriteTestCA(t)
	clientCert, clientKey := writeKeyPair(t, "client")
	trustedCA := WriteTestCA(t)

	poison := func(t *testing.T, named bool) {
		t.Helper()
		t.Setenv("PGPASSFILE", passfile)
		t.Setenv("PGSERVICEFILE", servicefile)
		t.Setenv("PGSSLROOTCERT", poisonedCA)
		t.Setenv("PGSSLCERT", clientCert)
		t.Setenv("PGSSLKEY", clientKey)
		if named {
			t.Setenv("PGSERVICE", "probe")
		}
	}

	t.Run("the driver consumes them when nothing neutralises them", func(t *testing.T) {
		poison(t, false)
		consumed, err := pgx.ParseConfig("postgres://svc@db.example:6432/store?sslmode=verify-full")
		if err != nil {
			t.Fatalf("the driver refused the bare string: %v", err)
		}
		if consumed.Password != "password-from-the-passfile" {
			t.Error("the passfile was not consumed; this test no longer demonstrates the hazard")
		}
		if len(consumed.TLSConfig.Certificates) != 1 {
			t.Error("the client certificate was not consumed; this test no longer demonstrates the hazard")
		}
		if !consumed.TLSConfig.RootCAs.Equal(poolFrom(t, poisonedCA)) {
			t.Error("the poisoned authority was not adopted; this test no longer demonstrates the hazard")
		}
	})

	t.Run("a named service redirects when nothing neutralises it", func(t *testing.T) {
		poison(t, true)
		redirected, err := pgx.ParseConfig("user=svc password=pw dbname=store")
		if err != nil {
			t.Fatalf("the driver refused the keyword form: %v", err)
		}
		if redirected.Host != "elsewhere.example" || redirected.Port != 6543 {
			t.Error("the service file did not redirect; this test no longer demonstrates the hazard")
		}
	})

	t.Run("the rebuilt string consumes none of them", func(t *testing.T) {
		poison(t, false)
		want := probeTarget()
		settings := probeSettings(persistence.TLSVerifyFull, trustedCA)
		resolved, err := pgx.ParseConfig(connString(want, settings))
		if err != nil {
			t.Fatalf("the rebuilt string was refused: %v", err)
		}
		if err := verifyResolved(resolved, want, settings); err != nil {
			t.Fatalf("the rebuilt configuration failed verification: %v", err)
		}
		if resolved.Password != want.Password.Reveal() {
			t.Error("the password came from the passfile")
		}
		if resolved.Host != want.Host.Reveal() || resolved.Port != want.Port {
			t.Errorf("the destination moved to %s:%d", resolved.Host, resolved.Port)
		}
		if len(resolved.TLSConfig.Certificates) != 0 {
			t.Error("a client certificate was attached")
		}
		if !resolved.TLSConfig.RootCAs.Equal(poolFrom(t, trustedCA)) {
			t.Error("the trust roots are not the configured ones")
		}
		if resolved.TLSConfig.RootCAs.Equal(poolFrom(t, poisonedCA)) {
			t.Error("the poisoned authority is trusted")
		}
	})

	// Emptying servicefile turns a named service into a refusal rather than a
	// redirect. The adapter never reaches this: PGSERVICE is refused at startup.
	t.Run("a named service cannot redirect the rebuilt string", func(t *testing.T) {
		poison(t, true)
		if _, err := pgx.ParseConfig(connString(probeTarget(), probeSettings(persistence.TLSVerifyFull, trustedCA))); err == nil {
			t.Fatal("the rebuilt string accepted a service redirect")
		}
	})
}

// TestOnlyANonEmptyDriverVariableIsRefused matches the guard to the driver: it
// takes a variable into account only when its value is not empty.
func TestOnlyANonEmptyDriverVariableIsRefused(t *testing.T) {
	cases := map[string]struct {
		set      bool
		value    string
		accepted bool
	}{
		"absent":         {set: false, accepted: true},
		"exactly empty":  {set: true, value: "", accepted: true},
		"a single space": {set: true, value: " ", accepted: false},
		"several spaces": {set: true, value: "   ", accepted: false},
		"a tab":          {set: true, value: "\t", accepted: false},
		"a newline":      {set: true, value: "\n", accepted: false},
		"a value":        {set: true, value: "elsewhere.example", accepted: false},
	}
	for _, name := range libpqEnvironment {
		for label, c := range cases {
			t.Run(name+" "+label, func(t *testing.T) {
				err := refuseAmbientSettings(func(key string) (string, bool) {
					if key == name && c.set {
						return c.value, true
					}
					return "", false
				})
				if accepted := err == nil; accepted != c.accepted {
					t.Fatalf("accepted=%t, want %t (error %v)", accepted, c.accepted, err)
				}
				if err != nil && !strings.Contains(err.Error(), name) {
					t.Errorf("the refusal does not name %s: %v", name, err)
				}
			})
		}
	}
}

// TestTheRefusalNamesEveryCarryingVariableAndNothingElse keeps a mixed
// environment from reporting variables that carry nothing.
func TestTheRefusalNamesEveryCarryingVariableAndNothingElse(t *testing.T) {
	const secret = "s3cr3t-ambient-probe"
	carrying := map[string]string{
		"PGHOST":     "elsewhere.example",
		"PGPASSWORD": secret,
		"PGSERVICE":  "probe",
	}
	empty := []string{"PGUSER", "PGDATABASE", "PGSSLMODE", "PGPORT"}

	err := refuseAmbientSettings(func(key string) (string, bool) {
		if value, ok := carrying[key]; ok {
			return value, true
		}
		if slices.Contains(empty, key) {
			return "", true
		}
		return "", false
	})
	if err == nil {
		t.Fatal("a mixed environment was accepted")
	}
	for name := range carrying {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("the refusal omits %s, which carries a value: %v", name, err)
		}
	}
	for _, name := range empty {
		if strings.Contains(err.Error(), name) {
			t.Errorf("the refusal names %s, which carries nothing: %v", name, err)
		}
	}
	for _, value := range carrying {
		if strings.Contains(err.Error(), value) {
			t.Errorf("the refusal exposed a value: %v", err)
		}
	}
}

// TestAnEmptyDriverVariableChangesNothingResolved closes the loop: an empty
// variable never reaches the settings the driver resolves.
func TestAnEmptyDriverVariableChangesNothingResolved(t *testing.T) {
	for _, name := range libpqEnvironment {
		t.Setenv(name, "")
	}
	want := probeTarget()
	settings := probeSettings(persistence.TLSVerifyFull, newAuthority(t).path)

	if err := refuseAmbientSettings(os.LookupEnv); err != nil {
		t.Fatalf("an environment of empty variables was refused: %v", err)
	}
	resolved, err := pgx.ParseConfig(connString(want, settings))
	if err != nil {
		t.Fatalf("the rebuilt string was refused: %v", err)
	}
	if err := verifyResolved(resolved, want, settings); err != nil {
		t.Fatalf("empty variables changed the resolved configuration: %v", err)
	}
	if resolved.Host != want.Host.Reveal() || resolved.Port != want.Port {
		t.Errorf("the destination moved to %s:%d", resolved.Host, resolved.Port)
	}
	if resolved.User != want.User.Reveal() || resolved.Database != want.Database.Reveal() {
		t.Error("the identity moved")
	}
	if resolved.Password != want.Password.Reveal() {
		t.Error("the password moved")
	}
}
