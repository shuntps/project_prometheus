package postgres_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres"
)

// The driver's own messages carry the host, the user and the database name, so
// none of them may reach the caller.
func TestNoFailureReproducesTheConnectionString(t *testing.T) {
	const probePassword = "s3cr3t-adapter-probe"
	const probeHost = "db.internal.adapter.example"

	cases := map[string]persistence.DSN{
		"unresolvable host": persistence.NewDSN("postgres://svc_probe:" + probePassword + "@" + probeHost + ":6432/probe_database"),
		"unparsable":        persistence.NewDSN("postgres://svc probe:" + probePassword + "@ho st:99/probe_database"),
		"refused port":      persistence.NewDSN("postgres://svc_probe:" + probePassword + "@" + closedAddress(t) + "/probe_database"),
	}
	settings := localSettings()
	settings.ConnectTimeout = time.Second

	for name, dsn := range cases {
		t.Run(name, func(t *testing.T) {
			pool, err := postgres.Open(context.Background(), dsn, settings)
			if err == nil {
				pool.Close()
				t.Fatal("expected a refusal")
			}
			for label, secret := range map[string]string{
				"password": probePassword,
				"host":     probeHost,
				"user":     "svc_probe",
				"database": "probe_database",
			} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("the error exposed the %s: %v", label, err)
				}
			}
		})
	}
}

// The boundary closes independently of the loader: the driver treats an empty
// string as an instruction to build the connection from PG* variables.
func TestAnEmptyConnectionStringIsRefusedWhileTheEnvironmentCouldCompleteIt(t *testing.T) {
	t.Setenv("PGHOST", "elsewhere.example")
	t.Setenv("PGPORT", "6543")
	t.Setenv("PGUSER", "someone_else")
	t.Setenv("PGDATABASE", "other_store")

	// What the guard prevents: the driver resolves the environment's destination.
	resolved, err := pgconn.ParseConfig("")
	if err != nil {
		t.Fatalf("the driver refused an empty string: %v", err)
	}
	if resolved.Host != "elsewhere.example" || resolved.Database != "other_store" {
		t.Fatalf("the driver resolved %s/%s; this test no longer demonstrates the hazard", resolved.Host, resolved.Database)
	}

	pool, err := postgres.Open(context.Background(), persistence.NewDSN(""), localSettings())
	if err == nil {
		pool.Close()
		t.Fatal("an empty connection string opened a store")
	}
	if !errors.Is(err, persistence.ErrConfiguration) {
		t.Errorf("error is %v, want it to wrap ErrConfiguration", err)
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("the refusal does not name the cause: %v", err)
	}
}

func TestAConnectionStringTheCallerDidNotFullyDetermineIsRefused(t *testing.T) {
	cases := map[string]string{
		"blank":                  "   ",
		"no user":                "postgres://db.example:6432/store",
		"no password":            "postgres://svc@db.example:6432/store",
		"empty password":         "postgres://svc:@db.example:6432/store",
		"no host":                "postgres:///store",
		"no database":            "postgres://svc:pw@db.example:6432/",
		"wrong scheme":           "mysql://svc:pw@db.example:3306/store",
		"port out of range":      "postgres://svc:pw@db.example:0/store",
		"carries sslmode":        "postgres://svc:pw@db.example:6432/store?sslmode=disable",
		"carries a service":      "postgres://svc:pw@db.example:6432/store?service=elsewhere",
		"carries a service file": "postgres://svc:pw@db.example:6432/store?servicefile=/nonexistent/probe.conf",
		"carries a pass file":    "postgres://svc:pw@db.example:6432/store?passfile=/nonexistent/probe.pgpass",
		"carries a root cert":    "postgres://svc:pw@db.example:6432/store?sslrootcert=/nonexistent/probe.crt",
		"carries a client key":   "postgres://svc:pw@db.example:6432/store?sslkey=/nonexistent/probe.key",
		"carries a pool bound":   "postgres://svc:pw@db.example:6432/store?pool_max_conns=99",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			pool, err := postgres.Open(context.Background(), persistence.NewDSN(raw), localSettings())
			if err == nil {
				pool.Close()
				t.Fatal("the connection string was accepted")
			}
			if !errors.Is(err, persistence.ErrConfiguration) {
				t.Errorf("error is %v, want it to wrap ErrConfiguration", err)
			}
		})
	}
}

// TestAServiceFileCannotReplaceTheTransportOrTheDestination demonstrates the
// hazard against the driver, then shows the adapter refuses before any read.
func TestAServiceFileCannotReplaceTheTransportOrTheDestination(t *testing.T) {
	path := filepath.Join(t.TempDir(), "probe.conf")
	body := "[probe]\nhost=elsewhere.example\nport=6543\nsslmode=disable\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing the service file failed: %v", err)
	}
	t.Setenv("PGSERVICEFILE", path)
	t.Setenv("PGSERVICE", "probe")

	// What the guard prevents: a key absent from the connection string is taken
	// from the service file, which replaces the posture and the destination.
	resolved, err := pgconn.ParseConfig("postgres://svc:pw@db.example:6432/store")
	if err != nil {
		t.Fatalf("the driver refused the string: %v", err)
	}
	if resolved.TLSConfig != nil {
		t.Fatal("the service file did not replace the posture; this test no longer demonstrates the hazard")
	}
	redirected, err := pgconn.ParseConfig("user=svc password=pw dbname=store")
	if err != nil {
		t.Fatalf("the driver refused the keyword form: %v", err)
	}
	if redirected.Host != "elsewhere.example" || redirected.Port != 6543 {
		t.Fatalf("the service file did not redirect; this test no longer demonstrates the hazard")
	}

	pool, err := postgres.Open(context.Background(), persistence.NewDSN("postgres://svc:pw@db.example:6432/store"), localSettings())
	if err == nil {
		pool.Close()
		t.Fatal("the adapter connected while a service file was in force")
	}
	if !errors.Is(err, persistence.ErrConfiguration) {
		t.Errorf("error is %v, want it to wrap ErrConfiguration", err)
	}
	for _, name := range []string{"PGSERVICE", "PGSERVICEFILE"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("the refusal does not name %s: %v", name, err)
		}
	}
}

// TestAmbientVariablesCannotReplaceTheConfiguredPosture covers the transport
// channel specifically: the typed setting must not be overridable from outside.
func TestAmbientVariablesCannotReplaceTheConfiguredPosture(t *testing.T) {
	settings := localSettings()
	settings.TLSMode = persistence.TLSVerifyFull
	settings.TLSRoot = persistence.TLSRoot(postgres.WriteTestCA(t))

	for _, name := range []string{"PGSSLMODE", "PGSSLROOTCERT", "PGSSLCERT", "PGSSLKEY", "PGPASSFILE", "PGPASSWORD"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "disable")
			pool, err := postgres.Open(context.Background(), realDSN(t), settings)
			if err == nil {
				pool.Close()
				t.Fatal("the adapter connected while an ambient variable was set")
			}
			if !strings.Contains(err.Error(), name) {
				t.Errorf("the refusal does not name %s: %v", name, err)
			}
		})
	}
}
