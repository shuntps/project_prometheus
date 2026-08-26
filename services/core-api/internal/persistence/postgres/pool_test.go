package postgres_test

import (
	"context"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres"
)

// The image is pinned by digest so this evidence is reproducible. The credentials
// are fictitious, live only in the throwaway container and are never production.
const (
	postgresImage    = "postgres:18.6-alpine@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2"
	postgresDatabase = "core_api_test"
	postgresUser     = "core_api_test"
	postgresPassword = "test-only-not-a-production-secret"
)

var (
	storeOnce sync.Once
	storeDSN  string
	storeErr  error
	storeStop func()
)

func TestMain(m *testing.M) {
	code := m.Run()
	if storeStop != nil {
		storeStop()
	}
	os.Exit(code)
}

func realDSN(t *testing.T) persistence.DSN {
	t.Helper()
	storeOnce.Do(startPostgres)
	if storeErr != nil {
		t.Fatalf("starting PostgreSQL failed: %v", storeErr)
	}
	return persistence.NewDSN(storeDSN)
}

func startPostgres() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	container, err := tcpostgres.Run(ctx, postgresImage,
		tcpostgres.WithDatabase(postgresDatabase),
		tcpostgres.WithUsername(postgresUser),
		tcpostgres.WithPassword(postgresPassword),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(2*time.Minute),
		),
	)
	if err != nil {
		storeErr = err
		return
	}
	storeStop = func() { _ = testcontainers.TerminateContainer(container) }

	// No extra argument: the connection string must carry no sslmode, because
	// the typed setting is the single authority over the transport posture.
	dsn, err := container.ConnectionString(ctx)
	if err != nil {
		storeErr = err
		return
	}
	storeDSN = dsn
}

func localSettings() persistence.Settings {
	return persistence.Settings{
		TLSMode:         persistence.TLSDisable,
		MaxConns:        4,
		MinConns:        0,
		MaxConnLifetime: time.Hour,
		MaxConnIdleTime: 30 * time.Minute,
		ConnectTimeout:  5 * time.Second,
		CheckTimeout:    2 * time.Second,
	}
}

func closedAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not reserve a port: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("could not release the reserved port: %v", err)
	}
	return address
}

func TestOpenEstablishesTheConnectionAndChecksSucceed(t *testing.T) {
	pool, err := postgres.Open(context.Background(), realDSN(t), localSettings())
	if err != nil {
		t.Fatalf("opening the store failed: %v", err)
	}
	t.Cleanup(pool.Close)

	if err := pool.Check(context.Background()); err != nil {
		t.Fatalf("the check failed against a running server: %v", err)
	}
}

// TestOpenRefusesAnUnreachableServerWithinTheBound proves the constructor does
// not merely build a pool: an unreachable server must fail here, on time.
func TestOpenRefusesAnUnreachableServerWithinTheBound(t *testing.T) {
	settings := localSettings()
	settings.ConnectTimeout = 500 * time.Millisecond
	dsn := persistence.NewDSN("postgres://" + postgresUser + ":" + postgresPassword + "@" + closedAddress(t) + "/" + postgresDatabase)

	started := time.Now()
	pool, err := postgres.Open(context.Background(), dsn, settings)
	elapsed := time.Since(started)

	if err == nil {
		pool.Close()
		t.Fatal("a pool was returned for a server that is not listening")
	}
	if !errors.Is(err, persistence.ErrUnavailable) {
		t.Errorf("error is %v, want it to wrap ErrUnavailable", err)
	}
	if elapsed > 5*time.Second {
		t.Errorf("the attempt took %s, which is not bounded by the configured timeout", elapsed)
	}
}

func TestInvalidSettingsAreRefusedBeforeAnyConnection(t *testing.T) {
	pool, err := postgres.Open(context.Background(), realDSN(t), persistence.Settings{})
	if err == nil {
		pool.Close()
		t.Fatal("empty settings opened a store")
	}
	if !errors.Is(err, persistence.ErrConfiguration) {
		t.Errorf("error is %v, want it to wrap ErrConfiguration", err)
	}
}

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

// More goroutines than the pool holds connections, which is how readiness probes
// and request traffic reach it at the same time.
func TestChecksAreSafeUnderConcurrency(t *testing.T) {
	pool, err := postgres.Open(context.Background(), realDSN(t), localSettings())
	if err != nil {
		t.Fatalf("opening the store failed: %v", err)
	}
	t.Cleanup(pool.Close)

	const workers, rounds = 24, 8
	errs := make(chan error, workers*rounds)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range rounds {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				errs <- pool.Check(ctx)
				cancel()
			}
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("a concurrent check failed: %v", err)
		}
	}
}

func TestCloseReleasesEveryServerSideConnection(t *testing.T) {
	dsn := realDSN(t)
	settings := localSettings()
	settings.MinConns = 2

	pool, err := postgres.Open(context.Background(), dsn, settings)
	if err != nil {
		t.Fatalf("opening the store failed: %v", err)
	}
	for range 4 {
		if err := pool.Check(context.Background()); err != nil {
			t.Fatalf("the check failed: %v", err)
		}
	}
	pool.Close()

	if remaining := backendCount(t, dsn); remaining != 0 {
		t.Errorf("%d server-side connection(s) survived Close", remaining)
	}
}

// backendCount asks the server, not the pool, what the database still holds. The
// observer connects directly: a counting method would be production API for a test.
func backendCount(t *testing.T, dsn persistence.DSN) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	parsed, err := url.Parse(dsn.Reveal())
	if err != nil {
		t.Fatal("the connection string could not be inspected")
	}
	database := strings.TrimPrefix(parsed.Path, "/")
	query := parsed.Query()
	query.Set("sslmode", string(persistence.TLSDisable))
	parsed.RawQuery = query.Encode()

	conn, err := pgx.Connect(ctx, parsed.String())
	if err != nil {
		t.Fatal("the observer could not reach the server")
	}
	defer func() { _ = conn.Close(ctx) }()

	const statement = `SELECT count(*) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`
	deadline := time.Now().Add(10 * time.Second)
	var count int
	for time.Now().Before(deadline) {
		if err := conn.QueryRow(ctx, statement, database).Scan(&count); err != nil {
			t.Fatal("counting backends failed")
		}
		if count == 0 {
			return 0
		}
		time.Sleep(50 * time.Millisecond)
	}
	return count
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
