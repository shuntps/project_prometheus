package postgres_test

import (
	"context"
	"errors"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres"
	"github.com/shuntps/project_prometheus/services/core-api/internal/testsupport/postgresfixture"
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

	// No argument is passed: this adapter refuses a connection string carrying any
	// parameter, because the typed settings are its single authority.
	instance, err := postgresfixture.Start(ctx)
	storeStop = instance.Terminate
	if err != nil {
		storeErr = err
		return
	}
	storeDSN = instance.DSN()
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
	dsn := persistence.NewDSN("postgres://" + postgresfixture.User + ":" + postgresfixture.Password + "@" + closedAddress(t) + "/" + postgresfixture.Database)

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
