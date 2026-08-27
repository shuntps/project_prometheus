package migration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
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

func startPostgres() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	container, err := tcpostgres.Run(ctx, postgresImage,
		tcpostgres.WithDatabase(postgresDatabase),
		tcpostgres.WithUsername(postgresUser),
		tcpostgres.WithPassword(postgresPassword),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(2*time.Minute),
		),
	)
	if err != nil {
		storeErr = err
		return
	}
	storeStop = func() { _ = testcontainers.TerminateContainer(container) }
	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		storeErr = err
		return
	}
	storeDSN = dsn
}

// freshPool hands out a pool onto an empty schema, so one test never inherits
// what another applied.
func freshPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	storeOnce.Do(startPostgres)
	if storeErr != nil {
		t.Fatalf("starting PostgreSQL failed: %v", storeErr)
	}

	pool, err := pgxpool.New(context.Background(), storeDSN)
	if err != nil {
		t.Fatalf("opening the pool failed: %v", err)
	}
	t.Cleanup(pool.Close)

	const reset = `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`
	if _, err := pool.Exec(context.Background(), reset); err != nil {
		t.Fatalf("resetting the schema failed: %v", err)
	}
	return pool
}

func fixture(version int64, name, body string) Migration {
	sum := sha256.Sum256([]byte(body))
	return Migration{Version: version, Name: name, SQL: body, Checksum: hex.EncodeToString(sum[:])}
}

func tableExists(t *testing.T, pool *pgxpool.Pool, name string) bool {
	t.Helper()
	const query = `SELECT EXISTS (SELECT 1 FROM information_schema.tables
		WHERE table_schema = 'public' AND table_name = $1)`
	var exists bool
	if err := pool.QueryRow(context.Background(), query, name).Scan(&exists); err != nil {
		t.Fatalf("inspecting the schema failed: %v", err)
	}
	return exists
}

func recorded(t *testing.T, pool *pgxpool.Pool) []int64 {
	t.Helper()
	rows, err := pool.Query(context.Background(), "SELECT version FROM schema_migrations ORDER BY version")
	if err != nil {
		t.Fatalf("reading the ledger failed: %v", err)
	}
	defer rows.Close()

	var versions []int64
	for rows.Next() {
		var version int64
		if err := rows.Scan(&version); err != nil {
			t.Fatalf("reading the ledger failed: %v", err)
		}
		versions = append(versions, version)
	}
	return versions
}

func TestTheEmbeddedSetAppliesAndIsRecorded(t *testing.T) {
	pool := freshPool(t)
	migrations, err := Load()
	if err != nil {
		t.Fatalf("loading the embedded set failed: %v", err)
	}

	result, err := Apply(context.Background(), pool, migrations)
	if err != nil {
		t.Fatalf("applying failed: %v", err)
	}
	if len(result.Applied) != len(migrations) {
		t.Fatalf("%d of %d migrations were applied", len(result.Applied), len(migrations))
	}
	for _, table := range []string{
		"accounts", "account_email_identities", "account_password_credentials",
		"account_role_grants", "account_sessions", "account_security_events",
	} {
		if !tableExists(t, pool, table) {
			t.Errorf("table %q was not created", table)
		}
	}
}

// TestRunningAgainOnACurrentSchemaChangesNothing is what makes the operation safe
// to repeat during a deployment.
func TestRunningAgainOnACurrentSchemaChangesNothing(t *testing.T) {
	pool := freshPool(t)
	migrations, err := Load()
	if err != nil {
		t.Fatalf("loading failed: %v", err)
	}

	if _, err := Apply(context.Background(), pool, migrations); err != nil {
		t.Fatalf("the first run failed: %v", err)
	}
	before := recorded(t, pool)

	second, err := Apply(context.Background(), pool, migrations)
	if err != nil {
		t.Fatalf("the second run failed: %v", err)
	}
	if len(second.Applied) != 0 {
		t.Fatalf("the second run applied %v", second.Applied)
	}
	if got := recorded(t, pool); len(got) != len(before) {
		t.Fatalf("the ledger moved from %v to %v", before, got)
	}
}

// TestConcurrentRunnersApplyEachMigrationOnce exercises the advisory lock against
// a real server: several runners start at once on an empty schema.
func TestConcurrentRunnersApplyEachMigrationOnce(t *testing.T) {
	pool := freshPool(t)
	migrations, err := Load()
	if err != nil {
		t.Fatalf("loading failed: %v", err)
	}

	const runners = 8
	start := make(chan struct{})
	results := make(chan Result, runners)
	failures := make(chan error, runners)

	var wg sync.WaitGroup
	for range runners {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			result, err := Apply(ctx, pool, migrations)
			if err != nil {
				failures <- err
				return
			}
			results <- result
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	close(failures)

	for err := range failures {
		t.Fatalf("a concurrent runner failed: %v", err)
	}
	total := 0
	for result := range results {
		total += len(result.Applied)
	}
	if total != len(migrations) {
		t.Fatalf("%d migrations were applied in total, want exactly %d", total, len(migrations))
	}
	if got := recorded(t, pool); len(got) != len(migrations) {
		t.Fatalf("the ledger holds %v", got)
	}
}

// No partial schema and no ledger row. PostgreSQL already wraps one multi-statement
// Exec implicitly, so the test below is what discriminates the explicit transaction.
func TestAFailingMigrationLeavesNothingBehind(t *testing.T) {
	pool := freshPool(t)
	set := []Migration{
		fixture(1, "first", "CREATE TABLE first_table (id int PRIMARY KEY);"),
		fixture(2, "second", "CREATE TABLE second_table (id int PRIMARY KEY); CREATE TABLE second_table (id int PRIMARY KEY);"),
	}

	if _, err := Apply(context.Background(), pool, set); err == nil {
		t.Fatal("a failing migration was reported as applied")
	}
	if !tableExists(t, pool, "first_table") {
		t.Error("the migration that succeeded was rolled back too")
	}
	if tableExists(t, pool, "second_table") {
		t.Error("the failing migration left a table behind")
	}
	if got := recorded(t, pool); len(got) != 1 || got[0] != 1 {
		t.Fatalf("the ledger holds %v, want only version 1", got)
	}

	// The set can be repaired and applied without any manual cleanup.
	set[1] = fixture(2, "second", "CREATE TABLE second_table (id int PRIMARY KEY);")
	if _, err := Apply(context.Background(), pool, set); err != nil {
		t.Fatalf("the repaired set was refused: %v", err)
	}
	if !tableExists(t, pool, "second_table") {
		t.Error("the repaired migration did not apply")
	}
}

// The statements and their ledger row are two separate commands, so only an
// explicit transaction makes the schema change vanish when the second one fails.
func TestAMigrationAndItsLedgerRowCommitTogether(t *testing.T) {
	pool := freshPool(t)
	set := []Migration{
		fixture(1, "first", "CREATE TABLE first_table (id int PRIMARY KEY);"),
		fixture(2, "second", "CREATE TABLE second_table (id int PRIMARY KEY); DROP TABLE schema_migrations;"),
	}

	if _, err := Apply(context.Background(), pool, set); err == nil {
		t.Fatal("a migration that broke its own ledger reported success")
	}
	if !tableExists(t, pool, "schema_migrations") {
		t.Fatal("the ledger was dropped; the statements were not rolled back with the failed record")
	}
	if tableExists(t, pool, "second_table") {
		t.Fatal("the schema change survived although its ledger row was never written")
	}
	if got := recorded(t, pool); len(got) != 1 || got[0] != 1 {
		t.Fatalf("the ledger holds %v, want only version 1", got)
	}
}

// TestAnAppliedMigrationThatChangedIsRefused keeps history from being rewritten:
// forward-only work adds a compensating migration instead.
func TestAnAppliedMigrationThatChangedIsRefused(t *testing.T) {
	pool := freshPool(t)
	original := []Migration{fixture(1, "first", "CREATE TABLE first_table (id int PRIMARY KEY);")}
	if _, err := Apply(context.Background(), pool, original); err != nil {
		t.Fatalf("the first run failed: %v", err)
	}

	edited := []Migration{fixture(1, "first", "CREATE TABLE first_table (id int PRIMARY KEY, extra text);")}
	_, err := Apply(context.Background(), pool, edited)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("got %v, want a history conflict", err)
	}

	// Nothing was applied, and the original set still runs clean.
	if _, err := Apply(context.Background(), pool, original); err != nil {
		t.Fatalf("the unchanged set was refused after the conflict: %v", err)
	}
}

// TestAHistoryThatCannotBeContinuedIsRefused covers a database that has moved
// beyond, or diverged from, the set being applied.
func TestAHistoryThatCannotBeContinuedIsRefused(t *testing.T) {
	pool := freshPool(t)
	applied := []Migration{
		fixture(1, "first", "CREATE TABLE first_table (id int PRIMARY KEY);"),
		fixture(2, "second", "CREATE TABLE second_table (id int PRIMARY KEY);"),
	}
	if _, err := Apply(context.Background(), pool, applied); err != nil {
		t.Fatalf("the first run failed: %v", err)
	}

	shorter := applied[:1]
	if _, err := Apply(context.Background(), pool, shorter); !errors.Is(err, ErrConflict) {
		t.Fatalf("got %v, want a conflict when the database is ahead of the set", err)
	}

	invalid := []Migration{fixture(2, "second", "SELECT 1;")}
	if _, err := Apply(context.Background(), pool, invalid); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want a refusal for a set that does not start at one", err)
	}
}

// TestAnUnreachableDatabaseFailsClosed keeps a run from reporting success when it
// never reached the server.
func TestAnUnreachableDatabaseFailsClosed(t *testing.T) {
	pool := freshPool(t)
	migrations, err := Load()
	if err != nil {
		t.Fatalf("loading failed: %v", err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Apply(cancelled, pool, migrations); err == nil {
		t.Fatal("a cancelled run reported success")
	}
	if tableExists(t, pool, "accounts") {
		t.Error("a cancelled run applied part of the schema")
	}
	if tableExists(t, pool, "schema_migrations") {
		t.Error("a cancelled run created the ledger")
	}
}

// TestACancelledRunGivesBackTheLockAndTheConnection keeps an interrupted
// operation from leaving the next one waiting forever.
func TestACancelledRunGivesBackTheLockAndTheConnection(t *testing.T) {
	pool := freshPool(t)
	migrations, err := Load()
	if err != nil {
		t.Fatalf("loading failed: %v", err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Apply(cancelled, pool, migrations); err == nil {
		t.Fatal("a cancelled run reported success")
	}

	if held := advisoryLocksHeld(t, pool); held != 0 {
		t.Fatalf("%d advisory lock(s) survived the cancelled run", held)
	}
	if used := pool.Stat().AcquiredConns(); used != 0 {
		t.Fatalf("%d connection(s) were still held after the cancelled run", used)
	}

	// The next run must not wait on anything the cancelled one left behind.
	bounded, stop := context.WithTimeout(context.Background(), 20*time.Second)
	defer stop()
	if _, err := Apply(bounded, pool, migrations); err != nil {
		t.Fatalf("the run after a cancellation was blocked: %v", err)
	}
}

// advisoryLockCount reads the current count once, without waiting.
func advisoryLockCount(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var held int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM pg_locks WHERE locktype = 'advisory'`).Scan(&held); err != nil {
		t.Fatalf("reading the locks failed: %v", err)
	}
	return held
}

// assertConnectionDestroyed proves the connection left the pool for good: its
// server session is gone, and the pool never hands that session back.
func assertConnectionDestroyed(t *testing.T, pool *pgxpool.Pool, pid int) {
	t.Helper()
	if !sessionEnded(t, pool, pid) {
		t.Error("the server session was not ended")
	}
	for range 8 {
		conn, err := pool.Acquire(context.Background())
		if err != nil {
			t.Fatalf("acquiring failed: %v", err)
		}
		reused := backendPID(t, conn)
		conn.Release()
		if reused == pid {
			t.Fatalf("the pool handed back the discarded session %d", pid)
		}
	}
	if used := pool.Stat().AcquiredConns(); used != 0 {
		t.Errorf("%d connection(s) are still checked out", used)
	}
}

func advisoryLocksHeld(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	const query = `SELECT count(*) FROM pg_locks WHERE locktype = 'advisory'`
	var held int
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if err := pool.QueryRow(context.Background(), query).Scan(&held); err != nil {
			t.Fatalf("reading the locks failed: %v", err)
		}
		if held == 0 {
			return 0
		}
		time.Sleep(50 * time.Millisecond)
	}
	return held
}

// TestARenamedMigrationIsRefused keeps the ledger and the set from diverging on
// anything the ledger records.
func TestARenamedMigrationIsRefused(t *testing.T) {
	pool := freshPool(t)
	original := []Migration{fixture(1, "first", "CREATE TABLE first_table (id int PRIMARY KEY);")}
	if _, err := Apply(context.Background(), pool, original); err != nil {
		t.Fatalf("the first run failed: %v", err)
	}

	renamed := []Migration{fixture(1, "renamed", "CREATE TABLE first_table (id int PRIMARY KEY);")}
	if _, err := Apply(context.Background(), pool, renamed); !errors.Is(err, ErrConflict) {
		t.Fatalf("got %v, want a history conflict on the recorded name", err)
	}
	if _, err := Apply(context.Background(), pool, original); err != nil {
		t.Fatalf("the unchanged set was refused after the conflict: %v", err)
	}
}

// TestAConnectionThatMightStillHoldTheLockIsNeverPooled forces the cleanup to fail:
// a session lock outlives the transaction, so an unproven unlock must leave the pool.
func TestAConnectionThatMightStillHoldTheLockIsNeverPooled(t *testing.T) {
	pool := freshPool(t)

	// This connection holds no advisory lock, so pg_advisory_unlock reports
	// false: exactly the outcome that must not lead back to the pool.
	conn, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquiring failed: %v", err)
	}
	pid := backendPID(t, conn)
	var released bool
	if err := conn.QueryRow(context.Background(), "SELECT pg_advisory_unlock($1)", advisoryLockKey).Scan(&released); err != nil {
		t.Fatalf("probing the unlock failed: %v", err)
	}
	if released {
		t.Fatal("the probe held the lock; this test no longer forces a failed cleanup")
	}

	releaseRunner(context.Background(), conn)

	assertConnectionDestroyed(t, pool, pid)

	// The pool remains usable, and hands out a live connection.
	var alive int
	if err := pool.QueryRow(context.Background(), "SELECT 1").Scan(&alive); err != nil {
		t.Fatalf("the pool stopped working after the hijack: %v", err)
	}
}

// TestASuccessfulCleanupReturnsTheConnection is the other half: when the unlock
// is proven, the connection is reused rather than discarded.
func TestASuccessfulCleanupReturnsTheConnection(t *testing.T) {
	pool := freshPool(t)
	conn, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquiring failed: %v", err)
	}
	if _, err := conn.Exec(context.Background(), "SELECT pg_advisory_lock($1)", advisoryLockKey); err != nil {
		t.Fatalf("taking the lock failed: %v", err)
	}
	pid := backendPID(t, conn)

	releaseRunner(context.Background(), conn)

	if !sessionEnded(t, pool, pid) {
		// The session must still be alive: a clean release keeps the connection.
		if held := advisoryLocksHeld(t, pool); held != 0 {
			t.Fatalf("%d advisory lock(s) survived a clean release", held)
		}
		return
	}
	t.Fatal("a clean release destroyed the connection instead of returning it")
}

// backendPID names the server session behind a pooled connection, so a test can
// observe whether that session was really ended.
func backendPID(t *testing.T, conn *pgxpool.Conn) int {
	t.Helper()
	var pid int
	if err := conn.QueryRow(context.Background(), "SELECT pg_backend_pid()").Scan(&pid); err != nil {
		t.Fatalf("reading the backend identifier failed: %v", err)
	}
	return pid
}

func sessionEnded(t *testing.T, pool *pgxpool.Pool, pid int) bool {
	t.Helper()
	const query = `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid = $1)`
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var alive bool
		if err := pool.QueryRow(context.Background(), query, pid).Scan(&alive); err != nil {
			t.Fatalf("reading the server activity failed: %v", err)
		}
		if !alive {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// TestApplyDestroysItsConnectionWhenTheLockCallFails fails the lock on a server
// statement timeout, which leaves the connection healthy enough for Release to reuse.
func TestApplyDestroysItsConnectionWhenTheLockCallFails(t *testing.T) {
	storeOnce.Do(startPostgres)
	if storeErr != nil {
		t.Fatalf("starting PostgreSQL failed: %v", storeErr)
	}

	holderPool := freshPool(t)
	holder, err := holderPool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquiring failed: %v", err)
	}
	defer holder.Release()
	if _, err := holder.Exec(context.Background(), "SELECT pg_advisory_lock($1)", advisoryLockKey); err != nil {
		t.Fatalf("taking the lock failed: %v", err)
	}

	config, err := pgxpool.ParseConfig(storeDSN)
	if err != nil {
		t.Fatalf("parsing the connection string failed: %v", err)
	}
	config.MaxConns = 1
	config.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET statement_timeout = '500ms'")
		return err
	}
	runnerPool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatalf("opening the pool failed: %v", err)
	}
	t.Cleanup(runnerPool.Close)

	warm, err := runnerPool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquiring failed: %v", err)
	}
	victim := backendPID(t, warm)
	warm.Release()

	migrations, err := Load()
	if err != nil {
		t.Fatalf("loading failed: %v", err)
	}
	// The context stays generous: the failure must come from the server, so the
	// connection is left healthy and Release would return it to the pool.
	bounded, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := Apply(bounded, runnerPool, migrations); err == nil {
		t.Fatal("the run reported success while another session held the lock")
	}

	if !sessionEnded(t, holderPool, victim) {
		t.Fatal("the connection whose lock call failed was returned to the pool")
	}
}

// TestAnAmbiguousLockAcquisitionDestroysTheConnection models what the client cannot
// resolve: the server holds the lock, the client learned nothing, so the connection goes.
func TestAnAmbiguousLockAcquisitionDestroysTheConnection(t *testing.T) {
	pool := freshPool(t)
	conn, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquiring failed: %v", err)
	}
	pid := backendPID(t, conn)
	if _, err := conn.Exec(context.Background(), "SELECT pg_advisory_lock($1)", advisoryLockKey); err != nil {
		t.Fatalf("taking the lock failed: %v", err)
	}
	if held := advisoryLockCount(t, pool); held == 0 {
		t.Fatal("the server does not hold the lock; this test no longer models the hazard")
	}

	discardRunner(context.Background(), conn)

	assertConnectionDestroyed(t, pool, pid)
	if held := advisoryLocksHeld(t, pool); held != 0 {
		t.Errorf("%d advisory lock(s) survived", held)
	}

	// A later run must not wait on anything that connection left behind.
	migrations, err := Load()
	if err != nil {
		t.Fatalf("loading failed: %v", err)
	}
	bounded, stop := context.WithTimeout(context.Background(), 20*time.Second)
	defer stop()
	if _, err := Apply(bounded, pool, migrations); err != nil {
		t.Fatalf("the run after an ambiguous acquisition was blocked: %v", err)
	}
}

// TestAQueryErrorDuringTheUnlockDestroysTheConnection covers a real failure of
// the unlock call, which the boolean-false case does not exercise.
func TestAQueryErrorDuringTheUnlockDestroysTheConnection(t *testing.T) {
	pool := freshPool(t)
	conn, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquiring failed: %v", err)
	}
	pid := backendPID(t, conn)
	if _, err := conn.Exec(context.Background(), "SELECT pg_advisory_lock($1)", advisoryLockKey); err != nil {
		t.Fatalf("taking the lock failed: %v", err)
	}

	// The backend is terminated from another connection, so the unlock call fails
	// as a query rather than by returning false.
	var terminated bool
	if err := pool.QueryRow(context.Background(), "SELECT pg_terminate_backend($1)", pid).Scan(&terminated); err != nil {
		t.Fatalf("terminating the backend failed: %v", err)
	}
	if !terminated {
		t.Fatal("the backend was not terminated; this test no longer models the hazard")
	}

	releaseRunner(context.Background(), conn)

	assertConnectionDestroyed(t, pool, pid)
	var alive int
	if err := pool.QueryRow(context.Background(), "SELECT 1").Scan(&alive); err != nil {
		t.Fatalf("the pool stopped working: %v", err)
	}
}

// TestAFailedAcquisitionPreservesItsCauseWithoutRenderingIt drives the real
// acquisition path with a live context, so the failure is never contextual.
func TestAFailedAcquisitionPreservesItsCauseWithoutRenderingIt(t *testing.T) {
	storeOnce.Do(startPostgres)
	if storeErr != nil {
		t.Fatalf("starting PostgreSQL failed: %v", storeErr)
	}
	migrations, err := Load()
	if err != nil {
		t.Fatalf("loading failed: %v", err)
	}

	t.Run("a closed pool keeps its cause recognisable", func(t *testing.T) {
		closed, err := pgxpool.New(context.Background(), storeDSN)
		if err != nil {
			t.Fatalf("opening the pool failed: %v", err)
		}
		closed.Close()

		live := context.Background()
		_, cause := closed.Acquire(live)
		if cause == nil {
			t.Fatal("a closed pool handed out a connection; this case no longer models the hazard")
		}
		if live.Err() != nil {
			t.Fatal("the context is not active; this case no longer models the hazard")
		}

		_, applyErr := Apply(live, closed, migrations)
		if applyErr == nil {
			t.Fatal("the run reported success against a closed pool")
		}
		if !errors.Is(applyErr, cause) {
			t.Fatalf("the acquisition cause was not preserved: %v", applyErr)
		}

		// Nothing was applied: the schema is untouched by the failed run.
		observer := freshPool(t)
		if tableExists(t, observer, "schema_migrations") {
			t.Error("a failed acquisition created the ledger")
		}
		if tableExists(t, observer, "accounts") {
			t.Error("a failed acquisition changed the schema")
		}
	})

	t.Run("a connection failure keeps its detail out of the message", func(t *testing.T) {
		const probeUser, probeDatabase, probeHost = "probe_user", "probe_database", "203.0.113.9"
		unreachable, err := pgxpool.New(context.Background(),
			"postgres://"+probeUser+":pw@"+probeHost+":5432/"+probeDatabase+"?sslmode=disable&connect_timeout=1")
		if err != nil {
			t.Fatalf("opening the pool failed: %v", err)
		}
		t.Cleanup(unreachable.Close)

		bounded, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, applyErr := Apply(bounded, unreachable, migrations)
		if applyErr == nil {
			t.Fatal("the run reported success against an unreachable destination")
		}
		if bounded.Err() != nil {
			t.Fatal("the context expired; this case no longer models a non-contextual failure")
		}
		if errors.Unwrap(applyErr) == nil {
			t.Fatal("the acquisition cause was discarded")
		}
		for label, secret := range map[string]string{
			"user": probeUser, "database": probeDatabase, "host": probeHost,
		} {
			if strings.Contains(applyErr.Error(), secret) {
				t.Errorf("the message exposed the %s", label)
			}
		}
	})
}
