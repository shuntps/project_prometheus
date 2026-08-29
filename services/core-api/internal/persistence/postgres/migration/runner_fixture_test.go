package migration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

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

func startPostgres() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	instance, err := postgresfixture.Start(ctx, "sslmode=disable")
	storeStop = instance.Terminate
	if err != nil {
		storeErr = err
		return
	}
	storeDSN = instance.DSN()
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
