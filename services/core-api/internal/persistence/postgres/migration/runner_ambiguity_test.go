package migration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

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
