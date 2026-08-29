package migration

import (
	"context"
	"testing"
	"time"
)

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
