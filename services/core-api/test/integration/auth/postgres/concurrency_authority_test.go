package integration_test

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/authstore"
)

// TestConcurrentSessionWorkStaysConsistent exercises the store the way traffic
// would: many goroutines creating and resolving at once.
func TestConcurrentSessionWorkStaysConsistent(t *testing.T) {
	store, _ := freshStore(t)
	now := time.Now().UTC()
	account := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)

	const workers = 16
	errs := make(chan error, workers*2)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sess, token, err := session.Issue(account.ID, iam.KindViewer, iam.SurfacePublic, lifetimes(), now, rand.Reader)
			if err != nil {
				errs <- err
				return
			}
			if _, err := store.ReplaceSession(context.Background(), nil, sess, sess.CreatedAt); err != nil {
				errs <- err
				return
			}
			if _, err := store.Resolve(context.Background(), token, now); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent session work failed: %v", err)
	}

	revoked, err := store.RevokeAccountSessions(context.Background(), account.ID, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("revoking failed: %v", err)
	}
	if revoked != workers {
		t.Fatalf("%d sessions were revoked, want %d", revoked, workers)
	}
}

// TestConcurrentActivityAndRevocationCannotLeaveASessionUsable judges every result:
// a discarded one is how the cycle between these two operations stayed invisible.
func TestConcurrentActivityAndRevocationCannotLeaveASessionUsable(t *testing.T) {
	for attempt := 0; attempt < 10; attempt++ {
		store, pool := freshStore(t)
		now := time.Now().UTC().Truncate(time.Second)
		account := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
		sess, token := openSession(t, store, account.ID, iam.SurfacePublic, now)
		at := now.Add(10 * time.Minute)
		ctx := context.Background()

		renewals := make(chan error, 2)
		revocation := make(chan error, 1)
		start := make(chan struct{})
		for range 2 {
			go func() {
				<-start
				_, err := store.RecordActivity(ctx, sess.ID, at, lifetimes())
				renewals <- err
			}()
		}
		go func() { <-start; revocation <- store.RevokeSession(ctx, sess.ID, at) }()
		close(start)

		// Whichever way the three linearise, a renewal either wrote or found the
		// record unusable. A storage failure is neither and is never permitted.
		for range 2 {
			switch err := receive(t, renewals, "renewal"); {
			case err == nil, errors.Is(err, authstore.ErrNotFound):
			default:
				t.Fatalf("attempt %d: a renewal returned %v, want success or the unusable-record answer", attempt, err)
			}
		}
		if err := receive(t, revocation, "revocation"); err != nil {
			t.Fatalf("attempt %d: the revocation returned %v, want success", attempt, err)
		}

		if _, err := store.Resolve(ctx, token, at); !errors.Is(err, authstore.ErrNotFound) {
			t.Fatalf("attempt %d: a revoked session stayed usable: %v", attempt, err)
		}
		_, idle, absolute := deadlines(t, pool, sess.ID)
		if idle.After(absolute) {
			t.Fatalf("attempt %d: the inactivity deadline %s passed the absolute one %s", attempt, idle, absolute)
		}
	}
}

// TestActivityWaitsForAnUncommittedSuspension: the account status is not part of
// the update's own conditions, so only the lock serialises against a suspension.
func TestActivityWaitsForAnUncommittedSuspension(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	account := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
	sess, _ := openSession(t, store, account.ID, iam.SurfacePublic, now)
	activeBefore, idleBefore, _ := deadlines(t, pool, sess.ID)

	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("beginning the suspension failed: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `UPDATE accounts SET status = 'suspended', updated_at = $2 WHERE id = $1`,
		account.ID.String(), now); err != nil {
		t.Fatalf("suspending failed: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := store.RecordActivity(ctx, sess.ID, now.Add(10*time.Minute), lifetimes())
		done <- err
	}()

	// The server itself reports the renewal blocked on the lock.
	if pid := waitForLockWait(t, pool, "kind, status FROM accounts"); pid == 0 {
		t.Fatal("no waiting backend was identified")
	}
	select {
	case err := <-done:
		t.Fatalf("the renewal completed while it was reported waiting: %v", err)
	default:
	}
	if active, idle, _ := deadlines(t, pool, sess.ID); !active.Equal(activeBefore) || !idle.Equal(idleBefore) {
		t.Fatalf("the renewal wrote while waiting: %s / %s", active, idle)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("committing the suspension failed: %v", err)
	}
	if err := <-done; !errors.Is(err, authstore.ErrNotFound) {
		t.Fatalf("the renewal returned %v after the suspension committed, want the unusable-record answer", err)
	}
	active, idle, _ := deadlines(t, pool, sess.ID)
	if !active.Equal(activeBefore) || !idle.Equal(idleBefore) {
		t.Errorf("the suspension won but the renewal still wrote: %s / %s", active, idle)
	}
}

// TestActivityRefusesAPrincipalWithoutItsOwnPermission fixes the permission at the
// operation, so no caller can pick a more convenient rule.
func TestActivityRefusesAPrincipalWithoutItsOwnPermission(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	// An account holding no role at all is granted nothing by the domain matrix.
	account := newAccount(t, store, iam.KindViewer, iam.StatusActive)
	sess, _ := openSession(t, store, account.ID, iam.SurfacePublic, now)
	activeBefore, idleBefore, _ := deadlines(t, pool, sess.ID)

	_, err := store.RecordActivity(context.Background(), sess.ID, now.Add(10*time.Minute), lifetimes())
	if !errors.Is(err, iam.ErrDenied) {
		t.Fatalf("recording activity returned %v, want the denial answer", err)
	}
	if errors.Is(err, authstore.ErrNotFound) || errors.Is(err, authstore.ErrStore) {
		t.Error("the denial is not distinct from an absence or a storage failure")
	}
	if active, idle, _ := deadlines(t, pool, sess.ID); !active.Equal(activeBefore) || !idle.Equal(idleBefore) {
		t.Errorf("a denied renewal changed the stamps to %s / %s", active, idle)
	}

	// Granting the role that carries the permission makes the same call succeed.
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO account_role_grants (account_id, role, granted_at) VALUES ($1, $2, now())`,
		account.ID.String(), string(iam.RoleViewer)); err != nil {
		t.Fatalf("granting failed: %v", err)
	}
	if _, err := store.RecordActivity(context.Background(), sess.ID, now.Add(10*time.Minute), lifetimes()); err != nil {
		t.Fatalf("recording activity failed after the grant: %v", err)
	}
}

// TestActivityRefusesASessionReassignedUnderTheLock covers the window between the
// unlocked discovery of the owning account and the session lock itself.
func TestActivityRefusesASessionReassignedUnderTheLock(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	accountA := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
	accountB := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
	sess, _ := openSession(t, store, accountA.ID, iam.SurfacePublic, now)
	activeBefore, idleBefore, _ := deadlines(t, pool, sess.ID)

	ctx := context.Background()
	// Holding A's row suspends the renewal after its discovery, before its lock.
	holder, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("beginning failed: %v", err)
	}
	defer func() { _ = holder.Rollback(ctx) }()
	if _, err := holder.Exec(ctx, `SELECT id FROM accounts WHERE id = $1 FOR UPDATE`, accountA.ID.String()); err != nil {
		t.Fatalf("locking account A failed: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := store.RecordActivity(ctx, sess.ID, now.Add(10*time.Minute), lifetimes())
		done <- err
	}()
	if pid := waitForLockWait(t, pool, "kind, status FROM accounts"); pid == 0 {
		t.Fatal("the renewal never waited on account A")
	}

	// While it waits, the session is reassigned to another account and committed.
	if _, err := pool.Exec(ctx, `UPDATE account_sessions SET account_id = $2 WHERE id = $1`,
		sess.ID.String(), accountB.ID.String()); err != nil {
		t.Fatalf("reassigning the session failed: %v", err)
	}
	if err := holder.Commit(ctx); err != nil {
		t.Fatalf("releasing account A failed: %v", err)
	}

	if err := <-done; !errors.Is(err, authstore.ErrNotFound) {
		t.Fatalf("the renewal returned %v, want the unusable-record answer", err)
	}
	if active, idle, _ := deadlines(t, pool, sess.ID); !active.Equal(activeBefore) || !idle.Equal(idleBefore) {
		t.Errorf("a session decided with another account's authority was renewed: %s / %s", active, idle)
	}
}

// TestActivityWaitsForAnUncommittedRoleWithdrawal locks the grants, so a withdrawal
// cannot slip between the decision and the write it authorises.
func TestActivityWaitsForAnUncommittedRoleWithdrawal(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	account := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
	sess, _ := openSession(t, store, account.ID, iam.SurfacePublic, now)
	activeBefore, idleBefore, _ := deadlines(t, pool, sess.ID)

	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("beginning failed: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `DELETE FROM account_role_grants WHERE account_id = $1`, account.ID.String()); err != nil {
		t.Fatalf("withdrawing the role failed: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := store.RecordActivity(ctx, sess.ID, now.Add(10*time.Minute), lifetimes())
		done <- err
	}()
	if pid := waitForLockWait(t, pool, "account_role_grants"); pid == 0 {
		t.Fatal("the renewal never waited on the grant rows")
	}
	select {
	case err := <-done:
		t.Fatalf("the renewal completed while it was reported waiting: %v", err)
	default:
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("committing the withdrawal failed: %v", err)
	}
	if err := <-done; !errors.Is(err, iam.ErrDenied) {
		t.Fatalf("the renewal returned %v after the withdrawal committed, want the denial", err)
	}
	if active, idle, _ := deadlines(t, pool, sess.ID); !active.Equal(activeBefore) || !idle.Equal(idleBefore) {
		t.Errorf("a renewal on a withdrawn permission wrote: %s / %s", active, idle)
	}
}

// TestARoleWithdrawalWaitsForAnActivityInFlight is the opposite order: the
// renewal linearises first, and the withdrawal takes effect for what follows.
func TestARoleWithdrawalWaitsForAnActivityInFlight(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	account := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
	sess, _ := openSession(t, store, account.ID, iam.SurfacePublic, now)

	ctx := context.Background()
	// A transaction that holds the session row makes the renewal stop after it has
	// taken the account and the grants, so the withdrawal below must queue behind it.
	blocker, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("beginning failed: %v", err)
	}
	// Without this the row stays locked past a failed assertion and the operations
	// waiting on it hang the binary, hiding the real verdict behind a timeout.
	defer func() { _ = blocker.Rollback(ctx) }()
	if _, err := blocker.Exec(ctx, `SELECT id FROM account_sessions WHERE id = $1 FOR UPDATE`, sess.ID.String()); err != nil {
		t.Fatalf("locking the session failed: %v", err)
	}

	renewal := make(chan error, 1)
	go func() {
		_, err := store.RecordActivity(ctx, sess.ID, now.Add(10*time.Minute), lifetimes())
		renewal <- err
	}()
	if pid := waitForLockWait(t, pool, "account_sessions"); pid == 0 {
		t.Fatal("the renewal never reached the session lock")
	}

	withdrawal := make(chan error, 1)
	go func() {
		_, err := pool.Exec(ctx, `DELETE FROM account_role_grants WHERE account_id = $1`, account.ID.String())
		withdrawal <- err
	}()
	if pid := waitForLockWait(t, pool, "account_role_grants"); pid == 0 {
		t.Fatal("the withdrawal never waited on the grants the renewal holds")
	}

	if err := blocker.Commit(ctx); err != nil {
		t.Fatalf("releasing the session failed: %v", err)
	}
	if err := <-renewal; err != nil {
		t.Fatalf("the renewal that linearised first failed: %v", err)
	}
	if err := <-withdrawal; err != nil {
		t.Fatalf("the withdrawal failed: %v", err)
	}
	// It renewed, and the withdrawal governs every later attempt.
	if _, idle, _ := deadlines(t, pool, sess.ID); !idle.After(now.Add(lifetimes().Idle)) {
		t.Error("the renewal that won did not extend the deadline")
	}
	if _, err := store.RecordActivity(ctx, sess.ID, now.Add(20*time.Minute), lifetimes()); !errors.Is(err, iam.ErrDenied) {
		t.Fatalf("a later renewal returned %v, want the denial", err)
	}
}
