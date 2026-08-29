package authstore_test

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/authstore"
)

// TestConcurrentSessionWorkStaysConsistent exercises the store the way traffic
// would: many goroutines creating and resolving at once.
func TestConcurrentSessionWorkStaysConsistent(t *testing.T) {
	store, _ := freshStore(t)
	now := time.Now().UTC()
	account := newAccount(t, store, auth.KindViewer, auth.StatusActive, auth.RoleViewer)

	const workers = 16
	errs := make(chan error, workers*2)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sess, token, err := session.Issue(account.ID, auth.KindViewer, auth.SurfacePublic, lifetimes(), now, rand.Reader)
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

// receive takes one result, failing rather than blocking, so an operation that
// never returns is reported as itself instead of as the package's timeout.
func receive(t *testing.T, results <-chan error, label string) error {
	t.Helper()
	select {
	case err := <-results:
		return err
	case <-time.After(30 * time.Second):
		t.Fatalf("the %s never returned", label)
		return nil
	}
}

// accountWideOutcome carries what RevokeAccountSessions reports, so the count and
// the error travel together and are judged together.
type accountWideOutcome struct {
	affected int64
	err      error
}

// receiveAccountWide bounds the account-wide result as receive bounds the others, so
// an operation stuck after launch is named instead of hitting the package timeout.
func receiveAccountWide(t *testing.T, results <-chan accountWideOutcome, label string) accountWideOutcome {
	t.Helper()
	select {
	case ended := <-results:
		return ended
	case <-time.After(30 * time.Second):
		t.Fatalf("the %s never returned", label)
		return accountWideOutcome{}
	}
}

// TestConcurrentActivityAndRevocationCannotLeaveASessionUsable judges every result:
// a discarded one is how the cycle between these two operations stayed invisible.
func TestConcurrentActivityAndRevocationCannotLeaveASessionUsable(t *testing.T) {
	for attempt := 0; attempt < 10; attempt++ {
		store, pool := freshStore(t)
		now := time.Now().UTC().Truncate(time.Second)
		account := newAccount(t, store, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
		sess, token := openSession(t, store, account.ID, auth.SurfacePublic, now)
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
	account := newAccount(t, store, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	sess, _ := openSession(t, store, account.ID, auth.SurfacePublic, now)
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
	account := newAccount(t, store, auth.KindViewer, auth.StatusActive)
	sess, _ := openSession(t, store, account.ID, auth.SurfacePublic, now)
	activeBefore, idleBefore, _ := deadlines(t, pool, sess.ID)

	_, err := store.RecordActivity(context.Background(), sess.ID, now.Add(10*time.Minute), lifetimes())
	if !errors.Is(err, auth.ErrDenied) {
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
		account.ID.String(), string(auth.RoleViewer)); err != nil {
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
	accountA := newAccount(t, store, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	accountB := newAccount(t, store, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	sess, _ := openSession(t, store, accountA.ID, auth.SurfacePublic, now)
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
	account := newAccount(t, store, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	sess, _ := openSession(t, store, account.ID, auth.SurfacePublic, now)
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
	if err := <-done; !errors.Is(err, auth.ErrDenied) {
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
	account := newAccount(t, store, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	sess, _ := openSession(t, store, account.ID, auth.SurfacePublic, now)

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
	if _, err := store.RecordActivity(ctx, sess.ID, now.Add(20*time.Minute), lifetimes()); !errors.Is(err, auth.ErrDenied) {
		t.Fatalf("a later renewal returned %v, want the denial", err)
	}
}

// Statement fragments that identify one waiting backend without ambiguity: each
// appears on a single line of exactly one lock statement.
const (
	activityLockFragment = "surface, last_active_at"
	rotationLockFragment = "created_at, revoked_at"
	revocationFragment   = "UPDATE account_sessions SET revoked_at"
	accountWideFragment  = "WHERE account_id = $1 AND revoked_at IS NULL"
	eventInsertFragment  = "INSERT INTO account_security_events"
	authorityFragment    = "kind, status FROM accounts"
)

// deadlocksBroken counts the cycles PostgreSQL resolved by aborting a transaction.
// The store turns SQLSTATE 40P01 into ErrStore, so only this counter can tell them apart.
func deadlocksBroken(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	var count int64
	if err := pool.QueryRow(context.Background(),
		`SELECT deadlocks FROM pg_stat_database WHERE datname = current_database()`).Scan(&count); err != nil {
		t.Fatalf("reading the deadlock counter failed: %v", err)
	}
	return count
}

// lifecycleOf reports the two terminal marks a session row can carry.
func lifecycleOf(t *testing.T, pool *pgxpool.Pool, id auth.SessionID) (revoked, rotated bool) {
	t.Helper()
	if err := pool.QueryRow(context.Background(),
		`SELECT revoked_at IS NOT NULL, rotated_to IS NOT NULL FROM account_sessions WHERE id = $1`,
		id.String()).Scan(&revoked, &rotated); err != nil {
		t.Fatalf("reading the lifecycle marks failed: %v", err)
	}
	return revoked, rotated
}

// suspendSession holds the session row so an operation reaching it stops there,
// with the account family it already took still held.
func suspendSession(t *testing.T, pool *pgxpool.Pool, id auth.SessionID) (release func(), abandon func()) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("beginning failed: %v", err)
	}
	if _, err := tx.Exec(ctx, `SELECT id FROM account_sessions WHERE id = $1 FOR UPDATE`, id.String()); err != nil {
		t.Fatalf("locking the session failed: %v", err)
	}
	return func() {
			if err := tx.Commit(ctx); err != nil {
				t.Fatalf("releasing the session failed: %v", err)
			}
		}, func() {
			_ = tx.Rollback(ctx)
		}
}

func successorOf(t *testing.T, sess session.Session, now time.Time) session.Session {
	t.Helper()
	kind := auth.KindViewer
	if sess.Surface == auth.SurfaceOperator {
		kind = auth.KindOperator
	}
	next, _, err := session.Issue(sess.Account, kind, sess.Surface, lifetimes(), now, rand.Reader)
	if err != nil {
		t.Fatalf("issuing the successor failed: %v", err)
	}
	return next
}

// TestActivityAndRotationDoNotDeadlockInEitherOrder takes the account family before
// the session in both, so the second arrival waits rather than holding what the first needs.
func TestActivityAndRotationDoNotDeadlockInEitherOrder(t *testing.T) {
	t.Run("activity holds the authority first", func(t *testing.T) {
		store, pool := freshStore(t)
		now := time.Now().UTC().Truncate(time.Second)
		account := newAccount(t, store, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
		sess, _ := openSession(t, store, account.ID, auth.SurfacePublic, now)
		successor := successorOf(t, sess, now.Add(10*time.Minute))
		ctx := context.Background()

		cyclesBefore := deadlocksBroken(t, pool)
		release, abandon := suspendSession(t, pool, sess.ID)
		defer abandon()

		activity := make(chan error, 1)
		go func() {
			_, err := store.RecordActivity(ctx, sess.ID, now.Add(10*time.Minute), lifetimes())
			activity <- err
		}()
		activityPID := waitForLockWait(t, pool, activityLockFragment)

		rotation := make(chan error, 1)
		go func() { rotation <- store.Rotate(ctx, sess.ID, successor, now.Add(10*time.Minute)) }()
		rotationPID := waitForLockWait(t, pool, authorityFragment)
		if activityPID == rotationPID {
			t.Fatalf("both operations were observed on one backend %d", activityPID)
		}

		release()
		activityErr, rotationErr := <-activity, <-rotation
		if broken := deadlocksBroken(t, pool) - cyclesBefore; broken != 0 {
			t.Fatalf("PostgreSQL broke %d lock cycle(s): %v / %v", broken, activityErr, rotationErr)
		}
		if activityErr != nil {
			t.Fatalf("the renewal that linearised first failed: %v", activityErr)
		}
		if rotationErr != nil {
			t.Fatalf("the rotation that followed failed: %v", rotationErr)
		}
		if _, rotated := lifecycleOf(t, pool, sess.ID); !rotated {
			t.Error("the rotation left no successor on the previous session")
		}
	})

	t.Run("rotation holds the authority first", func(t *testing.T) {
		store, pool := freshStore(t)
		now := time.Now().UTC().Truncate(time.Second)
		account := newAccount(t, store, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
		sess, _ := openSession(t, store, account.ID, auth.SurfacePublic, now)
		successor := successorOf(t, sess, now.Add(10*time.Minute))
		ctx := context.Background()

		cyclesBefore := deadlocksBroken(t, pool)
		release, abandon := suspendSession(t, pool, sess.ID)
		defer abandon()

		rotation := make(chan error, 1)
		go func() { rotation <- store.Rotate(ctx, sess.ID, successor, now.Add(10*time.Minute)) }()
		rotationPID := waitForLockWait(t, pool, rotationLockFragment)

		activity := make(chan error, 1)
		go func() {
			_, err := store.RecordActivity(ctx, sess.ID, now.Add(10*time.Minute), lifetimes())
			activity <- err
		}()
		activityPID := waitForLockWait(t, pool, authorityFragment)
		if activityPID == rotationPID {
			t.Fatalf("both operations were observed on one backend %d", activityPID)
		}
		activeBefore, idleBefore, _ := deadlines(t, pool, sess.ID)

		release()
		rotationErr, activityErr := <-rotation, <-activity
		if broken := deadlocksBroken(t, pool) - cyclesBefore; broken != 0 {
			t.Fatalf("PostgreSQL broke %d lock cycle(s): %v / %v", broken, activityErr, rotationErr)
		}
		if rotationErr != nil {
			t.Fatalf("the rotation that linearised first failed: %v", rotationErr)
		}
		// The session it would have renewed no longer exists as a live record.
		if !errors.Is(activityErr, authstore.ErrNotFound) {
			t.Fatalf("the renewal returned %v after the rotation committed, want the unusable-record answer", activityErr)
		}
		if active, idle, _ := deadlines(t, pool, sess.ID); !active.Equal(activeBefore) || !idle.Equal(idleBefore) {
			t.Errorf("a rotated session was renewed: %s / %s", active, idle)
		}
	})
}

// TestActivityAndReplacementDoNotDeadlockInEitherOrder is the same property for the
// operation that revokes a session while establishing its replacement.
func TestActivityAndReplacementDoNotDeadlockInEitherOrder(t *testing.T) {
	t.Run("activity holds the authority first", func(t *testing.T) {
		store, pool := freshStore(t)
		now := time.Now().UTC().Truncate(time.Second)
		account := newAccount(t, store, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
		sess, _ := openSession(t, store, account.ID, auth.SurfacePublic, now)
		successor := successorOf(t, sess, now.Add(10*time.Minute))
		ctx := context.Background()

		cyclesBefore := deadlocksBroken(t, pool)
		release, abandon := suspendSession(t, pool, sess.ID)
		defer abandon()

		activity := make(chan error, 1)
		go func() {
			_, err := store.RecordActivity(ctx, sess.ID, now.Add(10*time.Minute), lifetimes())
			activity <- err
		}()
		activityPID := waitForLockWait(t, pool, activityLockFragment)

		replacement := make(chan error, 1)
		go func() {
			_, err := store.ReplaceSession(ctx, &sess.ID, successor, now.Add(10*time.Minute))
			replacement <- err
		}()
		replacementPID := waitForLockWait(t, pool, authorityFragment)
		if activityPID == replacementPID {
			t.Fatalf("both operations were observed on one backend %d", activityPID)
		}

		release()
		activityErr, replacementErr := <-activity, <-replacement
		if broken := deadlocksBroken(t, pool) - cyclesBefore; broken != 0 {
			t.Fatalf("PostgreSQL broke %d lock cycle(s): %v / %v", broken, activityErr, replacementErr)
		}
		if activityErr != nil {
			t.Fatalf("the renewal that linearised first failed: %v", activityErr)
		}
		if replacementErr != nil {
			t.Fatalf("the replacement that followed failed: %v", replacementErr)
		}
		if revoked, _ := lifecycleOf(t, pool, sess.ID); !revoked {
			t.Error("the replaced session was left live")
		}
	})

	t.Run("replacement holds the authority first", func(t *testing.T) {
		store, pool := freshStore(t)
		now := time.Now().UTC().Truncate(time.Second)
		account := newAccount(t, store, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
		sess, _ := openSession(t, store, account.ID, auth.SurfacePublic, now)
		successor := successorOf(t, sess, now.Add(10*time.Minute))
		ctx := context.Background()

		cyclesBefore := deadlocksBroken(t, pool)
		release, abandon := suspendSession(t, pool, sess.ID)
		defer abandon()

		replacement := make(chan error, 1)
		go func() {
			_, err := store.ReplaceSession(ctx, &sess.ID, successor, now.Add(10*time.Minute))
			replacement <- err
		}()
		replacementPID := waitForLockWait(t, pool, revocationFragment)

		activity := make(chan error, 1)
		go func() {
			_, err := store.RecordActivity(ctx, sess.ID, now.Add(10*time.Minute), lifetimes())
			activity <- err
		}()
		activityPID := waitForLockWait(t, pool, authorityFragment)
		if activityPID == replacementPID {
			t.Fatalf("both operations were observed on one backend %d", activityPID)
		}
		activeBefore, idleBefore, _ := deadlines(t, pool, sess.ID)

		release()
		replacementErr, activityErr := <-replacement, <-activity
		if broken := deadlocksBroken(t, pool) - cyclesBefore; broken != 0 {
			t.Fatalf("PostgreSQL broke %d lock cycle(s): %v / %v", broken, activityErr, replacementErr)
		}
		if replacementErr != nil {
			t.Fatalf("the replacement that linearised first failed: %v", replacementErr)
		}
		if !errors.Is(activityErr, authstore.ErrNotFound) {
			t.Fatalf("the renewal returned %v after the revocation committed, want the unusable-record answer", activityErr)
		}
		if active, idle, _ := deadlines(t, pool, sess.ID); !active.Equal(activeBefore) || !idle.Equal(idleBefore) {
			t.Errorf("a revoked session was renewed: %s / %s", active, idle)
		}
	})
}

// TestActivityAndRevocationCannotDeadlockOverTheSameAccount stages the one order the
// renewal cannot impose: revocation reaches the account through its event's foreign key.
func TestActivityAndRevocationCannotDeadlockOverTheSameAccount(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	account := newAccount(t, store, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	sess, token := openSession(t, store, account.ID, auth.SurfacePublic, now)
	ctx := context.Background()
	cyclesBefore := deadlocksBroken(t, pool)

	holdAccount, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("beginning failed: %v", err)
	}
	defer func() { _ = holdAccount.Rollback(ctx) }()
	if _, err := holdAccount.Exec(ctx, `SELECT id FROM accounts WHERE id = $1 FOR UPDATE`, account.ID.String()); err != nil {
		t.Fatalf("locking the account failed: %v", err)
	}

	// The renewal queues for the account first, so it is the one that holds the
	// account and then wants the session the revocation is about to take.
	activity := make(chan error, 1)
	go func() {
		_, err := store.RecordActivity(ctx, sess.ID, now.Add(10*time.Minute), lifetimes())
		activity <- err
	}()
	activityPID := waitForLockWait(t, pool, authorityFragment)

	revocation := make(chan error, 1)
	go func() { revocation <- store.RevokeSession(ctx, sess.ID, now.Add(10*time.Minute)) }()
	// Waiting on the event insert places the revocation past its own update, in
	// the same transaction, and on the account it reaches through a foreign key.
	revocationPID := waitForLockWait(t, pool, eventInsertFragment)
	if revocationPID == activityPID {
		t.Fatalf("both operations were observed on one backend %d", activityPID)
	}

	if err := holdAccount.Commit(ctx); err != nil {
		t.Fatalf("releasing the account failed: %v", err)
	}
	activityErr, revocationErr := receive(t, activity, "renewal"), receive(t, revocation, "revocation")

	if broken := deadlocksBroken(t, pool) - cyclesBefore; broken != 0 {
		t.Fatalf("PostgreSQL broke %d lock cycle(s): renewal %v, revocation %v", broken, activityErr, revocationErr)
	}
	if revocationErr != nil {
		t.Fatalf("the revocation returned %v, want success", revocationErr)
	}
	if !errors.Is(activityErr, authstore.ErrNotFound) {
		t.Fatalf("the renewal returned %v, want the unusable-record answer", activityErr)
	}
	if _, err := store.Resolve(ctx, token, now.Add(10*time.Minute)); !errors.Is(err, authstore.ErrNotFound) {
		t.Fatalf("the revoked session stayed usable: %v", err)
	}
}

// accountWideEvents counts the account-wide revocation records written for one
// account, so the audit trail is judged rather than assumed.
func accountWideEvents(t *testing.T, pool *pgxpool.Pool, account auth.AccountID) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM account_security_events
			WHERE account_id = $1 AND kind = 'sessions_revoked_for_account'`,
		account.String()).Scan(&count); err != nil {
		t.Fatalf("counting the account-wide events failed: %v", err)
	}
	return count
}

// TestActivityAndAccountWideRevocationDoNotDeadlock covers the same inversion as the
// single revocation, over every session of one account and in both orders.
func TestActivityAndAccountWideRevocationDoNotDeadlock(t *testing.T) {
	t.Run("revocation reaches the account while the renewal holds it", func(t *testing.T) {
		store, pool := freshStore(t)
		now := time.Now().UTC().Truncate(time.Second)
		account := newAccount(t, store, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
		first, firstToken := openSession(t, store, account.ID, auth.SurfacePublic, now)
		_, secondToken := openSession(t, store, account.ID, auth.SurfacePublic, now.Add(time.Second))
		ctx := context.Background()
		cyclesBefore := deadlocksBroken(t, pool)

		holdAccount, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("beginning failed: %v", err)
		}
		defer func() { _ = holdAccount.Rollback(ctx) }()
		if _, err := holdAccount.Exec(ctx, `SELECT id FROM accounts WHERE id = $1 FOR UPDATE`, account.ID.String()); err != nil {
			t.Fatalf("locking the account failed: %v", err)
		}

		activity := make(chan error, 1)
		go func() {
			_, err := store.RecordActivity(ctx, first.ID, now.Add(10*time.Minute), lifetimes())
			activity <- err
		}()
		activityPID := waitForLockWait(t, pool, authorityFragment)

		revocation := make(chan accountWideOutcome, 1)
		go func() {
			affected, err := store.RevokeAccountSessions(ctx, account.ID, now.Add(10*time.Minute))
			revocation <- accountWideOutcome{affected, err}
		}()
		// Past its own update of both rows, waiting on the account its event references.
		revocationPID := waitForLockWait(t, pool, eventInsertFragment)
		if revocationPID == activityPID {
			t.Fatalf("both operations were observed on one backend %d", activityPID)
		}

		if err := holdAccount.Commit(ctx); err != nil {
			t.Fatalf("releasing the account failed: %v", err)
		}
		activityErr := receive(t, activity, "renewal")
		ended := receiveAccountWide(t, revocation, "account-wide revocation")

		if broken := deadlocksBroken(t, pool) - cyclesBefore; broken != 0 {
			t.Fatalf("PostgreSQL broke %d lock cycle(s): renewal %v, revocation %v", broken, activityErr, ended.err)
		}
		if ended.err != nil {
			t.Fatalf("the account-wide revocation returned %v, want success", ended.err)
		}
		if ended.affected != 2 {
			t.Fatalf("the revocation reported %d sessions, want 2", ended.affected)
		}
		if !errors.Is(activityErr, authstore.ErrNotFound) {
			t.Fatalf("the renewal returned %v, want the unusable-record answer", activityErr)
		}
		for name, token := range map[string]session.Token{"first": firstToken, "second": secondToken} {
			if _, err := store.Resolve(ctx, token, now.Add(10*time.Minute)); !errors.Is(err, authstore.ErrNotFound) {
				t.Errorf("the %s session stayed usable: %v", name, err)
			}
		}
		if events := accountWideEvents(t, pool, account.ID); events != 1 {
			t.Errorf("the account carries %d account-wide revocation records, want 1", events)
		}
	})

	t.Run("revocation queues behind a renewal in flight", func(t *testing.T) {
		store, pool := freshStore(t)
		now := time.Now().UTC().Truncate(time.Second)
		account := newAccount(t, store, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
		first, firstToken := openSession(t, store, account.ID, auth.SurfacePublic, now)
		_, secondToken := openSession(t, store, account.ID, auth.SurfacePublic, now.Add(time.Second))
		ctx := context.Background()
		cyclesBefore := deadlocksBroken(t, pool)

		release, abandon := suspendSession(t, pool, first.ID)
		defer abandon()

		activity := make(chan error, 1)
		go func() {
			_, err := store.RecordActivity(ctx, first.ID, now.Add(10*time.Minute), lifetimes())
			activity <- err
		}()
		activityPID := waitForLockWait(t, pool, activityLockFragment)

		revocation := make(chan accountWideOutcome, 1)
		go func() {
			affected, err := store.RevokeAccountSessions(ctx, account.ID, now.Add(20*time.Minute))
			revocation <- accountWideOutcome{affected, err}
		}()
		// It cannot pass the renewal: the row it must update is the one being held.
		revocationPID := waitForLockWait(t, pool, accountWideFragment)
		if revocationPID == activityPID {
			t.Fatalf("both operations were observed on one backend %d", activityPID)
		}

		release()
		activityErr := receive(t, activity, "renewal")
		ended := receiveAccountWide(t, revocation, "account-wide revocation")

		if broken := deadlocksBroken(t, pool) - cyclesBefore; broken != 0 {
			t.Fatalf("PostgreSQL broke %d lock cycle(s): renewal %v, revocation %v", broken, activityErr, ended.err)
		}
		if activityErr != nil {
			t.Fatalf("the renewal that linearised first returned %v, want success", activityErr)
		}
		if ended.err != nil {
			t.Fatalf("the account-wide revocation returned %v, want success", ended.err)
		}
		if ended.affected != 2 {
			t.Fatalf("the revocation reported %d sessions, want 2", ended.affected)
		}
		for name, token := range map[string]session.Token{"first": firstToken, "second": secondToken} {
			if _, err := store.Resolve(ctx, token, now.Add(20*time.Minute)); !errors.Is(err, authstore.ErrNotFound) {
				t.Errorf("the %s session stayed usable: %v", name, err)
			}
		}
		if events := accountWideEvents(t, pool, account.ID); events != 1 {
			t.Errorf("the account carries %d account-wide revocation records, want 1", events)
		}
	})
}
