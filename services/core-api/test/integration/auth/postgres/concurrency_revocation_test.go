package integration_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/authstore"
)

// TestActivityAndRevocationCannotDeadlockOverTheSameAccount stages the one order the
// renewal cannot impose: revocation reaches the account through its event's foreign key.
func TestActivityAndRevocationCannotDeadlockOverTheSameAccount(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	account := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
	sess, token := openSession(t, store, account.ID, iam.SurfacePublic, now)
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

// TestActivityAndAccountWideRevocationDoNotDeadlock covers the same inversion as the
// single revocation, over every session of one account and in both orders.
func TestActivityAndAccountWideRevocationDoNotDeadlock(t *testing.T) {
	t.Run("revocation reaches the account while the renewal holds it", func(t *testing.T) {
		store, pool := freshStore(t)
		now := time.Now().UTC().Truncate(time.Second)
		account := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
		first, firstToken := openSession(t, store, account.ID, iam.SurfacePublic, now)
		_, secondToken := openSession(t, store, account.ID, iam.SurfacePublic, now.Add(time.Second))
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
		account := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
		first, firstToken := openSession(t, store, account.ID, iam.SurfacePublic, now)
		_, secondToken := openSession(t, store, account.ID, iam.SurfacePublic, now.Add(time.Second))
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
