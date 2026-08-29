package integration_test

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/authstore"
)

// TestActivityMovesOnlyTheInactivityDeadlineAndNeverPastTheAbsoluteOne states the
// whole temporal contract of the operation in one place.
func TestActivityMovesOnlyTheInactivityDeadlineAndNeverPastTheAbsoluteOne(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	account := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
	sess, _ := openSession(t, store, account.ID, iam.SurfacePublic, now)
	_, idleBefore, absoluteBefore := deadlines(t, pool, sess.ID)

	at := now.Add(10 * time.Minute)
	written, err := store.RecordActivity(context.Background(), sess.ID, at, lifetimes())
	if err != nil {
		t.Fatalf("recording activity failed: %v", err)
	}
	if !written {
		t.Fatal("the update was suppressed although the interval had passed")
	}
	active, idle, absolute := deadlines(t, pool, sess.ID)
	if !active.Equal(at) {
		t.Errorf("the activity instant is %s, want %s", active, at)
	}
	if !idle.Equal(at.Add(lifetimes().Idle)) {
		t.Errorf("the inactivity deadline is %s, want %s", idle, at.Add(lifetimes().Idle))
	}
	if !idle.After(idleBefore) {
		t.Error("the inactivity deadline did not move")
	}
	if !absolute.Equal(absoluteBefore) {
		t.Errorf("the absolute deadline moved from %s to %s", absoluteBefore, absolute)
	}

	_ = idleBefore
}

// TestActivityIsCappedByTheAbsoluteDeadline uses a session whose two deadlines are
// close enough that a renewal would cross the absolute one.
func TestActivityIsCappedByTheAbsoluteDeadline(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	short := session.Lifetimes{Absolute: 40 * time.Minute, Idle: 30 * time.Minute, ActivityInterval: time.Minute}
	account := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)

	sess, _, err := session.Issue(account.ID, iam.KindViewer, iam.SurfacePublic, short, now, rand.Reader)
	if err != nil {
		t.Fatalf("issuing failed: %v", err)
	}
	if _, err := store.ReplaceSession(context.Background(), nil, sess, now); err != nil {
		t.Fatalf("creating the session failed: %v", err)
	}
	_, _, absoluteBefore := deadlines(t, pool, sess.ID)

	// Inside the idle window, but late enough that now+idle would cross absolute.
	at := now.Add(15 * time.Minute)
	written, err := store.RecordActivity(context.Background(), sess.ID, at, short)
	if err != nil {
		t.Fatalf("recording activity failed: %v", err)
	}
	if !written {
		t.Fatal("the renewal was suppressed although it would have extended the deadline")
	}
	_, idle, absolute := deadlines(t, pool, sess.ID)
	if idle.After(absolute) {
		t.Fatalf("the inactivity deadline %s passed the absolute one %s", idle, absolute)
	}
	if !idle.Equal(absoluteBefore) {
		t.Errorf("the capped deadline is %s, want it pinned to %s", idle, absoluteBefore)
	}
	if !absolute.Equal(absoluteBefore) {
		t.Errorf("the absolute deadline moved from %s to %s", absoluteBefore, absolute)
	}
	// Once pinned, a further renewal inside the window can add nothing.
	written, err = store.RecordActivity(context.Background(), sess.ID, at.Add(5*time.Minute), short)
	if err != nil {
		t.Fatalf("recording activity failed: %v", err)
	}
	if written {
		t.Error("a renewal was written although the deadline was already at the cap")
	}
}

// TestActivityIsPersistedAtMostOncePerInterval bounds the writes a burst costs,
// counted rather than timed.
func TestActivityIsPersistedAtMostOncePerInterval(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	account := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
	sess, _ := openSession(t, store, account.ID, iam.SurfacePublic, now)
	interval := lifetimes().ActivityInterval

	// A burst inside one interval costs exactly one write.
	writes := 0
	for i := 0; i < 50; i++ {
		at := now.Add(interval).Add(time.Duration(i) * time.Millisecond)
		written, err := store.RecordActivity(context.Background(), sess.ID, at, lifetimes())
		if err != nil {
			t.Fatalf("recording activity failed: %v", err)
		}
		if written {
			writes++
		}
	}
	if writes != 1 {
		t.Fatalf("%d writes for a burst of 50 events inside one interval, want 1", writes)
	}

	// A later burst, one interval further on, costs one more.
	for i := 0; i < 50; i++ {
		at := now.Add(2 * interval).Add(time.Duration(i) * time.Millisecond)
		written, err := store.RecordActivity(context.Background(), sess.ID, at, lifetimes())
		if err != nil {
			t.Fatalf("recording activity failed: %v", err)
		}
		if written {
			writes++
		}
	}
	if writes != 2 {
		t.Fatalf("%d writes for two bursts an interval apart, want 2", writes)
	}
	// Suppression never costs the session its deadline: it stays ahead of the
	// instant that was refused a write.
	_, idle, _ := deadlines(t, pool, sess.ID)
	if !idle.After(now.Add(2 * interval)) {
		t.Errorf("the deadline %s is not ahead of the suppressed instant", idle)
	}
}

// TestActivityNeverMovesADeadlineBackwards covers instants observed out of order,
// which a naive write would use to shorten the session.
func TestActivityNeverMovesADeadlineBackwards(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	account := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
	sess, _ := openSession(t, store, account.ID, iam.SurfacePublic, now)

	late := now.Add(20 * time.Minute)
	if _, err := store.RecordActivity(context.Background(), sess.ID, late, lifetimes()); err != nil {
		t.Fatalf("recording activity failed: %v", err)
	}
	activeAfter, idleAfter, _ := deadlines(t, pool, sess.ID)

	for _, earlier := range []time.Time{now.Add(5 * time.Minute), now, now.Add(-time.Hour)} {
		written, err := store.RecordActivity(context.Background(), sess.ID, earlier, lifetimes())
		if err != nil {
			t.Fatalf("recording activity failed: %v", err)
		}
		if written {
			t.Fatalf("an instant at %s was written after one at %s", earlier, late)
		}
	}
	active, idle, _ := deadlines(t, pool, sess.ID)
	if !active.Equal(activeAfter) || !idle.Equal(idleAfter) {
		t.Errorf("an earlier instant changed the stamps to %s / %s", active, idle)
	}
}

// TestActivityCannotReviveOrOutliveTheAccountsAuthority refuses every state where
// renewal would resurrect something or extend an account that may not authenticate.
func TestActivityCannotReviveOrOutliveTheAccountsAuthority(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cases := map[string]func(*testing.T, *authstore.Store, *pgxpool.Pool, iam.Account, session.Session){
		"revoked": func(t *testing.T, store *authstore.Store, _ *pgxpool.Pool, _ iam.Account, sess session.Session) {
			if err := store.RevokeSession(context.Background(), sess.ID, now); err != nil {
				t.Fatalf("revoking failed: %v", err)
			}
		},
		"replaced": func(t *testing.T, store *authstore.Store, _ *pgxpool.Pool, account iam.Account, sess session.Session) {
			successor, _, err := session.Issue(account.ID, iam.KindViewer, iam.SurfacePublic, lifetimes(), now, rand.Reader)
			if err != nil {
				t.Fatalf("issuing failed: %v", err)
			}
			if _, err := store.ReplaceSession(context.Background(), &sess.ID, successor, now); err != nil {
				t.Fatalf("replacing failed: %v", err)
			}
		},
		"suspended account": func(t *testing.T, store *authstore.Store, _ *pgxpool.Pool, account iam.Account, _ session.Session) {
			if err := store.Suspend(context.Background(), account.ID, now); err != nil {
				t.Fatalf("suspending failed: %v", err)
			}
		},
		"closed account": func(t *testing.T, _ *authstore.Store, pool *pgxpool.Pool, account iam.Account, _ session.Session) {
			if _, err := pool.Exec(context.Background(), `UPDATE accounts SET status = 'closed' WHERE id = $1`, account.ID.String()); err != nil {
				t.Fatalf("closing failed: %v", err)
			}
		},
		"kind no longer holds the surface": func(t *testing.T, _ *authstore.Store, pool *pgxpool.Pool, account iam.Account, _ session.Session) {
			if _, err := pool.Exec(context.Background(), `UPDATE accounts SET kind = 'operator' WHERE id = $1`, account.ID.String()); err != nil {
				t.Fatalf("changing the kind failed: %v", err)
			}
		},
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			store, pool := freshStore(t)
			account := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
			sess, _ := openSession(t, store, account.ID, iam.SurfacePublic, now)
			breakIt(t, store, pool, account, sess)

			// Snapshotted after the change, so the assertion measures the refused
			// renewal alone rather than the operation that made it unusable.
			before := readLedger(t, pool)
			activeBefore, idleBefore, _ := deadlines(t, pool, sess.ID)

			at := now.Add(10 * time.Minute)
			if _, err := store.RecordActivity(context.Background(), sess.ID, at, lifetimes()); !errors.Is(err, authstore.ErrNotFound) {
				t.Fatalf("recording activity returned %v, want the unusable-record answer", err)
			}
			active, idle, _ := deadlines(t, pool, sess.ID)
			if !active.Equal(activeBefore) || !idle.Equal(idleBefore) {
				t.Errorf("a refused renewal changed the stamps to %s / %s", active, idle)
			}
			if after := readLedger(t, pool); after.created != before.created {
				t.Error("a refused renewal wrote a session event")
			}
		})
	}

	// An expired session is refused on its own instant, without any other change.
	t.Run("expired", func(t *testing.T) {
		store, pool := freshStore(t)
		account := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
		sess, _ := openSession(t, store, account.ID, iam.SurfacePublic, now)
		_, idleBefore, _ := deadlines(t, pool, sess.ID)

		past := idleBefore.Add(time.Second)
		if _, err := store.RecordActivity(context.Background(), sess.ID, past, lifetimes()); !errors.Is(err, authstore.ErrNotFound) {
			t.Fatalf("an expired session was renewed: %v", err)
		}
		_, idle, _ := deadlines(t, pool, sess.ID)
		if !idle.Equal(idleBefore) {
			t.Errorf("the expired deadline moved to %s", idle)
		}
	})

	// An unknown session is the same answer.
	t.Run("unknown", func(t *testing.T) {
		store, _ := freshStore(t)
		drawn, err := session.NewID()
		if err != nil {
			t.Fatalf("drawing failed: %v", err)
		}
		if _, err := store.RecordActivity(context.Background(), drawn, now, lifetimes()); !errors.Is(err, authstore.ErrNotFound) {
			t.Fatalf("an unknown session returned %v", err)
		}
	})
}
