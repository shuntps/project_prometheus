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

// TestRotationInvalidatesThePreviousTokenAtomically covers the renewal required
// after authentication and after any privilege change.
func TestRotationInvalidatesThePreviousTokenAtomically(t *testing.T) {
	store, _ := freshStore(t)
	now := time.Now().UTC()
	account := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
	previous, previousToken := openSession(t, store, account.ID, iam.SurfacePublic, now)

	successor, successorToken, err := session.Issue(account.ID, iam.KindViewer, iam.SurfacePublic, lifetimes(), now.Add(time.Minute))
	if err != nil {
		t.Fatalf("issuing the successor failed: %v", err)
	}
	if err := store.Rotate(context.Background(), previous.ID, successor, successor.CreatedAt); err != nil {
		t.Fatalf("rotating failed: %v", err)
	}

	if previousToken.Reveal() == successorToken.Reveal() {
		t.Fatal("rotation reused the token")
	}
	if _, err := store.Resolve(context.Background(), previousToken, now.Add(2*time.Minute)); !errors.Is(err, authstore.ErrNotFound) {
		t.Error("the previous token still resolves after rotation")
	}
	if _, err := store.Resolve(context.Background(), successorToken, now.Add(2*time.Minute)); err != nil {
		t.Errorf("the successor does not resolve: %v", err)
	}
	if err := store.Rotate(context.Background(), previous.ID, successor, successor.CreatedAt); err == nil {
		t.Error("a session was rotated twice")
	}
}

// TestRotationRefusesASuccessorFromAnotherAccount keeps a rotation from moving a
// session into an authority it never had.
func TestRotationRefusesASuccessorFromAnotherAccount(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC()
	holder := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
	stranger := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
	previous, previousToken := openSession(t, store, holder.ID, iam.SurfacePublic, now)

	foreign, _, err := session.Issue(stranger.ID, iam.KindViewer, iam.SurfacePublic, lifetimes(), now.Add(time.Minute))
	if err != nil {
		t.Fatalf("issuing failed: %v", err)
	}
	if err := store.Rotate(context.Background(), previous.ID, foreign, foreign.CreatedAt); err == nil {
		t.Fatal("a session was rotated into another account")
	}
	assertNoSuccessorStored(t, pool, foreign.ID)
	if _, err := store.Resolve(context.Background(), previousToken, now.Add(2*time.Minute)); err != nil {
		t.Errorf("the refused rotation disturbed the original session: %v", err)
	}
}

// TestRotationRefusesASuccessorOnAnotherSurface guards the store against a caller
// that builds a session record itself rather than going through Issue.
func TestRotationRefusesASuccessorOnAnotherSurface(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC()
	holder := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
	previous, previousToken := openSession(t, store, holder.ID, iam.SurfacePublic, now)

	elevated, _, err := session.Issue(holder.ID, iam.KindViewer, iam.SurfacePublic, lifetimes(), now.Add(time.Minute))
	if err != nil {
		t.Fatalf("issuing failed: %v", err)
	}
	elevated.Surface = iam.SurfaceOperator

	if err := store.Rotate(context.Background(), previous.ID, elevated, elevated.CreatedAt); err == nil {
		t.Fatal("a public session was rotated into an operator session")
	}
	assertNoSuccessorStored(t, pool, elevated.ID)
	if _, err := store.Resolve(context.Background(), previousToken, now.Add(2*time.Minute)); err != nil {
		t.Errorf("the refused rotation disturbed the original session: %v", err)
	}
}

// TestRotationRefusesAnUnusablePredecessor covers every state a session can be in
// where it may no longer produce a successor.
func TestRotationRefusesAnUnusablePredecessor(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC()
	account := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)

	cases := map[string]func(t *testing.T, sess session.Session) time.Time{
		"already expired by idle": func(t *testing.T, sess session.Session) time.Time {
			return sess.IdleExpiresAt.Add(time.Second)
		},
		"already expired absolutely": func(t *testing.T, sess session.Session) time.Time {
			return sess.AbsoluteExpiresAt.Add(time.Second)
		},
		"already revoked": func(t *testing.T, sess session.Session) time.Time {
			if err := store.RevokeSession(context.Background(), sess.ID, now.Add(time.Minute)); err != nil {
				t.Fatalf("revoking failed: %v", err)
			}
			return now.Add(2 * time.Minute)
		},
		"successor predating it": func(t *testing.T, sess session.Session) time.Time {
			return sess.CreatedAt.Add(-time.Minute)
		},
	}
	for name, when := range cases {
		t.Run(name, func(t *testing.T) {
			previous, _ := openSession(t, store, account.ID, iam.SurfacePublic, now)
			at := when(t, previous)
			successor, _, err := session.Issue(account.ID, iam.KindViewer, iam.SurfacePublic, lifetimes(), at)
			if err != nil {
				t.Fatalf("issuing failed: %v", err)
			}
			if err := store.Rotate(context.Background(), previous.ID, successor, successor.CreatedAt); err == nil {
				t.Fatal("the rotation was accepted")
			}
			assertNoSuccessorStored(t, pool, successor.ID)
		})
	}

	if err := store.Rotate(context.Background(), mustSessionID(t), mustSession(t, account.ID, now), now); !errors.Is(err, authstore.ErrNotFound) {
		t.Errorf("a rotation from a session that does not exist was accepted: %v", err)
	}
}

func mustSessionID(t *testing.T) session.ID {
	t.Helper()
	idSession, _ := drawn(t)
	id := idSession.ID
	return id
}

// TestRotationJudgesThePredecessorOnItsOwnInstant closes the path where a record
// under the caller's control decided whether its predecessor was still alive.
func TestRotationJudgesThePredecessorOnItsOwnInstant(t *testing.T) {
	store, pool := freshStore(t)
	start := time.Now().UTC()
	account := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)

	t.Run("a backdated successor cannot revive an expired predecessor", func(t *testing.T) {
		previous, previousToken := openSession(t, store, account.ID, iam.SurfacePublic, start)
		rotatingAt := previous.IdleExpiresAt.Add(time.Minute)
		if _, err := store.Resolve(context.Background(), previousToken, rotatingAt); !errors.Is(err, authstore.ErrNotFound) {
			t.Fatal("the predecessor is still usable; this case no longer models the hazard")
		}

		backdated := previous.IdleExpiresAt.Add(-time.Minute)
		successor, successorToken, err := session.Issue(account.ID, iam.KindViewer, iam.SurfacePublic, lifetimes(), backdated)
		if err != nil {
			t.Fatalf("issuing failed: %v", err)
		}
		if err := store.Rotate(context.Background(), previous.ID, successor, rotatingAt); err == nil {
			t.Fatal("a backdated rotation of an expired session was accepted")
		}
		assertNoSuccessorStored(t, pool, successor.ID)
		assertNoRotationEvent(t, pool, account.ID)
		if _, err := store.Resolve(context.Background(), successorToken, rotatingAt); !errors.Is(err, authstore.ErrNotFound) {
			t.Error("an expired session produced a usable successor")
		}
	})

	t.Run("the predecessor keeps its real state after a refusal", func(t *testing.T) {
		previous, previousToken := openSession(t, store, account.ID, iam.SurfacePublic, start)
		alive := start.Add(time.Minute)
		stale := mustSession(t, account.ID, start.Add(-time.Hour))

		if err := store.Rotate(context.Background(), previous.ID, stale, alive); err == nil {
			t.Fatal("a successor from another instant was accepted")
		}
		assertNoSuccessorStored(t, pool, stale.ID)
		if _, err := store.Resolve(context.Background(), previousToken, alive); err != nil {
			t.Fatalf("a refused rotation disturbed a live predecessor: %v", err)
		}
	})

	t.Run("the successor must belong to this rotation", func(t *testing.T) {
		for _, drift := range []time.Duration{-time.Second, time.Second, -time.Hour, time.Hour} {
			previous, _ := openSession(t, store, account.ID, iam.SurfacePublic, start)
			at := start.Add(time.Minute)
			successor := mustSession(t, account.ID, at.Add(drift))
			if err := store.Rotate(context.Background(), previous.ID, successor, at); !errors.Is(err, iam.ErrInvalid) {
				t.Errorf("a successor created %s from the operation was accepted: %v", drift, err)
			}
			assertNoSuccessorStored(t, pool, successor.ID)
		}
	})

	t.Run("a live predecessor still rotates at the operation's instant", func(t *testing.T) {
		previous, previousToken := openSession(t, store, account.ID, iam.SurfacePublic, start)
		at := start.Add(time.Minute)
		successor, successorToken, err := session.Issue(account.ID, iam.KindViewer, iam.SurfacePublic, lifetimes(), at)
		if err != nil {
			t.Fatalf("issuing failed: %v", err)
		}
		if err := store.Rotate(context.Background(), previous.ID, successor, at); err != nil {
			t.Fatalf("a sound rotation was refused: %v", err)
		}
		if _, err := store.Resolve(context.Background(), previousToken, at); !errors.Is(err, authstore.ErrNotFound) {
			t.Error("the previous token survived the rotation")
		}
		if _, err := store.Resolve(context.Background(), successorToken, at); err != nil {
			t.Errorf("the successor does not resolve: %v", err)
		}
	})
}
