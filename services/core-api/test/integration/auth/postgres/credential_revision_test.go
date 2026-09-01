package integration_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/authstore"
)

/*
A password is read and verified outside any transaction, so a replacement may
commit between that verification and the session it would open. These prove the
revision is what closes that window, and that the lock is what makes it hold.
*/

// credentialLockFragment appears on one line of exactly one locking statement.
const credentialLockFragment = "revision FROM account_password_credentials"

// replacementHash is shaped as the schema demands and differs from the fixture's.
const replacementHash = "$argon2id$v=19$m=19456,t=2,p=1$BBBBBBBBBBBBBBBBBBBBBB$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

// blockedCallerDeadline bounds the operation launched into a goroutine. It is
// longer than lockWaitDeadline, so an observation that cannot be made fails
// first and says so, rather than being reported as an absence of blocking.
const blockedCallerDeadline = 2 * lockWaitDeadline

func credentialRevision(t *testing.T, pool *pgxpool.Pool, account iam.AccountID) password.Revision {
	t.Helper()
	var revision password.Revision
	if err := pool.QueryRow(context.Background(),
		`SELECT revision FROM account_password_credentials WHERE account_id = $1`,
		account.String()).Scan(&revision); err != nil {
		t.Fatalf("reading the credential revision failed: %v", err)
	}
	return revision
}

func sessionCount(t *testing.T, pool *pgxpool.Pool, account iam.AccountID) int {
	t.Helper()
	var stored int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM account_sessions WHERE account_id = $1`, account.String()).Scan(&stored); err != nil {
		t.Fatalf("counting the sessions failed: %v", err)
	}
	return stored
}

// holdCredential replaces the credential without committing, so anything that
// must read it under a lock stops there until release is called.
func holdCredential(t *testing.T, pool *pgxpool.Pool, account iam.AccountID) (release func(), abandon func()) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("beginning the credential writer failed: %v", err)
	}
	const update = `UPDATE account_password_credentials
		SET encoded_hash = $2, revision = revision + 1, updated_at = now()
		WHERE account_id = $1`
	if _, err := tx.Exec(ctx, update, account.String(), replacementHash); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("replacing the credential failed: %v", err)
	}
	return func() {
			if err := tx.Commit(ctx); err != nil {
				t.Fatalf("committing the credential writer failed: %v", err)
			}
		}, func() {
			_ = tx.Rollback(ctx)
		}
}

// TestReplacementWaitsOnACredentialBeingReplaced is the one proof an elapsed
// delay could not give: the backend is observed stopped on a lock.
func TestReplacementWaitsOnACredentialBeingReplaced(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC()
	account := newAccountAt(t, store, now, iam.KindViewer, iam.StatusActive, iam.RoleViewer)

	before := sessionCount(t, pool, account.ID)
	deadlocks := deadlocksBroken(t, pool)

	release, abandon := holdCredential(t, pool, account.ID)
	defer abandon()

	// The launched operation carries its own deadline, so it cannot outlive the
	// test even if an assertion below ends it early.
	ctx, cancel := context.WithTimeout(t.Context(), blockedCallerDeadline)
	successor := mustSession(t, account.ID, now)
	results := make(chan error, 1)
	go func() {
		_, err := store.ReplaceSession(ctx, nil, successor, password.FirstRevision, now)
		results <- err
	}()
	joined := false
	t.Cleanup(func() {
		cancel()
		if joined {
			return
		}
		select {
		case <-results:
		case <-time.After(blockedCallerDeadline):
			t.Error("the session replacement never returned")
		}
	})

	// PostgreSQL reports a backend waiting on the one statement matching this
	// fragment, and its PID is observed. An elapsed delay would prove nothing.
	if waitForLockWait(t, credentialLockFragment) == 0 {
		t.Fatal("no waiting backend was reported for the credential lock")
	}

	release()
	err := receive(t, results, "session replacement")
	joined = true
	if !errors.Is(err, authstore.ErrNotFound) {
		t.Fatalf("the replacement reported %v, want the ordinary refusal", err)
	}
	if got := sessionCount(t, pool, account.ID); got != before {
		t.Fatalf("%d session(s) exist, want %d: a superseded revision opened one", got, before)
	}
	if got := credentialRevision(t, pool, account.ID); got != password.FirstRevision+1 {
		t.Fatalf("the credential is at revision %d, want %d", got, password.FirstRevision+1)
	}
	if after := deadlocksBroken(t, pool); after != deadlocks {
		t.Fatalf("the deadlock counter moved from %d to %d", deadlocks, after)
	}
}

// TestReplacementRefusesARevisionAlreadySuperseded covers the settled case: the
// replacement committed long before, and nothing waits on anything.
func TestReplacementRefusesARevisionAlreadySuperseded(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC()
	account := newAccountAt(t, store, now, iam.KindViewer, iam.StatusActive, iam.RoleViewer)

	if err := store.SetPassword(context.Background(), account.ID,
		password.NewEncoded(replacementHash), now.Add(time.Minute)); err != nil {
		t.Fatalf("replacing the credential failed: %v", err)
	}
	if got := credentialRevision(t, pool, account.ID); got != password.FirstRevision+1 {
		t.Fatalf("the credential is at revision %d, want %d", got, password.FirstRevision+1)
	}

	before := sessionCount(t, pool, account.ID)
	successor := mustSession(t, account.ID, now)
	_, err := store.ReplaceSession(context.Background(), nil, successor, password.FirstRevision, now)
	if !errors.Is(err, authstore.ErrNotFound) {
		t.Fatalf("the replacement reported %v, want the ordinary refusal", err)
	}
	if got := sessionCount(t, pool, account.ID); got != before {
		t.Fatalf("%d session(s) exist, want %d: a superseded revision opened one", got, before)
	}
}

// TestReplacementAcceptsTheRevisionItVerified keeps the refusals above from
// passing because the replacement refuses everything.
func TestReplacementAcceptsTheRevisionItVerified(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC()
	account := newAccountAt(t, store, now, iam.KindViewer, iam.StatusActive, iam.RoleViewer)

	successor := mustSession(t, account.ID, now)
	if _, err := store.ReplaceSession(context.Background(), nil, successor, password.FirstRevision, now); err != nil {
		t.Fatalf("the replacement reported %v, want it to succeed", err)
	}
	if got := sessionCount(t, pool, account.ID); got != 1 {
		t.Fatalf("%d session(s) exist, want exactly 1", got)
	}
}

// TestEveryCredentialWriterStatesItsRevision drives the three writers that exist
// against the real schema, which is what the source guard cannot establish.
func TestEveryCredentialWriterStatesItsRevision(t *testing.T) {
	store, pool := freshStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	t.Run("creation writes the first revision", func(t *testing.T) {
		account := newAccountAt(t, store, now, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
		if got := credentialRevision(t, pool, account.ID); got != password.FirstRevision {
			t.Fatalf("a created credential is at revision %d, want %d", got, password.FirstRevision)
		}
	})

	t.Run("a direct change advances it", func(t *testing.T) {
		account := newAccountAt(t, store, now, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
		for step := password.Revision(1); step <= 2; step++ {
			if err := store.SetPassword(ctx, account.ID, password.NewEncoded(replacementHash),
				now.Add(time.Duration(step)*time.Minute)); err != nil {
				t.Fatalf("replacing the credential failed: %v", err)
			}
			if got, want := credentialRevision(t, pool, account.ID), password.FirstRevision+step; got != want {
				t.Fatalf("after %d change(s) the credential is at revision %d, want %d", step, got, want)
			}
		}
	})

	t.Run("registering again over a pending account advances it", func(t *testing.T) {
		address := freshAddress(t)
		if _, err := store.Register(ctx, address, password.NewEncoded(replacementHash),
			challengeLifetimes(), now); err != nil {
			t.Fatalf("registering failed: %v", err)
		}
		account := accountOfAddress(t, pool, address)
		if got := credentialRevision(t, pool, account); got != password.FirstRevision {
			t.Fatalf("a registered credential is at revision %d, want %d", got, password.FirstRevision)
		}

		// Past the resend interval, so the existing-identity path actually writes.
		later := now.Add(2 * time.Minute)
		if _, err := store.Register(ctx, address, password.NewEncoded(replacementHash),
			challengeLifetimes(), later); err != nil {
			t.Fatalf("registering again failed: %v", err)
		}
		if got, want := credentialRevision(t, pool, account), password.FirstRevision+1; got != want {
			t.Fatalf("after a second registration the credential is at revision %d, want %d", got, want)
		}
	})
}

func accountOfAddress(t *testing.T, pool *pgxpool.Pool, address iam.EmailAddress) iam.AccountID {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(),
		`SELECT account_id FROM account_email_identities WHERE address = $1`, address.Reveal()).Scan(&id); err != nil {
		t.Fatalf("reading the account of an address failed: %v", err)
	}
	parsed, err := iam.ParseAccountID(id)
	if err != nil {
		t.Fatalf("parsing the account identifier failed: %v", err)
	}
	return parsed
}
