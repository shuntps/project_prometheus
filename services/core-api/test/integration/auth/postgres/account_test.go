package integration_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/authstore"
)

// TestSuspendingAnAccountStopsItsSessionsWithoutTouchingThem is why status is
// read again on every resolution.
func TestSuspendingAnAccountStopsItsSessionsWithoutTouchingThem(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC()
	account := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
	_, token := openSession(t, store, account.ID, iam.SurfacePublic, now)

	if _, err := store.Resolve(context.Background(), token, now); err != nil {
		t.Fatalf("a live session was refused: %v", err)
	}
	if err := store.Suspend(context.Background(), account.ID, now.Add(time.Minute)); err != nil {
		t.Fatalf("suspending failed: %v", err)
	}
	if _, err := store.Resolve(context.Background(), token, now.Add(2*time.Minute)); !errors.Is(err, authstore.ErrNotFound) {
		t.Fatal("a suspended account's session still resolves")
	}

	var revoked *time.Time
	if err := pool.QueryRow(context.Background(), `SELECT revoked_at FROM account_sessions`).Scan(&revoked); err != nil {
		t.Fatalf("reading the session failed: %v", err)
	}
	if revoked != nil {
		t.Error("suspension rewrote the session row instead of being read on resolution")
	}
}

// TestOneLoginAddressBelongsToOneAccount is enforced by the database, not only
// by the application.
func TestOneLoginAddressBelongsToOneAccount(t *testing.T) {
	store, _ := freshStore(t)
	address, err := iam.NormaliseEmail("shared@example.com")
	if err != nil {
		t.Fatalf("normalising failed: %v", err)
	}
	create := func() error {
		_, err := store.CreateAccount(context.Background(), authstore.NewAccount{
			Kind: iam.KindViewer, Status: iam.StatusPending, Email: address,
		}, time.Now().UTC())
		return err
	}
	if err := create(); err != nil {
		t.Fatalf("the first account was refused: %v", err)
	}
	if err := create(); !errors.Is(err, authstore.ErrConflict) {
		t.Fatalf("got %v, want a conflict on the second account", err)
	}
}

// TestAnAccountSuspendedAfterItsCredentialWasReadCreatesNoSession: the credential
// check and the hashing take real time, and the account may change meanwhile.
func TestAnAccountSuspendedAfterItsCredentialWasReadCreatesNoSession(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC()
	account := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)

	// The credential is read while the account is still usable.
	if _, err := store.CredentialByEmail(context.Background(), emailOf(t, pool, account)); err != nil {
		t.Fatalf("reading the credential failed: %v", err)
	}

	// Then the account is suspended, before the session would be created.
	if err := store.Suspend(context.Background(), account.ID, now); err != nil {
		t.Fatalf("suspending failed: %v", err)
	}
	before := readLedger(t, pool)

	successor, _, err := session.Issue(account.ID, iam.KindViewer, iam.SurfacePublic, lifetimes(), now)
	if err != nil {
		t.Fatalf("issuing failed: %v", err)
	}
	if _, err := store.ReplaceSession(context.Background(), nil, successor, now); !errors.Is(err, authstore.ErrNotFound) {
		t.Fatalf("the replacement returned %v, want the unusable-record answer", err)
	}
	// The refusal is the same shape any unusable account produces, so a caller
	// cannot tell this apart from an address that never existed.
	if after := readLedger(t, pool); after != before {
		t.Fatalf("the database changed: %+v, want %+v", after, before)
	}
}

func emailOf(t *testing.T, pool *pgxpool.Pool, account iam.Account) iam.EmailAddress {
	t.Helper()
	var raw string
	if err := pool.QueryRow(context.Background(),
		`SELECT address FROM account_email_identities WHERE account_id = $1`, account.ID.String()).Scan(&raw); err != nil {
		t.Fatalf("reading the address failed: %v", err)
	}
	address, err := iam.NormaliseEmail(raw)
	if err != nil {
		t.Fatalf("normalising failed: %v", err)
	}
	return address
}

// TestCreationAndSuspensionSerialiseIntoAValidOrder forbids the third outcome: a
// session still usable after a suspension that was supposed to stop it.
func TestCreationAndSuspensionSerialiseIntoAValidOrder(t *testing.T) {
	for attempt := 0; attempt < 12; attempt++ {
		store, pool := freshStore(t)
		now := time.Now().UTC()
		account := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
		successor, token, err := session.Issue(account.ID, iam.KindViewer, iam.SurfacePublic, lifetimes(), now)
		if err != nil {
			t.Fatalf("issuing failed: %v", err)
		}

		var (
			wg         sync.WaitGroup
			createErr  error
			suspendErr error
			start      = make(chan struct{})
		)
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, createErr = store.ReplaceSession(context.Background(), nil, successor, now)
		}()
		go func() {
			defer wg.Done()
			<-start
			suspendErr = store.Suspend(context.Background(), account.ID, now)
		}()
		close(start)
		wg.Wait()

		if suspendErr != nil {
			t.Fatalf("suspending failed: %v", suspendErr)
		}

		var status string
		if err := pool.QueryRow(context.Background(), `SELECT status FROM accounts WHERE id = $1`, account.ID.String()).Scan(&status); err != nil {
			t.Fatalf("reading the status failed: %v", err)
		}
		if status != string(iam.StatusSuspended) {
			t.Fatalf("the account ended as %q, want suspended", status)
		}

		switch {
		case createErr == nil:
			// The sign-in linearised first. The suspension must then make the
			// session unusable immediately, with no further action needed.
			if _, err := store.Resolve(context.Background(), token, now); !errors.Is(err, authstore.ErrNotFound) {
				t.Fatalf("attempt %d: a session created before the suspension stayed usable: %v", attempt, err)
			}
		case errors.Is(createErr, authstore.ErrNotFound):
			// The suspension won. No session may exist.
			if l := readLedger(t, pool); l.sessions != 0 || l.created != 0 {
				t.Fatalf("attempt %d: the suspension won but left %+v", attempt, l)
			}
		default:
			t.Fatalf("attempt %d: the creation failed for an unexpected reason: %v", attempt, createErr)
		}
	}
}

// TestCreationWaitsForAnUncommittedSuspension observes the creation waiting on the
// row lock inside PostgreSQL, then requires it to see the committed suspension.
func TestCreationWaitsForAnUncommittedSuspension(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC()
	account := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
	successor, _, err := session.Issue(account.ID, iam.KindViewer, iam.SurfacePublic, lifetimes(), now)
	if err != nil {
		t.Fatalf("issuing failed: %v", err)
	}

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
		_, err := store.ReplaceSession(ctx, nil, successor, now)
		done <- err
	}()

	// The server itself reports the creation blocked on a lock. If it never does,
	// the test fails rather than concluding from an elapsed delay.
	pid := waitForLockWait(t, "kind, status FROM accounts")
	if pid == 0 {
		t.Fatal("no waiting backend was identified")
	}
	select {
	case err := <-done:
		t.Fatalf("the creation completed while it was reported waiting on the lock: %v", err)
	default:
	}
	// Nothing may be written while it waits.
	if l := readLedger(t, pool); l.sessions != 0 || l.created != 0 {
		t.Fatalf("the creation wrote %+v while waiting on the lock", l)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("committing the suspension failed: %v", err)
	}
	if err := <-done; !errors.Is(err, authstore.ErrNotFound) {
		t.Fatalf("the creation returned %v after the suspension committed, want the unusable-record answer", err)
	}
	if l := readLedger(t, pool); l.sessions != 0 || l.created != 0 {
		t.Fatalf("the suspension won but the creation left %+v", l)
	}
}
