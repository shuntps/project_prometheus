package integration_test

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

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
func lifecycleOf(t *testing.T, pool *pgxpool.Pool, id session.ID) (revoked, rotated bool) {
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
func suspendSession(t *testing.T, pool *pgxpool.Pool, id session.ID) (release func(), abandon func()) {
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
	kind := iam.KindViewer
	if sess.Surface == iam.SurfaceOperator {
		kind = iam.KindOperator
	}
	next, _, err := session.Issue(sess.Account, kind, sess.Surface, lifetimes(), now, rand.Reader)
	if err != nil {
		t.Fatalf("issuing the successor failed: %v", err)
	}
	return next
}

// accountWideEvents counts the account-wide revocation records written for one
// account, so the audit trail is judged rather than assumed.
func accountWideEvents(t *testing.T, pool *pgxpool.Pool, account iam.AccountID) int {
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
