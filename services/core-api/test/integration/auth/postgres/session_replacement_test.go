package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

// injectFault raises inside the transaction under test, so the failure happens
// where a driver or a constraint would raise it, not before the operation starts.
func injectFault(t *testing.T, pool *pgxpool.Pool, statements ...string) {
	t.Helper()
	const fn = `CREATE OR REPLACE FUNCTION injected_fault() RETURNS trigger AS $$
		BEGIN RAISE EXCEPTION 'injected fault'; END; $$ LANGUAGE plpgsql`
	if _, err := pool.Exec(context.Background(), fn); err != nil {
		t.Fatalf("declaring the fault function failed: %v", err)
	}
	for _, statement := range statements {
		if _, err := pool.Exec(context.Background(), statement); err != nil {
			t.Fatalf("installing the fault failed: %v", err)
		}
	}
}

// TestAFailedReplacementRollsBackInsidePostgreSQL raises at a different point in
// the real transaction each time; every point must leave the database as it was.
func TestAFailedReplacementRollsBackInsidePostgreSQL(t *testing.T) {
	cases := map[string]string{
		"after the predecessor is revoked, before the successor is inserted": `
			CREATE TRIGGER fault_on_session_insert BEFORE INSERT ON account_sessions
			FOR EACH ROW EXECUTE FUNCTION injected_fault()`,
		"after the successor is inserted, while its creation event is written": `
			CREATE TRIGGER fault_on_created_event BEFORE INSERT ON account_security_events
			FOR EACH ROW WHEN (NEW.kind = 'session_created') EXECUTE FUNCTION injected_fault()`,
		"at commit, through a deferred constraint": `
			CREATE CONSTRAINT TRIGGER fault_at_commit AFTER INSERT ON account_sessions
			DEFERRABLE INITIALLY DEFERRED
			FOR EACH ROW EXECUTE FUNCTION injected_fault()`,
	}
	for name, statement := range cases {
		t.Run(name, func(t *testing.T) {
			store, pool := freshStore(t)
			now := time.Now().UTC()
			account := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
			predecessor, token := openSession(t, store, account.ID, iam.SurfacePublic, now)

			before := readLedger(t, pool)
			if before.sessions != 1 {
				t.Fatalf("%d sessions before the failure, want 1", before.sessions)
			}
			injectFault(t, pool, statement)

			successor, _, err := session.Issue(account.ID, iam.KindViewer, iam.SurfacePublic, lifetimes(), now)
			if err != nil {
				t.Fatalf("issuing the successor failed: %v", err)
			}
			if _, err := store.ReplaceSession(context.Background(), &predecessor.ID, successor, now); err == nil {
				t.Fatal("the replacement reported success despite the injected fault")
			}

			after := readLedger(t, pool)
			if after != before {
				t.Fatalf("the database changed: %+v, want %+v", after, before)
			}
			// The predecessor is untouched, so no revocation survived the rollback.
			resolved, err := store.Resolve(context.Background(), token, now)
			if err != nil {
				t.Fatalf("the predecessor stopped working after a rolled-back failure: %v", err)
			}
			if resolved.Session.ID != predecessor.ID {
				t.Fatal("the resolution returned a different session")
			}
			var successors int
			if err := pool.QueryRow(context.Background(),
				`SELECT count(*) FROM account_sessions WHERE id = $1`, successor.ID.String()).Scan(&successors); err != nil {
				t.Fatalf("counting the successor failed: %v", err)
			}
			if successors != 0 {
				t.Fatalf("%d successor rows survived the rollback", successors)
			}
		})
	}
}
