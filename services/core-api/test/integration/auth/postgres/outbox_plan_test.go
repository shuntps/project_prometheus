package integration_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/authstore"
)

// The population is deliberately asymmetric and is what the queue actually looks
// like: the challenge history is never emptied and grows without limit, while
// the outbox holds pending work only and stays small.
const (
	challengeHistory = 50_000
	pendingWork      = 40
)

// TestNeitherTheClaimNorTheSweepReadsTheChallengeHistory keeps the hot path from
// degrading with every registration ever made. It is read from the plans of the
// statements actually issued, not asserted from their shape.
func TestNeitherTheClaimNorTheSweepReadsTheChallengeHistory(t *testing.T) {
	_, pool := freshStore(t)
	now := time.Now().UTC()
	populateQueue(t, pool, now)
	store, tracer := recordingStore(t)

	claimed, err := store.ClaimDeliveries(context.Background(), uuid.New(), outboxBatch, outboxMaxAttempts, outboxLease, now)
	if err != nil {
		t.Fatalf("claiming failed: %v", err)
	}
	if len(claimed) != outboxBatch {
		t.Fatalf("claimed %d deliveries, want the batch of %d", len(claimed), outboxBatch)
	}

	if _, err := store.SweepDeliveries(context.Background(), outboxBatch, outboxMaxAttempts, now); err != nil {
		t.Fatalf("sweeping failed: %v", err)
	}

	claimStatement, held := tracer.capturedFor("claimable")
	if !held {
		t.Fatal("the claim issued no statement this proof could read")
	}
	sweepStatement, held := tracer.capturedFor("lapsed")
	if !held {
		t.Fatal("the sweep issued no statement this proof could read")
	}
	claimPlan := explain(t, pool, claimStatement.sql, claimStatement.args...)
	sweepPlan := explain(t, pool, sweepStatement.sql, sweepStatement.args...)
	t.Logf("claim plan:\n%s", claimPlan)
	t.Logf("sweep plan:\n%s", sweepPlan)

	// A sequential scan of the challenges is the exact degradation being ruled
	// out: that table is never emptied.
	for name, plan := range map[string]string{"claim": claimPlan, "sweep": sweepPlan} {
		if strings.Contains(plan, "Seq Scan on account_email_verifications") {
			t.Errorf("the %s reads the whole challenge history:\n%s", name, plan)
		}
	}
}

// TestALargeQueueIsClaimedThroughItsDeliveryIndexes covers the other shape: a
// queue big enough that scanning it would matter. Each of the two populations a
// claim considers has its own partial index, and the counters report their use.
func TestALargeQueueIsClaimedThroughItsDeliveryIndexes(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC()
	populateLargeQueue(t, pool, now)

	before := indexScans(t, pool)
	claimed, err := store.ClaimDeliveries(context.Background(), uuid.New(), outboxBatch, outboxMaxAttempts, outboxLease, now)
	if err != nil {
		t.Fatalf("claiming failed: %v", err)
	}
	if len(claimed) != outboxBatch {
		t.Fatalf("claimed %d deliveries, want the batch of %d", len(claimed), outboxBatch)
	}
	after := waitForIndexScans(t, pool, before,
		"account_email_deliveries_unleased_due", "account_email_deliveries_lease_deadline")
	for _, index := range []string{
		"account_email_deliveries_unleased_due",
		"account_email_deliveries_lease_deadline",
	} {
		t.Logf("index %s scans %d -> %d", index, before[index], after[index])
	}
	if after["account_email_deliveries_unleased_due"] == before["account_email_deliveries_unleased_due"] &&
		after["account_email_deliveries_lease_deadline"] == before["account_email_deliveries_lease_deadline"] {
		t.Fatalf("the claim scanned neither delivery index on a %d-row queue", largeQueue)
	}
}

const largeQueue = 20_000

// populateLargeQueue writes a queue whose rows are split between the two
// populations a claim considers: never claimed, and lease lapsed.
func populateLargeQueue(t *testing.T, pool *pgxpool.Pool, now time.Time) {
	t.Helper()
	at := now.Add(-time.Hour)
	statements := []string{
		`INSERT INTO accounts (id, kind, status, created_at, updated_at)
		 SELECT md5('a' || i)::uuid, 'viewer', 'pending', $2::timestamptz, $2::timestamptz
		 FROM generate_series(1, $1) AS i`,
		`INSERT INTO account_email_identities (id, account_id, address, created_at)
		 SELECT md5('e' || i)::uuid, md5('a' || i)::uuid, 'queued' || i || '@example.com', $2::timestamptz
		 FROM generate_series(1, $1) AS i`,
		`INSERT INTO account_email_verifications (id, identity_id, token_fingerprint, issued_at, expires_at)
		 SELECT md5('v' || i)::uuid, md5('e' || i)::uuid, sha256(('t' || i)::bytea),
			$2::timestamptz, $2::timestamptz + interval '8 hours'
		 FROM generate_series(1, $1) AS i`,
		`INSERT INTO account_email_deliveries (id, challenge_id, token, created_at, available_at,
			expires_at, attempts, claimed_at, claim_expires_at, claim_id)
		 SELECT md5('d' || i)::uuid, md5('v' || i)::uuid,
			rtrim(translate(encode(sha256(('k' || i)::bytea), 'base64'), '+/', '-_'), '='),
			$2::timestamptz - interval '2 hours', $2::timestamptz + (i || ' seconds')::interval,
			$2::timestamptz + interval '8 hours', 0,
			CASE WHEN i % 4 = 0 THEN $2::timestamptz - interval '1 hour' END,
			CASE WHEN i % 4 = 0 THEN $2::timestamptz - interval '30 minutes' END,
			CASE WHEN i % 4 = 0 THEN md5('c' || i)::uuid END
		 FROM generate_series(1, $1) AS i`,
	}
	for _, statement := range statements {
		if _, err := pool.Exec(context.Background(), statement, largeQueue, at); err != nil {
			t.Fatalf("populating the queue failed: %v", err)
		}
	}
	if _, err := pool.Exec(context.Background(),
		`ANALYZE accounts, account_email_identities, account_email_verifications, account_email_deliveries`); err != nil {
		t.Fatalf("analysing the queue failed: %v", err)
	}
}

// statementTracer records the SQL the adapter actually issues, so a plan is read
// from the statement itself rather than from a copy of it that could drift.
type statementTracer struct {
	mu         sync.Mutex
	statements map[string]traced
}

type traced struct {
	sql  string
	args []any
}

// sweepMarkers names the CTEs the sweep issues; tracedMarkers adds the claim's.
var (
	sweepMarkers  = []string{"lapsed", "spent"}
	tracedMarkers = append([]string{"claimable"}, sweepMarkers...)
)

func (t *statementTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.Contains(data.SQL, "account_email_deliveries") {
		t.mu.Lock()
		for _, marker := range tracedMarkers {
			if strings.Contains(data.SQL, "WITH "+marker+" AS") {
				t.statements[marker] = traced{sql: data.SQL, args: data.Args}
			}
		}
		t.mu.Unlock()
	}
	return ctx
}

func (t *statementTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// capturedSweeps returns every statement the sweep issued, in the order the
// adapter runs them.
func capturedSweeps(t *testing.T, tracer *statementTracer) []traced {
	t.Helper()
	var out []traced
	for _, name := range sweepMarkers {
		if captured, held := tracer.capturedFor(name); held {
			out = append(out, captured)
		}
	}
	if len(out) == 0 {
		t.Fatal("the sweep issued no statement this proof could read")
	}
	return out
}

func (t *statementTracer) capturedFor(name string) (traced, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	captured, held := t.statements[name]
	return captured, held
}

// recordingStore opens a second pool over the same database whose queries are
// recorded, and builds a store on it.
func recordingStore(t *testing.T) (*authstore.Store, *statementTracer) {
	t.Helper()
	tracer := &statementTracer{statements: map[string]traced{}}
	settings, err := pgxpool.ParseConfig(storeDSN)
	if err != nil {
		t.Fatalf("parsing the connection string failed: %v", err)
	}
	settings.ConnConfig.Tracer = tracer
	pool, err := pgxpool.NewWithConfig(context.Background(), settings)
	if err != nil {
		t.Fatalf("opening the traced pool failed: %v", err)
	}
	t.Cleanup(pool.Close)
	store, err := authstore.New(pool)
	if err != nil {
		t.Fatalf("building the traced store failed: %v", err)
	}
	return store, tracer
}

// populateQueue writes the history in bulk, without going through the store: the
// subject here is the planner, not the writing path.
func populateQueue(t *testing.T, pool *pgxpool.Pool, now time.Time) {
	t.Helper()
	at := now.Add(-time.Hour)
	statements := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO accounts (id, kind, status, created_at, updated_at)
		 SELECT md5('a' || i)::uuid, 'viewer', 'pending', $2::timestamptz, $2::timestamptz
		 FROM generate_series(1, $1) AS i`, []any{challengeHistory, at}},
		{`INSERT INTO account_email_identities (id, account_id, address, created_at)
		 SELECT md5('e' || i)::uuid, md5('a' || i)::uuid, 'queued' || i || '@example.com', $2::timestamptz
		 FROM generate_series(1, $1) AS i`, []any{challengeHistory, at}},
		// Most of the history is consumed, which is what an address that was
		// verified long ago leaves behind for ever.
		{`INSERT INTO account_email_verifications (id, identity_id, token_fingerprint, issued_at, expires_at, consumed_at)
		 SELECT md5('v' || i)::uuid, md5('e' || i)::uuid, sha256(('t' || i)::bytea),
			$2::timestamptz - interval '2 days', $2::timestamptz - interval '1 day',
			CASE WHEN i > $3 THEN $2::timestamptz - interval '2 days' + interval '1 minute' END
		 FROM generate_series(1, $1) AS i`, []any{challengeHistory, at, pendingWork}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(context.Background(), statement.sql, statement.args...); err != nil {
			t.Fatalf("populating the history failed: %v", err)
		}
	}
	// The pending work: a small outbox over the few challenges still current.
	const deliveries = `INSERT INTO account_email_deliveries (id, challenge_id, token, created_at,
			available_at, expires_at, attempts)
		SELECT md5('d' || i)::uuid, md5('v' || i)::uuid,
			rtrim(translate(encode(sha256(('k' || i)::bytea), 'base64'), '+/', '-_'), '='),
			$2::timestamptz - interval '2 days', $2::timestamptz - interval '2 days',
			$2::timestamptz - interval '1 day', 0
		FROM generate_series(1, $1) AS i`
	if _, err := pool.Exec(context.Background(), deliveries, pendingWork, at); err != nil {
		t.Fatalf("populating the queue failed: %v", err)
	}
	// The current challenges are made live again, so the claim has work to take.
	if _, err := pool.Exec(context.Background(),
		`UPDATE account_email_verifications SET expires_at = $1 WHERE consumed_at IS NULL`,
		now.Add(time.Hour)); err != nil {
		t.Fatalf("refreshing the current challenges failed: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`UPDATE account_email_deliveries SET expires_at = $1`, now.Add(time.Hour)); err != nil {
		t.Fatalf("refreshing the deliveries failed: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`ANALYZE accounts, account_email_identities, account_email_verifications, account_email_deliveries`); err != nil {
		t.Fatalf("analysing the queue failed: %v", err)
	}
}

// waitForIndexScans polls the counters, which PostgreSQL flushes after the
// statement rather than during it. A single read would measure the delay.
func waitForIndexScans(t *testing.T, pool *pgxpool.Pool, before map[string]int64, names ...string) map[string]int64 {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		current := indexScans(t, pool)
		for _, name := range names {
			if current[name] > before[name] {
				return current
			}
		}
		if time.Now().After(deadline) {
			return current
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func indexScans(t *testing.T, pool *pgxpool.Pool) map[string]int64 {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT indexrelname, idx_scan FROM pg_stat_user_indexes WHERE relname LIKE 'account_email_%'`)
	if err != nil {
		t.Fatalf("reading the index counters failed: %v", err)
	}
	defer rows.Close()

	counters := map[string]int64{}
	for rows.Next() {
		var name string
		var scans *int64
		if err := rows.Scan(&name, &scans); err != nil {
			t.Fatalf("scanning an index counter failed: %v", err)
		}
		if scans != nil {
			counters[name] = *scans
		}
	}
	if rows.Err() != nil {
		t.Fatalf("reading the index counters failed: %v", rows.Err())
	}
	return counters
}

func explain(t *testing.T, pool *pgxpool.Pool, query string, args ...any) string {
	t.Helper()
	rows, err := pool.Query(context.Background(), "EXPLAIN "+query, args...)
	if err != nil {
		t.Fatalf("explaining failed: %v", err)
	}
	defer rows.Close()

	plan := ""
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatalf("scanning the plan failed: %v", err)
		}
		plan += line + "\n"
	}
	return plan
}
