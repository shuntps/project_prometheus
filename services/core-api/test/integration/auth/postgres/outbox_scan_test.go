package integration_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// liveQueue is large enough that examining it all is visible in the counters.
const (
	liveQueue = 20_000
	cleanable = 5
	sweepLot  = 3
)

// scanned is what one execution actually touched on the outbox: the rows the
// scan emitted and the pages it read.
type scanned struct {
	rows   float64
	blocks float64
}

// measureSweep runs the statement the adapter issued, under EXPLAIN ANALYZE
// inside a transaction that is rolled back, so the plan is real and the queue is
// left as it was.
func measureSweep(t *testing.T, pool *pgxpool.Pool, statement traced) scanned {
	t.Helper()
	conn, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquiring a connection failed: %v", err)
	}
	defer conn.Release()

	tx, err := conn.Begin(context.Background())
	if err != nil {
		t.Fatalf("opening the measuring transaction failed: %v", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(context.Background())) }()

	var raw []byte
	query := "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) " + statement.sql
	if err := tx.QueryRow(context.Background(), query, statement.args...).Scan(&raw); err != nil {
		t.Fatalf("measuring the statement failed: %v", err)
	}
	var plans []struct {
		Plan map[string]any `json:"Plan"`
	}
	if err := json.Unmarshal(raw, &plans); err != nil {
		t.Fatalf("reading the plan failed: %v", err)
	}
	if len(plans) != 1 {
		t.Fatalf("the plan came back as %d documents, want one", len(plans))
	}
	var total scanned
	walkPlan(plans[0].Plan, &total)
	t.Logf("outbox scan: %.0f rows emitted, %.0f pages read", total.rows, total.blocks)
	return total
}

// walkPlan sums what every node reading the outbox emitted and read.
func walkPlan(node map[string]any, total *scanned) {
	if name, held := node["Relation Name"].(string); held && name == "account_email_deliveries" {
		if rows, held := node["Actual Rows"].(float64); held {
			loops, _ := node["Actual Loops"].(float64)
			if loops == 0 {
				loops = 1
			}
			total.rows += rows * loops
		}
		for _, key := range []string{"Shared Hit Blocks", "Shared Read Blocks"} {
			if blocks, held := node[key].(float64); held {
				total.blocks += blocks
			}
		}
	}
	children, held := node["Plans"].([]any)
	if !held {
		return
	}
	for _, child := range children {
		if next, held := child.(map[string]any); held {
			walkPlan(next, total)
		}
	}
}

// TestTheSweepFindsASmallLotWithoutExaminingALargeQueue is the property a small
// batch is supposed to buy. The cleanable rows are placed last in the order the
// statement walks, so a scan that merely stops at the limit is not enough.
func TestTheSweepFindsASmallLotWithoutExaminingALargeQueue(t *testing.T) {
	_, pool := freshStore(t)
	now := time.Now().UTC()
	populateLiveQueue(t, pool, now)
	store, tracer := recordingStore(t)

	removed, err := store.SweepDeliveries(context.Background(), sweepLot, outboxMaxAttempts, now)
	if err != nil {
		t.Fatalf("sweeping failed: %v", err)
	}
	if removed != sweepLot {
		t.Fatalf("removed %d rows, want the lot of %d", removed, sweepLot)
	}

	statements := capturedSweeps(t, tracer)
	var total scanned
	for _, statement := range statements {
		one := measureSweep(t, pool, statement)
		total.rows += one.rows
		total.blocks += one.blocks
	}

	requireBoundedScan(t, pool, total, "expired challenges")
}

// requireBoundedScan compares what the sweep read against the queue's own
// footprint. Emitted rows are not the measure: a filtered sequential scan emits
// only what passed, while still reading every page.
func requireBoundedScan(t *testing.T, pool *pgxpool.Pool, total scanned, cause string) {
	t.Helper()
	var pages float64
	if err := pool.QueryRow(context.Background(),
		`SELECT relpages FROM pg_class WHERE relname = 'account_email_deliveries'`).Scan(&pages); err != nil {
		t.Fatalf("reading the table size failed: %v", err)
	}
	ceiling := pages / 5
	t.Logf("%s: %.0f pages read of the %.0f the queue occupies", cause, total.blocks, pages)
	if total.blocks > ceiling {
		t.Fatalf("the sweep read %.0f pages to remove %d rows, of the %.0f the queue occupies",
			total.blocks, sweepLot, pages)
	}
}

// populateLiveQueue writes a queue that is almost entirely live and not
// cleanable, with the few cleanable rows last in identifier order.
func populateLiveQueue(t *testing.T, pool *pgxpool.Pool, now time.Time) {
	t.Helper()
	at := now.Add(-time.Hour)
	statements := []string{
		`INSERT INTO accounts (id, kind, status, created_at, updated_at)
		 SELECT lpad(to_hex(i), 32, '0')::uuid, 'viewer', 'pending', $2::timestamptz, $2::timestamptz
		 FROM generate_series(1, $1) AS i`,
		`INSERT INTO account_email_identities (id, account_id, address, created_at)
		 SELECT lpad(to_hex(i + 1000000), 32, '0')::uuid, lpad(to_hex(i), 32, '0')::uuid,
			'live' || i || '@example.com', $2::timestamptz
		 FROM generate_series(1, $1) AS i`,
		`INSERT INTO account_email_verifications (id, identity_id, token_fingerprint, issued_at, expires_at)
		 SELECT lpad(to_hex(i + 2000000), 32, '0')::uuid, lpad(to_hex(i + 1000000), 32, '0')::uuid,
			sha256(('t' || i)::bytea), $2::timestamptz, $2::timestamptz + interval '8 hours'
		 FROM generate_series(1, $1) AS i`,
		`INSERT INTO account_email_deliveries (id, challenge_id, token, created_at, available_at,
			expires_at, attempts)
		 SELECT lpad(to_hex(i + 3000000), 32, '0')::uuid, lpad(to_hex(i + 2000000), 32, '0')::uuid,
			rtrim(translate(encode(sha256(('k' || i)::bytea), 'base64'), '+/', '-_'), '='),
			$2::timestamptz, $2::timestamptz, $2::timestamptz + interval '8 hours', 0
		 FROM generate_series(1, $1) AS i`,
	}
	for _, statement := range statements {
		if _, err := pool.Exec(context.Background(), statement, liveQueue, at); err != nil {
			t.Fatalf("populating the live queue failed: %v", err)
		}
	}
	// The cleanable rows are the highest identifiers, so a walk in that order
	// reaches them only after the whole queue.
	if _, err := pool.Exec(context.Background(),
		`UPDATE account_email_verifications
		 SET issued_at = $1::timestamptz - interval '2 hours',
		     expires_at = $1::timestamptz - interval '1 hour'
		 WHERE id >= lpad(to_hex($2 + 2000000), 32, '0')::uuid`,
		at, liveQueue-cleanable+1); err != nil {
		t.Fatalf("expiring the last challenges failed: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`UPDATE account_email_deliveries
		 SET created_at = $1::timestamptz - interval '3 hours',
		     available_at = $1::timestamptz - interval '3 hours',
		     expires_at = $1::timestamptz - interval '1 hour'
		 WHERE id >= lpad(to_hex($2 + 3000000), 32, '0')::uuid`,
		at, liveQueue-cleanable+1); err != nil {
		t.Fatalf("expiring the last deliveries failed: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`ANALYZE accounts, account_email_identities, account_email_verifications, account_email_deliveries`); err != nil {
		t.Fatalf("analysing the queue failed: %v", err)
	}
}

// TestTheSweepFindsSpentAttemptsWithoutExaminingALargeQueue is the second cause,
// measured the same way: a handful of rows whose attempts are spent, in a queue
// that is otherwise entirely live.
func TestTheSweepFindsSpentAttemptsWithoutExaminingALargeQueue(t *testing.T) {
	_, pool := freshStore(t)
	now := time.Now().UTC()
	populateLiveQueue(t, pool, now)
	// Undo the expiry the population applies, so only the second cause remains.
	if _, err := pool.Exec(context.Background(),
		`UPDATE account_email_deliveries SET expires_at = $1`, now.Add(8*time.Hour)); err != nil {
		t.Fatalf("refreshing the deliveries failed: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`UPDATE account_email_deliveries
		 SET attempts = $2, claimed_at = $3::timestamptz - interval '1 hour',
		     claim_expires_at = $3, claim_id = gen_random_uuid()
		 WHERE id >= lpad(to_hex($1 + 3000000), 32, '0')::uuid`,
		liveQueue-cleanable+1, outboxMaxAttempts, now.Add(-time.Hour)); err != nil {
		t.Fatalf("spending the last attempts failed: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `ANALYZE account_email_deliveries`); err != nil {
		t.Fatalf("analysing the queue failed: %v", err)
	}
	store, tracer := recordingStore(t)

	removed, err := store.SweepDeliveries(context.Background(), sweepLot, outboxMaxAttempts, now)
	if err != nil {
		t.Fatalf("sweeping failed: %v", err)
	}
	if removed != sweepLot {
		t.Fatalf("removed %d rows, want the lot of %d", removed, sweepLot)
	}

	var total scanned
	for _, statement := range capturedSweeps(t, tracer) {
		one := measureSweep(t, pool, statement)
		total.rows += one.rows
		total.blocks += one.blocks
	}
	requireBoundedScan(t, pool, total, "spent attempts")
}

// TestTheBatchIsSharedBetweenTheCauses keeps a call bounded across both causes
// rather than once per cause.
func TestTheBatchIsSharedBetweenTheCauses(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC()
	const expired, spent, batch = 4, 4, 5
	cleanableQueue(t, store, pool, expired+spent, now)

	// Half the cleanable rows are made live again and given spent attempts, so
	// each cause holds some of them.
	if _, err := pool.Exec(context.Background(),
		`UPDATE account_email_deliveries SET expires_at = $1, attempts = $2
		 WHERE id IN (SELECT id FROM account_email_deliveries ORDER BY id LIMIT $3)`,
		now.Add(time.Hour), outboxMaxAttempts, spent); err != nil {
		t.Fatalf("spending the attempts failed: %v", err)
	}

	removed, err := store.SweepDeliveries(context.Background(), batch, outboxMaxAttempts, now)
	if err != nil {
		t.Fatalf("sweeping failed: %v", err)
	}
	if removed != batch {
		t.Fatalf("one call removed %d rows across both causes, want at most the batch of %d", removed, batch)
	}
	if outstanding := deliveryCount(t, pool); outstanding != expired+spent-batch {
		t.Fatalf("outstanding = %d, want %d", outstanding, expired+spent-batch)
	}

	// Repeated calls drain both causes.
	for ticks := 0; deliveryCount(t, pool) > 0; ticks++ {
		if ticks > expired+spent {
			t.Fatal("the calls stopped making progress")
		}
		if _, err := store.SweepDeliveries(context.Background(), batch, outboxMaxAttempts, now); err != nil {
			t.Fatalf("sweeping failed: %v", err)
		}
	}
}
