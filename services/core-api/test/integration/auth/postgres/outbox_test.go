package integration_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/authstore"
)

const (
	outboxBatch       = 16
	outboxMaxAttempts = 3
	outboxLease       = 2 * time.Minute
)

// TestAClaimHoldsItsWorkForTheLengthOfItsLease is what a dead process is
// recovered by: the lock goes with the connection, the lease does not.
func TestAClaimHoldsItsWorkForTheLengthOfItsLease(t *testing.T) {
	store, pool := freshStore(t)
	address := freshAddress(t)
	now := time.Now().UTC()

	if _, err := store.Register(context.Background(), address, firstHash, challengeLifetimes(), now); err != nil {
		t.Fatalf("registering failed: %v", err)
	}

	first := uuid.New()
	claimed, err := store.ClaimDeliveries(context.Background(), first, outboxBatch, outboxMaxAttempts, outboxLease, now)
	if err != nil {
		t.Fatalf("claiming failed: %v", err)
	}
	if len(claimed) != 1 {
		t.Fatalf("claimed %d deliveries, want one", len(claimed))
	}
	if claimed[0].Attempts != 1 {
		t.Fatalf("attempts = %d, want the counter charged at the claim", claimed[0].Attempts)
	}
	if claimed[0].Address.Reveal() != address.Reveal() {
		t.Fatal("the claim carried the wrong address")
	}
	if claimed[0].Token.IsZero() || claimed[0].ExpiresAt.IsZero() {
		t.Fatal("the claim carried no token or no expiry")
	}

	// Inside the lease nothing else takes it, whatever else asks.
	again, err := store.ClaimDeliveries(context.Background(), uuid.New(), outboxBatch, outboxMaxAttempts, outboxLease,
		now.Add(outboxLease-time.Second))
	if err != nil {
		t.Fatalf("the second claim failed: %v", err)
	}
	if len(again) != 0 {
		t.Fatal("work under a live lease was taken again")
	}

	// Past the lease it is recovered, and the counter has moved.
	recovered, err := store.ClaimDeliveries(context.Background(), uuid.New(), outboxBatch, outboxMaxAttempts, outboxLease,
		now.Add(outboxLease))
	if err != nil {
		t.Fatalf("recovering the lapsed work failed: %v", err)
	}
	if len(recovered) != 1 || recovered[0].ID != claimed[0].ID {
		t.Fatalf("recovered %d deliveries, want the same one back", len(recovered))
	}
	if recovered[0].Attempts != 2 {
		t.Fatalf("attempts = %d, want the second claim charged", recovered[0].Attempts)
	}

	// The first owner may no longer settle it: its lease was taken over.
	settled, err := store.SettleDelivery(context.Background(), claimed[0].ID, first)
	if err != nil {
		t.Fatalf("settling failed: %v", err)
	}
	if settled {
		t.Fatal("a lapsed owner removed work a newer claim holds")
	}
	if outstanding := deliveryCount(t, pool); outstanding != 1 {
		t.Fatalf("outstanding = %d, want the work still queued", outstanding)
	}
}

// TestWorkWhoseAttemptsAreSpentIsSwept covers the row a process leaves behind by
// dying after the claim that reached the limit: no claim query would take it
// again, so nothing but the sweep removes it.
func TestWorkWhoseAttemptsAreSpentIsSwept(t *testing.T) {
	store, pool := freshStore(t)
	address := freshAddress(t)
	now := time.Now().UTC()

	if _, err := store.Register(context.Background(), address, firstHash, challengeLifetimes(), now); err != nil {
		t.Fatalf("registering failed: %v", err)
	}

	// Every permitted attempt is claimed and abandoned, which is exactly what a
	// process that dies mid-attempt leaves behind.
	for attempt := 1; attempt <= outboxMaxAttempts; attempt++ {
		at := now.Add(time.Duration(attempt-1) * outboxLease)
		claimed, err := store.ClaimDeliveries(context.Background(), uuid.New(), outboxBatch, outboxMaxAttempts, outboxLease, at)
		if err != nil {
			t.Fatalf("claim %d failed: %v", attempt, err)
		}
		if len(claimed) != 1 {
			t.Fatalf("claim %d took %d deliveries, want one", attempt, len(claimed))
		}
	}
	stuck := now.Add(time.Duration(outboxMaxAttempts) * outboxLease)

	// It is now unreachable by the claim query, so it would sit there for ever.
	unreachable, err := store.ClaimDeliveries(context.Background(), uuid.New(), outboxBatch, outboxMaxAttempts, outboxLease, stuck)
	if err != nil {
		t.Fatalf("claiming failed: %v", err)
	}
	if len(unreachable) != 0 {
		t.Fatal("work past its attempt limit was claimed again")
	}
	if outstanding := deliveryCount(t, pool); outstanding != 1 {
		t.Fatalf("outstanding = %d, want the stuck row still present before the sweep", outstanding)
	}

	removed, err := store.SweepDeliveries(context.Background(), outboxBatch, outboxMaxAttempts, stuck)
	if err != nil {
		t.Fatalf("sweeping failed: %v", err)
	}
	if removed != 1 {
		t.Fatalf("swept %d rows, want the stuck one", removed)
	}
	if outstanding := deliveryCount(t, pool); outstanding != 0 {
		t.Fatalf("outstanding = %d, want nothing left blocked", outstanding)
	}
}

// TestWorkIsSweptWhenItsChallengeCanNoLongerBeUsed keeps the queue free of
// messages nothing would accept, and keeps no bearer token behind them.
func TestWorkIsSweptWhenItsChallengeCanNoLongerBeUsed(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC()

	expired := freshAddress(t)
	if _, err := store.Register(context.Background(), expired, firstHash, challengeLifetimes(), now); err != nil {
		t.Fatalf("registering failed: %v", err)
	}
	record, _ := readRegistration(t, pool, expired)
	expireChallenge(t, pool, record.current.id, now)

	// A consumed challenge and a superseded one take their delivery with them in
	// the transaction that ends them; only expiry needs the sweep.
	consumed := freshAddress(t)
	if _, err := store.Register(context.Background(), consumed, firstHash, challengeLifetimes(), now); err != nil {
		t.Fatalf("registering failed: %v", err)
	}
	token := tokenFor(t, pool, consumed)
	if _, err := store.ConsumeVerification(context.Background(), token.Fingerprint(), now.Add(time.Minute)); err != nil {
		t.Fatalf("verifying failed: %v", err)
	}

	superseded := freshAddress(t)
	if _, err := store.Register(context.Background(), superseded, firstHash, challengeLifetimes(), now); err != nil {
		t.Fatalf("registering failed: %v", err)
	}
	if _, err := store.Register(context.Background(), superseded, secondHash, challengeLifetimes(),
		now.Add(challengeLifetimes().ResendInterval)); err != nil {
		t.Fatalf("reissuing failed: %v", err)
	}

	// Two remain queued: the reissued one, and the expired one until it is swept.
	if outstanding := deliveryCount(t, pool); outstanding != 2 {
		t.Fatalf("outstanding = %d, want the consumed and superseded ones already gone", outstanding)
	}

	removed, err := store.SweepDeliveries(context.Background(), outboxBatch, outboxMaxAttempts, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("sweeping failed: %v", err)
	}
	if removed != 1 {
		t.Fatalf("swept %d rows, want the expired one", removed)
	}
	if outstanding := deliveryCount(t, pool); outstanding != 1 {
		t.Fatalf("outstanding = %d, want only the live work left", outstanding)
	}
}

func TestRescheduledWorkIsReleasedAndTakenLater(t *testing.T) {
	store, pool := freshStore(t)
	address := freshAddress(t)
	now := time.Now().UTC()

	if _, err := store.Register(context.Background(), address, firstHash, challengeLifetimes(), now); err != nil {
		t.Fatalf("registering failed: %v", err)
	}
	claim := uuid.New()
	claimed, err := store.ClaimDeliveries(context.Background(), claim, outboxBatch, outboxMaxAttempts, outboxLease, now)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claiming failed: %d %v", len(claimed), err)
	}

	if moved, err := store.RescheduleDelivery(context.Background(), claimed[0].ID, uuid.New(), now.Add(time.Minute)); err != nil || moved {
		t.Fatalf("moved=%v err=%v, want a stale owner refused", moved, err)
	}
	if moved, err := store.RescheduleDelivery(context.Background(), claimed[0].ID, claim, now.Add(time.Minute)); err != nil || !moved {
		t.Fatalf("moved=%v err=%v, want the lease owner to release it", moved, err)
	}

	early, err := store.ClaimDeliveries(context.Background(), uuid.New(), outboxBatch, outboxMaxAttempts, outboxLease,
		now.Add(30*time.Second))
	if err != nil {
		t.Fatalf("claiming failed: %v", err)
	}
	if len(early) != 0 {
		t.Fatal("work was taken before the instant it was moved to")
	}
	due, err := store.ClaimDeliveries(context.Background(), uuid.New(), outboxBatch, outboxMaxAttempts, outboxLease,
		now.Add(time.Minute))
	if err != nil {
		t.Fatalf("claiming failed: %v", err)
	}
	if len(due) != 1 {
		t.Fatalf("claimed %d deliveries when due, want one", len(due))
	}
	if outstanding := deliveryCount(t, pool); outstanding != 1 {
		t.Fatalf("outstanding = %d, want the work still queued", outstanding)
	}
}

func TestAnAcceptedMessageRemovesItsRowOnce(t *testing.T) {
	store, pool := freshStore(t)
	address := freshAddress(t)
	now := time.Now().UTC()

	if _, err := store.Register(context.Background(), address, firstHash, challengeLifetimes(), now); err != nil {
		t.Fatalf("registering failed: %v", err)
	}
	claim := uuid.New()
	claimed, err := store.ClaimDeliveries(context.Background(), claim, outboxBatch, outboxMaxAttempts, outboxLease, now)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claiming failed: %d %v", len(claimed), err)
	}

	removed, err := store.SettleDelivery(context.Background(), claimed[0].ID, claim)
	if err != nil || !removed {
		t.Fatalf("removed=%v err=%v, want the work removed", removed, err)
	}
	if outstanding := deliveryCount(t, pool); outstanding != 0 {
		t.Fatalf("outstanding = %d, want nothing left", outstanding)
	}
	// Removing it again reports that nothing was there, so no caller can conclude
	// a second message is owed.
	if removed, err := store.SettleDelivery(context.Background(), claimed[0].ID, claim); err != nil || removed {
		t.Fatalf("removed=%v err=%v, want no second removal", removed, err)
	}
	if _, err := store.SweepDeliveries(context.Background(), outboxBatch, outboxMaxAttempts, now); err != nil {
		t.Fatalf("sweeping failed: %v", err)
	}
}

func deliveryCount(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var outstanding int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM account_email_deliveries`).
		Scan(&outstanding); err != nil {
		t.Fatalf("counting the deliveries failed: %v", err)
	}
	return outstanding
}

var _ = authstore.ErrNotFound

// cleanableQueue writes n registrations and moves every challenge past its
// expiry, so every delivery is work no attempt could complete.
func cleanableQueue(t *testing.T, store *authstore.Store, pool *pgxpool.Pool, n int, now time.Time) {
	t.Helper()
	for i := 0; i < n; i++ {
		address := freshAddress(t)
		if _, err := store.Register(context.Background(), address, firstHash, challengeLifetimes(), now); err != nil {
			t.Fatalf("registering failed: %v", err)
		}
	}
	if _, err := pool.Exec(context.Background(),
		`UPDATE account_email_verifications SET issued_at = $1, expires_at = $2`,
		now.Add(-2*time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatalf("ageing the challenges failed: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`UPDATE account_email_deliveries SET created_at = $1, available_at = $1, expires_at = $2`,
		now.Add(-3*time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatalf("ageing the deliveries failed: %v", err)
	}
	if outstanding := deliveryCount(t, pool); outstanding != n {
		t.Fatalf("outstanding = %d, want %d cleanable rows", outstanding, n)
	}
}

// TestASweepNeverRemovesMoreThanItsBatch bounds the work one tick does, whatever
// the queue holds, and shows that repeated ticks still drain it.
func TestASweepNeverRemovesMoreThanItsBatch(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC()
	const cleanable, batch = 10, 3
	cleanableQueue(t, store, pool, cleanable, now)

	removed, err := store.SweepDeliveries(context.Background(), batch, outboxMaxAttempts, now)
	if err != nil {
		t.Fatalf("sweeping failed: %v", err)
	}
	if removed != batch {
		t.Fatalf("one tick removed %d rows, want at most the batch of %d", removed, batch)
	}
	if outstanding := deliveryCount(t, pool); outstanding != cleanable-batch {
		t.Fatalf("outstanding = %d, want %d", outstanding, cleanable-batch)
	}

	ticks := 1
	for deliveryCount(t, pool) > 0 {
		removed, err := store.SweepDeliveries(context.Background(), batch, outboxMaxAttempts, now)
		if err != nil {
			t.Fatalf("tick %d failed: %v", ticks+1, err)
		}
		if removed > batch {
			t.Fatalf("tick %d removed %d rows, want at most %d", ticks+1, removed, batch)
		}
		ticks++
		if ticks > cleanable {
			t.Fatal("the ticks stopped making progress")
		}
	}
	if want := (cleanable + batch - 1) / batch; ticks != want {
		t.Fatalf("the queue drained in %d ticks, want %d", ticks, want)
	}
}

// TestConcurrentSweepsRemoveEachRowOnce keeps two dispatchers from disagreeing
// about the same row: the deletes are bounded and each row leaves once.
func TestConcurrentSweepsRemoveEachRowOnce(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC()
	const cleanable = 12
	cleanableQueue(t, store, pool, cleanable, now)
	deadlocksBefore := deadlockCount(t, pool)

	const sweepers = 4
	removed := make(chan int64, sweepers)
	var done sync.WaitGroup
	for i := 0; i < sweepers; i++ {
		done.Add(1)
		go func() {
			defer done.Done()
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			count, err := store.SweepDeliveries(ctx, cleanable, outboxMaxAttempts, now)
			if err != nil {
				removed <- -1
				return
			}
			removed <- count
		}()
	}
	done.Wait()
	close(removed)

	var total int64
	for count := range removed {
		if count < 0 {
			t.Fatal("a concurrent sweep failed")
		}
		total += count
	}
	if total != cleanable {
		t.Fatalf("%d removals for %d rows, want each row removed exactly once", total, cleanable)
	}
	if outstanding := deliveryCount(t, pool); outstanding != 0 {
		t.Fatalf("outstanding = %d, want nothing left", outstanding)
	}
	if after := deadlockCount(t, pool); after != deadlocksBefore {
		t.Fatalf("deadlocks moved from %d to %d", deadlocksBefore, after)
	}
}

// TestASweepLeavesWorkUnderALiveLease keeps a dispatcher's in-flight work from
// being removed under it, for either cause, until its lease has lapsed. The
// instants are chosen so both causes apply while the lease is still running.
func TestASweepLeavesWorkUnderALiveLease(t *testing.T) {
	store, pool := freshStore(t)
	claimedAt := time.Now().UTC()
	address := freshAddress(t)
	if _, err := store.Register(context.Background(), address, firstHash, challengeLifetimes(), claimedAt); err != nil {
		t.Fatalf("registering failed: %v", err)
	}

	claim := uuid.New()
	claimed, err := store.ClaimDeliveries(context.Background(), claim, outboxBatch, outboxMaxAttempts,
		outboxLease, claimedAt)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claiming failed: %d %v", len(claimed), err)
	}

	// The work is now cleanable by both causes, and its lease runs until
	// claimedAt plus the lease.
	if _, err := pool.Exec(context.Background(),
		`UPDATE account_email_deliveries SET attempts = $1, expires_at = $2`,
		outboxMaxAttempts, claimedAt.Add(time.Minute)); err != nil {
		t.Fatalf("making the work cleanable failed: %v", err)
	}

	live := claimedAt.Add(90 * time.Second)
	removed, err := store.SweepDeliveries(context.Background(), outboxBatch, outboxMaxAttempts, live)
	if err != nil {
		t.Fatalf("sweeping failed: %v", err)
	}
	if removed != 0 {
		t.Fatalf("the sweep removed %d rows a dispatcher still holds", removed)
	}
	if outstanding := deliveryCount(t, pool); outstanding != 1 {
		t.Fatalf("outstanding = %d, want the leased work untouched", outstanding)
	}

	lapsed := claimedAt.Add(outboxLease)
	removed, err = store.SweepDeliveries(context.Background(), outboxBatch, outboxMaxAttempts, lapsed)
	if err != nil {
		t.Fatalf("sweeping failed: %v", err)
	}
	if removed != 1 {
		t.Fatalf("the sweep removed %d rows after the lease lapsed, want one", removed)
	}
}
