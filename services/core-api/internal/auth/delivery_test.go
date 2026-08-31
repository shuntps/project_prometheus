package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/emailverification"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

var sendRefused = errors.New("the transport refused")

// outbox is the queue as the dispatcher sees it, with each answer chosen by the
// test rather than by a store.
type outbox struct {
	claim        []auth.ClaimedDelivery
	claimErr     error
	sweepErr     error
	settled      []emailverification.DeliveryID
	settledOK    bool
	settleErr    error
	rescheduled  map[emailverification.DeliveryID]time.Time
	rescheduleOK bool
	claims       []uuid.UUID
}

func (o *outbox) ClaimDeliveries(_ context.Context, claim uuid.UUID, _, _ int, _ time.Duration, _ time.Time) ([]auth.ClaimedDelivery, error) {
	o.claims = append(o.claims, claim)
	return o.claim, o.claimErr
}

func (o *outbox) SettleDelivery(_ context.Context, id emailverification.DeliveryID, _ uuid.UUID) (bool, error) {
	o.settled = append(o.settled, id)
	return o.settledOK, o.settleErr
}

func (o *outbox) RescheduleDelivery(_ context.Context, id emailverification.DeliveryID, _ uuid.UUID, at time.Time) (bool, error) {
	if o.rescheduled == nil {
		o.rescheduled = map[emailverification.DeliveryID]time.Time{}
	}
	o.rescheduled[id] = at
	return o.rescheduleOK, nil
}

func (o *outbox) SweepDeliveries(context.Context, int, int, time.Time) (int64, error) {
	return 0, o.sweepErr
}

// transport records what it was handed, so a duplicate is observed by identifier
// rather than inferred.
type transport struct {
	sent []emailverification.DeliveryID
	fail bool
}

func (s *transport) Send(_ context.Context, message emailverification.Message) error {
	s.sent = append(s.sent, message.Delivery)
	if s.fail {
		return sendRefused
	}
	return nil
}

// testLink stands for the composition's builder: the dispatcher receives one and
// never knows what a public origin is.
func testLink(token emailverification.Token) string {
	return "https://app.example.com/verify-email#token=" + token.Reveal()
}

func deliveryPolicy() emailverification.DeliveryPolicy {
	return emailverification.DeliveryPolicy{
		Interval: 5 * time.Second, Batch: 16, MaxAttempts: 3,
		Lease: 2 * time.Minute, SendTimeout: 30 * time.Second,
		Backoff: 30 * time.Second,
	}
}

func claimed(t *testing.T, attempts int, expires time.Time) auth.ClaimedDelivery {
	t.Helper()
	identity, err := iam.NewIdentityID()
	if err != nil {
		t.Fatalf("drawing an identity identifier failed: %v", err)
	}
	_, token, err := emailverification.Issue(identity, challengeLifetimes, fixedNow)
	if err != nil {
		t.Fatalf("issuing failed: %v", err)
	}
	delivery, err := emailverification.NewDeliveryID()
	if err != nil {
		t.Fatalf("drawing a delivery identifier failed: %v", err)
	}
	address, err := iam.NormaliseEmail("recipient@example.invalid")
	if err != nil {
		t.Fatalf("normalising the address failed: %v", err)
	}
	return auth.ClaimedDelivery{ID: delivery, Address: address, Token: token, ExpiresAt: expires, Attempts: attempts}
}

func dispatcher(t *testing.T, queue *outbox, out *transport) *auth.Deliveries {
	t.Helper()
	built, err := auth.NewDeliveries(auth.DeliveryOptions{
		Repository: queue, Sender: out, Link: testLink, Policy: deliveryPolicy(), Now: clock(),
	})
	if err != nil {
		t.Fatalf("building the dispatcher failed: %v", err)
	}
	return built
}

func TestAnAcceptedMessageRemovesItsWork(t *testing.T) {
	one := claimed(t, 1, fixedNow.Add(time.Hour))
	queue := &outbox{claim: []auth.ClaimedDelivery{one}, settledOK: true}
	out := &transport{}

	result, err := dispatcher(t, queue, out).Dispatch(context.Background())
	if err != nil {
		t.Fatalf("the tick failed: %v", err)
	}
	if result.Delivered != 1 || result.Rescheduled != 0 || result.Lost != 0 {
		t.Fatalf("result = %+v, want one delivery", result)
	}
	if len(out.sent) != 1 || len(queue.settled) != 1 || queue.settled[0] != one.ID {
		t.Fatalf("sent=%d settled=%v, want the accepted work removed", len(out.sent), queue.settled)
	}
}

// TestALostLeaseRecreatesNothing is the race a verification, a supersession or an
// expiry opens: the row is gone by the time the outcome is recorded, and the
// dispatcher must not put it back.
func TestALostLeaseRecreatesNothing(t *testing.T) {
	one := claimed(t, 1, fixedNow.Add(time.Hour))
	queue := &outbox{claim: []auth.ClaimedDelivery{one}, settledOK: false}
	out := &transport{}

	result, err := dispatcher(t, queue, out).Dispatch(context.Background())
	if err != nil {
		t.Fatalf("the tick failed: %v", err)
	}
	if result.Lost != 1 || result.Delivered != 0 {
		t.Fatalf("result = %+v, want the lease reported lost", result)
	}
	if len(out.sent) != 1 {
		t.Fatal("the message was not sent, so the race is not the one being proven")
	}
	if len(queue.rescheduled) != 0 {
		t.Fatal("work was put back after its row had gone")
	}
}

func TestARefusedMessageIsRescheduledUntilItsAttemptsAreSpent(t *testing.T) {
	one := claimed(t, 1, fixedNow.Add(time.Hour))
	queue := &outbox{claim: []auth.ClaimedDelivery{one}, rescheduleOK: true}
	out := &transport{fail: true}

	result, err := dispatcher(t, queue, out).Dispatch(context.Background())
	if err != nil {
		t.Fatalf("the tick failed: %v", err)
	}
	if result.Rescheduled != 1 || result.Discarded != 0 {
		t.Fatalf("result = %+v, want one reschedule", result)
	}
	if at := queue.rescheduled[one.ID]; !at.Equal(fixedNow.Add(30 * time.Second)) {
		t.Fatalf("next attempt at %s, want the first backoff", at)
	}

	// The last permitted attempt is not rescheduled: the work is removed instead.
	last := claimed(t, deliveryPolicy().MaxAttempts, fixedNow.Add(time.Hour))
	spent := &outbox{claim: []auth.ClaimedDelivery{last}, settledOK: true}
	result, err = dispatcher(t, spent, &transport{fail: true}).Dispatch(context.Background())
	if err != nil {
		t.Fatalf("the tick failed: %v", err)
	}
	if result.Discarded != 1 || result.Rescheduled != 0 {
		t.Fatalf("result = %+v, want the spent work removed", result)
	}
}

// TestABackoffPastTheExpiryRemovesTheWork keeps the queue from holding a row
// whose challenge will have expired before its next attempt.
func TestABackoffPastTheExpiryRemovesTheWork(t *testing.T) {
	one := claimed(t, 1, fixedNow.Add(10*time.Second))
	queue := &outbox{claim: []auth.ClaimedDelivery{one}, settledOK: true, rescheduleOK: true}

	result, err := dispatcher(t, queue, &transport{fail: true}).Dispatch(context.Background())
	if err != nil {
		t.Fatalf("the tick failed: %v", err)
	}
	if result.Discarded != 1 || result.Rescheduled != 0 {
		t.Fatalf("result = %+v, want the work removed rather than moved past its expiry", result)
	}
	if len(queue.rescheduled) != 0 {
		t.Fatal("work was scheduled beyond the instant it could still be done")
	}
}

// TestOnlyAnUndecidedStoreStopsATick keeps a transport failure from being
// reported as a reason to stop the service.
func TestOnlyAnUndecidedStoreStopsATick(t *testing.T) {
	if _, err := dispatcher(t, &outbox{sweepErr: storeDown}, &transport{}).Dispatch(context.Background()); err == nil {
		t.Error("a sweep that could not be decided was tolerated")
	}
	if _, err := dispatcher(t, &outbox{claimErr: storeDown}, &transport{}).Dispatch(context.Background()); err == nil {
		t.Error("a claim that could not be decided was tolerated")
	}
	one := claimed(t, 1, fixedNow.Add(time.Hour))
	queue := &outbox{claim: []auth.ClaimedDelivery{one}, settleErr: storeDown}
	if _, err := dispatcher(t, queue, &transport{}).Dispatch(context.Background()); err == nil {
		t.Error("an outcome that could not be recorded was tolerated")
	}

	refused := &outbox{claim: []auth.ClaimedDelivery{one}, rescheduleOK: true}
	if _, err := dispatcher(t, refused, &transport{fail: true}).Dispatch(context.Background()); err != nil {
		t.Errorf("a refused message stopped the tick: %v", err)
	}
}

// TestEachTickCarriesItsOwnLeaseOwner is what makes a stale write refusable: two
// ticks never present the same owner.
func TestEachTickCarriesItsOwnLeaseOwner(t *testing.T) {
	queue := &outbox{}
	dispatch := dispatcher(t, queue, &transport{})
	for i := 0; i < 3; i++ {
		if _, err := dispatch.Dispatch(context.Background()); err != nil {
			t.Fatalf("tick %d failed: %v", i, err)
		}
	}
	seen := map[uuid.UUID]bool{}
	for _, claim := range queue.claims {
		if seen[claim] {
			t.Fatal("two ticks presented the same lease owner")
		}
		seen[claim] = true
	}
}
