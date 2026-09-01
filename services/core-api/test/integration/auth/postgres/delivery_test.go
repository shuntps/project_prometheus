package integration_test

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/emailverification"
	"github.com/shuntps/project_prometheus/services/core-api/internal/browser"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/authstore"
)

// collector stands in for the transport. It records what it was handed, so a
// duplicate is observed by identifier rather than inferred.
type collector struct {
	mu       sync.Mutex
	sent     []emailverification.Message
	onSend   func(emailverification.Message)
	failNext bool
}

func (c *collector) Send(_ context.Context, message emailverification.Message) error {
	c.mu.Lock()
	c.sent = append(c.sent, message)
	hook := c.onSend
	fail := c.failNext
	c.failNext = false
	c.mu.Unlock()
	if hook != nil {
		hook(message)
	}
	if fail {
		return context.DeadlineExceeded
	}
	return nil
}

func (c *collector) delivered() []emailverification.Message {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]emailverification.Message(nil), c.sent...)
}

// interrupted stands for a process that dies between the transport accepting a
// message and the row being removed. Its lease is left behind exactly as a dead
// process would leave it.
type interrupted struct {
	auth.DeliveryRepository
	skipSettle bool
}

func (i *interrupted) SettleDelivery(ctx context.Context, id emailverification.DeliveryID, claim uuid.UUID) (bool, error) {
	if i.skipSettle {
		return true, nil
	}
	return i.DeliveryRepository.SettleDelivery(ctx, id, claim)
}

func deliveryPolicy() emailverification.DeliveryPolicy {
	return emailverification.DeliveryPolicy{
		Interval: time.Second, Batch: 8, MaxAttempts: 3,
		Lease: 2 * time.Minute, SendTimeout: 30 * time.Second,
		Backoff: 30 * time.Second,
	}
}

// testOrigin is the browser boundary the composition would supply. The link is
// built there, never inside the authentication domain.
var testOrigin = mustOrigin("https://app.example.com")

func mustOrigin(raw string) browser.Origin {
	origin, err := browser.ParseOrigin(raw)
	if err != nil {
		panic(err)
	}
	return origin
}

func newDispatcher(t *testing.T, repository auth.DeliveryRepository, sender auth.VerificationSender,
	now func() time.Time) *auth.Deliveries {
	t.Helper()
	built, err := auth.NewDeliveries(auth.DeliveryOptions{
		Repository: repository, Sender: sender, Policy: deliveryPolicy(), Now: now,
		Link: func(token emailverification.Token) string {
			return testOrigin.VerificationLink(token.Reveal())
		},
	})
	if err != nil {
		t.Fatalf("building the dispatcher failed: %v", err)
	}
	return built
}

func repositoryOf(t *testing.T, pool *pgxpool.Pool) authstore.Repository {
	t.Helper()
	store, err := authstore.New(pool)
	if err != nil {
		t.Fatalf("building the store failed: %v", err)
	}
	repository, err := authstore.NewRepository(store)
	if err != nil {
		t.Fatalf("building the repository failed: %v", err)
	}
	return repository
}

func TestAQueuedVerificationReachesTheTransportOnceAndLeavesTheQueue(t *testing.T) {
	store, pool := freshStore(t)
	address := freshAddress(t)
	now := time.Now().UTC()

	if _, err := store.Register(context.Background(), address, firstHash, challengeLifetimes(), now); err != nil {
		t.Fatalf("registering failed: %v", err)
	}
	out := &collector{}
	dispatcher := newDispatcher(t, repositoryOf(t, pool), out, func() time.Time { return now })

	result, err := dispatcher.Dispatch(context.Background())
	if err != nil {
		t.Fatalf("the tick failed: %v", err)
	}
	if result.Delivered != 1 || result.Lost != 0 {
		t.Fatalf("result = %+v, want one delivery", result)
	}
	sent := out.delivered()
	if len(sent) != 1 {
		t.Fatalf("the transport received %d messages, want one", len(sent))
	}
	if sent[0].To.Reveal() != address.Reveal() {
		t.Fatal("the message went to the wrong address")
	}
	// The token travels in the fragment, so nothing a request carries holds it.
	parsed, err := url.Parse(sent[0].Link)
	if err != nil {
		t.Fatalf("the delivered link is not a URL: %v", err)
	}
	if parsed.Path != browser.VerificationPath || parsed.RawQuery != "" {
		t.Fatalf("link = %q, want the reserved path and no query", sent[0].Link)
	}
	if strings.Contains(parsed.RequestURI(), "token") {
		t.Fatalf("request URI %q carries the token", parsed.RequestURI())
	}
	if deliveryCount(t, pool) != 0 {
		t.Fatal("accepted work stayed in the queue")
	}

	// A second tick has nothing to do, so no message is owed twice in the nominal
	// path.
	if result, err = dispatcher.Dispatch(context.Background()); err != nil || result.Claimed != 0 {
		t.Fatalf("result = %+v, err = %v, want an empty tick", result, err)
	}
	if len(out.delivered()) != 1 {
		t.Fatal("the nominal path sent a second message")
	}
}

// TestAMessageMayBeSentTwiceAfterAnInterruptedTick is the contract, proven rather
// than hidden: a process that dies between the transport accepting and the row
// being removed leaves work another tick will do again.
func TestAMessageMayBeSentTwiceAfterAnInterruptedTick(t *testing.T) {
	store, pool := freshStore(t)
	address := freshAddress(t)
	now := time.Now().UTC()

	if _, err := store.Register(context.Background(), address, firstHash, challengeLifetimes(), now); err != nil {
		t.Fatalf("registering failed: %v", err)
	}
	out := &collector{}
	dying := &interrupted{DeliveryRepository: repositoryOf(t, pool), skipSettle: true}

	clock := now
	dispatcher := newDispatcher(t, dying, out, func() time.Time { return clock })
	if _, err := dispatcher.Dispatch(context.Background()); err != nil {
		t.Fatalf("the interrupted tick failed: %v", err)
	}
	if len(out.delivered()) != 1 {
		t.Fatalf("the transport received %d messages before the interruption, want one", len(out.delivered()))
	}
	if deliveryCount(t, pool) != 1 {
		t.Fatal("the interrupted tick removed its work, so nothing is being proven")
	}

	// Inside the lease nothing takes it: the interruption costs nothing yet.
	clock = now.Add(time.Minute)
	if _, err := dispatcher.Dispatch(context.Background()); err != nil {
		t.Fatalf("the tick inside the lease failed: %v", err)
	}
	if len(out.delivered()) != 1 {
		t.Fatal("work under a live lease was sent again")
	}

	// Past the lease it is recovered, and the same message goes out a second time.
	clock = now.Add(3 * time.Minute)
	dying.skipSettle = false
	if _, err := dispatcher.Dispatch(context.Background()); err != nil {
		t.Fatalf("the recovering tick failed: %v", err)
	}
	sent := out.delivered()
	if len(sent) != 2 {
		t.Fatalf("the transport received %d messages, want the duplicate the contract permits", len(sent))
	}
	if sent[0].Delivery != sent[1].Delivery {
		t.Fatal("the duplicate carried a different identifier, so no transport could deduplicate it")
	}
	if deliveryCount(t, pool) != 0 {
		t.Fatal("the recovered work stayed in the queue")
	}
}

// TestAMessageMadeObsoleteDuringTheCallIsNotRecalled is the race a verification
// opens: the row is gone by the time the outcome is recorded, the message was
// already in flight, and the token it carries is refused on arrival.
func TestAMessageMadeObsoleteDuringTheCallIsNotRecalled(t *testing.T) {
	store, pool := freshStore(t)
	address := freshAddress(t)
	now := time.Now().UTC()

	if _, err := store.Register(context.Background(), address, firstHash, challengeLifetimes(), now); err != nil {
		t.Fatalf("registering failed: %v", err)
	}
	token := tokenFor(t, pool, address)

	// The address is verified while the transport still holds the message.
	out := &collector{onSend: func(emailverification.Message) {
		if _, err := store.ConsumeVerification(context.Background(), token.Fingerprint(), now); err != nil {
			t.Errorf("verifying during the call failed: %v", err)
		}
	}}
	dispatcher := newDispatcher(t, repositoryOf(t, pool), out, func() time.Time { return now })

	result, err := dispatcher.Dispatch(context.Background())
	if err != nil {
		t.Fatalf("the tick failed: %v", err)
	}
	if len(out.delivered()) != 1 {
		t.Fatalf("the transport received %d messages, want the one already in flight", len(out.delivered()))
	}
	if result.Lost != 1 || result.Delivered != 0 {
		t.Fatalf("result = %+v, want the row reported gone", result)
	}
	if deliveryCount(t, pool) != 0 {
		t.Fatal("the obsolete work was put back")
	}

	// The message may arrive; the token it carries no longer opens anything.
	if _, err := store.ConsumeVerification(context.Background(), token.Fingerprint(), now); err != nil {
		t.Fatalf("the replay was refused rather than answered idempotently: %v", err)
	}
	stored, _ := readRegistration(t, pool, address)
	if got := eventCount(t, pool, stored.account, "email_verification_completed"); got != 1 {
		t.Fatalf("completion events = %d, want one", got)
	}
}

// TestARefusedTransportKeepsTheWorkUntilItsAttemptsAreSpent walks the whole
// retry path against the real queue.
func TestARefusedTransportKeepsTheWorkUntilItsAttemptsAreSpent(t *testing.T) {
	store, pool := freshStore(t)
	address := freshAddress(t)
	now := time.Now().UTC()

	if _, err := store.Register(context.Background(), address, firstHash, challengeLifetimes(), now); err != nil {
		t.Fatalf("registering failed: %v", err)
	}
	out := &collector{}
	clock := now
	dispatcher := newDispatcher(t, repositoryOf(t, pool), out, func() time.Time { return clock })

	policy := deliveryPolicy()
	for attempt := 1; attempt <= policy.MaxAttempts; attempt++ {
		out.failNext = true
		result, err := dispatcher.Dispatch(context.Background())
		if err != nil {
			t.Fatalf("attempt %d failed: %v", attempt, err)
		}
		if attempt < policy.MaxAttempts {
			if result.Rescheduled != 1 {
				t.Fatalf("attempt %d: result = %+v, want a reschedule", attempt, result)
			}
			clock = clock.Add(policy.Backoff * 8)
			continue
		}
		if result.Discarded != 1 {
			t.Fatalf("the last attempt: result = %+v, want the work removed", result)
		}
	}
	if len(out.delivered()) != policy.MaxAttempts {
		t.Fatalf("the transport was called %d times, want %d", len(out.delivered()), policy.MaxAttempts)
	}
	if deliveryCount(t, pool) != 0 {
		t.Fatal("spent work stayed in the queue")
	}
}
