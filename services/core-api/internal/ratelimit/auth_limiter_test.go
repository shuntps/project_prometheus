package ratelimit_test

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
	"github.com/shuntps/project_prometheus/services/core-api/internal/ratelimit"
)

func policy(client, identity int) ratelimit.AuthPolicy {
	return ratelimit.AuthPolicy{
		ClientAttempts:   client,
		IdentityAttempts: identity,
		Window:           15 * time.Minute,
		Capacity:         ratelimit.MinAuthCapacity,
	}
}

func limiter(t *testing.T, p ratelimit.AuthPolicy) *ratelimit.AuthLimiter {
	t.Helper()
	made, err := ratelimit.NewAuthLimiter(p)
	if err != nil {
		t.Fatalf("building the limiter failed: %v", err)
	}
	return made
}

func TestTheClientDimensionBoundsOneClient(t *testing.T) {
	l := limiter(t, policy(3, 1_000))
	now := time.Unix(1_700_000_000, 0).UTC()

	for attempt := 1; attempt <= 3; attempt++ {
		if !l.Allow("198.51.100.7", fmt.Sprintf("user%d@example.com", attempt), now) {
			t.Fatalf("attempt %d was refused before the client bound", attempt)
		}
	}
	// A fresh address does not buy the same client another attempt.
	if l.Allow("198.51.100.7", "never-seen@example.com", now) {
		t.Fatal("varying only the address granted a new quota")
	}
	// Another client is unaffected.
	if !l.Allow("198.51.100.8", "never-seen@example.com", now) {
		t.Fatal("one client's exhaustion refused another")
	}
}

func TestTheIdentityDimensionBoundsOneAddressAcrossClients(t *testing.T) {
	l := limiter(t, policy(1_000, 3))
	now := time.Unix(1_700_000_000, 0).UTC()

	for attempt := 1; attempt <= 3; attempt++ {
		if !l.Allow(fmt.Sprintf("198.51.100.%d", attempt), "victim@example.com", now) {
			t.Fatalf("attempt %d was refused before the identity bound", attempt)
		}
	}
	// A fresh client does not buy another attempt against the same address, which
	// is what a distributed credential-stuffing run would rely on.
	if l.Allow("203.0.113.44", "victim@example.com", now) {
		t.Fatal("varying only the client granted a new quota")
	}
	// Another address from that same fresh client is still allowed.
	if !l.Allow("203.0.113.44", "someone-else@example.com", now) {
		t.Fatal("one address's exhaustion refused another")
	}
}

// TestTheIdentifierIsCanonicalisedSoCaseAndSpaceDoNotSplitTheQuota keeps a
// trivial rewriting of the address from starting a new counter.
func TestTheIdentifierIsCanonicalisedSoCaseAndSpaceDoNotSplitTheQuota(t *testing.T) {
	l := limiter(t, policy(1_000, 2))
	now := time.Unix(1_700_000_000, 0).UTC()

	if !l.Allow("198.51.100.7", "victim@example.com", now) {
		t.Fatal("the first attempt was refused")
	}
	if !l.Allow("198.51.100.8", "  VICTIM@Example.com  ", now) {
		t.Fatal("the second attempt was refused")
	}
	if l.Allow("198.51.100.9", "Victim@EXAMPLE.com", now) {
		t.Fatal("a rewritten address escaped the identity bound")
	}
}

// TestExhaustionExpiresRatherThanLocking is the property that keeps an attacker
// from denying a victim their own account by exhausting its counter.
func TestExhaustionExpiresRatherThanLocking(t *testing.T) {
	p := policy(2, 2)
	l := limiter(t, p)
	now := time.Unix(1_700_000_000, 0).UTC()

	for attempt := 1; attempt <= 2; attempt++ {
		if !l.Allow("198.51.100.7", "victim@example.com", now) {
			t.Fatalf("attempt %d was refused before the bound", attempt)
		}
	}
	if l.Allow("198.51.100.7", "victim@example.com", now) {
		t.Fatal("the bound was not enforced")
	}
	// Still refused just before the window closes.
	if l.Allow("198.51.100.7", "victim@example.com", now.Add(p.Window-time.Second)) {
		t.Fatal("the window ended early")
	}
	// Recovered once it has passed, from any client.
	if !l.Allow("203.0.113.44", "victim@example.com", now.Add(p.Window)) {
		t.Fatal("the address stayed locked after its window")
	}
	if !l.Allow("198.51.100.7", "victim@example.com", now.Add(p.Window)) {
		t.Fatal("the client stayed locked after its window")
	}
}

// TestARefusedAttemptChargesNothing keeps one exhausted dimension from pushing
// the other one further from its own recovery.
func TestARefusedAttemptChargesNothing(t *testing.T) {
	l := limiter(t, policy(1, 1_000))
	now := time.Unix(1_700_000_000, 0).UTC()

	if !l.Allow("198.51.100.7", "victim@example.com", now) {
		t.Fatal("the first attempt was refused")
	}
	// The client is exhausted; these attempts must not consume the address quota.
	for i := 0; i < 50; i++ {
		if l.Allow("198.51.100.7", "victim@example.com", now) {
			t.Fatal("the client bound was not enforced")
		}
	}
	// The address has spent exactly one attempt, so a different client still has
	// the remaining allowance against it.
	if !l.Allow("203.0.113.44", "victim@example.com", now) {
		t.Fatal("refused attempts were charged to the address")
	}
}

func TestConcurrentAttemptsNeverExceedTheBound(t *testing.T) {
	const allowed = 25
	l := limiter(t, policy(allowed, ratelimit.MaxAuthAttempts))
	now := time.Unix(1_700_000_000, 0).UTC()

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		granted int
	)
	for i := 0; i < 400; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if l.Allow("198.51.100.7", fmt.Sprintf("user%d@example.com", i), now) {
				mu.Lock()
				granted++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if granted != allowed {
		t.Fatalf("%d attempts were granted, want exactly %d", granted, allowed)
	}
}

// TestAnUnusualClockNeverGrantsMoreThanTheBound: neither a jump forward nor a
// jump backward may hand a caller attempts the window has not returned.
func TestAnUnusualClockNeverGrantsMoreThanTheBound(t *testing.T) {
	p := policy(2, 2)
	base := time.Unix(1_700_000_000, 0).UTC()

	t.Run("a rewind does not reopen an exhausted bound", func(t *testing.T) {
		l := limiter(t, p)
		for attempt := 1; attempt <= 2; attempt++ {
			if !l.Allow("198.51.100.7", "victim@example.com", base) {
				t.Fatalf("attempt %d was refused before the bound", attempt)
			}
		}
		for _, rewind := range []time.Duration{time.Second, time.Hour, 48 * time.Hour} {
			if l.Allow("198.51.100.7", "victim@example.com", base.Add(-rewind)) {
				t.Fatalf("a clock %s behind reopened an exhausted bound", rewind)
			}
		}
		// The bound is still exactly where it was once the clock is back.
		if l.Allow("198.51.100.7", "victim@example.com", base) {
			t.Fatal("the rewind left the bound spent")
		}
	})

	t.Run("a jump forward grants one window, not several", func(t *testing.T) {
		l := limiter(t, p)
		granted := 0
		// Ten windows pass at once; the counter starts over once, not ten times.
		for attempt := 0; attempt < 10; attempt++ {
			if l.Allow("198.51.100.7", "victim@example.com", base.Add(10*p.Window)) {
				granted++
			}
		}
		if granted != p.ClientAttempts {
			t.Fatalf("%d attempts were granted after the jump, want exactly %d", granted, p.ClientAttempts)
		}
	})
}

// TestUnusualInputsAreCountedRatherThanRefusedOrSplit: the limiter is charged on
// what was presented, before any validation, so nothing it receives may escape.
func TestUnusualInputsAreCountedRatherThanRefusedOrSplit(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	long := strings.Repeat("a", 100_000) + "@example.com"
	for name, value := range map[string]string{
		"empty":            "",
		"spaces only":      "   ",
		"extremely long":   long,
		"non ASCII":        "vïctïm@exämple.com",
		"control bytes":    "victim\x00@example.com",
		"invalid encoding": "victim\xff@example.com",
	} {
		t.Run("identity "+name, func(t *testing.T) {
			l := limiter(t, policy(1_000, 2))
			for attempt := 1; attempt <= 2; attempt++ {
				if !l.Allow("198.51.100.7", value, now) {
					t.Fatalf("attempt %d was refused before the bound", attempt)
				}
			}
			if l.Allow("203.0.113.44", value, now) {
				t.Fatal("the identity bound was not enforced")
			}
		})
		t.Run("client "+name, func(t *testing.T) {
			l := limiter(t, policy(2, 1_000))
			for attempt := 1; attempt <= 2; attempt++ {
				if !l.Allow(value, fmt.Sprintf("user%d@example.com", attempt), now) {
					t.Fatalf("attempt %d was refused before the bound", attempt)
				}
			}
			if l.Allow(value, "another@example.com", now) {
				t.Fatal("the client bound was not enforced")
			}
		})
	}

	// An empty client and an empty identity are one counter each, not a shared
	// bucket with anything else presented.
	l := limiter(t, policy(1_000, 1))
	if !l.Allow("", "", now) {
		t.Fatal("an empty pair was refused")
	}
	if !l.Allow("", "someone@example.com", now) {
		t.Fatal("the empty identity's bound was charged to another address")
	}
}

// TestTheIdentifierIsCountedAsTheLoginJourneyResolvesIt keeps this package from
// holding a second, quietly different rule for what one address is.
func TestTheIdentifierIsCountedAsTheLoginJourneyResolvesIt(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	// Stated here rather than derived from either rule: forms a reader can check.
	same := [][2]string{
		{"victim@example.com", "VICTIM@EXAMPLE.COM"},
		{"victim@example.com", "  victim@example.com  "},
		{"victim@example.com", "Victim@Example.Com"},
		{"first.last@example.com", "First.Last@Example.com"},
	}
	for _, pair := range same {
		left, err := iam.NormaliseEmail(pair[0])
		if err != nil {
			t.Fatalf("the login journey refused %q: %v", pair[0], err)
		}
		right, err := iam.NormaliseEmail(pair[1])
		if err != nil {
			t.Fatalf("the login journey refused %q: %v", pair[1], err)
		}
		if left.Reveal() != right.Reveal() {
			t.Fatalf("the login journey separates %q and %q, so the pair proves nothing", pair[0], pair[1])
		}
		l := limiter(t, policy(1_000, 1))
		if !l.Allow("198.51.100.7", pair[0], now) {
			t.Fatalf("the first attempt on %q was refused", pair[0])
		}
		if l.Allow("203.0.113.44", pair[1], now) {
			t.Fatalf("%q started a second quota the login journey would have merged with %q", pair[1], pair[0])
		}
	}

	// Two addresses the login journey keeps apart must not share one counter.
	apart := [][2]string{
		{"victim@example.com", "victim+tag@example.com"},
		{"victim@example.com", "vict.im@example.com"},
		{"victim@example.com", "victim@mail.example.com"},
	}
	for _, pair := range apart {
		left, err := iam.NormaliseEmail(pair[0])
		if err != nil {
			t.Fatalf("the login journey refused %q: %v", pair[0], err)
		}
		right, err := iam.NormaliseEmail(pair[1])
		if err != nil {
			t.Fatalf("the login journey refused %q: %v", pair[1], err)
		}
		if left.Reveal() == right.Reveal() {
			t.Fatalf("the login journey merges %q and %q, so the pair proves nothing", pair[0], pair[1])
		}
		l := limiter(t, policy(1_000, 1))
		if !l.Allow("198.51.100.7", pair[0], now) {
			t.Fatalf("the first attempt on %q was refused", pair[0])
		}
		if !l.Allow("203.0.113.44", pair[1], now) {
			t.Fatalf("%q was charged to %q, which the login journey keeps apart", pair[1], pair[0])
		}
	}
}

// TestARefusalByOneDimensionLeavesTheOtherUncharged is the symmetric half of the
// refusal rule: whichever dimension refuses, neither may be charged for it.
func TestARefusalByOneDimensionLeavesTheOtherUncharged(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()

	t.Run("the identity refuses, the client keeps its allowance", func(t *testing.T) {
		l := limiter(t, policy(4, 1))
		if !l.Allow("198.51.100.7", "victim@example.com", now) {
			t.Fatal("the first attempt was refused")
		}
		// The address is spent; these attempts must not consume the client's.
		for i := 0; i < 50; i++ {
			if l.Allow("198.51.100.7", "victim@example.com", now) {
				t.Fatal("the identity bound was not enforced")
			}
		}
		// One attempt has been charged to the client, so three remain.
		for attempt := 2; attempt <= 4; attempt++ {
			if !l.Allow("198.51.100.7", fmt.Sprintf("other%d@example.com", attempt), now) {
				t.Fatalf("refusals by the identity were charged to the client: attempt %d refused", attempt)
			}
		}
		if l.Allow("198.51.100.7", "one-too-many@example.com", now) {
			t.Fatal("the client bound was not enforced")
		}
	})

	t.Run("the client refuses, the identity keeps its allowance", func(t *testing.T) {
		l := limiter(t, policy(1, 4))
		if !l.Allow("198.51.100.7", "victim@example.com", now) {
			t.Fatal("the first attempt was refused")
		}
		for i := 0; i < 50; i++ {
			if l.Allow("198.51.100.7", "victim@example.com", now) {
				t.Fatal("the client bound was not enforced")
			}
		}
		for attempt := 2; attempt <= 4; attempt++ {
			if !l.Allow(fmt.Sprintf("203.0.113.%d", attempt), "victim@example.com", now) {
				t.Fatalf("refusals by the client were charged to the identity: attempt %d refused", attempt)
			}
		}
		if l.Allow("203.0.113.99", "victim@example.com", now) {
			t.Fatal("the identity bound was not enforced")
		}
	})
}
