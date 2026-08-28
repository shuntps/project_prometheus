package ratelimit_test

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

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
	made, err := ratelimit.NewAuthLimiter(p, nil)
	if err != nil {
		t.Fatalf("building the limiter failed: %v", err)
	}
	return made
}

func TestAnIncompleteAuthPolicyIsRefused(t *testing.T) {
	valid := policy(10, 5)
	cases := map[string]ratelimit.AuthPolicy{
		"zero value":         {},
		"no client bound":    {ClientAttempts: 0, IdentityAttempts: 5, Window: valid.Window, Capacity: valid.Capacity},
		"no identity bound":  {ClientAttempts: 10, IdentityAttempts: 0, Window: valid.Window, Capacity: valid.Capacity},
		"no window":          {ClientAttempts: 10, IdentityAttempts: 5, Capacity: valid.Capacity},
		"window too long":    {ClientAttempts: 10, IdentityAttempts: 5, Window: 48 * time.Hour, Capacity: valid.Capacity},
		"no capacity":        {ClientAttempts: 10, IdentityAttempts: 5, Window: valid.Window},
		"capacity too small": {ClientAttempts: 10, IdentityAttempts: 5, Window: valid.Window, Capacity: ratelimit.MinAuthCapacity - 1},
		"client above bound": {ClientAttempts: ratelimit.MaxAuthAttempts + 1, IdentityAttempts: 5, Window: valid.Window, Capacity: valid.Capacity},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			if err := p.Validate(); err == nil {
				t.Fatal("an unusable policy was accepted")
			}
			if made, err := ratelimit.NewAuthLimiter(p, nil); err == nil || made != nil {
				t.Fatal("a limiter was built on an unusable policy")
			}
		})
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("a complete policy was refused: %v", err)
	}
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

// saturate fills one dimension with live counters, so the table holds only
// bounds that are still inside their window.
func saturate(t *testing.T, l *ratelimit.AuthLimiter, dimension string, now time.Time) {
	t.Helper()
	for i := 0; i < l.Policy().Capacity*2; i++ {
		switch dimension {
		case "identity":
			l.Allow("198.51.100.7", fmt.Sprintf("flood%d@example.com", i), now)
		case "client":
			l.Allow(fmt.Sprintf("10.%d.%d.%d", i/65536%256, i/256%256, i%256), "flood@example.com", now)
		default:
			t.Fatalf("unknown dimension %q", dimension)
		}
	}
}

// TestAnExhaustedIdentityStaysRefusedThroughSaturation is the property flooding
// would otherwise buy: filling the table must never discard a bound in force.
func TestAnExhaustedIdentityStaysRefusedThroughSaturation(t *testing.T) {
	p := policy(ratelimit.MaxAuthAttempts, 2)
	l := limiter(t, p)
	now := time.Unix(1_700_000_000, 0).UTC()

	for attempt := 1; attempt <= 2; attempt++ {
		if !l.Allow("198.51.100.7", "victim@example.com", now) {
			t.Fatalf("attempt %d was refused before the bound", attempt)
		}
	}
	if l.Allow("198.51.100.7", "victim@example.com", now) {
		t.Fatal("the identity bound was not enforced")
	}

	saturate(t, l, "identity", now)

	if l.Allow("198.51.100.7", "victim@example.com", now) {
		t.Fatal("saturation restored an exhausted identity")
	}
	if l.Allow("203.0.113.44", "victim@example.com", now) {
		t.Fatal("saturation restored an exhausted identity for another client")
	}
}

// TestAnExhaustedClientStaysRefusedThroughSaturation is the same property on the
// other dimension.
func TestAnExhaustedClientStaysRefusedThroughSaturation(t *testing.T) {
	p := policy(2, ratelimit.MaxAuthAttempts)
	l := limiter(t, p)
	now := time.Unix(1_700_000_000, 0).UTC()

	for attempt := 1; attempt <= 2; attempt++ {
		if !l.Allow("198.51.100.7", fmt.Sprintf("user%d@example.com", attempt), now) {
			t.Fatalf("attempt %d was refused before the bound", attempt)
		}
	}
	if l.Allow("198.51.100.7", "another@example.com", now) {
		t.Fatal("the client bound was not enforced")
	}

	saturate(t, l, "client", now)

	if l.Allow("198.51.100.7", "yet-another@example.com", now) {
		t.Fatal("saturation restored an exhausted client")
	}
}

// TestOneDimensionsSaturationCannotEvictTheOther keeps the two tables from
// competing: filling either must leave the other's bounds exactly as they were.
func TestOneDimensionsSaturationCannotEvictTheOther(t *testing.T) {
	t.Run("identity flood leaves the client bound", func(t *testing.T) {
		l := limiter(t, policy(2, ratelimit.MaxAuthAttempts))
		now := time.Unix(1_700_000_000, 0).UTC()
		for attempt := 1; attempt <= 2; attempt++ {
			if !l.Allow("198.51.100.7", fmt.Sprintf("user%d@example.com", attempt), now) {
				t.Fatalf("attempt %d was refused before the bound", attempt)
			}
		}
		saturate(t, l, "identity", now)
		if l.Allow("198.51.100.7", "fresh@example.com", now) {
			t.Fatal("flooding identifiers removed the client bound")
		}
	})

	t.Run("client flood leaves the identity bound", func(t *testing.T) {
		l := limiter(t, policy(ratelimit.MaxAuthAttempts, 2))
		now := time.Unix(1_700_000_000, 0).UTC()
		for attempt := 1; attempt <= 2; attempt++ {
			if !l.Allow(fmt.Sprintf("198.51.100.%d", attempt), "victim@example.com", now) {
				t.Fatalf("attempt %d was refused before the bound", attempt)
			}
		}
		saturate(t, l, "client", now)
		if l.Allow("203.0.113.99", "victim@example.com", now) {
			t.Fatal("flooding clients removed the identity bound")
		}
	})
}

// TestAFullDimensionRefusesAnUnseenKeyRatherThanDroppingABound: saturation fails
// closed, reducing what the instance accepts and never what it enforces.
func TestAFullDimensionRefusesAnUnseenKeyRatherThanDroppingABound(t *testing.T) {
	p := policy(ratelimit.MaxAuthAttempts, ratelimit.MaxAuthAttempts)
	l := limiter(t, p)
	now := time.Unix(1_700_000_000, 0).UTC()

	// One known client is charged before the flood, so it is inside the table.
	if !l.Allow("198.51.100.7", "known@example.com", now) {
		t.Fatal("the first attempt was refused")
	}
	saturate(t, l, "identity", now)

	if l.Allow("198.51.100.7", "never-seen@example.com", now) {
		t.Fatal("a full identity table admitted an unseen key")
	}
	// The known identifier still has its own allowance, so saturation refuses new
	// keys without disturbing the counters already held.
	if !l.Allow("198.51.100.7", "known@example.com", now) {
		t.Fatal("saturation refused a key the table already holds")
	}
}

// TestExpiredCountersAreReclaimedSoAFullInstanceRecovers keeps fail-closed from
// becoming permanent: once the window passes, the slots come back.
func TestExpiredCountersAreReclaimedSoAFullInstanceRecovers(t *testing.T) {
	p := policy(ratelimit.MaxAuthAttempts, ratelimit.MaxAuthAttempts)
	l := limiter(t, p)
	now := time.Unix(1_700_000_000, 0).UTC()

	saturate(t, l, "identity", now)
	if l.Allow("198.51.100.7", "never-seen@example.com", now) {
		t.Fatal("the table was not saturated, so this test proves nothing")
	}
	if !l.Allow("198.51.100.7", "never-seen@example.com", now.Add(p.Window)) {
		t.Fatal("a full instance never recovered after its window")
	}
}

// TestBothDimensionsStayStrictlyBounded proves the memory guarantee holds under
// flooding of either dimension, and of both at once.
func TestBothDimensionsStayStrictlyBounded(t *testing.T) {
	p := policy(ratelimit.MaxAuthAttempts, ratelimit.MaxAuthAttempts)
	l := limiter(t, p)
	now := time.Unix(1_700_000_000, 0).UTC()

	for i := 0; i < p.Capacity*4; i++ {
		l.Allow(fmt.Sprintf("10.%d.%d.%d", i/65536%256, i/256%256, i%256), fmt.Sprintf("flood%d@example.com", i), now)
	}
	if size := l.Size(); size > 2*p.Capacity {
		t.Fatalf("the instance holds %d counters, above the two-dimension bound of %d", size, 2*p.Capacity)
	}
	saturate(t, l, "identity", now)
	saturate(t, l, "client", now)
	if size := l.Size(); size > 2*p.Capacity {
		t.Fatalf("after flooding both dimensions the instance holds %d counters, above %d", size, 2*p.Capacity)
	}
}

// TestTheCounterKeyDiscloseNoAddress keeps the presented identifier out of
// anything the limiter holds or hands back.
func TestTheCounterKeyDiscloseNoAddress(t *testing.T) {
	l := limiter(t, policy(10, 5))
	const address = "victim@example.com"

	key := l.IdentityKey(address)
	if strings.Contains(key, address) || strings.Contains(key, "victim") || strings.Contains(key, "example.com") {
		t.Fatalf("the counter key carries the address: %q", key)
	}
	// Two processes derive different keys for the same address, so a key cannot be
	// recomputed outside the process that made it.
	other := limiter(t, policy(10, 5))
	if other.IdentityKey(address) == key {
		t.Fatal("the identity key does not depend on the per-process key")
	}
	if l.IdentityKey(address) != key {
		t.Fatal("the same address resolved to two keys in one process")
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
