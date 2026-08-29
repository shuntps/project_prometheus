package ratelimit_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/ratelimit"
)

// saturate fills one dimension with live counters, so the table holds only
// bounds still inside their window. The capacity is the caller's, not the limiter's.
func saturate(t *testing.T, l *ratelimit.AuthLimiter, dimension string, capacity int, now time.Time) {
	t.Helper()
	for i := 0; i < capacity*2; i++ {
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

	saturate(t, l, "identity", p.Capacity, now)

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

	saturate(t, l, "client", p.Capacity, now)

	if l.Allow("198.51.100.7", "yet-another@example.com", now) {
		t.Fatal("saturation restored an exhausted client")
	}
}

// TestOneDimensionsSaturationCannotEvictTheOther keeps the two tables from
// competing: filling either must leave the other's bounds exactly as they were.
func TestOneDimensionsSaturationCannotEvictTheOther(t *testing.T) {
	t.Run("identity flood leaves the client bound", func(t *testing.T) {
		p := policy(2, ratelimit.MaxAuthAttempts)
		l := limiter(t, p)
		now := time.Unix(1_700_000_000, 0).UTC()
		for attempt := 1; attempt <= 2; attempt++ {
			if !l.Allow("198.51.100.7", fmt.Sprintf("user%d@example.com", attempt), now) {
				t.Fatalf("attempt %d was refused before the bound", attempt)
			}
		}
		saturate(t, l, "identity", p.Capacity, now)
		if l.Allow("198.51.100.7", "fresh@example.com", now) {
			t.Fatal("flooding identifiers removed the client bound")
		}
	})

	t.Run("client flood leaves the identity bound", func(t *testing.T) {
		p := policy(ratelimit.MaxAuthAttempts, 2)
		l := limiter(t, p)
		now := time.Unix(1_700_000_000, 0).UTC()
		for attempt := 1; attempt <= 2; attempt++ {
			if !l.Allow(fmt.Sprintf("198.51.100.%d", attempt), "victim@example.com", now) {
				t.Fatalf("attempt %d was refused before the bound", attempt)
			}
		}
		saturate(t, l, "client", p.Capacity, now)
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
	saturate(t, l, "identity", p.Capacity, now)

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

	saturate(t, l, "identity", p.Capacity, now)
	if l.Allow("198.51.100.7", "never-seen@example.com", now) {
		t.Fatal("the table was not saturated, so this test proves nothing")
	}
	if !l.Allow("198.51.100.7", "never-seen@example.com", now.Add(p.Window)) {
		t.Fatal("a full instance never recovered after its window")
	}
}
