package ratelimit

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestRefusalsWhileSaturatedDoNotRescanTheTable measures cleanup passes, not
// elapsed time: a scan per refusal would spend O(capacity) under the shared lock.
func TestRefusalsWhileSaturatedDoNotRescanTheTable(t *testing.T) {
	p := AuthPolicy{
		ClientAttempts: MaxAuthAttempts, IdentityAttempts: MaxAuthAttempts,
		Window: 15 * time.Minute, Capacity: MinAuthCapacity,
	}
	l, err := NewAuthLimiter(p)
	if err != nil {
		t.Fatalf("building the limiter failed: %v", err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()

	for i := 0; i < p.Capacity; i++ {
		l.Allow("198.51.100.7", fmt.Sprintf("flood%d@example.com", i), now)
	}
	if len(l.identities.buckets) != p.Capacity {
		t.Fatalf("the identity table holds %d counters, want it full at %d", len(l.identities.buckets), p.Capacity)
	}

	const refusals = 500
	before := l.identities.sweeps
	for i := 0; i < refusals; i++ {
		if l.Allow("198.51.100.7", fmt.Sprintf("unseen%d@example.com", i), now) {
			t.Fatalf("refusal %d was admitted while the table was full", i)
		}
	}
	// One pass is allowed: the first refusal may find the recorded deadline stale.
	// What must not happen is a pass per refusal.
	if spent := l.identities.sweeps - before; spent > 1 {
		t.Fatalf("%d cleanup passes for %d refusals, want at most 1", spent, refusals)
	}

	// Once the earliest deadline has passed, exactly one pass reclaims the slots
	// and the instance accepts again.
	before = l.identities.sweeps
	if !l.Allow("198.51.100.7", "after-the-window@example.com", now.Add(p.Window)) {
		t.Fatal("the instance never recovered after its window")
	}
	if spent := l.identities.sweeps - before; spent != 1 {
		t.Fatalf("recovery took %d cleanup passes, want exactly 1", spent)
	}
	if len(l.identities.buckets) > p.Capacity {
		t.Fatalf("the table holds %d counters after recovery, above %d", len(l.identities.buckets), p.Capacity)
	}
}

// TestTheEarliestDeadlineTracksWhatTheTableHolds keeps the short-circuit honest:
// a recorded deadline later than a counter actually held would skip a reclaim.
func TestTheEarliestDeadlineTracksWhatTheTableHolds(t *testing.T) {
	p := AuthPolicy{
		ClientAttempts: MaxAuthAttempts, IdentityAttempts: MaxAuthAttempts,
		Window: 15 * time.Minute, Capacity: MinAuthCapacity,
	}
	l, err := NewAuthLimiter(p)
	if err != nil {
		t.Fatalf("building the limiter failed: %v", err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()

	for i := 0; i < 10; i++ {
		l.Allow("198.51.100.7", fmt.Sprintf("user%d@example.com", i), now.Add(time.Duration(i)*time.Minute))
	}
	earliest := time.Time{}
	for _, bucket := range l.identities.buckets {
		if earliest.IsZero() || bucket.resetAt.Before(earliest) {
			earliest = bucket.resetAt
		}
	}
	if !l.identities.nextExpiry.Equal(earliest) {
		t.Fatalf("the recorded deadline is %s, want the earliest held %s", l.identities.nextExpiry, earliest)
	}
	if l.identities.nextExpiry.After(earliest) {
		t.Fatal("a deadline later than a counter held would skip a reclaim")
	}
}

// TestASweepThatFreesNothingStillStopsTheNextOnes: a table still full after a
// pass must not make every later refusal scan again.
func TestASweepThatFreesNothingStillStopsTheNextOnes(t *testing.T) {
	p := AuthPolicy{
		ClientAttempts: MaxAuthAttempts, IdentityAttempts: MaxAuthAttempts,
		Window: 15 * time.Minute, Capacity: MinAuthCapacity,
	}
	l, err := NewAuthLimiter(p)
	if err != nil {
		t.Fatalf("building the limiter failed: %v", err)
	}
	base := time.Unix(1_700_000_000, 0).UTC()

	// One counter deadlines first; the rest deadline half a window later.
	l.Allow("198.51.100.7", "first@example.com", base)
	for i := 0; i < p.Capacity-1; i++ {
		l.Allow("198.51.100.7", fmt.Sprintf("later%d@example.com", i), base.Add(p.Window/2))
	}
	if len(l.identities.buckets) != p.Capacity {
		t.Fatalf("the table holds %d counters, want it full at %d", len(l.identities.buckets), p.Capacity)
	}

	// At the earliest deadline the first counter is renewed rather than dropped,
	// so the table stays full while the recorded deadline is now behind.
	at := base.Add(p.Window)
	l.Allow("198.51.100.7", "first@example.com", at)
	if len(l.identities.buckets) != p.Capacity {
		t.Fatalf("the table holds %d counters after the renewal, want %d", len(l.identities.buckets), p.Capacity)
	}

	const refusals = 200
	before := l.identities.sweeps
	for i := 0; i < refusals; i++ {
		if l.Allow("198.51.100.7", fmt.Sprintf("unseen%d@example.com", i), at) {
			t.Fatalf("refusal %d was admitted while the table was full", i)
		}
	}
	if spent := l.identities.sweeps - before; spent > 1 {
		t.Fatalf("%d passes for %d refusals after a pass that freed nothing, want at most 1", spent, refusals)
	}
}

// TestBothDimensionsStayStrictlyBounded proves the memory guarantee holds under
// flooding of either dimension, and of both at once.
func TestBothDimensionsStayStrictlyBounded(t *testing.T) {
	p := AuthPolicy{
		ClientAttempts: MaxAuthAttempts, IdentityAttempts: MaxAuthAttempts,
		Window: 15 * time.Minute, Capacity: MinAuthCapacity,
	}
	l, err := NewAuthLimiter(p)
	if err != nil {
		t.Fatalf("building the limiter failed: %v", err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()

	for i := 0; i < p.Capacity*4; i++ {
		l.Allow(fmt.Sprintf("10.%d.%d.%d", i/65536%256, i/256%256, i%256), fmt.Sprintf("flood%d@example.com", i), now)
		l.Allow("198.51.100.7", fmt.Sprintf("other%d@example.com", i), now)
	}
	if held := len(l.clients.buckets); held > p.Capacity {
		t.Errorf("the client table holds %d counters, above %d", held, p.Capacity)
	}
	if held := len(l.identities.buckets); held > p.Capacity {
		t.Errorf("the identity table holds %d counters, above %d", held, p.Capacity)
	}
}

// TestNoCounterKeyCarriesTheValueItCounts inspects the tables themselves: both
// dimensions must hold keyed material, never the client or the address.
func TestNoCounterKeyCarriesTheValueItCounts(t *testing.T) {
	p := AuthPolicy{
		ClientAttempts: 10, IdentityAttempts: 10,
		Window: 15 * time.Minute, Capacity: MinAuthCapacity,
	}
	l, err := NewAuthLimiter(p)
	if err != nil {
		t.Fatalf("building the limiter failed: %v", err)
	}
	const (
		client  = "198.51.100.7"
		address = "victim@example.com"
	)
	if !l.Allow(client, address, time.Unix(1_700_000_000, 0).UTC()) {
		t.Fatal("the first attempt was refused")
	}

	probes := []string{client, address, "victim", "example.com", "198.51.100"}
	for name, table := range map[string]*dimension{"client": &l.clients, "identity": &l.identities} {
		for key := range table.buckets {
			for _, probe := range probes {
				if strings.Contains(key, probe) {
					t.Errorf("the %s key carries %q", name, probe)
				}
			}
			// base64 of a SHA-256 tag, unpadded: one length for every input.
			if want := base64.RawURLEncoding.EncodedLen(sha256.Size); len(key) != want {
				t.Errorf("the %s key is %d characters, want the fixed %d", name, len(key), want)
			}
		}
	}
}

// TestACounterKeyBelongsToOneProcess keeps a key from being recomputed outside
// the instance that made it, and stable inside it.
func TestACounterKeyBelongsToOneProcess(t *testing.T) {
	p := AuthPolicy{
		ClientAttempts: 10, IdentityAttempts: 10,
		Window: 15 * time.Minute, Capacity: MinAuthCapacity,
	}
	first, err := NewAuthLimiter(p)
	if err != nil {
		t.Fatalf("building the limiter failed: %v", err)
	}
	second, err := NewAuthLimiter(p)
	if err != nil {
		t.Fatalf("building the second limiter failed: %v", err)
	}
	const address = "victim@example.com"
	if first.counterKey(address) == second.counterKey(address) {
		t.Error("two instances derived the same key, so it does not depend on the drawn secret")
	}
	if first.counterKey(address) != first.counterKey(address) {
		t.Error("one instance derived two keys for the same value")
	}
	if first.counterKey(address) != first.counterKey("  VICTIM@Example.com  ") {
		t.Error("case and surrounding space produced a second counter")
	}
}
