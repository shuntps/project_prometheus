package ratelimit_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/ratelimit"
)

func clientPolicy(attempts int) ratelimit.ClientPolicy {
	return ratelimit.ClientPolicy{Attempts: attempts, Window: time.Minute, Capacity: ratelimit.MinAuthCapacity}
}

func TestAClientPolicyIsBoundedOnItsOnlyDimension(t *testing.T) {
	refused := map[string]ratelimit.ClientPolicy{
		"zero":             {},
		"no attempt":       {Attempts: 0, Window: time.Minute, Capacity: ratelimit.MinAuthCapacity},
		"too many":         {Attempts: ratelimit.MaxAuthAttempts + 1, Window: time.Minute, Capacity: ratelimit.MinAuthCapacity},
		"window too short": {Attempts: 1, Window: time.Millisecond, Capacity: ratelimit.MinAuthCapacity},
		"window too long":  {Attempts: 1, Window: 48 * time.Hour, Capacity: ratelimit.MinAuthCapacity},
		"capacity too low": {Attempts: 1, Window: time.Minute, Capacity: ratelimit.MinAuthCapacity - 1},
	}
	for name, candidate := range refused {
		t.Run(name, func(t *testing.T) {
			if err := candidate.Validate(); err == nil {
				t.Fatal("an unbounded policy was accepted")
			}
			if _, err := ratelimit.NewClientLimiter(candidate); err == nil {
				t.Fatal("a limiter was built on an unbounded policy")
			}
		})
	}
	if err := clientPolicy(3).Validate(); err != nil {
		t.Fatalf("a usable policy was refused: %v", err)
	}
}

// TestOneClientIsBoundedAndRecoversWithItsWindow is the whole guarantee: the
// dimension bounds a client, and nothing else does.
func TestOneClientIsBoundedAndRecoversWithItsWindow(t *testing.T) {
	limiter, err := ratelimit.NewClientLimiter(clientPolicy(3))
	if err != nil {
		t.Fatalf("building the limiter failed: %v", err)
	}
	now := time.Now().UTC()

	for attempt := 1; attempt <= 3; attempt++ {
		if !limiter.Allow("198.51.100.7", now) {
			t.Fatalf("attempt %d was refused inside the allowance", attempt)
		}
	}
	if limiter.Allow("198.51.100.7", now) {
		t.Fatal("the allowance was exceeded")
	}
	// Another client is unaffected: there is one table and one key per client.
	if !limiter.Allow("203.0.113.9", now) {
		t.Fatal("an unrelated client was refused")
	}
	if !limiter.Allow("198.51.100.7", now.Add(time.Minute)) {
		t.Fatal("the counter did not recover with its window")
	}
}

// TestAnExhaustedClientStaysRefusedThroughSaturation keeps flooding from buying
// the erasure of a bound already in force.
func TestAnExhaustedClientLimiterStaysRefusedThroughSaturation(t *testing.T) {
	limiter, err := ratelimit.NewClientLimiter(clientPolicy(1))
	if err != nil {
		t.Fatalf("building the limiter failed: %v", err)
	}
	now := time.Now().UTC()

	if !limiter.Allow("198.51.100.7", now) {
		t.Fatal("the first attempt was refused")
	}
	for i := 0; i < ratelimit.MinAuthCapacity*2; i++ {
		limiter.Allow(fmt.Sprintf("10.%d.%d.%d", i/65536%256, i/256%256, i%256), now)
	}
	if limiter.Allow("198.51.100.7", now) {
		t.Fatal("a bound in force was discarded by flooding the table")
	}
}
