package emailverification_test

import (
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/emailverification"
)

func policy() emailverification.DeliveryPolicy {
	return emailverification.DeliveryPolicy{
		Interval: 5 * time.Second, Batch: 16, MaxAttempts: 5,
		Lease: 2 * time.Minute, SendTimeout: 30 * time.Second,
		Backoff: 30 * time.Second,
	}
}

// TestALeaseShorterThanTheCallItProtectsIsRefused is the one setting that would
// produce duplicates by construction: the row would be taken again while the
// call it protects was still in flight.
func TestALeaseShorterThanTheCallItProtectsIsRefused(t *testing.T) {
	refused := map[string]func(*emailverification.DeliveryPolicy){
		"no interval":       func(p *emailverification.DeliveryPolicy) { p.Interval = 0 },
		"empty batch":       func(p *emailverification.DeliveryPolicy) { p.Batch = 0 },
		"no attempt":        func(p *emailverification.DeliveryPolicy) { p.MaxAttempts = 0 },
		"no send timeout":   func(p *emailverification.DeliveryPolicy) { p.SendTimeout = 0 },
		"no backoff":        func(p *emailverification.DeliveryPolicy) { p.Backoff = 0 },
		"lease equals call": func(p *emailverification.DeliveryPolicy) { p.Lease = p.SendTimeout },
		"lease under call":  func(p *emailverification.DeliveryPolicy) { p.Lease = p.SendTimeout - time.Second },
	}
	for name, mutate := range refused {
		t.Run(name, func(t *testing.T) {
			candidate := policy()
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("an unusable policy was accepted")
			}
		})
	}
	if err := policy().Validate(); err != nil {
		t.Fatalf("a usable policy was refused: %v", err)
	}
}
