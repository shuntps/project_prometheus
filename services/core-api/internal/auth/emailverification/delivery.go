package emailverification

import (
	"fmt"
	"strings"
	"time"
)

// MaxBackoffFactor caps the doubling, so a long-lived failure keeps retrying at
// a bounded pace rather than drifting past every useful instant.
const MaxBackoffFactor = 8

// DeliveryPolicy is what the dispatcher runs on.
type DeliveryPolicy struct {
	// Interval is how often a tick runs.
	Interval time.Duration
	// Batch bounds how many deliveries one tick claims.
	Batch int
	// MaxAttempts bounds how many times one delivery may be attempted.
	MaxAttempts int
	// Lease is how long a claim protects a delivery from being taken again.
	Lease time.Duration
	// SendTimeout bounds one call to the transport.
	SendTimeout time.Duration
	// Backoff is the first delay after a failed attempt; it doubles up to a cap.
	Backoff time.Duration
}

// Validate refuses a policy that would produce duplicates by construction: a
// lease shorter than the call it protects is reclaimed while that call is still
// in flight.
func (p DeliveryPolicy) Validate() error {
	var problems []string
	if p.Interval <= 0 {
		problems = append(problems, "the dispatch interval must be greater than zero")
	}
	if p.Batch < 1 {
		problems = append(problems, "the batch must be at least one")
	}
	if p.MaxAttempts < 1 {
		problems = append(problems, "the attempt limit must be at least one")
	}
	if p.SendTimeout <= 0 {
		problems = append(problems, "the send timeout must be greater than zero")
	}
	if p.Backoff <= 0 {
		problems = append(problems, "the backoff must be greater than zero")
	}
	if p.SendTimeout > 0 && p.Lease <= p.SendTimeout {
		problems = append(problems, "the lease must be longer than the send timeout")
	}
	if len(problems) > 0 {
		return fmt.Errorf("email delivery policy: %s", strings.Join(problems, "; "))
	}
	return nil
}
