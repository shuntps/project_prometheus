package auth

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/emailverification"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

// VerificationSender carries one message to one address. It is the only outbound
// boundary the dispatcher knows, and it never sees the store.
type VerificationSender interface {
	Send(ctx context.Context, message emailverification.Message) error
}

// VerificationLink builds the browser reference a recipient follows. It is
// supplied by the composition, so no part of the authentication domain holds a
// web route or knows what a public origin is.
type VerificationLink func(token emailverification.Token) string

// ClaimedDelivery is one outbox row the dispatcher holds a lease on.
type ClaimedDelivery struct {
	ID        emailverification.DeliveryID
	Address   iam.EmailAddress
	Token     emailverification.Token
	ExpiresAt time.Time
	Attempts  int
}

// DeliveryRepository is the outbox as the dispatcher needs it. The claim commits
// before any message leaves the process, and the outcome is recorded afterwards
// in its own transaction, so no network call is ever inside one.
type DeliveryRepository interface {
	ClaimDeliveries(ctx context.Context, claim uuid.UUID, batch, maxAttempts int,
		lease time.Duration, now time.Time) ([]ClaimedDelivery, error)
	SettleDelivery(ctx context.Context, id emailverification.DeliveryID, claim uuid.UUID) (bool, error)
	RescheduleDelivery(ctx context.Context, id emailverification.DeliveryID, claim uuid.UUID, at time.Time) (bool, error)
	SweepDeliveries(ctx context.Context, batch, maxAttempts int, now time.Time) (int64, error)
}

// DispatchResult is what one tick did. Lost counts the deliveries whose lease
// had been taken over before the outcome could be recorded.
type DispatchResult struct {
	Swept       int64
	Claimed     int
	Delivered   int
	Rescheduled int
	Discarded   int
	Lost        int
}

type DeliveryOptions struct {
	Repository DeliveryRepository
	Sender     VerificationSender
	Link       VerificationLink
	Policy     emailverification.DeliveryPolicy
	Now        func() time.Time
}

// Deliveries drains the outbox. Its guarantee is at least once: a process that
// dies after the transport accepted a message and before the row is removed
// leaves that row to be taken again, and the message is sent twice.
type Deliveries struct {
	repository DeliveryRepository
	sender     VerificationSender
	link       VerificationLink
	policy     emailverification.DeliveryPolicy
	now        func() time.Time
}

func NewDeliveries(opts DeliveryOptions) (*Deliveries, error) {
	switch {
	case opts.Repository == nil:
		return nil, errors.New("delivering verifications requires a repository")
	case opts.Sender == nil:
		return nil, errors.New("delivering verifications requires a transport")
	case opts.Link == nil:
		return nil, errors.New("delivering verifications requires a link builder")
	}
	if err := opts.Policy.Validate(); err != nil {
		return nil, err
	}
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Deliveries{
		repository: opts.Repository, sender: opts.Sender, link: opts.Link,
		policy: opts.Policy, now: now,
	}, nil
}

// Interval is how often the caller should run a tick.
func (d *Deliveries) Interval() time.Duration { return d.policy.Interval }

// Dispatch runs one tick. A transport failure is never returned: it is a
// rescheduled or exhausted delivery. Only a store that could not decide is.
func (d *Deliveries) Dispatch(ctx context.Context) (DispatchResult, error) {
	now := d.now().UTC()
	var result DispatchResult

	swept, err := d.repository.SweepDeliveries(ctx, d.policy.Batch, d.policy.MaxAttempts, now)
	if err != nil {
		return result, ErrUnavailable
	}
	result.Swept = swept

	claim, err := uuid.NewRandom()
	if err != nil {
		return result, ErrUnavailable
	}
	claimed, err := d.repository.ClaimDeliveries(ctx, claim, d.policy.Batch, d.policy.MaxAttempts, d.policy.Lease, now)
	if err != nil {
		return result, ErrUnavailable
	}
	result.Claimed = len(claimed)

	for _, one := range claimed {
		// The transport is called outside every transaction, under its own bound.
		// A verification, a supersession or an expiry may remove the row while this
		// call is in flight; a message already accepted cannot be recalled.
		sendCtx, cancel := context.WithTimeout(ctx, d.policy.SendTimeout)
		sendErr := d.sender.Send(sendCtx, emailverification.Message{
			Delivery:  one.ID,
			To:        one.Address,
			ExpiresAt: one.ExpiresAt,
			Link:      d.link(one.Token),
		})
		cancel()

		settle := sendErr == nil || one.Attempts >= d.policy.MaxAttempts
		if !settle {
			next := d.now().UTC().Add(d.backoff(one.Attempts))
			// A backoff past the challenge's own expiry would schedule work that can
			// never be done, so the row is removed instead of moved.
			if next.Before(one.ExpiresAt) {
				moved, err := d.repository.RescheduleDelivery(ctx, one.ID, claim, next)
				if err != nil {
					return result, ErrUnavailable
				}
				if moved {
					result.Rescheduled++
				} else {
					result.Lost++
				}
				continue
			}
			settle = true
		}

		removed, err := d.repository.SettleDelivery(ctx, one.ID, claim)
		if err != nil {
			return result, ErrUnavailable
		}
		switch {
		case !removed:
			// The lease was taken over, or the row is gone because the challenge was
			// consumed, superseded or expired meanwhile. Nothing is recreated.
			result.Lost++
		case sendErr == nil:
			result.Delivered++
		default:
			result.Discarded++
		}
	}
	return result, nil
}

// backoff doubles from the configured base, capped, so a delivery that keeps
// failing keeps a bounded pace.
func (d *Deliveries) backoff(attempts int) time.Duration {
	delay := d.policy.Backoff
	ceiling := d.policy.Backoff * emailverification.MaxBackoffFactor
	for i := 1; i < attempts && delay < ceiling; i++ {
		delay *= 2
	}
	if delay > ceiling {
		delay = ceiling
	}
	return delay
}
