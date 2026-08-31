package auth

import (
	"context"
	"errors"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/emailverification"
)

// VerificationRepository decides and applies one verification. An expected
// refusal is a value; only an undecided operation is an error.
type VerificationRepository interface {
	ConsumeVerification(ctx context.Context, fingerprint emailverification.Fingerprint,
		now time.Time) (accepted bool, err error)
}

// ClientLimiter bounds attempts from one resolved client and declares no second
// dimension. A verification has no honest identifier to key one on: the token is
// the caller's to choose, so a counter over it would be fresh at every guess.
type ClientLimiter interface {
	Allow(client string, now time.Time) bool
}

// VerificationRequest carries the token the transport read from the request
// body. No path reads it from a route, a query string or a GET.
type VerificationRequest struct {
	ClientKey string
	Token     string
}

type VerificationOptions struct {
	Repository VerificationRepository
	Limiter    ClientLimiter
	Now        func() time.Time
}

type Verifications struct {
	repository VerificationRepository
	limiter    ClientLimiter
	now        func() time.Time
}

func NewVerifications(opts VerificationOptions) (*Verifications, error) {
	switch {
	case opts.Repository == nil:
		return nil, errors.New("verifying an address requires a repository")
	case opts.Limiter == nil:
		return nil, errors.New("verifying an address requires an attempt limiter")
	}
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Verifications{repository: opts.Repository, limiter: opts.Limiter, now: now}, nil
}

// Execute consumes a verification token. Success opens no session: proving
// control of an address is not authenticating, and the caller signs in
// afterwards through the ordinary mechanism.
func (v *Verifications) Execute(ctx context.Context, req VerificationRequest) (Outcome, error) {
	now := v.now().UTC()
	if !v.limiter.Allow(req.ClientKey, now) {
		return OutcomeRateLimited, nil
	}
	token, err := emailverification.ParseToken(req.Token)
	if err != nil {
		return OutcomeRejected, nil
	}
	accepted, err := v.repository.ConsumeVerification(ctx, token.Fingerprint(), now)
	if err != nil {
		return OutcomeUnknown, ErrUnavailable
	}
	if !accepted {
		return OutcomeRejected, nil
	}
	return OutcomeSucceeded, nil
}
