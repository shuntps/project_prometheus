package auth

import (
	"context"
	"errors"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/emailverification"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

// RegistrationRepository is what public registration needs from persistence. A
// collision on the login address is a value, because two callers may legitimately
// reach an unknown address at the same instant.
type RegistrationRepository interface {
	Register(ctx context.Context, email iam.EmailAddress, encoded password.Encoded,
		lifetimes emailverification.Lifetimes, now time.Time) (collided bool, err error)
	Reissue(ctx context.Context, email iam.EmailAddress,
		lifetimes emailverification.Lifetimes, now time.Time) error
}

// RegistrationRequest carries what the transport already extracted.
type RegistrationRequest struct {
	ClientKey string
	Email     string
	Password  string
}

// ReissueRequest asks for another verification message and carries no password.
type ReissueRequest struct {
	ClientKey string
	Email     string
}

type RegistrationOptions struct {
	Repository RegistrationRepository
	Hasher     PasswordVerifier
	Limiter    AttemptLimiter
	Lifetimes  emailverification.Lifetimes
	Now        func() time.Time
}

type Registrations struct {
	repository RegistrationRepository
	hasher     PasswordVerifier
	limiter    AttemptLimiter
	lifetimes  emailverification.Lifetimes
	now        func() time.Time
}

func NewRegistrations(opts RegistrationOptions) (*Registrations, error) {
	switch {
	case opts.Repository == nil:
		return nil, errors.New("registering requires a repository")
	case opts.Hasher == nil:
		return nil, errors.New("registering requires a password hasher")
	case opts.Limiter == nil:
		return nil, errors.New("registering requires an attempt limiter")
	}
	if err := opts.Lifetimes.Validate(); err != nil {
		return nil, err
	}
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Registrations{
		repository: opts.Repository, hasher: opts.Hasher, limiter: opts.Limiter,
		lifetimes: opts.Lifetimes, now: now,
	}, nil
}

// Execute registers a public viewer. Every admitted call leaves by the same
// door, whatever the address turns out to be, so nothing here distinguishes a
// new address from one already registered.
func (r *Registrations) Execute(ctx context.Context, req RegistrationRequest) (Outcome, error) {
	now := r.now().UTC()
	// The limiter is charged on what was presented, before any lookup, so an
	// address already registered consumes quota exactly as a new one does.
	if !r.limiter.Allow(req.ClientKey, req.Email, now) {
		return OutcomeRateLimited, nil
	}

	email, err := iam.NormaliseEmail(req.Email)
	if err != nil {
		return OutcomeRejected, nil
	}
	// The password is hashed before the address is looked at, so the work
	// performed does not depend on whether an account exists. Parity of the
	// intended work, not of duration.
	encoded, err := r.hasher.Hash(req.Password)
	switch {
	case errors.Is(err, password.ErrEntropy):
		return OutcomeUnknown, ErrUnavailable
	case err != nil:
		return OutcomeRejected, nil
	}

	collided, err := r.repository.Register(ctx, email, encoded, r.lifetimes, now)
	if err != nil {
		return OutcomeUnknown, ErrUnavailable
	}
	if collided {
		// One retry, never a loop. The address exists now, so the second call takes
		// the existing-identity path, where the resend interval decides what it
		// writes. Its own collision flag cannot be set and is not examined.
		if _, err := r.repository.Register(ctx, email, encoded, r.lifetimes, now); err != nil {
			return OutcomeUnknown, ErrUnavailable
		}
	}
	return OutcomeSucceeded, nil
}

// Reissue asks for another verification message. It never creates an account, so
// an address nobody registered leaves nothing behind.
func (r *Registrations) Reissue(ctx context.Context, req ReissueRequest) (Outcome, error) {
	now := r.now().UTC()
	if !r.limiter.Allow(req.ClientKey, req.Email, now) {
		return OutcomeRateLimited, nil
	}
	email, err := iam.NormaliseEmail(req.Email)
	if err != nil {
		return OutcomeRejected, nil
	}
	if err := r.repository.Reissue(ctx, email, r.lifetimes, now); err != nil {
		return OutcomeUnknown, ErrUnavailable
	}
	return OutcomeSucceeded, nil
}
