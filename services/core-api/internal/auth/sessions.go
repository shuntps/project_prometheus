package auth

import (
	"context"
	"errors"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

// Resolved is a session and the authority its account carries right now. Status
// and roles are read on every resolution, never carried inside the token.
type Resolved struct {
	Session   session.Session
	Principal iam.Principal
}

// Authenticated is a resolved session and the instant it was decided at. An
// operation that must not observe a later clock is anchored to that instant.
type Authenticated struct {
	Resolved Resolved
	At       time.Time
}

// SessionRepository is what the session use cases need from persistence. An
// expected absence is a value; only an undecided operation is an error.
type SessionRepository interface {
	ResolveSession(ctx context.Context, token session.Token, now time.Time) (Resolved, bool, error)
	RevokeSession(ctx context.Context, id session.ID, now time.Time) (bool, error)
	RecordActivity(ctx context.Context, id session.ID, now time.Time, lifetimes session.Lifetimes) (bool, error)
}

type SessionsOptions struct {
	Repository SessionRepository
	Lifetimes  session.Lifetimes
	Now        func() time.Time
}

type Sessions struct {
	repository SessionRepository
	lifetimes  session.Lifetimes
	now        func() time.Time
}

func NewSessions(opts SessionsOptions) (*Sessions, error) {
	if opts.Repository == nil {
		return nil, errors.New("the session use cases require a repository")
	}
	if err := opts.Lifetimes.Validate(); err != nil {
		return nil, err
	}
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Sessions{repository: opts.Repository, lifetimes: opts.Lifetimes, now: now}, nil
}

// Authenticate resolves the caller from the token alone. The authority comes back
// read afresh, never from anything the token carried.
func (s *Sessions) Authenticate(ctx context.Context, token session.Token) (Authenticated, Outcome, error) {
	at := s.now().UTC()
	resolved, found, err := s.repository.ResolveSession(ctx, token, at)
	switch {
	case err != nil:
		// A store that failed says nothing about the caller. Reporting an absence
		// would assert something that was never established.
		return Authenticated{}, OutcomeUnknown, ErrUnavailable
	case !found:
		return Authenticated{}, OutcomeUnauthenticated, nil
	}
	return Authenticated{Resolved: resolved, At: at}, OutcomeSucceeded, nil
}

// Authorise resolves the caller and puts that principal through the domain rule.
func (s *Sessions) Authorise(ctx context.Context, token session.Token, permission iam.Permission) (Authenticated, Outcome, error) {
	authenticated, outcome, err := s.Authenticate(ctx, token)
	if err != nil || outcome != OutcomeSucceeded {
		return Authenticated{}, outcome, err
	}
	if err := iam.Authorize(authenticated.Resolved.Principal, permission); err != nil {
		return Authenticated{}, OutcomeForbidden, nil
	}
	return authenticated, OutcomeSucceeded, nil
}

// End revokes a session. A session already gone reports its absence, and the
// outcome the caller asked for holds either way.
func (s *Sessions) End(ctx context.Context, id session.ID) (Outcome, error) {
	found, err := s.repository.RevokeSession(ctx, id, s.now().UTC())
	switch {
	case err != nil:
		return OutcomeUnknown, ErrUnavailable
	case !found:
		return OutcomeUnauthenticated, nil
	}
	return OutcomeSucceeded, nil
}

// RenewActivity extends the inactivity deadline, anchored to the instant the
// session was resolved at. The write decides its own permission.
func (s *Sessions) RenewActivity(ctx context.Context, id session.ID, at time.Time) (Outcome, error) {
	found, err := s.repository.RecordActivity(ctx, id, at, s.lifetimes)
	switch {
	case errors.Is(err, iam.ErrDenied):
		return OutcomeForbidden, nil
	case err != nil:
		return OutcomeUnknown, ErrUnavailable
	case !found:
		return OutcomeUnauthenticated, nil
	}
	return OutcomeSucceeded, nil
}
