package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

// Credential is what a login attempt needs in order to decide, and nothing more.
type Credential struct {
	Account  iam.AccountID
	Kind     iam.Kind
	Status   iam.Status
	Password password.Encoded
}

// PasswordVerifier is the credential check. Hashing is required too: the decoy is
// built with the very parameters a real credential is verified against.
type PasswordVerifier interface {
	Hash(plaintext string) (password.Encoded, error)
	Verify(encoded password.Encoded, plaintext string) (rehash bool, err error)
}

// AttemptLimiter bounds attempts on a client dimension and an identifier
// dimension at once; both must permit an attempt.
type AttemptLimiter interface {
	Allow(client, identifier string, now time.Time) bool
}

// SignInRepository is what signing in needs from persistence. An expected absence
// is a value, never an error, so a missing record is never read as a failure.
type SignInRepository interface {
	CredentialByEmail(ctx context.Context, email iam.EmailAddress) (Credential, bool, error)
	ResolveSession(ctx context.Context, token session.Token, now time.Time) (Resolved, bool, error)
	ReplaceSession(ctx context.Context, previous *session.ID, successor session.Session, now time.Time) (Resolved, bool, error)
}

// SignInRequest carries what the transport already extracted. It holds no header,
// no cookie and no framework value.
type SignInRequest struct {
	ClientKey string
	Email     string
	Password  string
	Presented *session.Token
}

// SignInResult is the decision. Its zero value carries OutcomeUnknown, which no
// caller may serve.
type SignInResult struct {
	Outcome   Outcome
	Token     session.Token
	Session   session.Session
	Principal iam.Principal
}

type SignInOptions struct {
	Repository SignInRepository
	Hasher     PasswordVerifier
	Limiter    AttemptLimiter
	Lifetimes  session.Lifetimes
	Now        func() time.Time
}

type SignIn struct {
	repository SignInRepository
	hasher     PasswordVerifier
	limiter    AttemptLimiter
	lifetimes  session.Lifetimes
	now        func() time.Time
	// issue emits the session a successful sign-in replaces the presented one
	// with. It is held rather than consumed at construction.
	issue issueFunc
	// decoy carries the configured parameters, so verifying against it costs the
	// same memory and passes as verifying a real credential.
	decoy password.Encoded
}

// issueFunc is what emits a session. It matches session.Issue, which the public
// constructor always supplies; the private one takes it so a failure is provable.
type issueFunc func(iam.AccountID, iam.Kind, iam.Surface, session.Lifetimes, time.Time) (session.Session, session.Token, error)

// NewSignIn builds the sign-in use case. It always draws the decoy seed from the
// process entropy source and always emits sessions through session.Issue.
func NewSignIn(opts SignInOptions) (*SignIn, error) {
	return newSignIn(opts, rand.Reader, session.Issue)
}

// newSignIn takes the entropy source and the emitter so both failure paths stay
// provable. It is unexported: no caller outside this package may choose either.
func newSignIn(opts SignInOptions, random io.Reader, issue issueFunc) (*SignIn, error) {
	if issue == nil {
		return nil, errors.New("signing in requires a session emitter")
	}
	switch {
	case opts.Repository == nil:
		return nil, errors.New("signing in requires a repository")
	case opts.Hasher == nil:
		return nil, errors.New("signing in requires a password hasher")
	case opts.Limiter == nil:
		return nil, errors.New("signing in requires an attempt limiter")
	}
	if err := opts.Lifetimes.Validate(); err != nil {
		return nil, err
	}

	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}

	// The decoy is hashed from a value drawn here and never stored, so no
	// deployment shares it and nothing can be matched against it.
	seed := make([]byte, 32)
	if _, err := io.ReadFull(random, seed); err != nil {
		return nil, errors.New("authentication surface could not prepare its verification path")
	}
	decoy, err := opts.Hasher.Hash(base64.RawURLEncoding.EncodeToString(seed))
	if err != nil {
		return nil, err
	}

	return &SignIn{
		repository: opts.Repository, hasher: opts.Hasher, limiter: opts.Limiter,
		lifetimes: opts.Lifetimes, now: now, issue: issue, decoy: decoy,
	}, nil
}

// Execute authenticates a public account. Every refusal leaves by the same door,
// and the cryptographic work happens whether or not the address is registered.
func (s *SignIn) Execute(ctx context.Context, req SignInRequest) (SignInResult, error) {
	now := s.now().UTC()
	// The limiter is charged on what was presented, before any lookup, so an
	// unregistered address consumes quota exactly as a registered one does.
	if !s.limiter.Allow(req.ClientKey, req.Email, now) {
		return SignInResult{Outcome: OutcomeRateLimited}, nil
	}

	credential, found, err := s.lookup(ctx, req.Email)
	if err != nil {
		// The verification still runs, so a failure is not distinguishable from an
		// absence by the work done, and nothing is decided about the caller.
		_, _ = s.hasher.Verify(s.decoy, req.Password)
		return SignInResult{}, ErrUnavailable
	}
	if !found {
		// The decoy makes the work independent of whether the address exists.
		// Parity of work, not of duration.
		_, _ = s.hasher.Verify(s.decoy, req.Password)
		return SignInResult{Outcome: OutcomeRejected}, nil
	}

	if _, err := s.hasher.Verify(credential.Password, req.Password); err != nil {
		return SignInResult{Outcome: OutcomeRejected}, nil
	}
	// Usability is decided after verification so that a suspended, closed or
	// pending account is indistinguishable from a wrong password.
	if !credential.Status.CanAuthenticate() {
		return SignInResult{Outcome: OutcomeRejected}, nil
	}
	// The surface is fixed here, never taken from the request: an operator account
	// cannot obtain a public session, and no caller can ask for another surface.
	if err := iam.ValidateSurface(credential.Kind, iam.SurfacePublic); err != nil {
		return SignInResult{Outcome: OutcomeRejected}, nil
	}

	// The session the request carried is identified before anything is written. A
	// store failure here stops the sign-in: continuing could leave two live tokens.
	previous, err := s.presented(ctx, req.Presented, now)
	if err != nil {
		return SignInResult{}, ErrUnavailable
	}
	// The successor exists before any irreversible write, so the replacement below
	// either ends the old session and creates this one, or changes nothing.
	successor, token, err := s.issue(credential.Account, credential.Kind, iam.SurfacePublic, s.lifetimes, now)
	if err != nil {
		return SignInResult{}, ErrUnavailable
	}
	resolved, replaced, err := s.repository.ReplaceSession(ctx, previous, successor, now)
	switch {
	case err != nil:
		return SignInResult{}, ErrUnavailable
	case !replaced:
		// The account stopped being usable meanwhile. That is an authentication
		// outcome, not a failure, and it leaves by the same door.
		return SignInResult{Outcome: OutcomeRejected}, nil
	}

	return SignInResult{
		Outcome: OutcomeSucceeded, Token: token,
		Session: resolved.Session, Principal: resolved.Principal,
	}, nil
}

// presented names the session the request arrived with. A store failure is
// reported rather than ignored: proceeding blind could leave two sessions alive.
func (s *SignIn) presented(ctx context.Context, token *session.Token, now time.Time) (*session.ID, error) {
	if token == nil {
		return nil, nil
	}
	resolved, found, err := s.repository.ResolveSession(ctx, *token, now)
	switch {
	case err != nil:
		return nil, ErrUnavailable
	case !found:
		return nil, nil
	}
	id := resolved.Session.ID
	return &id, nil
}

// lookup separates three outcomes the caller must not conflate: a credential, a
// genuine absence, and a store that failed. A malformed address is an absence.
func (s *SignIn) lookup(ctx context.Context, raw string) (Credential, bool, error) {
	email, err := iam.NormaliseEmail(raw)
	if err != nil {
		return Credential{}, false, nil
	}
	credential, found, err := s.repository.CredentialByEmail(ctx, email)
	if err != nil {
		return Credential{}, false, err
	}
	return credential, found, nil
}
