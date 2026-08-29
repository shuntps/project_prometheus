// Package session issues and evaluates server-side sessions. The browser holds
// an opaque reference only; nothing about the account travels in the token.
package session

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

var (
	// ErrInvalid reports a session the domain refuses to construct.
	ErrInvalid = errors.New("invalid session")
	// ErrUnusable reports a session that exists but may not be used.
	ErrUnusable = errors.New("session is not usable")
)

// Session is the server-side record. It holds the fingerprint, never the token.
type Session struct {
	ID                ID
	Account           iam.AccountID
	Surface           iam.Surface
	Fingerprint       Fingerprint
	CSRF              CSRFToken
	CreatedAt         time.Time
	LastActiveAt      time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	RevokedAt         *time.Time
	RotatedTo         *ID
}

// Issue builds a session and its token together. The token is returned once and
// is never derivable from what is stored.
func Issue(account iam.AccountID, kind iam.Kind, surface iam.Surface, lifetimes Lifetimes, now time.Time, random io.Reader) (Session, Token, error) {
	if account.IsZero() {
		return Session{}, Token{}, fmt.Errorf("%w: no account was named", ErrInvalid)
	}
	// The surface is bound to the kind here, not left to the caller: an operator
	// session may only ever belong to an operator account.
	if err := iam.ValidateSurface(kind, surface); err != nil {
		return Session{}, Token{}, fmt.Errorf("%w: %s", ErrInvalid, err)
	}
	if err := lifetimes.Validate(); err != nil {
		return Session{}, Token{}, err
	}

	id, err := NewID()
	if err != nil {
		return Session{}, Token{}, fmt.Errorf("%w: no session identifier could be drawn", ErrInvalid)
	}
	token, err := NewToken(random)
	if err != nil {
		return Session{}, Token{}, err
	}
	csrf, err := NewCSRFToken(random)
	if err != nil {
		return Session{}, Token{}, err
	}

	issued := now.UTC()
	built := Session{
		ID:                id,
		Account:           account,
		Surface:           surface,
		Fingerprint:       token.Fingerprint(),
		CSRF:              csrf,
		CreatedAt:         issued,
		LastActiveAt:      issued,
		IdleExpiresAt:     issued.Add(lifetimes.Idle),
		AbsoluteExpiresAt: issued.Add(lifetimes.Absolute),
	}
	if err := built.Validate(kind); err != nil {
		return Session{}, Token{}, err
	}
	return built, token, nil
}

// Validate is the single authority on a record about to be written: every write
// path runs it, so no boundary can store what another would have refused.
func (s Session) Validate(kind iam.Kind) error {
	var problems []string
	if s.ID.IsZero() {
		problems = append(problems, "the session identifier is zero")
	}
	if s.Account.IsZero() {
		problems = append(problems, "the account is zero")
	}
	if s.Fingerprint.IsZero() {
		problems = append(problems, "the token fingerprint is zero")
	}
	if s.CSRF.IsZero() {
		problems = append(problems, "the CSRF token is zero")
	}
	if s.RevokedAt != nil || s.RotatedTo != nil {
		problems = append(problems, "a new session may not already be revoked or rotated")
	}
	if err := iam.ValidateSurface(kind, s.Surface); err != nil {
		problems = append(problems, err.Error())
	}

	switch {
	case s.CreatedAt.IsZero(), s.LastActiveAt.IsZero(), s.IdleExpiresAt.IsZero(), s.AbsoluteExpiresAt.IsZero():
		problems = append(problems, "every instant must be set")
	default:
		if s.LastActiveAt.Before(s.CreatedAt) {
			problems = append(problems, "activity may not predate creation")
		}
		if !s.IdleExpiresAt.After(s.LastActiveAt) {
			problems = append(problems, "the idle expiry must follow the last activity")
		}
		if !s.AbsoluteExpiresAt.After(s.CreatedAt) {
			problems = append(problems, "the absolute expiry must follow creation")
		}
		if s.IdleExpiresAt.After(s.AbsoluteExpiresAt) {
			problems = append(problems, "the idle expiry may not exceed the absolute expiry")
		}
	}

	if len(problems) == 0 {
		// A record that is already unusable at the instant it is written would be
		// stored dead, and rotation would have invalidated its predecessor for it.
		if err := s.UsableAt(s.CreatedAt); err != nil {
			problems = append(problems, "the session is already unusable at its own creation")
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalid, strings.Join(problems, "; "))
	}
	return nil
}

// RenewedIdleAt returns the inactivity deadline an accepted activity signal would
// produce, capped by the absolute expiry, which this operation never moves.
func (s Session) RenewedIdleAt(now time.Time, lifetimes Lifetimes) time.Time {
	renewed := now.UTC().Add(lifetimes.Idle)
	if renewed.After(s.AbsoluteExpiresAt) {
		return s.AbsoluteExpiresAt
	}
	return renewed
}

// ActivityIsWorthPersisting keeps a burst from becoming a write each, and refuses
// an instant moving a stamp backwards, so out-of-order requests shorten nothing.
func (s Session) ActivityIsWorthPersisting(now time.Time, lifetimes Lifetimes) bool {
	if now.UTC().Sub(s.LastActiveAt) < lifetimes.ActivityInterval {
		return false
	}
	return s.RenewedIdleAt(now, lifetimes).After(s.IdleExpiresAt)
}

// UsableAt reports why a session may not be used, checking every reason rather
// than only the first, so no path treats an unknown state as usable.
func (s Session) UsableAt(now time.Time) error {
	switch {
	case s.ID.IsZero() || s.Account.IsZero():
		return fmt.Errorf("%w: the session record is incomplete", ErrUnusable)
	case s.RevokedAt != nil:
		return fmt.Errorf("%w: it was revoked", ErrUnusable)
	case s.RotatedTo != nil:
		return fmt.Errorf("%w: it was rotated", ErrUnusable)
	case !now.UTC().Before(s.AbsoluteExpiresAt):
		return fmt.Errorf("%w: it reached its absolute expiry", ErrUnusable)
	case !now.UTC().Before(s.IdleExpiresAt):
		return fmt.Errorf("%w: it reached its idle expiry", ErrUnusable)
	default:
		return nil
	}
}
