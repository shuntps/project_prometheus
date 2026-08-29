// Package session issues and evaluates server-side sessions. The browser holds
// an opaque reference only; nothing about the account travels in the token.
package session

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
)

var (
	// ErrInvalid reports a session the domain refuses to construct.
	ErrInvalid = errors.New("invalid session")
	// ErrUnusable reports a session that exists but may not be used.
	ErrUnusable = errors.New("session is not usable")
)

// TokenBytes gives 256 bits of entropy, comfortably above the 128 bits ASVS
// v5.0.0-7.2.3 requires, at no interoperability cost for an opaque cookie value.
const TokenBytes = 32

// Token is the value the browser holds. Every rendering path is overridden so it
// cannot reach a record, an error, a metric or a test failure.
type Token struct {
	raw string
}

// NewToken draws a token from the injected CSPRNG.
func NewToken(random io.Reader) (Token, error) {
	if random == nil {
		random = rand.Reader
	}
	raw := make([]byte, TokenBytes)
	if _, err := io.ReadFull(random, raw); err != nil {
		return Token{}, fmt.Errorf("%w: no token could be drawn", ErrInvalid)
	}
	return Token{raw: base64.RawURLEncoding.EncodeToString(raw)}, nil
}

// ParseToken accepts only a value of the exact shape this package issues.
func ParseToken(raw string) (Token, error) {
	trimmed := strings.TrimSpace(raw)
	decoded, err := base64.RawURLEncoding.DecodeString(trimmed)
	if err != nil || len(decoded) != TokenBytes {
		return Token{}, fmt.Errorf("%w: the token is not of the issued shape", ErrInvalid)
	}
	return Token{raw: trimmed}, nil
}

// Reveal returns the value. Only the transport that sets the cookie and the
// lookup that fingerprints it may call this.
func (t Token) Reveal() string { return t.raw }

func (t Token) IsZero() bool { return t.raw == "" }

func (t Token) String() string { return auth.Redacted }

func (t Token) GoString() string { return auth.Redacted }

func (t Token) LogValue() slog.Value { return slog.StringValue(auth.Redacted) }

func (t Token) MarshalText() ([]byte, error) { return []byte(auth.Redacted), nil }

func (t Token) MarshalJSON() ([]byte, error) { return []byte(`"` + auth.Redacted + `"`), nil }

// Fingerprint is what the database holds. SHA-256 fits and a password hash does
// not: the token already carries full entropy, so there is nothing to slow down.
type Fingerprint struct {
	value [sha256.Size]byte
}

// Fingerprint derives the stored value. The token cannot be recovered from it.
func (t Token) Fingerprint() Fingerprint {
	return Fingerprint{value: sha256.Sum256([]byte(t.raw))}
}

// Bytes returns a copy for the store. It is the only path to the value.
func (f Fingerprint) Bytes() []byte {
	out := make([]byte, len(f.value))
	copy(out, f.value[:])
	return out
}

// FingerprintFrom rebuilds a fingerprint read back from the store.
func FingerprintFrom(raw []byte) (Fingerprint, error) {
	if len(raw) != sha256.Size {
		return Fingerprint{}, fmt.Errorf("%w: the fingerprint is not of the stored size", ErrInvalid)
	}
	var f Fingerprint
	copy(f.value[:], raw)
	return f, nil
}

func (f Fingerprint) IsZero() bool { return f == Fingerprint{} }

func (f Fingerprint) String() string { return auth.Redacted }

func (f Fingerprint) GoString() string { return auth.Redacted }

func (f Fingerprint) LogValue() slog.Value { return slog.StringValue(auth.Redacted) }

func (f Fingerprint) MarshalText() ([]byte, error) { return []byte(auth.Redacted), nil }

func (f Fingerprint) MarshalJSON() ([]byte, error) { return []byte(`"` + auth.Redacted + `"`), nil }

// CSRFTokenBytes matches the session token: the value is a bearer secret for the
// request that carries it, so it is drawn at the same strength.
const CSRFTokenBytes = 32

// CSRFToken is the synchronizer token bound to one session. Unlike the session
// token it is stored as issued, because the server has to hand it back.
type CSRFToken struct {
	raw string
}

// NewCSRFToken draws a token from the injected CSPRNG.
func NewCSRFToken(random io.Reader) (CSRFToken, error) {
	if random == nil {
		random = rand.Reader
	}
	raw := make([]byte, CSRFTokenBytes)
	if _, err := io.ReadFull(random, raw); err != nil {
		return CSRFToken{}, fmt.Errorf("%w: no CSRF token could be drawn", ErrInvalid)
	}
	return CSRFToken{raw: base64.RawURLEncoding.EncodeToString(raw)}, nil
}

// ParseCSRFToken accepts only a value of the exact shape this package issues.
func ParseCSRFToken(raw string) (CSRFToken, error) {
	trimmed := strings.TrimSpace(raw)
	decoded, err := base64.RawURLEncoding.DecodeString(trimmed)
	if err != nil || len(decoded) != CSRFTokenBytes {
		return CSRFToken{}, fmt.Errorf("%w: the CSRF token is not of the issued shape", ErrInvalid)
	}
	return CSRFToken{raw: trimmed}, nil
}

// Reveal returns the value. Only the transport that hands the token to the client
// and the comparison that checks it back may call this.
func (c CSRFToken) Reveal() string { return c.raw }

// Equals compares in constant time, so a mismatch discloses nothing about how far
// a forged value matched.
func (c CSRFToken) Equals(other CSRFToken) bool {
	if c.IsZero() || other.IsZero() {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.raw), []byte(other.raw)) == 1
}

func (c CSRFToken) IsZero() bool { return c.raw == "" }

func (c CSRFToken) String() string { return auth.Redacted }

func (c CSRFToken) GoString() string { return auth.Redacted }

func (c CSRFToken) LogValue() slog.Value { return slog.StringValue(auth.Redacted) }

func (c CSRFToken) MarshalText() ([]byte, error) { return []byte(auth.Redacted), nil }

func (c CSRFToken) MarshalJSON() ([]byte, error) { return []byte(`"` + auth.Redacted + `"`), nil }

// Lifetimes bounds how long a session may live and how long it may sit idle.
type Lifetimes struct {
	Absolute time.Duration
	Idle     time.Duration
	// ActivityInterval is the shortest spacing between two persisted activity
	// updates, so a burst of user events costs one write rather than one per event.
	ActivityInterval time.Duration
}

const (
	MinIdle             = time.Minute
	MinAbsolute         = 5 * time.Minute
	MaxAbsolute         = 30 * 24 * time.Hour
	MinActivityInterval = time.Second
)

// Validate keeps the two expiries distinct and ordered.
func (l Lifetimes) Validate() error {
	var problems []string
	if l.Idle < MinIdle {
		problems = append(problems, fmt.Sprintf("the idle lifetime must be at least %s", MinIdle))
	}
	if l.Absolute < MinAbsolute || l.Absolute > MaxAbsolute {
		problems = append(problems, fmt.Sprintf("the absolute lifetime must be between %s and %s", MinAbsolute, MaxAbsolute))
	}
	if l.Idle >= MinIdle && l.Absolute >= MinAbsolute && l.Idle > l.Absolute {
		problems = append(problems, "the idle lifetime must not exceed the absolute lifetime")
	}
	if l.ActivityInterval < MinActivityInterval {
		problems = append(problems, fmt.Sprintf("the activity interval must be at least %s", MinActivityInterval))
	}
	// An interval at or above the idle lifetime would let a session expire between
	// two updates the policy permits, which is the opposite of what it is for.
	if l.ActivityInterval >= MinActivityInterval && l.Idle >= MinIdle && l.ActivityInterval >= l.Idle {
		problems = append(problems, "the activity interval must be shorter than the idle lifetime")
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalid, strings.Join(problems, "; "))
	}
	return nil
}

// Session is the server-side record. It holds the fingerprint, never the token.
type Session struct {
	ID                auth.SessionID
	Account           auth.AccountID
	Surface           auth.Surface
	Fingerprint       Fingerprint
	CSRF              CSRFToken
	CreatedAt         time.Time
	LastActiveAt      time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	RevokedAt         *time.Time
	RotatedTo         *auth.SessionID
}

// Issue builds a session and its token together. The token is returned once and
// is never derivable from what is stored.
func Issue(account auth.AccountID, kind auth.Kind, surface auth.Surface, lifetimes Lifetimes, now time.Time, random io.Reader) (Session, Token, error) {
	if account.IsZero() {
		return Session{}, Token{}, fmt.Errorf("%w: no account was named", ErrInvalid)
	}
	// The surface is bound to the kind here, not left to the caller: an operator
	// session may only ever belong to an operator account.
	if err := auth.ValidateSurface(kind, surface); err != nil {
		return Session{}, Token{}, fmt.Errorf("%w: %s", ErrInvalid, err)
	}
	if err := lifetimes.Validate(); err != nil {
		return Session{}, Token{}, err
	}

	id, err := auth.NewSessionID()
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

// Validate is the single authority on a session record about to be written. Every
// write path runs it, so no record can enter storage through one boundary that
// another would have refused.
func (s Session) Validate(kind auth.Kind) error {
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
	if err := auth.ValidateSurface(kind, s.Surface); err != nil {
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

// ActivityIsWorthPersisting keeps a burst of events from becoming a write each.
// It also refuses an instant that would move a stamp backwards, so requests
// observed out of order can never shorten a deadline.
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
