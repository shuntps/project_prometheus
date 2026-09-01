// Package emailverification issues and evaluates the challenge that proves
// control of a login address. Control of a mailbox is all it establishes: it is
// neither an age assurance nor an identity proof.
package emailverification

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

var (
	// ErrInvalid reports a challenge the domain refuses to construct.
	ErrInvalid = errors.New("invalid email verification")
	// ErrUnusable reports a challenge that exists but may not be consumed.
	ErrUnusable = errors.New("email verification is not usable")
)

// ID identifies a stored challenge row. It is never the verification token.
type ID uuid.UUID

func (i ID) String() string { return uuid.UUID(i).String() }

func (i ID) IsZero() bool { return uuid.UUID(i) == uuid.Nil }

// Lifetimes bounds how long a challenge may be consumed and how often a new one
// may be issued for the same identity.
type Lifetimes struct {
	// Lifetime is how long an issued challenge stays consumable.
	Lifetime time.Duration
	// ResendInterval is the shortest spacing between two issuances, so a caller
	// cannot make the service send an unbounded stream of messages.
	ResendInterval time.Duration
}

const (
	minLifetime       = time.Minute
	maxLifetime       = 24 * time.Hour
	minResendInterval = time.Second
)

// Validate keeps the two durations ordered: an interval at or above the lifetime
// would let every challenge expire before another could be asked for.
func (l Lifetimes) Validate() error {
	var problems []string
	if l.Lifetime < minLifetime || l.Lifetime > maxLifetime {
		problems = append(problems, fmt.Sprintf("the verification lifetime must be between %s and %s", minLifetime, maxLifetime))
	}
	if l.ResendInterval < minResendInterval {
		problems = append(problems, fmt.Sprintf("the resend interval must be at least %s", minResendInterval))
	}
	if l.Lifetime >= minLifetime && l.ResendInterval >= minResendInterval && l.ResendInterval >= l.Lifetime {
		problems = append(problems, "the resend interval must be shorter than the verification lifetime")
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalid, strings.Join(problems, "; "))
	}
	return nil
}

// Challenge is the server-side record. It holds the fingerprint, never the token.
type Challenge struct {
	ID           ID
	Identity     iam.IdentityID
	Fingerprint  Fingerprint
	IssuedAt     time.Time
	ExpiresAt    time.Time
	ConsumedAt   *time.Time
	SupersededAt *time.Time
}

// Issue builds a challenge and its token together, and is the only way to emit a
// new pair. The token is returned once and is never derivable from what is stored.
func Issue(identity iam.IdentityID, lifetimes Lifetimes, now time.Time) (Challenge, Token, error) {
	return issue(identity, lifetimes, now, rand.Reader)
}

// issue takes the entropy source so that both draws stay provable. It is
// unexported: no caller outside this package may choose it.
func issue(identity iam.IdentityID, lifetimes Lifetimes, now time.Time, random io.Reader) (Challenge, Token, error) {
	// Every argument is settled before a single byte of entropy is spent.
	if identity.IsZero() {
		return Challenge{}, Token{}, fmt.Errorf("%w: no identity was named", ErrInvalid)
	}
	if err := lifetimes.Validate(); err != nil {
		return Challenge{}, Token{}, err
	}
	if now.IsZero() {
		return Challenge{}, Token{}, fmt.Errorf("%w: no issue instant was given", ErrInvalid)
	}
	issued := now.UTC()

	value, err := uuid.NewRandomFromReader(random)
	if err != nil {
		return Challenge{}, Token{}, fmt.Errorf("%w: no challenge identifier could be drawn", ErrInvalid)
	}
	token, err := newToken(random)
	if err != nil {
		return Challenge{}, Token{}, err
	}

	built := Challenge{
		ID:          ID(value),
		Identity:    identity,
		Fingerprint: token.Fingerprint(),
		IssuedAt:    issued,
		ExpiresAt:   issued.Add(lifetimes.Lifetime),
	}
	if err := built.Validate(); err != nil {
		return Challenge{}, Token{}, err
	}
	return built, token, nil
}

// Validate is the single authority on a record about to be written, so no write
// path can store what another would have refused.
func (c Challenge) Validate() error {
	var problems []string
	if c.ID.IsZero() {
		problems = append(problems, "the challenge identifier is zero")
	}
	if c.Identity.IsZero() {
		problems = append(problems, "the identity is zero")
	}
	if c.Fingerprint.IsZero() {
		problems = append(problems, "the token fingerprint is zero")
	}
	if c.ConsumedAt != nil || c.SupersededAt != nil {
		problems = append(problems, "a new challenge may not already be consumed or superseded")
	}
	switch {
	case c.IssuedAt.IsZero(), c.ExpiresAt.IsZero():
		problems = append(problems, "every instant must be set")
	case !c.ExpiresAt.After(c.IssuedAt):
		problems = append(problems, "the expiry must follow the issuance")
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalid, strings.Join(problems, "; "))
	}
	return nil
}

// UsableAt reports why a challenge may not be consumed, checking every reason
// rather than only the first, so no path treats an unknown state as usable.
func (c Challenge) UsableAt(now time.Time) error {
	switch {
	case c.ID.IsZero() || c.Identity.IsZero():
		return fmt.Errorf("%w: the challenge record is incomplete", ErrUnusable)
	case c.ConsumedAt != nil:
		return fmt.Errorf("%w: it was already consumed", ErrUnusable)
	case c.SupersededAt != nil:
		return fmt.Errorf("%w: it was superseded", ErrUnusable)
	case !now.UTC().Before(c.ExpiresAt):
		return fmt.Errorf("%w: it reached its expiry", ErrUnusable)
	default:
		return nil
	}
}

// MayReissueAt bounds how often a new challenge is emitted for one identity. It
// is decided on the issuance instant, never on the expiry: a challenge that has
// expired inside the interval still holds the caller back.
func (c Challenge) MayReissueAt(now time.Time, lifetimes Lifetimes) bool {
	return now.UTC().Sub(c.IssuedAt) >= lifetimes.ResendInterval
}
