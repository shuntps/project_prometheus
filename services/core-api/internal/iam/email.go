package iam

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Redacted is what every sensitive value renders as. The real value is reached
// only through an explicit call at the boundary that needs it.
const Redacted = "[redacted]"

// EmailAddress is a normalised login address. It is one way to reach an account
// and is never the account's identity.
type EmailAddress struct {
	value string
}

const maxEmailLength = 254

// NormaliseEmail folds case and trims surrounding space, and nothing else. Dots,
// plus-addressing and provider rules are left alone: rewriting merges accounts.
func NormaliseEmail(raw string) (EmailAddress, error) {
	trimmed := strings.ToLower(strings.TrimSpace(raw))

	switch {
	case trimmed == "":
		return EmailAddress{}, fmt.Errorf("%w: the login address is empty", ErrInvalid)
	case len(trimmed) > maxEmailLength:
		return EmailAddress{}, fmt.Errorf("%w: the login address exceeds %d bytes", ErrInvalid, maxEmailLength)
	case strings.ContainsAny(trimmed, " \t\r\n"):
		return EmailAddress{}, fmt.Errorf("%w: the login address carries whitespace", ErrInvalid)
	}

	local, domain, found := strings.Cut(trimmed, "@")
	if !found || local == "" || domain == "" || strings.Contains(domain, "@") {
		return EmailAddress{}, fmt.Errorf("%w: the login address is not a single local part and domain", ErrInvalid)
	}
	if !strings.Contains(domain, ".") || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return EmailAddress{}, fmt.Errorf("%w: the login address carries no usable domain", ErrInvalid)
	}
	return EmailAddress{value: trimmed}, nil
}

// Reveal returns the address. Only the store that persists it and the comparison
// that matches it may call this.
func (e EmailAddress) Reveal() string { return e.value }

func (e EmailAddress) IsZero() bool { return e.value == "" }

func (e EmailAddress) String() string { return Redacted }

func (e EmailAddress) GoString() string { return Redacted }

func (e EmailAddress) LogValue() slog.Value { return slog.StringValue(Redacted) }

func (e EmailAddress) MarshalText() ([]byte, error) { return []byte(Redacted), nil }

func (e EmailAddress) MarshalJSON() ([]byte, error) { return []byte(`"` + Redacted + `"`), nil }

// EmailIdentity binds a login address to an account and records whether it has
// been proven. Verification state is separate from the address itself.
type EmailIdentity struct {
	ID         uuid.UUID
	Account    AccountID
	Address    EmailAddress
	VerifiedAt *time.Time
	CreatedAt  time.Time
}

// IsVerified reports proven control of the address, which is not identity
// proofing, not age assurance and not know-your-customer verification.
func (e EmailIdentity) IsVerified() bool { return e.VerifiedAt != nil }
