// Package iam owns the operational accounts, the login identities, and the roles,
// permissions and surfaces that decide what an account may do.
package iam

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Kind is what an account is, which is separate from what it may do.
type Kind string

const (
	KindViewer   Kind = "viewer"
	KindCreator  Kind = "creator"
	KindOperator Kind = "operator"
)

// Status is the operational state of an account.
type Status string

const (
	StatusPending   Status = "pending"
	StatusActive    Status = "active"
	StatusSuspended Status = "suspended"
	StatusClosed    Status = "closed"
)

// CanAuthenticate reports whether the status permits a session to be used. Only
// an explicitly usable status qualifies; an unknown one never does.
func (s Status) CanAuthenticate() bool { return s == StatusActive }

// ParseKind resolves no default: an unset or unknown value is not a kind.
func ParseKind(raw string) (Kind, bool) {
	switch kind := Kind(strings.TrimSpace(raw)); kind {
	case KindViewer, KindCreator, KindOperator:
		return kind, true
	default:
		return "", false
	}
}

// AccountID is the random, non-sequential internal identity of an account. It is
// not a secret and never on its own sufficient protection for an object.
type AccountID uuid.UUID

// NewAccountID draws an identifier from the package's CSPRNG-backed generator.
func NewAccountID() (AccountID, error) {
	value, err := uuid.NewRandom()
	if err != nil {
		return AccountID{}, fmt.Errorf("%w: no account identifier could be drawn", ErrInvalid)
	}
	return AccountID(value), nil
}

func (a AccountID) String() string { return uuid.UUID(a).String() }

func (a AccountID) IsZero() bool { return uuid.UUID(a) == uuid.Nil }

// ParseAccountID accepts only a well-formed, non-zero identifier.
func ParseAccountID(raw string) (AccountID, error) {
	value, err := uuid.Parse(strings.TrimSpace(raw))
	if err != nil || value == uuid.Nil {
		return AccountID{}, fmt.Errorf("%w: the account identifier is not usable", ErrInvalid)
	}
	return AccountID(value), nil
}

// Account is the operational record: an identifier, a kind, a status, a display
// name and its timestamps. It carries no login address.
type Account struct {
	ID          AccountID
	Kind        Kind
	Status      Status
	DisplayName string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// IdentityID identifies one login identity row. It is not the account, and
// changing an address never changes the account it reaches.
type IdentityID uuid.UUID

// NewIdentityID draws an identifier from the package's CSPRNG-backed generator.
func NewIdentityID() (IdentityID, error) {
	value, err := uuid.NewRandom()
	if err != nil {
		return IdentityID{}, fmt.Errorf("%w: no identity identifier could be drawn", ErrInvalid)
	}
	return IdentityID(value), nil
}

func (i IdentityID) String() string { return uuid.UUID(i).String() }

func (i IdentityID) IsZero() bool { return uuid.UUID(i) == uuid.Nil }
