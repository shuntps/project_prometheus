package session

import (
	"fmt"
	"io"

	"github.com/google/uuid"
)

// ID identifies a stored session row. It is never the session token.
type ID uuid.UUID

// newID draws a version 4 identifier from the entropy source Issue was built
// with, so the three draws of one issuance share one provable source.
func newID(random io.Reader) (ID, error) {
	value, err := uuid.NewRandomFromReader(random)
	if err != nil {
		return ID{}, fmt.Errorf("%w: no session identifier could be drawn", ErrInvalid)
	}
	return ID(value), nil
}

func (s ID) String() string { return uuid.UUID(s).String() }

func (s ID) IsZero() bool { return uuid.UUID(s) == uuid.Nil }
