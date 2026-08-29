package session

import (
	"fmt"

	"github.com/google/uuid"
)

// ID identifies a stored session row. It is never the session token.
type ID uuid.UUID

func NewID() (ID, error) {
	value, err := uuid.NewRandom()
	if err != nil {
		return ID{}, fmt.Errorf("%w: no session identifier could be drawn", ErrInvalid)
	}
	return ID(value), nil
}

func (s ID) String() string { return uuid.UUID(s).String() }

func (s ID) IsZero() bool { return uuid.UUID(s) == uuid.Nil }
