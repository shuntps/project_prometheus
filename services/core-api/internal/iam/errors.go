package iam

import (
	"errors"
)

var (
	// ErrInvalid reports a value the domain refuses to construct.
	ErrInvalid = errors.New("invalid authentication value")
	// ErrDenied reports an action the caller is not authorised to take.
	ErrDenied = errors.New("not authorised")
)
