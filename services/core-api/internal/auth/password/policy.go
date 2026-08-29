package password

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

var (
	// ErrInvalidParams reports parameters the package refuses to hash with.
	ErrInvalidParams = errors.New("invalid password hashing parameters")
	// ErrMalformed reports a stored representation that cannot be read.
	ErrMalformed = errors.New("malformed password representation")
	// ErrMismatch reports a password that does not match the stored value.
	ErrMismatch = errors.New("password does not match")
	// ErrUnusable reports an input the policy refuses before any hashing.
	ErrUnusable = errors.New("unusable password")
	// ErrInvalidPolicy reports a length policy the package refuses to apply.
	ErrInvalidPolicy = errors.New("invalid password policy")
)

// The floor is the current OWASP Password Storage guidance for Argon2id
// (m=19456 KiB, t=2, p=1). Configuration may exceed it and may never go under.
const (
	FloorMemoryKiB  uint32 = 19456
	FloorIterations uint32 = 2
	FloorLanes      uint8  = 1

	SaltLength uint32 = 16
	KeyLength  uint32 = 32
)

const (
	// SingleFactorMinimum is what NIST SP 800-63B requires of a password used as
	// the only factor. No multi-factor journey exists, so nothing goes under it.
	SingleFactorMinimum = 15
	// MultiFactorMinimum is what the same text permits only alongside a second
	// factor. It is named so the distinction stays visible, and is not adopted.
	MultiFactorMinimum = 8
	// MaxBytes bounds the work one request can demand. It is a resource limit and
	// never a length policy; the two are checked separately.
	MaxBytes = 4096
)

// Policy is what a new or changed password must satisfy. It is not applied when
// verifying a credential already stored, so raising it strands nobody.
type Policy struct {
	MinCodePoints int
}

// Validate refuses a policy weaker than the single-factor minimum. It will only
// be safe to accept MultiFactorMinimum once a second factor is actually required.
func (p Policy) Validate() error {
	switch {
	case p.MinCodePoints < SingleFactorMinimum:
		return fmt.Errorf("%w: the minimum must be at least %d code points while a password is the only factor", ErrInvalidPolicy, SingleFactorMinimum)
	case p.MinCodePoints > MaxBytes:
		return fmt.Errorf("%w: the minimum must not exceed the %d-byte resource limit", ErrInvalidPolicy, MaxBytes)
	}
	return nil
}

// Check applies the policy to a password being created or changed. Each Unicode
// code point counts as one character, as NIST SP 800-63B requires.
func (p Policy) Check(plaintext string) error {
	if err := CheckResourceLimit(plaintext); err != nil {
		return err
	}
	if count := utf8.RuneCountInString(plaintext); count < p.MinCodePoints {
		return fmt.Errorf("%w: the password is %d code points, and %d are required", ErrUnusable, count, p.MinCodePoints)
	}
	return nil
}

// CheckResourceLimit is the only bound applied when verifying a stored
// credential. It refuses what cannot be processed, never what is merely short.
func CheckResourceLimit(plaintext string) error {
	if !utf8.ValidString(plaintext) {
		return fmt.Errorf("%w: the password is not valid UTF-8", ErrUnusable)
	}
	if len(plaintext) > MaxBytes {
		return fmt.Errorf("%w: the password exceeds %d bytes", ErrUnusable, MaxBytes)
	}
	return nil
}

// Params are the Argon2id cost settings. They are carried inside every stored
// representation, so a credential stays verifiable after the adopted set moves.
type Params struct {
	MemoryKiB  uint32
	Iterations uint32
	Lanes      uint8
}

// Validate refuses anything under the adopted floor, so no configuration path
// can silently weaken storage.
func (p Params) Validate() error {
	var problems []string
	if p.MemoryKiB < FloorMemoryKiB {
		problems = append(problems, fmt.Sprintf("memory must be at least %d KiB", FloorMemoryKiB))
	}
	if p.Iterations < FloorIterations {
		problems = append(problems, fmt.Sprintf("iterations must be at least %d", FloorIterations))
	}
	if p.Lanes < FloorLanes {
		problems = append(problems, fmt.Sprintf("parallelism must be at least %d", FloorLanes))
	}
	// An upper bound keeps a mistaken configuration from exhausting the host.
	if p.MemoryKiB > 1<<21 {
		problems = append(problems, "memory must not exceed 2 GiB")
	}
	if p.Iterations > 16 {
		problems = append(problems, "iterations must not exceed 16")
	}
	if p.Lanes > 16 {
		problems = append(problems, "parallelism must not exceed 16")
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalidParams, strings.Join(problems, "; "))
	}
	return nil
}

// strongerThan decides an upgrade, not any difference. A stored value at least as
// costly is left alone, and a change of parallelism alone counts as incomparable.
func (target Params) strongerThan(stored Params) bool {
	if target.Lanes != stored.Lanes {
		return false
	}
	if target.MemoryKiB < stored.MemoryKiB || target.Iterations < stored.Iterations {
		return false
	}
	return target.MemoryKiB > stored.MemoryKiB || target.Iterations > stored.Iterations
}
