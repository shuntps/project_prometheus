package password

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
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
	// ErrEntropy reports that no salt could be drawn. It names nothing about the
	// source that failed.
	ErrEntropy = errors.New("no salt could be drawn")
)

// The floor is the current OWASP Password Storage guidance for Argon2id
// (m=19456 KiB, t=2, p=1). Configuration may exceed it and may never go under.
const (
	FloorMemoryKiB  uint32 = 19456
	FloorIterations uint32 = 2
	FloorLanes      uint8  = 1

	// The ceilings reject unbounded or nonsensical cost settings; deployment-safe
	// limits still require calibration. No other layer restates them.
	ceilingMemoryKiB  uint32 = 1 << 21
	ceilingIterations uint32 = 16
	ceilingLanes      uint8  = 16

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

// count applies the policy to an already normalised value, so the number of code
// points is the one the stored representation was derived from. Each Unicode code
// point counts as one character, as NIST SP 800-63B requires.
func (p Policy) count(normalised string) error {
	if n := utf8.RuneCountInString(normalised); n < p.MinCodePoints {
		return fmt.Errorf("%w: the password is %d code points, and %d are required", ErrUnusable, n, p.MinCodePoints)
	}
	return nil
}

// prepare bounds the raw input, normalises it to NFC and bounds the result, so
// one single form reaches the policy and the derivation alike.
func prepare(plaintext string) (string, error) {
	if err := CheckResourceLimit(plaintext); err != nil {
		return "", err
	}
	// NFC decomposes canonically then recomposes what may be recomposed, so it can
	// lengthen a value. It never trims, folds case or maps compatibility forms.
	normalised := norm.NFC.String(plaintext)
	if err := CheckResourceLimit(normalised); err != nil {
		return "", err
	}
	return normalised, nil
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
	// The bound below is an absolute operational limit this package imposes; what
	// is safe for a given target still requires calibration.
	if p.MemoryKiB > ceilingMemoryKiB {
		problems = append(problems, fmt.Sprintf("memory must not exceed %d KiB", ceilingMemoryKiB))
	}
	if p.Iterations > ceilingIterations {
		problems = append(problems, fmt.Sprintf("iterations must not exceed %d", ceilingIterations))
	}
	if p.Lanes > ceilingLanes {
		problems = append(problems, fmt.Sprintf("parallelism must not exceed %d", ceilingLanes))
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalidParams, strings.Join(problems, "; "))
	}
	return nil
}

// strongerThan decides an upgrade on cost alone. Lanes are not treated as a
// monotonic cost dimension; changing lanes alone is not considered an upgrade.
func (target Params) strongerThan(stored Params) bool {
	if target.MemoryKiB < stored.MemoryKiB || target.Iterations < stored.Iterations {
		return false
	}
	return target.MemoryKiB > stored.MemoryKiB || target.Iterations > stored.Iterations
}
