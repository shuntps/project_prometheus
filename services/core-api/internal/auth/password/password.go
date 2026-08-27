// Package password stores and verifies passwords with Argon2id. It implements no
// cryptography of its own; the derivation comes from golang.org/x/crypto.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
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

// Encoded is a stored password representation. It redacts itself; the store that
// persists it and the verifier that reads it reach the value explicitly.
type Encoded struct {
	value string
}

// NewEncoded wraps a representation read back from storage.
func NewEncoded(raw string) Encoded { return Encoded{value: raw} }

// Reveal returns the representation. Only storage and verification call this.
func (e Encoded) Reveal() string { return e.value }

func (e Encoded) IsZero() bool { return e.value == "" }

func (e Encoded) String() string { return redacted }

func (e Encoded) GoString() string { return redacted }

func (e Encoded) LogValue() slog.Value { return slog.StringValue(redacted) }

func (e Encoded) MarshalText() ([]byte, error) { return []byte(redacted), nil }

func (e Encoded) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

const redacted = "[redacted]"

// Hasher derives and verifies stored representations.
type Hasher struct {
	params Params
	policy Policy
	random io.Reader
}

// NewHasher refuses parameters or a policy under the floor rather than
// correcting them.
func NewHasher(params Params, policy Policy, random io.Reader) (*Hasher, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	if random == nil {
		random = rand.Reader
	}
	return &Hasher{params: params, policy: policy, random: random}, nil
}

// Policy reports what a new password must satisfy.
func (h *Hasher) Policy() Policy { return h.policy }

// Params reports the settings new representations are written with.
func (h *Hasher) Params() Params { return h.params }

// Hash derives a representation with a fresh random salt, so two identical
// passwords never produce the same stored value.
func (h *Hasher) Hash(plaintext string) (Encoded, error) {
	if err := h.policy.Check(plaintext); err != nil {
		return Encoded{}, err
	}
	salt := make([]byte, SaltLength)
	if _, err := io.ReadFull(h.random, salt); err != nil {
		// No detail is carried: the caller must not learn anything about entropy.
		return Encoded{}, errors.New("no salt could be drawn")
	}
	key := argon2.IDKey([]byte(plaintext), salt, h.params.Iterations, h.params.MemoryKiB, h.params.Lanes, KeyLength)
	return Encoded{value: encode(h.params, salt, key)}, nil
}

// Verify compares in constant time and reports whether the representation should
// be written again with the currently adopted parameters.
func (h *Hasher) Verify(encoded Encoded, plaintext string) (rehash bool, err error) {
	stored, salt, key, err := decode(encoded.value)
	if err != nil {
		return false, err
	}
	// Only the resource limit applies here: a credential stored under an older,
	// shorter minimum must stay verifiable after the minimum rises.
	if err := CheckResourceLimit(plaintext); err != nil {
		return false, err
	}

	candidate := argon2.IDKey([]byte(plaintext), salt, stored.Iterations, stored.MemoryKiB, stored.Lanes, uint32(len(key)))
	if subtle.ConstantTimeCompare(candidate, key) != 1 {
		return false, ErrMismatch
	}
	return h.params.strongerThan(stored), nil
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

var encoding = base64.RawStdEncoding

// encode writes the PHC string format, which carries the algorithm, the
// algorithm version and every parameter needed to verify and to detect a rehash.
func encode(p Params, salt, key []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.MemoryKiB, p.Iterations, p.Lanes,
		encoding.EncodeToString(salt), encoding.EncodeToString(key))
}

func decode(encoded string) (Params, []byte, []byte, error) {
	fields := strings.Split(encoded, "$")
	if len(fields) != 6 || fields[0] != "" || fields[1] != "argon2id" {
		return Params{}, nil, nil, fmt.Errorf("%w: the representation is not an argon2id PHC string", ErrMalformed)
	}

	var version int
	if _, err := fmt.Sscanf(fields[2], "v=%d", &version); err != nil || fields[2] != fmt.Sprintf("v=%d", version) {
		return Params{}, nil, nil, fmt.Errorf("%w: the algorithm version is unreadable", ErrMalformed)
	}
	if version != argon2.Version {
		return Params{}, nil, nil, fmt.Errorf("%w: algorithm version %d is not supported", ErrMalformed, version)
	}

	var p Params
	if _, err := fmt.Sscanf(fields[3], "m=%d,t=%d,p=%d", &p.MemoryKiB, &p.Iterations, &p.Lanes); err != nil ||
		fields[3] != fmt.Sprintf("m=%d,t=%d,p=%d", p.MemoryKiB, p.Iterations, p.Lanes) {
		return Params{}, nil, nil, fmt.Errorf("%w: the parameters are unreadable", ErrMalformed)
	}
	if err := p.Validate(); err != nil {
		return Params{}, nil, nil, fmt.Errorf("%w: the stored parameters are not acceptable", ErrMalformed)
	}

	// The canonical sizes are required exactly, not as a lower bound.
	salt, err := encoding.DecodeString(fields[4])
	if err != nil || len(salt) != int(SaltLength) {
		return Params{}, nil, nil, fmt.Errorf("%w: the salt is not of the canonical size", ErrMalformed)
	}
	key, err := encoding.DecodeString(fields[5])
	if err != nil || len(key) != int(KeyLength) {
		return Params{}, nil, nil, fmt.Errorf("%w: the derived key is not of the canonical size", ErrMalformed)
	}
	return p, salt, key, nil
}
