// Package password stores and verifies passwords with Argon2id. It implements no
// cryptography of its own; the derivation comes from golang.org/x/crypto.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

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
