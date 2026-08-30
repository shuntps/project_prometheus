// Package password stores and verifies passwords with Argon2id. It implements no
// cryptography of its own; the derivation comes from golang.org/x/crypto.
package password

import (
	"crypto/rand"
	"crypto/subtle"
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
// correcting them. It is the only way in, and always draws from the process source.
func NewHasher(params Params, policy Policy) (*Hasher, error) {
	return newHasher(params, policy, rand.Reader)
}

// newHasher takes the entropy source so that the failure path Hash depends on
// stays provable. It is unexported: no caller outside this package may choose it.
func newHasher(params Params, policy Policy, random io.Reader) (*Hasher, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	return &Hasher{params: params, policy: policy, random: random}, nil
}

// Hash derives a representation with a fresh random salt, so two identical
// passwords never produce the same stored value.
func (h *Hasher) Hash(plaintext string) (Encoded, error) {
	// The password is settled before any entropy is drawn, so an unusable one
	// never consumes from the source.
	normalised, err := prepare(plaintext)
	if err != nil {
		return Encoded{}, err
	}
	if err := h.policy.count(normalised); err != nil {
		return Encoded{}, err
	}
	salt := make([]byte, SaltLength)
	if _, err := io.ReadFull(h.random, salt); err != nil {
		// The sentinel is fixed: the caller learns that nothing was derived and
		// nothing about the source that failed.
		return Encoded{}, ErrEntropy
	}
	key := argon2.IDKey([]byte(normalised), salt, h.params.Iterations, h.params.MemoryKiB, h.params.Lanes, KeyLength)
	return Encoded{value: encode(h.params, salt, key)}, nil
}

// Verify compares in constant time and reports whether the representation should
// be written again with the currently adopted parameters.
func (h *Hasher) Verify(encoded Encoded, plaintext string) (rehash bool, err error) {
	stored, salt, key, err := decode(encoded.value)
	if err != nil {
		return false, err
	}
	// Only the resource limit applies here, and the value is normalised exactly as
	// it was: a credential stored under an older minimum stays verifiable.
	normalised, err := prepare(plaintext)
	if err != nil {
		return false, err
	}

	candidate := argon2.IDKey([]byte(normalised), salt, stored.Iterations, stored.MemoryKiB, stored.Lanes, uint32(len(key)))
	if subtle.ConstantTimeCompare(candidate, key) != 1 {
		return false, ErrMismatch
	}
	return h.params.strongerThan(stored), nil
}
