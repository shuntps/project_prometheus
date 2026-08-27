package password_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
)

// NIST SP 800-63B: a password used as the only factor must be at least 15
// characters. No multi-factor journey exists, so nothing goes under it.
func TestTheSingleFactorMinimumIsFifteenCharacters(t *testing.T) {
	if password.SingleFactorMinimum != 15 {
		t.Fatalf("the single-factor minimum is %d, want 15", password.SingleFactorMinimum)
	}
	for _, minimum := range []int{0, 1, 7, 8, 12, 14} {
		if err := (password.Policy{MinCodePoints: minimum}).Validate(); !errors.Is(err, password.ErrInvalidPolicy) {
			t.Errorf("a minimum of %d was accepted while no second factor exists: %v", minimum, err)
		}
	}
	for _, minimum := range []int{15, 20, 64} {
		if err := (password.Policy{MinCodePoints: minimum}).Validate(); err != nil {
			t.Errorf("a minimum of %d was refused: %v", minimum, err)
		}
	}
}

// TestTheConfiguredMinimumIsWhatCreationActuallyEnforces closes the gap between
// the configured policy and the hasher.
func TestTheConfiguredMinimumIsWhatCreationActuallyEnforces(t *testing.T) {
	strict := mustHasherWith(t, floorParams(), password.Policy{MinCodePoints: 20})

	for _, length := range []int{15, 18, 19} {
		if _, err := strict.Hash(strings.Repeat("a", length)); !errors.Is(err, password.ErrUnusable) {
			t.Errorf("a password of %d characters was hashed under a policy of 20: %v", length, err)
		}
	}
	if _, err := strict.Hash(strings.Repeat("a", 20)); err != nil {
		t.Errorf("a password meeting the configured minimum was refused: %v", err)
	}
}

func TestFourteenIsRefusedAndFifteenIsAccepted(t *testing.T) {
	hasher := mustHasherWith(t, floorParams(), password.Policy{MinCodePoints: password.SingleFactorMinimum})

	if _, err := hasher.Hash(strings.Repeat("a", 14)); !errors.Is(err, password.ErrUnusable) {
		t.Errorf("fourteen characters were accepted: %v", err)
	}
	if _, err := hasher.Hash(strings.Repeat("a", 15)); err != nil {
		t.Errorf("fifteen characters were refused: %v", err)
	}
}

// TestLengthIsCountedInCodePointsNotBytes keeps a handful of multi-byte
// characters from passing a byte-counted minimum.
func TestLengthIsCountedInCodePointsNotBytes(t *testing.T) {
	hasher := mustHasherWith(t, floorParams(), password.Policy{MinCodePoints: password.SingleFactorMinimum})

	// Five code points, twenty bytes: long enough for a byte count, far too short
	// for a character count.
	short := strings.Repeat("𝔘", 5)
	if len(short) < password.SingleFactorMinimum {
		t.Fatalf("the probe is %d bytes; it no longer demonstrates the hazard", len(short))
	}
	if _, err := hasher.Hash(short); !errors.Is(err, password.ErrUnusable) {
		t.Errorf("%d code points in %d bytes were accepted: %v", 5, len(short), err)
	}

	// Fifteen code points of any width must be accepted.
	for _, wide := range []string{
		strings.Repeat("𝔘", 15),
		strings.Repeat("é", 15),
		strings.Repeat("パ", 15),
		strings.Repeat("🔐", 15),
	} {
		if _, err := hasher.Hash(wide); err != nil {
			t.Errorf("fifteen code points in %d bytes were refused: %v", len(wide), err)
		}
	}
}

// TestTheByteLimitStaysIndependentOfThePolicy keeps the resource bound from
// being read as a length policy.
func TestTheByteLimitStaysIndependentOfThePolicy(t *testing.T) {
	hasher := mustHasherWith(t, floorParams(), password.Policy{MinCodePoints: password.SingleFactorMinimum})

	// Well under the byte limit in code points, well over it in bytes.
	overLimit := strings.Repeat("🔐", password.MaxBytes/4+1)
	if len([]rune(overLimit)) >= password.MaxBytes {
		t.Fatal("the probe no longer separates the two limits")
	}
	if _, err := hasher.Hash(overLimit); !errors.Is(err, password.ErrUnusable) {
		t.Errorf("a password over the byte limit was accepted: %v", err)
	}
	if _, err := hasher.Hash(strings.Repeat("a", password.MaxBytes)); err != nil {
		t.Errorf("a password at the byte limit was refused: %v", err)
	}
}

// TestRaisingTheMinimumNeverMakesAnOldCredentialUnverifiable separates the policy
// applied at creation from the verification of a credential already stored.
func TestRaisingTheMinimumNeverMakesAnOldCredentialUnverifiable(t *testing.T) {
	const existing = "fifteen chars!!"
	lenient := mustHasherWith(t, floorParams(), password.Policy{MinCodePoints: password.SingleFactorMinimum})
	encoded, err := lenient.Hash(existing)
	if err != nil {
		t.Fatalf("hashing failed: %v", err)
	}

	stricter := mustHasherWith(t, floorParams(), password.Policy{MinCodePoints: 32})
	if _, err := stricter.Verify(encoded, existing); err != nil {
		t.Fatalf("a stored credential became unverifiable when the minimum rose: %v", err)
	}
	if _, err := stricter.Hash(existing); !errors.Is(err, password.ErrUnusable) {
		t.Error("the raised minimum was not applied to a new password")
	}
}
