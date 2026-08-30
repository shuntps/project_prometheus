package password_test

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
)

// The same address written two ways: e followed by a combining acute accent, and
// the precomposed character. NFC composes the first into the second.
const (
	decomposed = "mot de passe café tres long"
	composed   = "mot de passe café tres long"
)

// TestCanonicallyEquivalentPasswordsMatch keeps one password typed on two
// keyboards from becoming two credentials.
func TestCanonicallyEquivalentPasswordsMatch(t *testing.T) {
	if decomposed == composed {
		t.Fatal("the two spellings are identical, so the probe proves nothing")
	}
	if utf8.RuneCountInString(decomposed) == utf8.RuneCountInString(composed) {
		t.Fatal("the two spellings hold the same number of code points, so the probe is weak")
	}

	t.Run("stored decomposed, presented composed", func(t *testing.T) {
		hasher := mustHasher(t, floorParams())
		encoded, err := hasher.Hash(decomposed)
		if err != nil {
			t.Fatalf("hashing failed: %v", err)
		}
		if _, err := hasher.Verify(encoded, composed); err != nil {
			t.Fatalf("the composed spelling was refused: %v", err)
		}
	})

	t.Run("stored composed, presented decomposed", func(t *testing.T) {
		hasher := mustHasher(t, floorParams())
		encoded, err := hasher.Hash(composed)
		if err != nil {
			t.Fatalf("hashing failed: %v", err)
		}
		if _, err := hasher.Verify(encoded, decomposed); err != nil {
			t.Fatalf("the decomposed spelling was refused: %v", err)
		}
	})
}

// TestThePolicyCountsTheNormalisedForm keeps a decomposed spelling from buying
// code points the stored password does not have.
func TestThePolicyCountsTheNormalisedForm(t *testing.T) {
	// Fifteen accented letters: thirty code points decomposed, fifteen normalised.
	short := strings.Repeat("é", 15)
	if utf8.RuneCountInString(short) != 30 {
		t.Fatalf("the probe holds %d code points decomposed, want 30", utf8.RuneCountInString(short))
	}
	hasher := mustHasherWith(t, floorParams(), password.Policy{MinCodePoints: 16})
	if _, err := hasher.Hash(short); !errors.Is(err, password.ErrUnusable) {
		t.Fatalf("a password of 15 normalised code points passed a 16 code point minimum: %v", err)
	}
}

// TestNoTransformationBeyondCanonicalNormalisation keeps NFC from becoming
// trimming, case folding or a compatibility mapping.
func TestNoTransformationBeyondCanonicalNormalisation(t *testing.T) {
	cases := map[string][2]string{
		"leading and trailing spaces": {"  a password long enough  ", "a password long enough"},
		"case":                        {"A Password Long Enough", "a password long enough"},
		"compatibility only":          {"ﬁve passwords long enough", "five passwords long enough"},
		"full width digit":            {"password number １２３４", "password number 1234"},
	}
	for name, pair := range cases {
		t.Run(name, func(t *testing.T) {
			hasher := mustHasher(t, floorParams())
			encoded, err := hasher.Hash(pair[0])
			if err != nil {
				t.Fatalf("hashing failed: %v", err)
			}
			if _, err := hasher.Verify(encoded, pair[1]); !errors.Is(err, password.ErrMismatch) {
				t.Fatalf("%q and %q were treated as one password: %v", pair[0], pair[1], err)
			}
		})
	}
}

// TestAnNFCExpansionBeyondTheResourceLimitIsRefused exercises the second check:
// normalisation lengthens a code point excluded from recomposition.
func TestAnNFCExpansionBeyondTheResourceLimitIsRefused(t *testing.T) {
	// U+0958 is a Unicode composition exclusion, so NFC leaves it decomposed: three
	// bytes become six. See UAX #15.
	const excluded = "\u0958"
	raw := strings.Repeat(excluded, 1365)
	if len(raw) > password.MaxBytes {
		t.Fatalf("the raw input is %d bytes, already above the %d byte limit", len(raw), password.MaxBytes)
	}
	normalised := norm.NFC.String(raw)
	if len(normalised) <= password.MaxBytes {
		t.Fatalf("the normalised form is %d bytes, so it never crosses the %d byte limit", len(normalised), password.MaxBytes)
	}
	t.Logf("raw %d bytes, normalised %d bytes, limit %d", len(raw), len(normalised), password.MaxBytes)

	hasher := mustHasher(t, floorParams())
	if _, err := hasher.Hash(raw); !errors.Is(err, password.ErrUnusable) {
		t.Errorf("an input whose normalised form exceeds the limit was hashed: %v", err)
	}
	encoded, err := hasher.Hash(probePassword)
	if err != nil {
		t.Fatalf("hashing failed: %v", err)
	}
	if _, err := hasher.Verify(encoded, raw); !errors.Is(err, password.ErrUnusable) {
		t.Errorf("an input whose normalised form exceeds the limit was verified: %v", err)
	}
}

// TestTheRawInputIsBoundedBeforeNormalisation keeps normalisation from being
// reached by an input that is already too large or not valid UTF-8.
func TestTheRawInputIsBoundedBeforeNormalisation(t *testing.T) {
	hasher := mustHasher(t, floorParams())
	oversized := strings.Repeat("a", password.MaxBytes+1)
	if _, err := hasher.Hash(oversized); !errors.Is(err, password.ErrUnusable) {
		t.Errorf("an oversized raw input was accepted for hashing: %v", err)
	}
	encoded, err := hasher.Hash(probePassword)
	if err != nil {
		t.Fatalf("hashing failed: %v", err)
	}
	if _, err := hasher.Verify(encoded, oversized); !errors.Is(err, password.ErrUnusable) {
		t.Errorf("an oversized raw input was accepted for verification: %v", err)
	}

	invalid := "long enough password \xff\xfe"
	if utf8.ValidString(invalid) {
		t.Fatal("the probe is valid UTF-8, so it proves nothing")
	}
	if _, err := hasher.Hash(invalid); !errors.Is(err, password.ErrUnusable) {
		t.Errorf("invalid UTF-8 was accepted for hashing: %v", err)
	}
	if _, err := hasher.Verify(encoded, invalid); !errors.Is(err, password.ErrUnusable) {
		t.Errorf("invalid UTF-8 was accepted for verification: %v", err)
	}
}
