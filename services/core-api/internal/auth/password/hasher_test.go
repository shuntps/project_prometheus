package password_test

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
)

// The floor is what OWASP currently gives for Argon2id: m=19456, t=2, p=1.
func floorParams() password.Params {
	return password.Params{
		MemoryKiB:  password.FloorMemoryKiB,
		Iterations: password.FloorIterations,
		Lanes:      password.FloorLanes,
	}
}

func singleFactorPolicy() password.Policy {
	return password.Policy{MinCodePoints: password.SingleFactorMinimum}
}

func mustHasherWith(t *testing.T, params password.Params, policy password.Policy) *password.Hasher {
	t.Helper()
	hasher, err := password.NewHasher(params, policy, nil)
	if err != nil {
		t.Fatalf("building the hasher failed: %v", err)
	}
	return hasher
}

func mustHasher(t *testing.T, params password.Params) *password.Hasher {
	t.Helper()
	hasher, err := password.NewHasher(params, singleFactorPolicy(), nil)
	if err != nil {
		t.Fatalf("building the hasher failed: %v", err)
	}
	return hasher
}

const probePassword = "correct horse battery staple"

func TestTheSamePasswordNeverProducesTheSameStoredValue(t *testing.T) {
	hasher := mustHasher(t, floorParams())

	first, err := hasher.Hash(probePassword)
	if err != nil {
		t.Fatalf("hashing failed: %v", err)
	}
	second, err := hasher.Hash(probePassword)
	if err != nil {
		t.Fatalf("hashing failed: %v", err)
	}
	if first == second {
		t.Fatal("two hashes of the same password are identical; the salt is not random")
	}
	for _, encoded := range []password.Encoded{first, second} {
		if !strings.HasPrefix(encoded.Reveal(), "$argon2id$v=19$m=19456,t=2,p=1$") {
			t.Error("the representation does not carry its algorithm and parameters")
		}
	}
}

func TestTheRightPasswordIsAcceptedAndAnyOtherIsRefused(t *testing.T) {
	hasher := mustHasher(t, floorParams())
	encoded, err := hasher.Hash(probePassword)
	if err != nil {
		t.Fatalf("hashing failed: %v", err)
	}

	rehash, err := hasher.Verify(encoded, probePassword)
	if err != nil {
		t.Fatalf("the right password was refused: %v", err)
	}
	if rehash {
		t.Error("a representation written with the adopted parameters asked to be rewritten")
	}

	for _, wrong := range []string{
		probePassword + " ",
		" " + probePassword,
		strings.ToUpper(probePassword),
		"correct horse battery stapl3",
	} {
		if _, err := hasher.Verify(encoded, wrong); !errors.Is(err, password.ErrMismatch) {
			t.Errorf("password %q gave %v, want a mismatch", wrong, err)
		}
	}
}

// TestThePasswordNeverReachesAnErrorOrARecord is the storage half of the rule
// that a credential must not travel through diagnostics.
func TestThePasswordNeverReachesAnErrorOrARecord(t *testing.T) {
	const secret = "s3cr3t-password-probe-value"
	hasher := mustHasher(t, floorParams())

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))

	encoded, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("hashing failed: %v", err)
	}
	logger.Info("credential stored", slog.String("encoded_length", fmt.Sprint(len(encoded.Reveal()))))

	_, mismatch := hasher.Verify(encoded, secret+"-wrong")
	_, malformed := hasher.Verify(password.NewEncoded("$argon2id$broken"), secret)
	_, tooShort := hasher.Hash("short")
	_, tooLong := hasher.Hash(strings.Repeat("a", password.MaxBytes+1))

	renderings := map[string]string{
		"stored representation": encoded.Reveal(),
		"mismatch error":        fmt.Sprint(mismatch),
		"malformed error":       fmt.Sprint(malformed),
		"too short error":       fmt.Sprint(tooShort),
		"too long error":        fmt.Sprint(tooLong),
		"structured record":     logs.String(),
	}
	for name, rendering := range renderings {
		if strings.Contains(rendering, secret) {
			t.Errorf("%s exposed the password: %s", name, rendering)
		}
	}
}

func TestTheInputLimitIsEnforcedAtBothEnds(t *testing.T) {
	hasher := mustHasher(t, floorParams())

	if _, err := hasher.Hash(strings.Repeat("a", password.SingleFactorMinimum-1)); !errors.Is(err, password.ErrUnusable) {
		t.Errorf("a password under the minimum was accepted: %v", err)
	}
	if _, err := hasher.Hash(strings.Repeat("a", password.MaxBytes+1)); !errors.Is(err, password.ErrUnusable) {
		t.Errorf("a password over the limit was accepted: %v", err)
	}
	// ASVS v5.0.0-6.2.9 requires at least 64 characters to be accepted.
	for _, length := range []int{password.SingleFactorMinimum, 64, 128, password.MaxBytes} {
		if _, err := hasher.Hash(strings.Repeat("a", length)); err != nil {
			t.Errorf("a password of %d bytes was refused: %v", length, err)
		}
	}
}

// TestUnicodeAndSpacesSurviveWhole covers the rule that no password is silently
// shortened and that no character class is imposed.
func TestUnicodeAndSpacesSurviveWhole(t *testing.T) {
	hasher := mustHasher(t, floorParams())

	cases := map[string]string{
		"spaces throughout":    "  a pass phrase with spaces  ",
		"accented characters":  "mot de passe très sûr à utiliser",
		"non latin script":     "パスワードをここに入力してください",
		"emoji":                "🔐🔐🔐 a long enough passphrase 🔐🔐🔐",
		"only lowercase":       "aaaaaaaaaaaaaaaaaaaa",
		"punctuation and tabs": "tab\there\tand;punctuation!",
		"combining characters": "égalité fraternité liberté",
	}
	for name, secret := range cases {
		t.Run(name, func(t *testing.T) {
			encoded, err := hasher.Hash(secret)
			if err != nil {
				t.Fatalf("hashing failed: %v", err)
			}
			if _, err := hasher.Verify(encoded, secret); err != nil {
				t.Fatalf("the same password was refused: %v", err)
			}
			// A truncating implementation would accept a shortened prefix.
			runes := []rune(secret)
			if len(runes) > 1 {
				shortened := string(runes[:len(runes)-1])
				if _, err := hasher.Verify(encoded, shortened); err == nil {
					t.Error("a shortened password was accepted; the input is being truncated")
				}
			}
		})
	}
}
