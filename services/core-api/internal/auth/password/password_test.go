package password_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
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

func TestAMalformedRepresentationIsRefusedWithoutPanicking(t *testing.T) {
	hasher := mustHasher(t, floorParams())
	sound, err := hasher.Hash(probePassword)
	if err != nil {
		t.Fatalf("hashing failed: %v", err)
	}
	fields := strings.Split(sound.Reveal(), "$")

	cases := map[string]string{
		"empty":                  "",
		"not a PHC string":       "argon2id-somehash",
		"wrong algorithm":        strings.Replace(sound.Reveal(), "argon2id", "argon2i", 1),
		"unknown version":        strings.Replace(sound.Reveal(), "v=19", "v=17", 1),
		"unreadable version":     strings.Replace(sound.Reveal(), "v=19", "v=abc", 1),
		"unreadable parameters":  strings.Replace(sound.Reveal(), "m=19456,t=2,p=1", "m=x,t=y,p=z", 1),
		"parameters under floor": strings.Replace(sound.Reveal(), "m=19456,t=2,p=1", "m=8,t=1,p=1", 1),
		"unreadable salt":        strings.Join(append(append([]string{}, fields[:4]...), "!!!!", fields[5]), "$"),
		"short salt":             strings.Join(append(append([]string{}, fields[:4]...), "AAAA", fields[5]), "$"),
		"unreadable key":         strings.Join(append(append([]string{}, fields[:5]...), "!!!!"), "$"),
		"missing field":          strings.Join(fields[:5], "$"),
		"extra field":            sound.Reveal() + "$extra",
	}
	for name, encoded := range cases {
		t.Run(name, func(t *testing.T) {
			rehash, err := hasher.Verify(password.NewEncoded(encoded), probePassword)
			if !errors.Is(err, password.ErrMalformed) {
				t.Fatalf("got %v, want a malformed representation", err)
			}
			if rehash {
				t.Error("a malformed representation asked to be rewritten")
			}
		})
	}
}

func TestParametersUnderTheAdoptedFloorAreRefused(t *testing.T) {
	cases := map[string]password.Params{
		"no memory":          {MemoryKiB: 0, Iterations: 2, Lanes: 1},
		"memory below OWASP": {MemoryKiB: password.FloorMemoryKiB - 1, Iterations: 2, Lanes: 1},
		"one iteration":      {MemoryKiB: password.FloorMemoryKiB, Iterations: 1, Lanes: 1},
		"no iteration":       {MemoryKiB: password.FloorMemoryKiB, Iterations: 0, Lanes: 1},
		"no parallelism":     {MemoryKiB: password.FloorMemoryKiB, Iterations: 2, Lanes: 0},
		"zero value":         {},
		"memory absurd":      {MemoryKiB: 1 << 30, Iterations: 2, Lanes: 1},
		"iterations absurd":  {MemoryKiB: password.FloorMemoryKiB, Iterations: 1000, Lanes: 1},
		"lanes absurd":       {MemoryKiB: password.FloorMemoryKiB, Iterations: 2, Lanes: 200},
	}
	for name, params := range cases {
		t.Run(name, func(t *testing.T) {
			if err := params.Validate(); !errors.Is(err, password.ErrInvalidParams) {
				t.Fatalf("Validate gave %v, want a refusal", err)
			}
			if _, err := password.NewHasher(params, singleFactorPolicy(), nil); !errors.Is(err, password.ErrInvalidParams) {
				t.Fatalf("NewHasher gave %v, want a refusal", err)
			}
		})
	}

	// The floor itself, and anything above it, must be accepted.
	for name, params := range map[string]password.Params{
		"exactly the floor": floorParams(),
		"more memory":       {MemoryKiB: 47104, Iterations: 1 + password.FloorIterations, Lanes: 2},
	} {
		t.Run(name, func(t *testing.T) {
			if err := params.Validate(); err != nil {
				t.Fatalf("acceptable parameters were refused: %v", err)
			}
		})
	}
}

// TestARepresentationAsksToBeRewrittenWhenTheAdoptedParametersMove is what lets
// stored credentials follow guidance without forcing anyone to reset a password.
func TestARepresentationAsksToBeRewrittenWhenTheAdoptedParametersMove(t *testing.T) {
	old := mustHasher(t, floorParams())
	encoded, err := old.Hash(probePassword)
	if err != nil {
		t.Fatalf("hashing failed: %v", err)
	}

	stronger := mustHasher(t, password.Params{MemoryKiB: password.FloorMemoryKiB * 2, Iterations: 3, Lanes: 1})
	rehash, err := stronger.Verify(encoded, probePassword)
	if err != nil {
		t.Fatalf("a sound representation was refused after the parameters moved: %v", err)
	}
	if !rehash {
		t.Fatal("the representation did not ask to be rewritten with the adopted parameters")
	}

	rewritten, err := stronger.Hash(probePassword)
	if err != nil {
		t.Fatalf("rewriting failed: %v", err)
	}
	again, err := stronger.Verify(rewritten, probePassword)
	if err != nil {
		t.Fatalf("the rewritten representation was refused: %v", err)
	}
	if again {
		t.Error("the rewritten representation still asks to be rewritten")
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

// TestNoRewriteIsEverAskedForTowardWeakerParameters is the counter-proof: a
// stored representation that is already more costly must be left alone.
func TestNoRewriteIsEverAskedForTowardWeakerParameters(t *testing.T) {
	costly := password.Params{MemoryKiB: 65536, Iterations: 4, Lanes: 1}
	stored := mustHasher(t, costly)
	encoded, err := stored.Hash(probePassword)
	if err != nil {
		t.Fatalf("hashing failed: %v", err)
	}

	weaker := mustHasher(t, floorParams())
	rehash, err := weaker.Verify(encoded, probePassword)
	if err != nil {
		t.Fatalf("a stronger stored representation was refused: %v", err)
	}
	if rehash {
		t.Fatal("a rewrite toward weaker parameters was requested")
	}
}

// TestTheUpgradeDecisionIsExplicitOnEveryDimension pins what does and does not
// count as a strengthening.
func TestTheUpgradeDecisionIsExplicitOnEveryDimension(t *testing.T) {
	base := password.Params{MemoryKiB: 32768, Iterations: 3, Lanes: 2}
	stored := mustHasher(t, base)
	encoded, err := stored.Hash(probePassword)
	if err != nil {
		t.Fatalf("hashing failed: %v", err)
	}

	cases := map[string]struct {
		current password.Params
		rehash  bool
	}{
		"identical":                {base, false},
		"more memory":              {password.Params{MemoryKiB: 65536, Iterations: 3, Lanes: 2}, true},
		"more iterations":          {password.Params{MemoryKiB: 32768, Iterations: 4, Lanes: 2}, true},
		"more of both":             {password.Params{MemoryKiB: 65536, Iterations: 5, Lanes: 2}, true},
		"less memory":              {password.Params{MemoryKiB: 19456, Iterations: 3, Lanes: 2}, false},
		"less iterations":          {password.Params{MemoryKiB: 32768, Iterations: 2, Lanes: 2}, false},
		"more memory, less time":   {password.Params{MemoryKiB: 65536, Iterations: 2, Lanes: 2}, false},
		"less memory, more time":   {password.Params{MemoryKiB: 19456, Iterations: 5, Lanes: 2}, false},
		"parallelism alone raised": {password.Params{MemoryKiB: 32768, Iterations: 3, Lanes: 4}, false},
		"parallelism alone cut":    {password.Params{MemoryKiB: 32768, Iterations: 3, Lanes: 1}, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			hasher := mustHasher(t, c.current)
			rehash, err := hasher.Verify(encoded, probePassword)
			if err != nil {
				t.Fatalf("verification failed: %v", err)
			}
			if rehash != c.rehash {
				t.Fatalf("rehash=%t, want %t", rehash, c.rehash)
			}
		})
	}
}

// TestTheParserRequiresTheCanonicalShape refuses a representation this package
// would never have produced.
func TestTheParserRequiresTheCanonicalShape(t *testing.T) {
	hasher := mustHasher(t, floorParams())
	sound, err := hasher.Hash(probePassword)
	if err != nil {
		t.Fatalf("hashing failed: %v", err)
	}
	fields := strings.Split(sound.Reveal(), "$")

	oversized := make([]byte, 64)
	rebuild := func(salt, key string) string {
		return strings.Join([]string{"", "argon2id", fields[2], fields[3], salt, key}, "$")
	}
	encode := func(b []byte) string { return strings.TrimRight(base64.StdEncoding.EncodeToString(b), "=") }

	cases := map[string]string{
		"version with a suffix":    strings.Replace(sound.Reveal(), "v=19", "v=19x", 1),
		"parameters with a suffix": strings.Replace(sound.Reveal(), "p=1$", "p=1x$", 1),
		"salt one byte too long":   rebuild(encode(oversized[:17]), fields[5]),
		"salt one byte too short":  rebuild(encode(oversized[:15]), fields[5]),
		"key one byte too long":    rebuild(fields[4], encode(oversized[:33])),
		"key one byte too short":   rebuild(fields[4], encode(oversized[:31])),
		"trailing separator":       sound.Reveal() + "$",
	}
	for name, encoded := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := hasher.Verify(password.NewEncoded(encoded), probePassword); !errors.Is(err, password.ErrMalformed) {
				t.Fatalf("got %v, want a malformed representation", err)
			}
		})
	}
}

// TestTheStoredRepresentationNeverRendersItself keeps an encoded hash from
// travelling as an ordinary string through records and errors.
func TestTheStoredRepresentationNeverRendersItself(t *testing.T) {
	hasher := mustHasher(t, floorParams())
	encoded, err := hasher.Hash(probePassword)
	if err != nil {
		t.Fatalf("hashing failed: %v", err)
	}
	probe := encoded.Reveal()

	holder := struct{ Credential password.Encoded }{Credential: encoded}
	nested, err := json.Marshal(holder)
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}
	direct, err := json.Marshal(encoded)
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}
	var logs bytes.Buffer
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("probe",
		slog.Any("credential", encoded), slog.Any("holder", holder))

	for name, rendering := range map[string]string{
		"verb %v":           fmt.Sprintf("%v", encoded),
		"verb %s":           fmt.Sprintf("%s", encoded),
		"verb %q":           fmt.Sprintf("%q", encoded),
		"verb %+v":          fmt.Sprintf("%+v", encoded),
		"verb %#v":          fmt.Sprintf("%#v", encoded),
		"inside a struct":   fmt.Sprintf("%+v", holder),
		"wrapped in error":  fmt.Errorf("storing failed: %v", encoded).Error(),
		"encoded as JSON":   string(direct),
		"nested JSON":       string(nested),
		"structured record": logs.String(),
	} {
		if strings.Contains(rendering, probe) {
			t.Errorf("the stored representation escaped through %s", name)
		}
	}
	if encoded.Reveal() != probe {
		t.Error("Reveal must still return the value the store persists")
	}
}
