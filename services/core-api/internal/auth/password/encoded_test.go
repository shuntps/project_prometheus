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
