package session_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

// TestTokensCarryTheAdoptedEntropyAndNeverRepeat covers ASVS v5.0.0-7.2.3: a
// CSPRNG and at least 128 bits. The adopted size is 256 bits.
func TestTokensCarryTheAdoptedEntropyAndNeverRepeat(t *testing.T) {
	const draws = 512
	seen := make(map[string]struct{}, draws)
	for range draws {
		token, err := session.NewToken(rand.Reader)
		if err != nil {
			t.Fatalf("drawing a token failed: %v", err)
		}
		decoded, err := base64.RawURLEncoding.DecodeString(token.Reveal())
		if err != nil {
			t.Fatalf("the token is not of the issued shape: %v", err)
		}
		if len(decoded) != session.TokenBytes || len(decoded)*8 < 128 {
			t.Fatalf("the token carries %d bits", len(decoded)*8)
		}
		if _, repeated := seen[token.Reveal()]; repeated {
			t.Fatal("the same token was drawn twice")
		}
		seen[token.Reveal()] = struct{}{}
	}
}

// TestAFailingRandomSourceRefusesRatherThanWeakening keeps a degraded entropy
// source from producing a predictable token.
func TestAFailingRandomSourceRefusesRatherThanWeakening(t *testing.T) {
	failing := io.LimitReader(rand.Reader, int64(session.TokenBytes-1))
	if _, err := session.NewToken(failing); !errors.Is(err, session.ErrInvalid) {
		t.Fatalf("got %v, want a refusal when the source runs short", err)
	}

	_, _, err := session.Issue(mustAccount(t), iam.KindViewer, iam.SurfacePublic, lifetimes(), time.Now(), io.LimitReader(rand.Reader, 4))
	if !errors.Is(err, session.ErrInvalid) {
		t.Fatalf("a session was issued from a short source: %v", err)
	}
}

// TestTheStoredFingerprintDoesNotYieldTheToken is why only the fingerprint is
// written: recovering the token from it must be infeasible, and it must differ.
func TestTheStoredFingerprintDoesNotYieldTheToken(t *testing.T) {
	sess, token := issue(t, time.Now())

	if bytes.Contains(sess.Fingerprint.Bytes(), []byte(token.Reveal())) {
		t.Fatal("the fingerprint carries the token")
	}
	if got := fmt.Sprintf("%x", sess.Fingerprint.Bytes()); strings.Contains(got, token.Reveal()) {
		t.Fatal("the rendered fingerprint carries the token")
	}
	if len(sess.Fingerprint.Bytes()) != 32 {
		t.Fatalf("the fingerprint is %d bytes", len(sess.Fingerprint.Bytes()))
	}

	// The same token always fingerprints the same way, and a different one never does.
	other, _ := session.NewToken(rand.Reader)
	if token.Fingerprint() != sess.Fingerprint {
		t.Error("the token does not fingerprint to the stored value")
	}
	if other.Fingerprint() == sess.Fingerprint {
		t.Error("two distinct tokens share a fingerprint")
	}
}

// TestTheTokenNeverRendersItself covers every path a token could leak through.
func TestTheTokenNeverRendersItself(t *testing.T) {
	_, token := issue(t, time.Now())
	raw := token.Reveal()

	holder := struct{ Token session.Token }{Token: token}
	encoded, err := json.Marshal(holder)
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}
	var logs bytes.Buffer
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("probe", slog.Any("token", token), slog.Any("holder", holder))

	renderings := map[string]string{
		"String":            token.String(),
		"GoString":          token.GoString(),
		"verb %v":           fmt.Sprintf("%v", token),
		"verb %s":           fmt.Sprintf("%s", token),
		"verb %q":           fmt.Sprintf("%q", token),
		"verb %+v":          fmt.Sprintf("%+v", token),
		"verb %#v":          fmt.Sprintf("%#v", token),
		"inside a struct":   fmt.Sprintf("%+v", holder),
		"wrapped in error":  fmt.Errorf("session lookup failed: %v", token).Error(),
		"encoded as JSON":   string(encoded),
		"structured record": logs.String(),
	}
	for name, rendering := range renderings {
		if strings.Contains(rendering, raw) {
			t.Errorf("%s exposed the token: %s", name, rendering)
		}
	}
	if token.Reveal() != raw {
		t.Error("Reveal must still return the value the cookie carries")
	}
}

func TestTokenParsingRefusesAnythingNotIssuedHere(t *testing.T) {
	for _, raw := range []string{
		"", "   ", "not base64!", base64.RawURLEncoding.EncodeToString([]byte("short")),
		base64.RawURLEncoding.EncodeToString(make([]byte, session.TokenBytes+1)),
		base64.StdEncoding.EncodeToString(make([]byte, session.TokenBytes)) + "==",
	} {
		if _, err := session.ParseToken(raw); !errors.Is(err, session.ErrInvalid) {
			t.Errorf("%q was accepted as a token", raw)
		}
	}
	_, token := issue(t, time.Now())
	parsed, err := session.ParseToken(token.Reveal())
	if err != nil || parsed.Fingerprint() != token.Fingerprint() {
		t.Fatalf("an issued token did not survive a round trip: %v", err)
	}
}

// TestTheFingerprintNeverRendersItself keeps the stored session identifier from
// escaping as a byte array through a record or an error.
func TestTheFingerprintNeverRendersItself(t *testing.T) {
	_, token := issue(t, time.Now())
	fingerprint := token.Fingerprint()
	probe := fmt.Sprintf("%x", fingerprint.Bytes())

	holder := struct{ Fingerprint session.Fingerprint }{Fingerprint: fingerprint}
	nested, err := json.Marshal(holder)
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}
	var logs bytes.Buffer
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("probe",
		slog.Any("fingerprint", fingerprint), slog.Any("holder", holder))

	for name, rendering := range map[string]string{
		"verb %v":           fmt.Sprintf("%v", fingerprint),
		"verb %s":           fmt.Sprintf("%s", fingerprint),
		"verb %q":           fmt.Sprintf("%q", fingerprint),
		"verb %+v":          fmt.Sprintf("%+v", fingerprint),
		"verb %#v":          fmt.Sprintf("%#v", fingerprint),
		"inside a struct":   fmt.Sprintf("%+v", holder),
		"wrapped in error":  fmt.Errorf("lookup failed: %v", fingerprint).Error(),
		"nested JSON":       string(nested),
		"structured record": logs.String(),
	} {
		if strings.Contains(rendering, probe) {
			t.Errorf("the fingerprint escaped through %s", name)
		}
	}

	// Bytes hands out a copy, so a caller cannot reach into the stored value.
	taken := fingerprint.Bytes()
	taken[0] ^= 0xff
	if fmt.Sprintf("%x", fingerprint.Bytes()) != probe {
		t.Error("mutating the returned slice changed the fingerprint")
	}

	rebuilt, err := session.FingerprintFrom(fingerprint.Bytes())
	if err != nil || rebuilt != fingerprint {
		t.Fatalf("a fingerprint did not survive a round trip: %v", err)
	}
	for _, wrong := range [][]byte{nil, {}, make([]byte, 31), make([]byte, 33)} {
		if _, err := session.FingerprintFrom(wrong); err == nil {
			t.Errorf("a fingerprint of %d bytes was accepted", len(wrong))
		}
	}
}
