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

func lifetimes() session.Lifetimes {
	return session.Lifetimes{Absolute: 12 * time.Hour, Idle: 30 * time.Minute, ActivityInterval: time.Minute}
}

func mustAccount(t *testing.T) iam.AccountID {
	t.Helper()
	id, err := iam.NewAccountID()
	if err != nil {
		t.Fatalf("drawing an account identifier failed: %v", err)
	}
	return id
}

func issue(t *testing.T, now time.Time) (session.Session, session.Token) {
	t.Helper()
	sess, token, err := session.Issue(mustAccount(t), iam.KindViewer, iam.SurfacePublic, lifetimes(), now, rand.Reader)
	if err != nil {
		t.Fatalf("issuing a session failed: %v", err)
	}
	return sess, token
}

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

// TestTheTwoExpiriesAreDistinctAndBothEnforced keeps an idle window from acting
// as an absolute one, and the reverse.
func TestTheTwoExpiriesAreDistinctAndBothEnforced(t *testing.T) {
	start := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	sess, _ := issue(t, start)

	if sess.IdleExpiresAt.Equal(sess.AbsoluteExpiresAt) {
		t.Fatal("the two expiries are the same instant")
	}
	if err := sess.UsableAt(start.Add(time.Minute)); err != nil {
		t.Fatalf("a fresh session was refused: %v", err)
	}
	if err := sess.UsableAt(start.Add(29 * time.Minute)); err != nil {
		t.Fatalf("a session inside its idle window was refused: %v", err)
	}
	if err := sess.UsableAt(sess.IdleExpiresAt); !errors.Is(err, session.ErrUnusable) {
		t.Error("a session was accepted at its idle expiry")
	}
	if err := sess.UsableAt(start.Add(time.Hour)); !errors.Is(err, session.ErrUnusable) {
		t.Error("a session was accepted past its idle expiry")
	}

	// Even continuously active, a session dies at its absolute expiry.
	fresh := sess
	fresh.IdleExpiresAt = fresh.AbsoluteExpiresAt
	if err := fresh.UsableAt(fresh.AbsoluteExpiresAt); !errors.Is(err, session.ErrUnusable) {
		t.Error("a session was accepted at its absolute expiry")
	}
}

func TestARevokedOrRotatedSessionIsNeverUsable(t *testing.T) {
	start := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	sess, _ := issue(t, start)

	revoked := sess
	when := start.Add(time.Minute)
	revoked.RevokedAt = &when
	if err := revoked.UsableAt(when.Add(time.Second)); !errors.Is(err, session.ErrUnusable) {
		t.Error("a revoked session was accepted")
	}

	rotated := sess
	successor, err := session.NewID()
	if err != nil {
		t.Fatalf("drawing a session identifier failed: %v", err)
	}
	rotated.RotatedTo = &successor
	if err := rotated.UsableAt(when); !errors.Is(err, session.ErrUnusable) {
		t.Error("a rotated session was accepted")
	}

	if err := (session.Session{}).UsableAt(start); !errors.Is(err, session.ErrUnusable) {
		t.Error("a zero session was accepted")
	}
}

func TestLifetimesAreBoundedAndOrdered(t *testing.T) {
	cases := map[string]session.Lifetimes{
		"zero value":                {},
		"no idle":                   {Absolute: time.Hour},
		"no absolute":               {Idle: time.Minute},
		"idle under the floor":      {Absolute: time.Hour, Idle: time.Second},
		"absolute under the floor":  {Absolute: time.Minute, Idle: time.Minute},
		"absolute over the ceiling": {Absolute: 365 * 24 * time.Hour, Idle: time.Hour},
		"idle beyond absolute":      {Absolute: time.Hour, Idle: 2 * time.Hour},
		"negative":                  {Absolute: -time.Hour, Idle: -time.Minute},
	}
	for name, l := range cases {
		t.Run(name, func(t *testing.T) {
			if err := l.Validate(); !errors.Is(err, session.ErrInvalid) {
				t.Fatalf("got %v, want a refusal", err)
			}
			if _, _, err := session.Issue(mustAccount(t), iam.KindViewer, iam.SurfacePublic, l, time.Now(), rand.Reader); err == nil {
				t.Fatal("a session was issued from unusable lifetimes")
			}
		})
	}
	if err := lifetimes().Validate(); err != nil {
		t.Fatalf("usable lifetimes were refused: %v", err)
	}
}

func TestASessionIsAlwaysBoundToOneKnownSurface(t *testing.T) {
	for _, surface := range []iam.Surface{"", "edge", "admin", "Operator"} {
		if _, _, err := session.Issue(mustAccount(t), iam.KindViewer, surface, lifetimes(), time.Now(), rand.Reader); !errors.Is(err, session.ErrInvalid) {
			t.Errorf("surface %q was accepted", surface)
		}
	}
	for surface, kind := range map[iam.Surface]iam.Kind{iam.SurfacePublic: iam.KindViewer, iam.SurfaceOperator: iam.KindOperator} {
		sess, _, err := session.Issue(mustAccount(t), kind, surface, lifetimes(), time.Now(), rand.Reader)
		if err != nil {
			t.Errorf("surface %q was refused: %v", surface, err)
			continue
		}
		if sess.Surface != surface {
			t.Errorf("the session settled on surface %q", sess.Surface)
		}
	}
	if _, _, err := session.Issue(iam.AccountID{}, iam.KindViewer, iam.SurfacePublic, lifetimes(), time.Now(), rand.Reader); !errors.Is(err, session.ErrInvalid) {
		t.Error("a session was issued for the zero account")
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
