package session_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

// nonCanonicalVariants returns the encodings that decode to the same bytes as
// canonical but are not what the encoder writes: the trailing bits differ.
func nonCanonicalVariants(t *testing.T, canonical string) []string {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, canonical[len(canonical)-1])
	if last < 0 {
		t.Fatalf("the canonical form ends outside the alphabet: %q", canonical)
	}
	var out []string
	for delta := 1; delta < 4; delta++ {
		variant := canonical[:len(canonical)-1] + string(alphabet[(last&^3)|((last+delta)&3)])
		decoded, err := base64.RawURLEncoding.DecodeString(variant)
		if err != nil || len(decoded) != 32 {
			t.Fatalf("the probe %q does not decode to 32 bytes", variant)
		}
		out = append(out, variant)
	}
	if len(out) != 3 {
		t.Fatalf("%d variants built, want 3", len(out))
	}
	return out
}

// standardAlphabet encodes deterministic bytes that really produce + and /, so
// the probe cannot pass by accident on an input the URL alphabet also accepts.
func standardAlphabet(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	raw[0], raw[1] = 0xFB, 0xF0
	encoded := base64.RawStdEncoding.EncodeToString(raw)
	if !strings.ContainsAny(encoded, "+/") {
		t.Fatalf("the probe %q carries neither + nor /", encoded)
	}
	return encoded
}

// TestOnlyTheCanonicalEncodingIsAccepted keeps the accepted set equal to the set
// this package issues, for both bearer values.
func TestOnlyTheCanonicalEncodingIsAccepted(t *testing.T) {
	sess, token := issue(t, time.Unix(1_700_000_000, 0).UTC())
	for name, subject := range map[string]struct {
		canonical string
		parse     func(string) error
	}{
		"session token": {token.Reveal(), func(raw string) error { _, err := session.ParseToken(raw); return err }},
		"CSRF token":    {sess.CSRF.Reveal(), func(raw string) error { _, err := session.ParseCSRFToken(raw); return err }},
	} {
		t.Run(name, func(t *testing.T) {
			if err := subject.parse(subject.canonical); err != nil {
				t.Fatalf("the canonical form this package issues was refused: %v", err)
			}

			refused := map[string]string{}
			for i, variant := range nonCanonicalVariants(t, subject.canonical) {
				refused[fmt.Sprintf("trailing bits variant %d", i+1)] = variant
			}
			refused["leading space"] = " " + subject.canonical
			refused["trailing space"] = subject.canonical + " "
			refused["embedded CR"] = subject.canonical[:20] + "\r" + subject.canonical[20:]
			refused["embedded LF"] = subject.canonical[:20] + "\n" + subject.canonical[20:]
			refused["leading LF"] = "\n" + subject.canonical
			refused["one character short"] = subject.canonical[:len(subject.canonical)-1]
			refused["one character long"] = subject.canonical + "A"
			refused["standard alphabet"] = standardAlphabet(t)

			for label, raw := range refused {
				if err := subject.parse(raw); !errors.Is(err, session.ErrInvalid) {
					t.Errorf("%s was accepted: %q gave %v", label, raw, err)
				}
			}
		})
	}
}

// TestEveryBearerValueMarshalsToTheRedactionMarker keeps the text encoders from
// passing by returning nothing: each must be exactly the marker.
func TestEveryBearerValueMarshalsToTheRedactionMarker(t *testing.T) {
	sess, token := issue(t, time.Unix(1_700_000_000, 0).UTC())
	fingerprint := token.Fingerprint()

	for name, marshal := range map[string]func() ([]byte, error){
		"token":       token.MarshalText,
		"CSRF token":  sess.CSRF.MarshalText,
		"fingerprint": fingerprint.MarshalText,
	} {
		text, err := marshal()
		if err != nil {
			t.Fatalf("marshalling the %s failed: %v", name, err)
		}
		if string(text) != iam.Redacted {
			t.Errorf("the %s marshalled to %q, want exactly %q", name, text, iam.Redacted)
		}
	}
}

// TestABearerValueUsedAsAJSONKeyBecomesTheMarker: encoding/json takes a map key
// through TextMarshaler, so the key itself must be the marker and nothing else.
func TestABearerValueUsedAsAJSONKeyBecomesTheMarker(t *testing.T) {
	sess, token := issue(t, time.Unix(1_700_000_000, 0).UTC())
	fingerprint := token.Fingerprint()

	for name, probe := range map[string]struct {
		encode func() ([]byte, error)
		secret string
	}{
		"token": {func() ([]byte, error) {
			return json.Marshal(map[session.Token]string{token: "value"})
		}, token.Reveal()},
		"CSRF token": {func() ([]byte, error) {
			return json.Marshal(map[session.CSRFToken]string{sess.CSRF: "value"})
		}, sess.CSRF.Reveal()},
		"fingerprint": {func() ([]byte, error) {
			return json.Marshal(map[session.Fingerprint]string{fingerprint: "value"})
		}, fmt.Sprintf("%x", fingerprint.Bytes())},
	} {
		t.Run(name, func(t *testing.T) {
			encoded, err := probe.encode()
			if err != nil {
				t.Fatalf("encoding failed: %v", err)
			}
			var decoded map[string]string
			if err := json.Unmarshal(encoded, &decoded); err != nil {
				t.Fatalf("the encoded map is not an object: %v", err)
			}
			if len(decoded) != 1 {
				t.Fatalf("the object holds %d keys, want exactly one", len(decoded))
			}
			for key := range decoded {
				if key != iam.Redacted {
					t.Errorf("the key is %q, want exactly %q", key, iam.Redacted)
				}
			}
			if strings.Contains(string(encoded), probe.secret) {
				t.Errorf("the %s escaped as a JSON object key", name)
			}
		})
	}
}

// TestTheZeroTokenIsSeparatedFromADrawnOne covers the accessor the store uses to
// decide whether a value was ever drawn.
func TestTheZeroTokenIsSeparatedFromADrawnOne(t *testing.T) {
	_, token := issue(t, time.Unix(1_700_000_000, 0).UTC())
	if !(session.Token{}).IsZero() {
		t.Error("the zero token does not report itself as zero")
	}
	if token.IsZero() {
		t.Error("a drawn token reports itself as zero")
	}
}
