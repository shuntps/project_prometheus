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

// TestTheBearerValuesAreRedactedThroughEveryEncoder completes the redaction
// matrix with the encoders the earlier proofs did not reach.
func TestTheBearerValuesAreRedactedThroughEveryEncoder(t *testing.T) {
	sess, token := issue(t, time.Unix(1_700_000_000, 0).UTC())
	fingerprint := token.Fingerprint()

	if (session.Token{}).IsZero() != true || token.IsZero() {
		t.Error("IsZero does not separate a drawn token from the zero value")
	}

	for name, probe := range map[string]struct {
		text  func() ([]byte, error)
		value string
	}{
		"token":       {token.MarshalText, token.Reveal()},
		"CSRF token":  {sess.CSRF.MarshalText, sess.CSRF.Reveal()},
		"fingerprint": {fingerprint.MarshalText, fmt.Sprintf("%x", fingerprint.Bytes())},
	} {
		text, err := probe.text()
		if err != nil {
			t.Fatalf("marshalling the %s failed: %v", name, err)
		}
		if strings.Contains(string(text), probe.value) {
			t.Errorf("MarshalText carries the %s", name)
		}
	}

	// A map key goes through TextMarshaler rather than through MarshalJSON.
	keyed, err := json.Marshal(map[session.Token]string{token: "value"})
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}
	if strings.Contains(string(keyed), token.Reveal()) {
		t.Error("the token escaped as a JSON object key")
	}
	keyedCSRF, err := json.Marshal(map[session.CSRFToken]string{sess.CSRF: "value"})
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}
	if strings.Contains(string(keyedCSRF), sess.CSRF.Reveal()) {
		t.Error("the CSRF token escaped as a JSON object key")
	}
}
