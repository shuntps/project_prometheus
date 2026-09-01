package emailverification_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/emailverification"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

func TestOnlyTheIssuedShapeParses(t *testing.T) {
	_, token := issued(t)
	raw := token.Reveal()
	if len(raw) != emailverification.EncodedTokenLength {
		t.Fatalf("token length = %d, want %d", len(raw), emailverification.EncodedTokenLength)
	}

	refused := map[string]string{
		"empty":           "",
		"padded":          raw[:len(raw)-1] + "=",
		"trailing space":  raw + " ",
		"leading space":   " " + raw,
		"one short":       raw[:len(raw)-1],
		"one long":        raw + "A",
		"standard base64": strings.ReplaceAll(strings.ReplaceAll(raw, "-", "+"), "_", "/") + "==",
		"not base64":      strings.Repeat("!", emailverification.EncodedTokenLength),
	}
	for name, candidate := range refused {
		t.Run(name, func(t *testing.T) {
			if _, err := emailverification.ParseToken(candidate); err == nil {
				t.Fatal("a value the package never issues was accepted")
			}
		})
	}
	if parsed, err := emailverification.ParseToken(raw); err != nil || parsed.Reveal() != raw {
		t.Fatalf("the issued value did not round-trip: %v", err)
	}
}

// TestTheTokenRedactsItselfEverywhere keeps the value from reaching a record, an
// error, a report or a test failure by any standard rendering path.
func TestTheTokenRedactsItselfEverywhere(t *testing.T) {
	_, token := issued(t)
	raw := token.Reveal()

	encoded, err := json.Marshal(struct {
		Token emailverification.Token `json:"token"`
	}{token})
	if err != nil {
		t.Fatalf("marshalling failed: %v", err)
	}
	renderings := map[string]string{
		"String":       token.String(),
		"GoString":     fmt.Sprintf("%#v", token),
		"verbose":      fmt.Sprintf("%+v", token),
		"plain":        fmt.Sprintf("%v", token),
		"wrapped":      fmt.Errorf("carrying %v", token).Error(),
		"log value":    token.LogValue().String(),
		"nested JSON":  string(encoded),
		"in a slice":   fmt.Sprintf("%v", []emailverification.Token{token}),
		"fingerprint":  fmt.Sprintf("%v %s %#v", token.Fingerprint(), token.Fingerprint(), token.Fingerprint()),
		"message":      fmt.Sprintf("%v %s %#v", message(), message(), message()),
		"message logs": message().LogValue().String(),
	}
	for name, rendered := range renderings {
		t.Run(name, func(t *testing.T) {
			if strings.Contains(rendered, raw) {
				t.Fatalf("%s carried the token", name)
			}
			if name != "message logs" && !strings.Contains(rendered, iam.Redacted) {
				t.Fatalf("%s = %q, want the redaction marker", name, rendered)
			}
		})
	}
}

// TestTheFingerprintDoesNotCarryTheToken is what makes the stored value safe: it
// is derived, of fixed size, and different for every token.
func TestTheFingerprintDoesNotCarryTheToken(t *testing.T) {
	_, first := issued(t)
	_, second := issued(t)

	if len(first.Fingerprint().Bytes()) != 32 {
		t.Fatalf("fingerprint size = %d, want 32", len(first.Fingerprint().Bytes()))
	}
	if string(first.Fingerprint().Bytes()) == string(second.Fingerprint().Bytes()) {
		t.Fatal("two tokens produced one fingerprint")
	}
	if strings.Contains(string(first.Fingerprint().Bytes()), first.Reveal()) {
		t.Fatal("the fingerprint carries the token")
	}
	// A copy is handed out, so a caller cannot reach into the stored value.
	taken := first.Fingerprint().Bytes()
	taken[0] ^= 0xff
	if taken[0] == first.Fingerprint().Bytes()[0] {
		t.Fatal("the fingerprint handed out its own storage")
	}
}

func message() emailverification.Message {
	address, err := iam.NormaliseEmail("recipient@example.invalid")
	if err != nil {
		panic(err)
	}
	delivery, err := emailverification.NewDeliveryID()
	if err != nil {
		panic(err)
	}
	return emailverification.Message{Delivery: delivery, To: address, Link: "https://app.example.com/verify-email#token=x"}
}
