package auth_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
)

// TestAccountIdentifiersAreRandomAndNonSequential keeps the canonical identity
// from revealing order or volume.
func TestAccountIdentifiersAreRandomAndNonSequential(t *testing.T) {
	const draws = 512
	seen := make(map[string]struct{}, draws)
	for range draws {
		id, err := auth.NewAccountID()
		if err != nil {
			t.Fatalf("drawing an identifier failed: %v", err)
		}
		if id.IsZero() {
			t.Fatal("a zero identifier was drawn")
		}
		if _, repeated := seen[id.String()]; repeated {
			t.Fatal("the same identifier was drawn twice")
		}
		seen[id.String()] = struct{}{}
	}
	if len(seen) != draws {
		t.Fatalf("%d distinct identifiers out of %d draws", len(seen), draws)
	}
}

func TestAccountIdentifierParsingRefusesTheZeroValue(t *testing.T) {
	for _, raw := range []string{"", "   ", "not-a-uuid", "00000000-0000-0000-0000-000000000000"} {
		if _, err := auth.ParseAccountID(raw); !errors.Is(err, auth.ErrInvalid) {
			t.Errorf("%q was accepted as an account identifier", raw)
		}
	}
	id, err := auth.NewAccountID()
	if err != nil {
		t.Fatalf("drawing an identifier failed: %v", err)
	}
	parsed, err := auth.ParseAccountID(id.String())
	if err != nil || parsed != id {
		t.Fatalf("a drawn identifier did not survive a round trip: %v", err)
	}
}

// TestEmailNormalisationIsConservative keeps two distinct addresses from being
// merged into one account by a rewriting rule.
func TestEmailNormalisationIsConservative(t *testing.T) {
	kept := map[string]string{
		"dots are kept":            "first.last@example.com",
		"plus addressing is kept":  "user+tag@example.com",
		"case is folded":           "User.Name+Tag@Example.COM",
		"surrounding space is cut": "  user@example.com  ",
		"subdomain is kept":        "user@mail.example.com",
	}
	want := map[string]string{
		"dots are kept":            "first.last@example.com",
		"plus addressing is kept":  "user+tag@example.com",
		"case is folded":           "user.name+tag@example.com",
		"surrounding space is cut": "user@example.com",
		"subdomain is kept":        "user@mail.example.com",
	}
	for name, raw := range kept {
		t.Run(name, func(t *testing.T) {
			address, err := auth.NormaliseEmail(raw)
			if err != nil {
				t.Fatalf("a usable address was refused: %v", err)
			}
			// The values are compared, never printed.
			if address.Reveal() != want[name] {
				t.Fatal("the address was not normalised as this case requires")
			}
		})
	}

	// Two addresses that differ by more than case must stay distinct.
	dotted, _ := auth.NormaliseEmail("first.last@example.com")
	undotted, _ := auth.NormaliseEmail("firstlast@example.com")
	tagged, _ := auth.NormaliseEmail("first+tag@example.com")
	untagged, _ := auth.NormaliseEmail("first@example.com")
	if dotted.Reveal() == undotted.Reveal() {
		t.Error("dots were stripped; two distinct addresses were merged")
	}
	if tagged.Reveal() == untagged.Reveal() {
		t.Error("plus addressing was stripped; two distinct addresses were merged")
	}
}

func TestUnusableLoginAddressesAreRefused(t *testing.T) {
	for _, raw := range []string{
		"", "   ", "user", "@example.com", "user@", "user@@example.com",
		"user@localhost", "user@.com", "user@example.", "user name@example.com",
		"user\t@example.com", "user@exa mple.com", strings.Repeat("a", 250) + "@example.com",
	} {
		if _, err := auth.NormaliseEmail(raw); !errors.Is(err, auth.ErrInvalid) {
			t.Errorf("a login address of %d bytes with an unusable shape was accepted", len(raw))
		}
	}
}

// TestVerificationStateIsSeparateFromTheAddress keeps proof of control distinct
// from the address itself, and from identity proofing of any kind.
func TestVerificationStateIsSeparateFromTheAddress(t *testing.T) {
	address, err := auth.NormaliseEmail("user@example.com")
	if err != nil {
		t.Fatalf("normalising failed: %v", err)
	}
	identity := auth.EmailIdentity{Address: address}
	if identity.IsVerified() {
		t.Fatal("a freshly built identity reports itself verified")
	}
}

// renderings collects every path a value could escape through. The probe is
// searched for, never printed, so a failure never republishes the value.
func renderings(t *testing.T, value any) map[string]string {
	t.Helper()
	holder := struct{ Value any }{Value: value}
	encoded, err := json.Marshal(holder)
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}
	direct, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}
	var logs bytes.Buffer
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("probe",
		slog.Any("value", value), slog.Any("holder", holder))

	return map[string]string{
		"verb %v":           fmt.Sprintf("%v", value),
		"verb %s":           fmt.Sprintf("%s", value),
		"verb %q":           fmt.Sprintf("%q", value),
		"verb %+v":          fmt.Sprintf("%+v", value),
		"verb %#v":          fmt.Sprintf("%#v", value),
		"inside a struct":   fmt.Sprintf("%+v", holder),
		"wrapped in error":  fmt.Errorf("operation failed: %v", value).Error(),
		"encoded as JSON":   string(direct),
		"nested JSON":       string(encoded),
		"structured record": logs.String(),
	}
}

func assertRedacted(t *testing.T, label string, value any, probe string) {
	t.Helper()
	for name, rendering := range renderings(t, value) {
		if strings.Contains(rendering, probe) {
			t.Errorf("%s exposed its value through %s", label, name)
		}
	}
}

// TestTheLoginAddressNeverRendersItself keeps a login address out of records and
// errors, which the slice rule requires as much as it requires it of a password.
func TestTheLoginAddressNeverRendersItself(t *testing.T) {
	const probe = "probe-user@probe-domain.example"
	address, err := auth.NormaliseEmail(probe)
	if err != nil {
		t.Fatalf("normalising failed: %v", err)
	}

	assertRedacted(t, "the login address", address, probe)
	assertRedacted(t, "an identity holding it", auth.EmailIdentity{Address: address}, probe)

	if address.Reveal() != probe {
		t.Error("Reveal must still return the value the store persists")
	}
	if address.String() != auth.Redacted {
		t.Error("the address does not render as redacted")
	}
}
