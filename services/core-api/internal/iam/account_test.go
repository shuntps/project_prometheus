package iam_test

import (
	"errors"
	"testing"

	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

// TestAccountIdentifiersAreRandomAndNonSequential keeps the canonical identity
// from revealing order or volume.
func TestAccountIdentifiersAreRandomAndNonSequential(t *testing.T) {
	const draws = 512
	seen := make(map[string]struct{}, draws)
	for range draws {
		id, err := iam.NewAccountID()
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
		if _, err := iam.ParseAccountID(raw); !errors.Is(err, iam.ErrInvalid) {
			t.Errorf("%q was accepted as an account identifier", raw)
		}
	}
	id, err := iam.NewAccountID()
	if err != nil {
		t.Fatalf("drawing an identifier failed: %v", err)
	}
	parsed, err := iam.ParseAccountID(id.String())
	if err != nil || parsed != id {
		t.Fatalf("a drawn identifier did not survive a round trip: %v", err)
	}
}

// TestOnlyAnExplicitlyUsableStatusAuthenticates keeps a suspended, closed,
// pending or unknown account from opening or keeping a session.
func TestOnlyAnExplicitlyUsableStatusAuthenticates(t *testing.T) {
	for status, usable := range map[iam.Status]bool{
		iam.StatusActive:      true,
		iam.StatusPending:     false,
		iam.StatusSuspended:   false,
		iam.StatusClosed:      false,
		iam.Status(""):        false,
		iam.Status("ACTIVE"):  false,
		iam.Status("enabled"): false,
	} {
		if got := status.CanAuthenticate(); got != usable {
			t.Errorf("status %q reported CanAuthenticate=%v, want %v", status, got, usable)
		}
	}
}

// TestKindParsingResolvesNoDefault keeps an unset or unknown value from becoming
// a kind, which every surface and grant decision then depends on.
func TestKindParsingResolvesNoDefault(t *testing.T) {
	for _, unknown := range []string{"", "   ", "admin", "Viewer"} {
		if kind, known := iam.ParseKind(unknown); known {
			t.Errorf("%q resolved to the kind %q", unknown, kind)
		}
	}
	for _, raw := range []string{"viewer", "creator", "operator", " operator "} {
		if _, known := iam.ParseKind(raw); !known {
			t.Errorf("%q was refused", raw)
		}
	}
}
