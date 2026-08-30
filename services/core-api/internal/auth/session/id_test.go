package session_test

import (
	"testing"

	"github.com/google/uuid"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"time"
)

// TestTheSessionIdentifierKeepsItsContract pins what every store, event and port
// depends on: a random UUID rendering, and a zero value that names nothing.
func TestTheSessionIdentifierKeepsItsContract(t *testing.T) {
	var zero session.ID
	if !zero.IsZero() {
		t.Fatal("the zero identifier did not report itself unset")
	}
	if zero.String() != uuid.Nil.String() {
		t.Errorf("the zero identifier rendered %q", zero.String())
	}

	seen := make(map[string]struct{}, 64)
	for range 64 {
		sess, _ := issue(t, time.Now())
		id := sess.ID
		if id.IsZero() {
			t.Fatal("a drawn identifier reported itself unset")
		}
		rendered := id.String()
		parsed, err := uuid.Parse(rendered)
		if err != nil {
			t.Fatalf("%q is not a UUID: %v", rendered, err)
		}
		if parsed.Version() != 4 {
			t.Errorf("%q is version %d, want a random one", rendered, parsed.Version())
		}
		if uuid.UUID(id) != parsed {
			t.Error("the rendering does not reproduce the value")
		}
		if _, repeated := seen[rendered]; repeated {
			t.Fatalf("%q was drawn twice", rendered)
		}
		seen[rendered] = struct{}{}
	}
}
