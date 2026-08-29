package integration_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

// countingVerifier records every credential check the surface performs.
type countingVerifier struct {
	inner *password.Hasher
	mu    sync.Mutex
	seen  []password.Encoded
}

func (v *countingVerifier) Hash(plaintext string) (password.Encoded, error) {
	return v.inner.Hash(plaintext)
}

func (v *countingVerifier) Verify(encoded password.Encoded, plaintext string) (bool, error) {
	v.mu.Lock()
	v.seen = append(v.seen, encoded)
	v.mu.Unlock()
	return v.inner.Verify(encoded, plaintext)
}

func (v *countingVerifier) calls() []password.Encoded {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]password.Encoded(nil), v.seen...)
}

func (v *countingVerifier) reset() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.seen = nil
}

// TestAnUnknownAddressPerformsTheSameCryptographicWork proves parity of the
// intended work and no early return, never equality of wall-clock duration.
func TestAnUnknownAddressPerformsTheSameCryptographicWork(t *testing.T) {
	inner, err := password.NewHasher(
		password.Params{MemoryKiB: password.FloorMemoryKiB, Iterations: password.FloorIterations, Lanes: password.FloorLanes},
		password.Policy{MinCodePoints: password.SingleFactorMinimum}, nil)
	if err != nil {
		t.Fatalf("building the hasher failed: %v", err)
	}
	verifier := &countingVerifier{inner: inner}
	s := newSurface(t, func(c *authConfig) { c.hasher = verifier })
	address, account := s.account(t, iam.KindViewer, iam.StatusActive, iam.RoleViewer)

	var stored string
	if err := s.pool.QueryRow(context.Background(),
		`SELECT encoded_hash FROM account_password_credentials WHERE account_id = $1`,
		account.ID.String()).Scan(&stored); err != nil {
		t.Fatalf("reading the credential failed: %v", err)
	}

	suspended, _ := s.account(t, iam.KindViewer, iam.StatusSuspended, iam.RoleViewer)
	closed, _ := s.account(t, iam.KindViewer, iam.StatusClosed, iam.RoleViewer)
	operator, _ := s.account(t, iam.KindOperator, iam.StatusActive, iam.RoleOperatorSupport)

	cases := []struct {
		name    string
		address string
	}{
		{"registered address", address},
		{"unregistered address", "nobody-here@example.com"},
		{"malformed address", "not-an-address"},
		// An unusable account must not short-circuit ahead of the verification:
		// skipping the work there would make its state measurable from outside.
		{"suspended account", suspended},
		{"closed account", closed},
		{"operator account", operator},
	}
	for _, c := range cases {
		verifier.reset()
		in := s.signIn(t, c.address, "wrong-"+probePassword)
		if in.response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s returned %d, want 401", c.name, in.response.StatusCode)
		}
		calls := verifier.calls()
		if len(calls) != 1 {
			t.Fatalf("%s performed %d verifications, want exactly 1", c.name, len(calls))
		}

		checked := calls[0].Reveal()
		params, ok := strings.CutPrefix(checked, "$argon2id$v=19$")
		if !ok {
			t.Fatalf("%s verified against a value that is not an Argon2id encoding", c.name)
		}
		wantParams := fmt.Sprintf("m=%d,t=%d,p=%d$", password.FloorMemoryKiB, password.FloorIterations, password.FloorLanes)
		if !strings.HasPrefix(params, wantParams) {
			t.Errorf("%s verified against parameters %q, want the configured %q", c.name, params, wantParams)
		}
		known := c.name != "unregistered address" && c.name != "malformed address"
		if !known && checked == stored {
			t.Errorf("%s was verified against a registered credential", c.name)
		}
		if c.address == address && checked != stored {
			t.Errorf("%s was not verified against its own credential", c.name)
		}
	}
}
