package emailverification

import (
	"errors"
	"io"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

// shortReader yields a fixed number of bytes and then fails, so each draw of one
// issuance can be starved in turn.
type shortReader struct{ remaining int }

func (r *shortReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.ErrUnexpectedEOF
	}
	n := len(p)
	if n > r.remaining {
		n = r.remaining
	}
	for i := range p[:n] {
		p[i] = 0x7f
	}
	r.remaining -= n
	return n, nil
}

// TestEveryDrawOfAnIssuanceIsAFailurePath starves the identifier and then the
// token, so no draw can fail silently and hand back a usable record.
func TestEveryDrawOfAnIssuanceIsAFailurePath(t *testing.T) {
	identity, err := iam.NewIdentityID()
	if err != nil {
		t.Fatalf("drawing an identity identifier failed: %v", err)
	}
	set := Lifetimes{Lifetime: 8 * time.Hour, ResendInterval: time.Minute}

	for name, available := range map[string]int{
		"no entropy at all":         0,
		"identifier only partially": 8,
		"identifier but no token":   16,
		"token only partially":      16 + 8,
	} {
		t.Run(name, func(t *testing.T) {
			challenge, token, err := issue(identity, set, time.Now().UTC(), &shortReader{remaining: available})
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v, want a refusal", err)
			}
			if !challenge.ID.IsZero() || !challenge.Fingerprint.IsZero() || !token.IsZero() {
				t.Fatal("a partial issuance was handed back")
			}
		})
	}

	// Enough for both draws: the same path succeeds, so the refusals above are the
	// entropy source and not the arguments.
	if _, _, err := issue(identity, set, time.Now().UTC(), &shortReader{remaining: 16 + 32}); err != nil {
		t.Fatalf("a fully supplied issuance failed: %v", err)
	}
}
