package session

import (
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

// countingReader yields a chosen number of bytes then fails, so a source that
// stops at any of the three draws can be built by choosing that number.
type countingReader struct {
	calls     int
	requested int
	yield     int
	err       error
}

func (r *countingReader) Read(p []byte) (int, error) {
	r.calls++
	r.requested += len(p)
	if r.err != nil {
		return 0, r.err
	}
	n := min(r.yield, len(p))
	r.yield -= n
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}

func usableLifetimes() Lifetimes {
	return Lifetimes{Absolute: 12 * time.Hour, Idle: 30 * time.Minute, ActivityInterval: time.Minute}
}

func anAccount(t *testing.T) iam.AccountID {
	t.Helper()
	id, err := iam.NewAccountID()
	if err != nil {
		t.Fatalf("drawing an account identifier failed: %v", err)
	}
	return id
}

// TestEachDrawOfAnIssuanceCanFailOnItsOwn walks the three draws in the order the
// issuance performs them, cutting the source shorter each time.
func TestEachDrawOfAnIssuanceCanFailOnItsOwn(t *testing.T) {
	// A version 4 identifier takes 16 bytes, then the token and the CSRF token
	// take 32 each. Cutting the source at each boundary reaches one draw at a time.
	for name, yield := range map[string]int{
		"the identifier draw": 0,
		"a short identifier":  8,
		"the token draw":      16,
		"a short token":       16 + 8,
		"the CSRF token draw": 16 + 32,
		"a short CSRF token":  16 + 32 + 8,
	} {
		t.Run(name, func(t *testing.T) {
			reader := &countingReader{yield: yield}
			sess, token, err := issue(anAccount(t), iam.KindViewer, iam.SurfacePublic, usableLifetimes(), time.Now(), reader)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("a session was issued from a source of %d bytes: %v", yield, err)
			}
			if !sess.ID.IsZero() || !sess.Fingerprint.IsZero() || !sess.CSRF.IsZero() || !token.IsZero() {
				t.Error("a partially usable session or token was returned")
			}
		})
	}
}

// TestAnIssuanceRefusalNamesNothingAboutItsSource keeps a degraded source from
// describing itself through the refusal a caller reads.
func TestAnIssuanceRefusalNamesNothingAboutItsSource(t *testing.T) {
	sentinel := errors.New("the entropy source is unavailable")
	_, _, err := issue(anAccount(t), iam.KindViewer, iam.SurfacePublic, usableLifetimes(), time.Now(),
		&countingReader{err: sentinel})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want the domain classification", err)
	}
	if strings.Contains(err.Error(), sentinel.Error()) {
		t.Errorf("the refusal %q carries the source's own failure", err)
	}
}

// TestBusinessArgumentsAreSettledBeforeAnyEntropyIsSpent keeps a refusal the
// domain decides from consuming the process entropy source.
func TestBusinessArgumentsAreSettledBeforeAnyEntropyIsSpent(t *testing.T) {
	for name, run := range map[string]func(io.Reader) error{
		"no account": func(r io.Reader) error {
			_, _, err := issue(iam.AccountID{}, iam.KindViewer, iam.SurfacePublic, usableLifetimes(), time.Now(), r)
			return err
		},
		"surface the kind may not open": func(r io.Reader) error {
			_, _, err := issue(anAccount(t), iam.KindViewer, iam.SurfaceOperator, usableLifetimes(), time.Now(), r)
			return err
		},
		"unusable lifetimes": func(r io.Reader) error {
			_, _, err := issue(anAccount(t), iam.KindViewer, iam.SurfacePublic, Lifetimes{}, time.Now(), r)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			reader := &countingReader{yield: 4096}
			if err := run(reader); !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v, want a refusal", err)
			}
			if reader.calls != 0 {
				t.Fatalf("the entropy source was read %d time(s) for an argument that was refused", reader.calls)
			}
		})
	}
}

// TestTheAdoptedSizesAreDrawnWhole covers ASVS v5.0.0-7.2.3: a CSPRNG and at
// least 128 bits. The adopted size is 256 bits for both bearer values.
func TestTheAdoptedSizesAreDrawnWhole(t *testing.T) {
	reader := &countingReader{yield: 4096}
	sess, token, err := issue(anAccount(t), iam.KindViewer, iam.SurfacePublic, usableLifetimes(), time.Now(), reader)
	if err != nil {
		t.Fatalf("issuing a session failed: %v", err)
	}
	for name, pair := range map[string]struct {
		raw  string
		want int
	}{
		"session token": {token.Reveal(), tokenBytes},
		"CSRF token":    {sess.CSRF.Reveal(), csrfTokenBytes},
	} {
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(pair.raw)
		if err != nil {
			t.Fatalf("the %s is not canonical base64url: %v", name, err)
		}
		if len(decoded) != pair.want || len(decoded)*8 < 128 {
			t.Fatalf("the %s carries %d bits", name, len(decoded)*8)
		}
	}
	if reader.requested < 16+tokenBytes+csrfTokenBytes {
		t.Fatalf("the source was asked for %d bytes, below the three draws", reader.requested)
	}
}

// TestTwoIssuancesShareNothing keeps a repeated draw from producing the same
// identifier, token or CSRF token.
func TestTwoIssuancesShareNothing(t *testing.T) {
	const draws = 256
	ids := make(map[string]struct{}, draws)
	tokens := make(map[string]struct{}, draws)
	csrfs := make(map[string]struct{}, draws)
	for range draws {
		sess, token, err := Issue(anAccount(t), iam.KindViewer, iam.SurfacePublic, usableLifetimes(), time.Now())
		if err != nil {
			t.Fatalf("issuing a session failed: %v", err)
		}
		for name, seen := range map[string]struct {
			set   map[string]struct{}
			value string
		}{
			"identifier":    {ids, sess.ID.String()},
			"session token": {tokens, token.Reveal()},
			"CSRF token":    {csrfs, sess.CSRF.Reveal()},
		} {
			if _, repeated := seen.set[seen.value]; repeated {
				t.Fatalf("the same %s was drawn twice", name)
			}
			seen.set[seen.value] = struct{}{}
		}
	}
}

// failingAt yields whole reads until the chosen one, which fails. It isolates a
// single draw so the error of that draw alone decides the outcome.
type failingAt struct {
	calls int
	at    int
}

func (r *failingAt) Read(p []byte) (int, error) {
	r.calls++
	if r.calls == r.at {
		return 0, io.ErrUnexpectedEOF
	}
	for i := range p {
		p[i] = byte(r.calls)
	}
	return len(p), nil
}

// TestEachDrawPropagatesItsOwnFailure keeps one draw's error from being covered
// by the next one also failing: only the chosen draw fails here.
func TestEachDrawPropagatesItsOwnFailure(t *testing.T) {
	for name, at := range map[string]int{
		"the identifier": 1,
		"the token":      2,
		"the CSRF token": 3,
	} {
		t.Run(name, func(t *testing.T) {
			reader := &failingAt{at: at}
			sess, token, err := issue(anAccount(t), iam.KindViewer, iam.SurfacePublic, usableLifetimes(), time.Now(), reader)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("a failure at draw %d gave %v, want the domain classification", at, err)
			}
			if reader.calls != at {
				t.Fatalf("the source was read %d time(s), want the failure at draw %d", reader.calls, at)
			}
			if !sess.ID.IsZero() || !sess.Fingerprint.IsZero() || !sess.CSRF.IsZero() || !token.IsZero() {
				t.Error("a partially usable session or token was returned")
			}
		})
	}
	// The same reader, allowed to complete, issues a usable session: the probe
	// fails for the chosen draw and for nothing else.
	if _, _, err := issue(anAccount(t), iam.KindViewer, iam.SurfacePublic, usableLifetimes(), time.Now(), &failingAt{at: 99}); err != nil {
		t.Fatalf("a source that never fails was refused: %v", err)
	}
}
