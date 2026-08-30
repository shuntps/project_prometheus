package auth

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

// shortReader yields a chosen number of bytes and then fails, so both a failing
// source and a source that stops early are exercised by one type.
type shortReader struct {
	calls int
	yield int
	err   error
}

func (r *shortReader) Read(p []byte) (int, error) {
	r.calls++
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

type stubHasher struct{}

func (stubHasher) Hash(string) (password.Encoded, error) { return password.NewEncoded("stored"), nil }
func (stubHasher) Verify(password.Encoded, string) (bool, error) {
	return false, password.ErrMismatch
}

type stubRepository struct{}

func (stubRepository) CredentialByEmail(context.Context, iam.EmailAddress) (Credential, bool, error) {
	return Credential{}, false, nil
}
func (stubRepository) ReplaceSession(context.Context, *session.ID, session.Session, time.Time) (Resolved, bool, error) {
	return Resolved{}, false, nil
}
func (stubRepository) ResolveSession(context.Context, session.Token, time.Time) (Resolved, bool, error) {
	return Resolved{}, false, nil
}

type stubLimiter struct{}

func (stubLimiter) Allow(string, string, time.Time) bool { return true }

func usableOptions() SignInOptions {
	return SignInOptions{
		Repository: stubRepository{},
		Hasher:     stubHasher{},
		Limiter:    stubLimiter{},
		Lifetimes:  session.Lifetimes{Absolute: 12 * time.Hour, Idle: time.Hour, ActivityInterval: time.Minute},
		Now:        func() time.Time { return time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC) },
	}
}

// TestADecoySeedThatCannotBeDrawnBuildsNoUseCase keeps the verification path from
// existing without the decoy every refusal is measured against.
func TestADecoySeedThatCannotBeDrawnBuildsNoUseCase(t *testing.T) {
	sentinel := errors.New("the entropy source is unavailable")
	for name, reader := range map[string]*shortReader{
		"the source fails":       {err: sentinel},
		"the source is empty":    {yield: 0},
		"the source falls short": {yield: 8},
	} {
		t.Run(name, func(t *testing.T) {
			built, err := newSignIn(usableOptions(), reader, session.Issue)
			if err == nil {
				t.Fatal("a use case was built without its decoy")
			}
			if built != nil {
				t.Error("a partially built use case was returned")
			}
			if strings.Contains(err.Error(), sentinel.Error()) {
				t.Errorf("the refusal %q carries the source's own failure", err)
			}
			if reader.calls == 0 {
				t.Error("the source was never read")
			}
		})
	}
}

// TestAnEmitterThatFailsIsTranslatedRatherThanLeaked keeps a failed emission from
// reaching the caller as anything but the use case's own unavailability.
func TestAnEmitterThatFailsIsTranslatedRatherThanLeaked(t *testing.T) {
	sentinel := errors.New("the emitter refused")
	failing := func(iam.AccountID, iam.Kind, iam.Surface, session.Lifetimes, time.Time) (session.Session, session.Token, error) {
		return session.Session{}, session.Token{}, sentinel
	}
	built, err := newSignIn(usableOptions(), constantReader{}, failing)
	if err != nil {
		t.Fatalf("building the use case failed: %v", err)
	}
	if built.issue == nil {
		t.Fatal("the injected emitter was not kept for Execute")
	}
	if _, _, err := built.issue(iam.AccountID{}, iam.KindViewer, iam.SurfacePublic, built.lifetimes, built.now()); !errors.Is(err, sentinel) {
		t.Fatalf("the held emitter is not the injected one: %v", err)
	}
}

// TestTheEmitterIsRequired keeps a use case from being built without one.
func TestTheEmitterIsRequired(t *testing.T) {
	if _, err := newSignIn(usableOptions(), constantReader{}, nil); err == nil {
		t.Fatal("a use case was built without a session emitter")
	}
}

// constantReader always yields bytes, so a construction under test never depends
// on the process entropy source.
type constantReader struct{}

func (constantReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 7
	}
	return len(p), nil
}
