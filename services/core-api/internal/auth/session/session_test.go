package session_test

import (
	"errors"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

// TestTheTwoExpiriesAreDistinctAndBothEnforced keeps an idle window from acting
// as an absolute one, and the reverse.
func TestTheTwoExpiriesAreDistinctAndBothEnforced(t *testing.T) {
	start := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	sess, _ := issue(t, start)

	if sess.IdleExpiresAt.Equal(sess.AbsoluteExpiresAt) {
		t.Fatal("the two expiries are the same instant")
	}
	if err := sess.UsableAt(start.Add(time.Minute)); err != nil {
		t.Fatalf("a fresh session was refused: %v", err)
	}
	if err := sess.UsableAt(start.Add(29 * time.Minute)); err != nil {
		t.Fatalf("a session inside its idle window was refused: %v", err)
	}
	if err := sess.UsableAt(sess.IdleExpiresAt); !errors.Is(err, session.ErrUnusable) {
		t.Error("a session was accepted at its idle expiry")
	}
	if err := sess.UsableAt(start.Add(time.Hour)); !errors.Is(err, session.ErrUnusable) {
		t.Error("a session was accepted past its idle expiry")
	}

	// Even continuously active, a session dies at its absolute expiry.
	fresh := sess
	fresh.IdleExpiresAt = fresh.AbsoluteExpiresAt
	if err := fresh.UsableAt(fresh.AbsoluteExpiresAt); !errors.Is(err, session.ErrUnusable) {
		t.Error("a session was accepted at its absolute expiry")
	}
}

func TestARevokedOrRotatedSessionIsNeverUsable(t *testing.T) {
	start := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	sess, _ := issue(t, start)

	revoked := sess
	when := start.Add(time.Minute)
	revoked.RevokedAt = &when
	if err := revoked.UsableAt(when.Add(time.Second)); !errors.Is(err, session.ErrUnusable) {
		t.Error("a revoked session was accepted")
	}

	rotated := sess
	next, _ := issue(t, time.Now())
	successor := next.ID
	rotated.RotatedTo = &successor
	if err := rotated.UsableAt(when); !errors.Is(err, session.ErrUnusable) {
		t.Error("a rotated session was accepted")
	}

	if err := (session.Session{}).UsableAt(start); !errors.Is(err, session.ErrUnusable) {
		t.Error("a zero session was accepted")
	}
}

func TestASessionIsAlwaysBoundToOneKnownSurface(t *testing.T) {
	for _, surface := range []iam.Surface{"", "edge", "admin", "Operator"} {
		if _, _, err := session.Issue(mustAccount(t), iam.KindViewer, surface, lifetimes(), time.Now()); !errors.Is(err, session.ErrInvalid) {
			t.Errorf("surface %q was accepted", surface)
		}
	}
	for surface, kind := range map[iam.Surface]iam.Kind{iam.SurfacePublic: iam.KindViewer, iam.SurfaceOperator: iam.KindOperator} {
		sess, _, err := session.Issue(mustAccount(t), kind, surface, lifetimes(), time.Now())
		if err != nil {
			t.Errorf("surface %q was refused: %v", surface, err)
			continue
		}
		if sess.Surface != surface {
			t.Errorf("the session settled on surface %q", sess.Surface)
		}
	}
	if _, _, err := session.Issue(iam.AccountID{}, iam.KindViewer, iam.SurfacePublic, lifetimes(), time.Now()); !errors.Is(err, session.ErrInvalid) {
		t.Error("a session was issued for the zero account")
	}
}
