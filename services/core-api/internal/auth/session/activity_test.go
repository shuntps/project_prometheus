package session_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
)

func base() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

// TestTheRenewedDeadlineNeverPassesTheAbsoluteOne keeps an activity signal from
// extending a session past the only expiry re-authentication moves.
func TestTheRenewedDeadlineNeverPassesTheAbsoluteOne(t *testing.T) {
	sess, _ := issue(t, base())
	life := lifetimes()

	within := sess.RenewedIdleAt(base().Add(time.Hour), life)
	if want := base().Add(time.Hour).Add(life.Idle); !within.Equal(want) {
		t.Errorf("a renewal inside the window gave %s, want %s", within, want)
	}

	// An instant close enough to the absolute expiry would otherwise push the idle
	// deadline beyond it.
	late := sess.AbsoluteExpiresAt.Add(-time.Minute)
	if capped := sess.RenewedIdleAt(late, life); !capped.Equal(sess.AbsoluteExpiresAt) {
		t.Errorf("a late renewal gave %s, want it capped at %s", capped, sess.AbsoluteExpiresAt)
	}
	if beyond := sess.RenewedIdleAt(sess.AbsoluteExpiresAt.Add(time.Hour), life); !beyond.Equal(sess.AbsoluteExpiresAt) {
		t.Errorf("a renewal past the absolute expiry gave %s", beyond)
	}
	if renewed := sess.RenewedIdleAt(base(), life); renewed.Location() != time.UTC {
		t.Errorf("the renewed deadline is not in UTC: %s", renewed)
	}
}

// TestActivityIsPersistedOnlyWhenItMovesTheDeadline pins the three reasons a
// signal is dropped: too soon, out of order, or already at the cap.
func TestActivityIsPersistedOnlyWhenItMovesTheDeadline(t *testing.T) {
	sess, _ := issue(t, base())
	life := lifetimes()

	for name, at := range map[string]time.Time{
		"at the same instant":    base(),
		"one nanosecond short":   base().Add(life.ActivityInterval - time.Nanosecond),
		"a second into the past": base().Add(-time.Second),
		"an hour into the past":  base().Add(-time.Hour),
	} {
		t.Run("refused "+name, func(t *testing.T) {
			if sess.ActivityIsWorthPersisting(at, life) {
				t.Fatalf("an activity signal at %s was persisted", at)
			}
		})
	}

	// A deadline already at the cap cannot be moved, so the signal buys nothing.
	// UsableAt guards this method against instants past the absolute expiry, so
	// that case is the caller's, not this one's.
	t.Run("refused when the deadline is already capped", func(t *testing.T) {
		capped := sess
		capped.IdleExpiresAt = capped.AbsoluteExpiresAt
		capped.LastActiveAt = base()
		if capped.ActivityIsWorthPersisting(base().Add(time.Hour), life) {
			t.Fatal("a signal that cannot move the deadline was persisted")
		}
	})

	t.Run("accepted exactly at the interval", func(t *testing.T) {
		if !sess.ActivityIsWorthPersisting(base().Add(life.ActivityInterval), life) {
			t.Fatal("a signal exactly at the interval was dropped")
		}
	})
	t.Run("accepted beyond the interval", func(t *testing.T) {
		if !sess.ActivityIsWorthPersisting(base().Add(time.Hour), life) {
			t.Fatal("a signal well past the interval was dropped")
		}
	})
}

// TestEveryInvariantOfAStoredRecordIsChecked names each reason a record is
// refused before it can be written.
func TestEveryInvariantOfAStoredRecordIsChecked(t *testing.T) {
	valid, _ := issue(t, base())
	revoked := base().Add(time.Minute)
	successor, _ := issue(t, base())

	cases := map[string]struct {
		mutate func(session.Session) session.Session
		names  string
	}{
		"zero identifier":          {func(s session.Session) session.Session { s.ID = session.ID{}; return s }, "identifier"},
		"zero account":             {func(s session.Session) session.Session { s.Account = zeroAccount(); return s }, "account"},
		"zero fingerprint":         {func(s session.Session) session.Session { s.Fingerprint = session.Fingerprint{}; return s }, "fingerprint"},
		"zero CSRF token":          {func(s session.Session) session.Session { s.CSRF = session.CSRFToken{}; return s }, "CSRF"},
		"already revoked":          {func(s session.Session) session.Session { s.RevokedAt = &revoked; return s }, "revoked"},
		"already rotated":          {func(s session.Session) session.Session { s.RotatedTo = &successor.ID; return s }, "rotated"},
		"unset creation":           {func(s session.Session) session.Session { s.CreatedAt = time.Time{}; return s }, "instant"},
		"unset activity":           {func(s session.Session) session.Session { s.LastActiveAt = time.Time{}; return s }, "instant"},
		"unset idle expiry":        {func(s session.Session) session.Session { s.IdleExpiresAt = time.Time{}; return s }, "instant"},
		"unset absolute expiry":    {func(s session.Session) session.Session { s.AbsoluteExpiresAt = time.Time{}; return s }, "instant"},
		"activity before creation": {func(s session.Session) session.Session { s.LastActiveAt = s.CreatedAt.Add(-time.Second); return s }, "predate"},
		"idle at the activity":     {func(s session.Session) session.Session { s.IdleExpiresAt = s.LastActiveAt; return s }, "idle expiry"},
		"absolute at creation":     {func(s session.Session) session.Session { s.AbsoluteExpiresAt = s.CreatedAt; return s }, "absolute expiry"},
		"idle past the absolute": {func(s session.Session) session.Session {
			s.IdleExpiresAt = s.AbsoluteExpiresAt.Add(time.Second)
			return s
		}, "exceed"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			err := c.mutate(valid).Validate(viewerKind())
			if !errors.Is(err, session.ErrInvalid) {
				t.Fatalf("an unusable record was accepted: %v", err)
			}
			if !strings.Contains(err.Error(), c.names) {
				t.Errorf("the refusal %q does not name %q", err, c.names)
			}
		})
	}
	if err := valid.Validate(viewerKind()); err != nil {
		t.Fatalf("a record this package issued was refused: %v", err)
	}
	// A surface the kind may not hold is refused whatever wrote the record.
	if err := valid.Validate(operatorKind()); err == nil {
		t.Error("a record was accepted against a kind that may not hold its surface")
	}
}
