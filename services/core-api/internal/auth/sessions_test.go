package auth_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

func newSessions(t *testing.T, repo *repository) *auth.Sessions {
	t.Helper()
	use, err := auth.NewSessions(auth.SessionsOptions{
		Repository: repo, Lifetimes: lifetimes, Now: clock(),
	})
	if err != nil {
		t.Fatalf("building the use cases failed: %v", err)
	}
	return use
}

func aToken(t *testing.T) session.Token {
	t.Helper()
	_, token := drawn(t)
	return token
}

// TestAStoreFailureIsNeverAnAbsentSession keeps a failed resolution from being
// answered as an established absence, which no observation supports.
func TestAStoreFailureIsNeverAnAbsentSession(t *testing.T) {
	_, outcome, err := newSessions(t, &repository{resolveErr: storeDown}).Authenticate(context.Background(), aToken(t))
	if !errors.Is(err, auth.ErrUnavailable) {
		t.Fatalf("a store failure reported %v", err)
	}
	if outcome == auth.OutcomeUnauthenticated {
		t.Fatal("a store failure was reported as an absent session")
	}

	_, outcome, err = newSessions(t, &repository{resolveFound: false}).Authenticate(context.Background(), aToken(t))
	if err != nil || outcome != auth.OutcomeUnauthenticated {
		t.Fatalf("an absence produced (%d, %v)", outcome, err)
	}
}

// TestAuthorisationSeparatesForbiddenFromUnauthenticated keeps the two apart: one
// says nobody is there, the other says who is there may not act.
func TestAuthorisationSeparatesForbiddenFromUnauthenticated(t *testing.T) {
	account, err := iam.NewAccountID()
	if err != nil {
		t.Fatalf("drawing an account failed: %v", err)
	}
	granted := auth.Resolved{Principal: iam.Principal{
		Account: account, Kind: iam.KindViewer, Status: iam.StatusActive,
		Surface: iam.SurfacePublic, Roles: []iam.Role{iam.RoleViewer},
	}}

	_, outcome, err := newSessions(t, &repository{resolved: granted, resolveFound: true}).
		Authorise(context.Background(), aToken(t), iam.PermissionOwnSessionRead)
	if err != nil || outcome != auth.OutcomeSucceeded {
		t.Fatalf("a granted permission produced (%d, %v)", outcome, err)
	}

	_, outcome, err = newSessions(t, &repository{resolved: granted, resolveFound: true}).
		Authorise(context.Background(), aToken(t), iam.PermissionPayoutRead)
	if err != nil {
		t.Fatalf("unexpected failure: %v", err)
	}
	if outcome != auth.OutcomeForbidden {
		t.Errorf("outcome %d, want OutcomeForbidden", outcome)
	}

	_, outcome, err = newSessions(t, &repository{resolveFound: false}).
		Authorise(context.Background(), aToken(t), iam.PermissionOwnSessionRead)
	if err != nil {
		t.Fatalf("unexpected failure: %v", err)
	}
	if outcome != auth.OutcomeUnauthenticated {
		t.Errorf("outcome %d, want OutcomeUnauthenticated", outcome)
	}
}

// TestActivityKeepsDeniedApartFromAbsent keeps the transaction's own authorisation
// verdict from being reported as a session that no longer exists.
func TestActivityKeepsDeniedApartFromAbsent(t *testing.T) {
	sess, _ := drawn(t)
	id := sess.ID
	cases := map[string]struct {
		repo    *repository
		outcome auth.Outcome
		failed  bool
	}{
		"denied inside the write": {&repository{activityErr: fmt.Errorf("%w: refused", iam.ErrDenied)}, auth.OutcomeForbidden, false},
		"session gone":            {&repository{activityFound: false}, auth.OutcomeUnauthenticated, false},
		"store failure":           {&repository{activityErr: storeDown}, auth.OutcomeUnknown, true},
		"renewed":                 {&repository{activityFound: true}, auth.OutcomeSucceeded, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			outcome, err := newSessions(t, c.repo).RenewActivity(context.Background(), id, fixedNow)
			if c.failed {
				if !errors.Is(err, auth.ErrUnavailable) {
					t.Fatalf("a store failure reported %v", err)
				}
			} else if err != nil {
				t.Fatalf("unexpected failure: %v", err)
			}
			if outcome != c.outcome {
				t.Errorf("outcome %d, want %d", outcome, c.outcome)
			}
		})
	}
}

// TestActivityIsAnchoredToTheResolutionInstant keeps a clock from moving between
// the resolution and the write, which could renew a session already expired.
func TestActivityIsAnchoredToTheResolutionInstant(t *testing.T) {
	sess, _ := drawn(t)
	id := sess.ID
	repo := &repository{activityFound: true}
	anchor := fixedNow.Add(-time.Minute)
	if _, err := newSessions(t, repo).RenewActivity(context.Background(), id, anchor); err != nil {
		t.Fatalf("the renewal failed: %v", err)
	}
	if !repo.activityAt.Equal(anchor) {
		t.Errorf("the write observed %s, want the resolution instant %s", repo.activityAt, anchor)
	}
}

// TestEndingASessionAlreadyGoneIsNotAFailure keeps sign-out idempotent while a
// store that failed stays distinguishable from a session already revoked.
func TestEndingASessionAlreadyGoneIsNotAFailure(t *testing.T) {
	sess, _ := drawn(t)
	id := sess.ID
	outcome, err := newSessions(t, &repository{revokeFound: false}).End(context.Background(), id)
	if err != nil || outcome != auth.OutcomeUnauthenticated {
		t.Fatalf("an already revoked session produced (%d, %v)", outcome, err)
	}
	outcome, err = newSessions(t, &repository{revokeErr: storeDown}).End(context.Background(), id)
	if !errors.Is(err, auth.ErrUnavailable) {
		t.Fatalf("a store failure reported %v", err)
	}
	if outcome != auth.OutcomeUnknown {
		t.Errorf("outcome %d, want OutcomeUnknown", outcome)
	}
}

// TestAPartialSessionUseCasesAreRefused keeps a set of session use cases missing
// a repository or a usable pair of lifetimes from ever being built.
func TestAPartialSessionUseCasesAreRefused(t *testing.T) {
	for name, opts := range map[string]auth.SessionsOptions{
		"no repository": {Lifetimes: lifetimes, Now: clock()},
		"no lifetimes":  {Repository: &repository{}, Now: clock()},
		"idle too long": {Repository: &repository{}, Now: clock(),
			Lifetimes: session.Lifetimes{Absolute: time.Hour, Idle: 2 * time.Hour, ActivityInterval: time.Minute}},
	} {
		t.Run(name, func(t *testing.T) {
			if use, err := auth.NewSessions(opts); err == nil || use != nil {
				t.Fatal("a partial set of session use cases was built")
			}
		})
	}
}
