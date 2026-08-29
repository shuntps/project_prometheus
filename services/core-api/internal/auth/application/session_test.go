package application_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/application"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

func newSessions(t *testing.T, repo *repository) *application.Sessions {
	t.Helper()
	use, err := application.NewSessions(application.SessionsOptions{
		Repository: repo, Lifetimes: lifetimes, Now: clock(),
	})
	if err != nil {
		t.Fatalf("building the use cases failed: %v", err)
	}
	return use
}

func aToken(t *testing.T) session.Token {
	t.Helper()
	token, err := session.NewToken(entropy())
	if err != nil {
		t.Fatalf("drawing a token failed: %v", err)
	}
	return token
}

// TestAStoreFailureIsNeverAnAbsentSession keeps a failed resolution from being
// answered as an established absence, which no observation supports.
func TestAStoreFailureIsNeverAnAbsentSession(t *testing.T) {
	_, outcome, err := newSessions(t, &repository{resolveErr: storeDown}).Authenticate(context.Background(), aToken(t))
	if !errors.Is(err, application.ErrUnavailable) {
		t.Fatalf("a store failure reported %v", err)
	}
	if outcome == application.OutcomeUnauthenticated {
		t.Fatal("a store failure was reported as an absent session")
	}

	_, outcome, err = newSessions(t, &repository{resolveFound: false}).Authenticate(context.Background(), aToken(t))
	if err != nil || outcome != application.OutcomeUnauthenticated {
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
	granted := application.Resolved{Principal: iam.Principal{
		Account: account, Kind: iam.KindViewer, Status: iam.StatusActive,
		Surface: iam.SurfacePublic, Roles: []iam.Role{iam.RoleViewer},
	}}

	_, outcome, err := newSessions(t, &repository{resolved: granted, resolveFound: true}).
		Authorise(context.Background(), aToken(t), iam.PermissionOwnSessionRead)
	if err != nil || outcome != application.OutcomeSucceeded {
		t.Fatalf("a granted permission produced (%d, %v)", outcome, err)
	}

	_, outcome, err = newSessions(t, &repository{resolved: granted, resolveFound: true}).
		Authorise(context.Background(), aToken(t), iam.PermissionPayoutRead)
	if err != nil {
		t.Fatalf("unexpected failure: %v", err)
	}
	if outcome != application.OutcomeForbidden {
		t.Errorf("outcome %d, want OutcomeForbidden", outcome)
	}

	_, outcome, err = newSessions(t, &repository{resolveFound: false}).
		Authorise(context.Background(), aToken(t), iam.PermissionOwnSessionRead)
	if err != nil {
		t.Fatalf("unexpected failure: %v", err)
	}
	if outcome != application.OutcomeUnauthenticated {
		t.Errorf("outcome %d, want OutcomeUnauthenticated", outcome)
	}
}

// TestActivityKeepsDeniedApartFromAbsent keeps the transaction's own authorisation
// verdict from being reported as a session that no longer exists.
func TestActivityKeepsDeniedApartFromAbsent(t *testing.T) {
	id, err := session.NewID()
	if err != nil {
		t.Fatalf("drawing a session identifier failed: %v", err)
	}
	cases := map[string]struct {
		repo    *repository
		outcome application.Outcome
		failed  bool
	}{
		"denied inside the write": {&repository{activityErr: fmt.Errorf("%w: refused", iam.ErrDenied)}, application.OutcomeForbidden, false},
		"session gone":            {&repository{activityFound: false}, application.OutcomeUnauthenticated, false},
		"store failure":           {&repository{activityErr: storeDown}, application.OutcomeUnknown, true},
		"renewed":                 {&repository{activityFound: true}, application.OutcomeSucceeded, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			outcome, err := newSessions(t, c.repo).RenewActivity(context.Background(), id, fixedNow)
			if c.failed {
				if !errors.Is(err, application.ErrUnavailable) {
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
	id, err := session.NewID()
	if err != nil {
		t.Fatalf("drawing a session identifier failed: %v", err)
	}
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
	id, err := session.NewID()
	if err != nil {
		t.Fatalf("drawing a session identifier failed: %v", err)
	}
	outcome, err := newSessions(t, &repository{revokeFound: false}).End(context.Background(), id)
	if err != nil || outcome != application.OutcomeUnauthenticated {
		t.Fatalf("an already revoked session produced (%d, %v)", outcome, err)
	}
	outcome, err = newSessions(t, &repository{revokeErr: storeDown}).End(context.Background(), id)
	if !errors.Is(err, application.ErrUnavailable) {
		t.Fatalf("a store failure reported %v", err)
	}
	if outcome != application.OutcomeUnknown {
		t.Errorf("outcome %d, want OutcomeUnknown", outcome)
	}
}
