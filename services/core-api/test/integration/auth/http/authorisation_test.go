package integration_test

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

// TestAuthorisationIsGrantedOnlyByAnExplicitRule drives the real principal through
// the domain function and proves both outcomes on the same running surface.
func TestAuthorisationIsGrantedOnlyByAnExplicitRule(t *testing.T) {
	s := newSurface(t)

	viewerAddress, _ := s.account(t, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
	creatorAddress, _ := s.account(t, iam.KindCreator, iam.StatusActive, iam.RoleViewer, iam.RoleCreator)
	bareAddress, _ := s.account(t, iam.KindViewer, iam.StatusActive)

	viewer := s.signIn(t, viewerAddress, probePassword)
	creator := s.signIn(t, creatorAddress, probePassword)
	bare := s.signIn(t, bareAddress, probePassword)
	for name, in := range map[string]signedIn{"viewer": viewer, "creator": creator, "bare": bare} {
		if in.response.StatusCode != http.StatusCreated {
			t.Fatalf("%s could not sign in: %d %s", name, in.response.StatusCode, in.body)
		}
	}

	// Only the role that explicitly carries the permission is granted it.
	if res := s.send(t, request{method: http.MethodGet, target: broadcastRoute, cookie: creator.token, origin: publicOrigin}); res.StatusCode != http.StatusOK {
		t.Errorf("a creator was refused the broadcast permission: %d", res.StatusCode)
	}
	if res := s.send(t, request{method: http.MethodGet, target: broadcastRoute, cookie: viewer.token, origin: publicOrigin}); res.StatusCode != http.StatusForbidden {
		t.Errorf("a viewer was granted the broadcast permission: %d", res.StatusCode)
	}
	// An account holding no role at all is granted nothing, not even the read every
	// named role carries.
	if res := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: bare.token, origin: publicOrigin}); res.StatusCode != http.StatusForbidden {
		t.Errorf("an account with no role read its own session: %d", res.StatusCode)
	}
	if res := s.send(t, request{method: http.MethodGet, target: broadcastRoute, cookie: bare.token, origin: publicOrigin}); res.StatusCode != http.StatusForbidden {
		t.Errorf("an account with no role was granted the broadcast permission: %d", res.StatusCode)
	}
}

// TestAuthorityIsReReadOnEveryRequestRatherThanFrozenInTheCookie changes the
// account behind a live session and requires every decision to follow at once.
func TestAuthorityIsReReadOnEveryRequestRatherThanFrozenInTheCookie(t *testing.T) {
	s := newSurface(t)
	address, account := s.account(t, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d: %s", in.response.StatusCode, in.body)
	}
	if roles, _ := in.view["roles"].([]any); len(roles) != 1 {
		t.Fatalf("the session opened with roles %v, want exactly the viewer role", in.view["roles"])
	}

	// A role granted after the cookie was issued is honoured on the next request,
	// which is only possible if the grants are read again rather than carried.
	if res := s.send(t, request{method: http.MethodGet, target: broadcastRoute, cookie: in.token, origin: publicOrigin}); res.StatusCode != http.StatusForbidden {
		t.Fatalf("a viewer already held the broadcast permission: %d", res.StatusCode)
	}
	if _, err := s.pool.Exec(context.Background(),
		`INSERT INTO account_role_grants (account_id, role, granted_at) VALUES ($1, $2, now())`,
		account.ID.String(), string(iam.RoleCreator)); err != nil {
		t.Fatalf("granting the role failed: %v", err)
	}
	// The account kind still refuses it: a viewer may not hold the creator role.
	if res := s.send(t, request{method: http.MethodGet, target: broadcastRoute, cookie: in.token, origin: publicOrigin}); res.StatusCode != http.StatusForbidden {
		t.Fatalf("a viewer kind exercised a creator role: %d", res.StatusCode)
	}
	if _, err := s.pool.Exec(context.Background(),
		`UPDATE accounts SET kind = $2 WHERE id = $1`, account.ID.String(), string(iam.KindCreator)); err != nil {
		t.Fatalf("changing the kind failed: %v", err)
	}
	if res := s.send(t, request{method: http.MethodGet, target: broadcastRoute, cookie: in.token, origin: publicOrigin}); res.StatusCode != http.StatusOK {
		t.Fatalf("a granted role was not honoured on the established session: %d", res.StatusCode)
	}

	// Withdrawing the grant withdraws the permission on the very next request.
	if _, err := s.pool.Exec(context.Background(),
		`DELETE FROM account_role_grants WHERE account_id = $1 AND role = $2`,
		account.ID.String(), string(iam.RoleCreator)); err != nil {
		t.Fatalf("withdrawing the role failed: %v", err)
	}
	if res := s.send(t, request{method: http.MethodGet, target: broadcastRoute, cookie: in.token, origin: publicOrigin}); res.StatusCode != http.StatusForbidden {
		t.Fatalf("a withdrawn role was still honoured: %d", res.StatusCode)
	}

	// A status change alone, with the session left untouched, ends every decision.
	for _, status := range []iam.Status{iam.StatusSuspended, iam.StatusClosed, iam.StatusPending} {
		if _, err := s.pool.Exec(context.Background(),
			`UPDATE accounts SET status = $2 WHERE id = $1`, account.ID.String(), string(status)); err != nil {
			t.Fatalf("changing the status failed: %v", err)
		}
		var live int
		if err := s.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM account_sessions WHERE account_id = $1 AND revoked_at IS NULL`,
			account.ID.String()).Scan(&live); err != nil {
			t.Fatalf("counting sessions failed: %v", err)
		}
		if live == 0 {
			t.Fatalf("the %s status revoked the session, so the re-read is not what refused it", status)
		}
		res := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin})
		if res.StatusCode == http.StatusOK {
			t.Fatalf("a %s account still used its established session", status)
		}
	}
}

// TestASessionReadWritesNothing: a top-level navigation carries the cookie under
// SameSite=Lax, so a read that renewed the idle window would hand it away.
func TestASessionReadWritesNothing(t *testing.T) {
	s := newSurface(t)
	address, account := s.account(t, iam.KindCreator, iam.StatusActive, iam.RoleViewer, iam.RoleCreator)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", in.response.StatusCode)
	}

	stamps := func() (time.Time, time.Time) {
		t.Helper()
		var active, idle time.Time
		if err := s.pool.QueryRow(context.Background(),
			`SELECT last_active_at, idle_expires_at FROM account_sessions WHERE account_id = $1`,
			account.ID.String()).Scan(&active, &idle); err != nil {
			t.Fatalf("reading the row failed: %v", err)
		}
		return active, idle
	}
	activeBefore, idleBefore := stamps()

	// Time moves on, so a renewal would be visible if one happened.
	s.clock.advance(10 * time.Minute)

	reads := []request{
		{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin},
		{method: http.MethodGet, target: broadcastRoute, cookie: in.token, origin: publicOrigin},
		// A top-level navigation: no Origin, no Fetch Metadata, cookie carried.
		{method: http.MethodGet, target: sessionRoute, cookie: in.token},
		{method: http.MethodGet, target: sessionRoute, cookie: in.token, fetchSite: "cross-site"},
	}
	for i, r := range reads {
		if res := s.send(t, r); res.StatusCode != http.StatusOK {
			t.Fatalf("read %d returned %d", i, res.StatusCode)
		}
		activeAfter, idleAfter := stamps()
		if !activeAfter.Equal(activeBefore) {
			t.Fatalf("read %d moved last_active_at from %s to %s", i, activeBefore, activeAfter)
		}
		if !idleAfter.Equal(idleBefore) {
			t.Fatalf("read %d moved idle_expires_at from %s to %s", i, idleBefore, idleAfter)
		}
	}

	// The idle expiry therefore still ends the session on its original schedule.
	s.clock.advance(21 * time.Minute)
	if res := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin}); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the session outlived its unrenewed idle window: %d", res.StatusCode)
	}
}

// TestServedRolesCarryTheApplicationOrder requires both public answers to use
// the same canonical role sequence. Sign-in and session reads take different
// store paths.
func TestServedRolesCarryTheApplicationOrder(t *testing.T) {
	s := newSurface(t)
	address, _ := s.account(t, iam.KindCreator, iam.StatusActive, iam.RoleViewer, iam.RoleCreator)
	want := []string{"creator", "viewer"}

	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("signing in returned %d: %s", in.response.StatusCode, in.body)
	}
	if got := rolesOf(t, in.view); !slices.Equal(got, want) {
		t.Fatalf("the sign-in answer carried the roles %v, want %v", got, want)
	}

	res := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("the session read returned %d", res.StatusCode)
	}
	var view map[string]any
	if err := json.Unmarshal([]byte(bodyOf(t, res)), &view); err != nil {
		t.Fatalf("decoding the session view failed: %v", err)
	}
	if got := rolesOf(t, view); !slices.Equal(got, want) {
		t.Fatalf("the session read carried the roles %v, want %v", got, want)
	}
}

func rolesOf(t *testing.T, view map[string]any) []string {
	t.Helper()
	raw, held := view["roles"].([]any)
	if !held {
		t.Fatalf("the view carries no roles array: %v", view["roles"])
	}
	roles := make([]string, 0, len(raw))
	for _, value := range raw {
		text, isText := value.(string)
		if !isText {
			t.Fatalf("a served role is not a string: %v", value)
		}
		roles = append(roles, text)
	}
	return roles
}
