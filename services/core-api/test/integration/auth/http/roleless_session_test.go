package integration_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

// resolveSession reads the session the way a browser does after a reload: the
// cookie alone, no origin, no synchronizer token, nothing else.
func resolveSession(t *testing.T, s *surface, cookie string) (int, map[string]any) {
	t.Helper()
	res := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: cookie})
	body := bodyOf(t, res)
	if res.StatusCode != http.StatusOK {
		return res.StatusCode, nil
	}
	var view map[string]any
	if err := json.Unmarshal([]byte(body), &view); err != nil {
		t.Fatalf("decoding the session view failed: %v (%s)", err, body)
	}
	return res.StatusCode, view
}

func csrfOf(t *testing.T, view map[string]any) string {
	t.Helper()
	token, held := view["csrf_token"].(string)
	if !held || token == "" {
		t.Fatalf("the session view carried no CSRF token: %v", view)
	}
	return token
}

// TestASessionWithNoRoleStaysReadableAndCanBeEnded covers the whole dead end: an
// account holding no role could sign in, then never recover the token its own
// sign-out requires, because the cookie is HttpOnly and the read was refused.
func TestASessionWithNoRoleStaysReadableAndCanBeEnded(t *testing.T) {
	s := newSurface(t)
	address, _ := s.account(t, iam.KindViewer, iam.StatusActive)

	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("an account with no role could not sign in: %d %s", in.response.StatusCode, in.body)
	}

	// Only the cookie survives a reload; the token the sign-in answered with is gone.
	status, view := resolveSession(t, s, in.token)
	if status != http.StatusOK {
		t.Fatalf("resolving a live session answered %d, want 200", status)
	}
	roles, held := view["roles"].([]any)
	if !held || len(roles) != 0 {
		t.Fatalf("the view carried the roles %v, want an empty list", view["roles"])
	}
	token := csrfOf(t, view)

	out := s.send(t, request{
		method: http.MethodDelete, target: sessionRoute,
		body: map[string]string{}, origin: publicOrigin, fetchSite: "same-origin",
		cookie: in.token, csrf: token,
	})
	if out.StatusCode != http.StatusNoContent {
		t.Fatalf("signing out answered %d, want 204: %s", out.StatusCode, bodyOf(t, out))
	}
	if cleared := sessionCookie(out); cleared == nil || cleared.Value != "" {
		t.Fatalf("the session cookie was not cleared: %v", cleared)
	}
	if again, _ := resolveSession(t, s, in.token); again != http.StatusUnauthorized {
		t.Fatalf("an ended session resolved with %d, want 401", again)
	}
}

// TestARoleWithdrawnAfterSignInLeavesTheSessionEndable is the realistic shape of
// the same dead end: the role disappears while the session is already live.
func TestARoleWithdrawnAfterSignInLeavesTheSessionEndable(t *testing.T) {
	s := newSurface(t)
	address, account := s.account(t, iam.KindViewer, iam.StatusActive, iam.RoleViewer)

	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d: %s", in.response.StatusCode, in.body)
	}
	if _, err := s.pool.Exec(context.Background(),
		`DELETE FROM account_role_grants WHERE account_id = $1`, account.ID.String()); err != nil {
		t.Fatalf("withdrawing the role failed: %v", err)
	}

	status, view := resolveSession(t, s, in.token)
	if status != http.StatusOK {
		t.Fatalf("resolving after the withdrawal answered %d, want 200", status)
	}
	if roles, held := view["roles"].([]any); !held || len(roles) != 0 {
		t.Fatalf("the view carried the roles %v, want an empty list", view["roles"])
	}
	token := csrfOf(t, view)

	// Reading the session is not a capability; renewing it still is.
	activity := s.send(t, request{
		method: http.MethodPost, target: activityRoute,
		body: map[string]string{}, origin: publicOrigin, fetchSite: "same-origin",
		cookie: in.token, csrf: token,
	})
	if activity.StatusCode != http.StatusForbidden {
		t.Fatalf("the activity signal answered %d after the withdrawal, want 403", activity.StatusCode)
	}
	if res := s.send(t, request{method: http.MethodGet, target: broadcastRoute, cookie: in.token, origin: publicOrigin}); res.StatusCode != http.StatusForbidden {
		t.Fatalf("broadcast access answered %d after the withdrawal, want 403", res.StatusCode)
	}

	out := s.send(t, request{
		method: http.MethodDelete, target: sessionRoute,
		body: map[string]string{}, origin: publicOrigin, fetchSite: "same-origin",
		cookie: in.token, csrf: token,
	})
	if out.StatusCode != http.StatusNoContent {
		t.Fatalf("signing out answered %d, want 204: %s", out.StatusCode, bodyOf(t, out))
	}
	if again, _ := resolveSession(t, s, in.token); again != http.StatusUnauthorized {
		t.Fatalf("an ended session resolved with %d, want 401", again)
	}
}

// TestReadingASessionRequiresNoOriginAndNoToken keeps the read free of the checks
// that guard mutations, and keeps the mutation's own checks in force.
func TestReadingASessionRequiresNoOriginAndNoToken(t *testing.T) {
	s := newSurface(t)
	address, _ := s.account(t, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
	in := s.signIn(t, address, probePassword)

	if status, _ := resolveSession(t, s, in.token); status != http.StatusOK {
		t.Fatalf("a read without an origin answered %d, want 200", status)
	}
	out := s.send(t, request{
		method: http.MethodDelete, target: sessionRoute,
		body: map[string]string{}, origin: publicOrigin, fetchSite: "same-origin", cookie: in.token,
	})
	if out.StatusCode != http.StatusForbidden {
		t.Fatalf("a sign-out without the token answered %d, want 403", out.StatusCode)
	}
}
