package httpapi_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
)

// TestACrossSiteContextIsRefusedBeforeAnythingHappens covers login CSRF too: with
// no session yet, the origin check and the request shape are the whole defence.
func TestACrossSiteContextIsRefusedBeforeAnythingHappens(t *testing.T) {
	s := newSurface(t)
	address, account := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)

	cases := []struct {
		name    string
		request request
		want    int
	}{
		{"foreign origin", request{method: http.MethodPost, target: sessionRoute, origin: foreignOrigin, fetchSite: "cross-site"}, http.StatusForbidden},
		{"absent origin", request{method: http.MethodPost, target: sessionRoute}, http.StatusForbidden},
		{"null origin", request{method: http.MethodPost, target: sessionRoute, origin: "null"}, http.StatusForbidden},
		{"sibling host", request{method: http.MethodPost, target: sessionRoute, origin: "https://app.example.com.attacker.example"}, http.StatusForbidden},
		{"plain-text origin", request{method: http.MethodPost, target: sessionRoute, origin: "http://app.example.com"}, http.StatusForbidden},
		{"cross-site fetch metadata", request{method: http.MethodPost, target: sessionRoute, origin: publicOrigin, fetchSite: "cross-site"}, http.StatusForbidden},
		{"same-site fetch metadata", request{method: http.MethodPost, target: sessionRoute, origin: publicOrigin, fetchSite: "same-site"}, http.StatusForbidden},
		{"form content type", request{method: http.MethodPost, target: sessionRoute, origin: publicOrigin, fetchSite: "same-origin", noJSON: true}, http.StatusUnsupportedMediaType},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := c.request
			r.body = map[string]string{"email": address, "password": probePassword}
			res := s.send(t, r)
			if res.StatusCode != c.want {
				t.Fatalf("returned %d, want %d: %s", res.StatusCode, c.want, bodyOf(t, res))
			}
			if sessionCookie(res) != nil {
				t.Error("a refused request still set a session cookie")
			}
		})
	}

	var sessions int
	if err := s.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM account_sessions WHERE account_id = $1`, account.ID.String()).Scan(&sessions); err != nil {
		t.Fatalf("counting sessions failed: %v", err)
	}
	if sessions != 0 {
		t.Fatalf("%d sessions were created by refused cross-site requests", sessions)
	}
}

// TestOneSessionsCSRFTokenIsWorthlessAgainstAnother: the token is bound to one
// session, so obtaining one by signing up buys nothing against anybody else.
func TestOneSessionsCSRFTokenIsWorthlessAgainstAnother(t *testing.T) {
	s := newSurface(t)
	victimAddress, _ := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	attackerAddress, _ := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)

	victim := s.signIn(t, victimAddress, probePassword)
	attacker := s.signIn(t, attackerAddress, probePassword)
	if victim.response.StatusCode != http.StatusCreated || attacker.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in failed: %d and %d", victim.response.StatusCode, attacker.response.StatusCode)
	}
	if victim.csrf == "" || attacker.csrf == "" {
		t.Fatal("a session was issued without a CSRF token")
	}
	if victim.csrf == attacker.csrf {
		t.Fatal("two sessions were issued the same CSRF token")
	}

	// A second session for the same account gets its own token too, so the value
	// is not a per-account constant either.
	again := s.signIn(t, victimAddress, probePassword)
	if again.response.StatusCode != http.StatusCreated {
		t.Fatalf("the second sign-in returned %d", again.response.StatusCode)
	}
	if again.csrf == victim.csrf {
		t.Fatal("two sessions of one account share a CSRF token")
	}

	var distinct int
	if err := s.pool.QueryRow(context.Background(),
		`SELECT count(DISTINCT csrf_token) FROM account_sessions`).Scan(&distinct); err != nil {
		t.Fatalf("counting tokens failed: %v", err)
	}
	if distinct != 3 {
		t.Fatalf("%d distinct CSRF tokens were stored for 3 sessions", distinct)
	}

	// Holding a token from one session authorises nothing on another.
	res := s.send(t, request{
		method: http.MethodDelete, target: sessionRoute,
		cookie: victim.token, csrf: attacker.csrf, origin: publicOrigin, fetchSite: "same-origin", contentType: "application/json"})
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("another session's CSRF token was accepted: %d", res.StatusCode)
	}
	check := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: victim.token, origin: publicOrigin})
	if check.StatusCode != http.StatusOK {
		t.Fatalf("the victim session was ended by a foreign token: %d", check.StatusCode)
	}
}
