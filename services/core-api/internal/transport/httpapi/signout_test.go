package httpapi_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
)

func TestSignOutRevokesTheSessionAndClearsTheCookie(t *testing.T) {
	s := newSurface(t)
	address, _ := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", in.response.StatusCode)
	}

	res := s.send(t, request{
		method: http.MethodDelete, target: sessionRoute,
		cookie: in.token, csrf: in.csrf, origin: publicOrigin, fetchSite: "same-origin", contentType: "application/json"})
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("sign-out returned %d: %s", res.StatusCode, bodyOf(t, res))
	}
	cleared := sessionCookie(res)
	if cleared == nil {
		t.Fatal("sign-out did not write a replacement cookie")
	}
	if cleared.Value != "" || cleared.MaxAge >= 0 {
		t.Errorf("the cookie was not cleared: value=%q max-age=%d", cleared.Value, cleared.MaxAge)
	}
	if !cleared.Secure || !cleared.HttpOnly || cleared.Path != "/" || cleared.Domain != "" {
		t.Error("the clearing cookie does not match the attributes it must replace")
	}

	// The token is inert immediately, and every repeat stays successful without
	// restoring anything.
	for attempt := 1; attempt <= 3; attempt++ {
		res := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin})
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("the session still resolved after sign-out (attempt %d): %d", attempt, res.StatusCode)
		}
		repeat := s.send(t, request{
			method: http.MethodDelete, target: sessionRoute,
			cookie: in.token, csrf: in.csrf, origin: publicOrigin, fetchSite: "same-origin", contentType: "application/json"})
		if repeat.StatusCode != http.StatusNoContent {
			t.Fatalf("repeat %d of sign-out returned %d", attempt, repeat.StatusCode)
		}
	}

	// Signing out with no cookie at all is the same successful answer.
	empty := s.send(t, request{method: http.MethodDelete, target: sessionRoute, origin: publicOrigin, fetchSite: "same-origin", contentType: "application/json"})
	if empty.StatusCode != http.StatusNoContent {
		t.Fatalf("sign-out without a session returned %d", empty.StatusCode)
	}
}

func TestSignOutRequiresTheSynchronizerToken(t *testing.T) {
	s := newSurface(t)
	address, _ := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", in.response.StatusCode)
	}
	forged, err := session.NewCSRFToken(nil)
	if err != nil {
		t.Fatalf("drawing failed: %v", err)
	}

	cases := map[string]string{
		"absent":    "",
		"forged":    forged.Reveal(),
		"malformed": "not-a-token",
		"truncated": in.csrf[:len(in.csrf)-1],
	}
	for name, token := range cases {
		res := s.send(t, request{
			method: http.MethodDelete, target: sessionRoute,
			cookie: in.token, csrf: token, origin: publicOrigin, fetchSite: "same-origin", contentType: "application/json"})
		if res.StatusCode != http.StatusForbidden {
			t.Errorf("a %s CSRF token returned %d, want 403", name, res.StatusCode)
		}
		// The session must survive a refused sign-out.
		check := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin})
		if check.StatusCode != http.StatusOK {
			t.Fatalf("a refused sign-out (%s) ended the session anyway: %d", name, check.StatusCode)
		}
	}

	// The genuine token still works, so the refusals above were the token's doing.
	res := s.send(t, request{
		method: http.MethodDelete, target: sessionRoute,
		cookie: in.token, csrf: in.csrf, origin: publicOrigin, fetchSite: "same-origin", contentType: "application/json"})
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("the genuine CSRF token was refused: %d", res.StatusCode)
	}
}

// TestSignOutNeverAnnouncesASignOutItDidNotPerform keeps a failure from producing
// a cleared cookie and a success code while the server session is still live.
func TestSignOutNeverAnnouncesASignOutItDidNotPerform(t *testing.T) {
	s := newSurface(t)
	address, account := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", in.response.StatusCode)
	}

	failures := map[string]func(){
		"resolution fails": func() { s.faults.resolve = func() error { return storeFailure() } },
		"revocation fails": func() { s.faults.revoke = func() error { return storeFailure() } },
	}
	for name, breakIt := range failures {
		t.Run(name, func(t *testing.T) {
			breakIt()
			res := s.send(t, request{
				method: http.MethodDelete, target: sessionRoute,
				cookie: in.token, csrf: in.csrf, origin: publicOrigin, fetchSite: "same-origin", contentType: "application/json"})
			s.faults.resolve, s.faults.revoke = nil, nil

			if res.StatusCode != http.StatusInternalServerError {
				t.Fatalf("sign-out returned %d, want 500", res.StatusCode)
			}
			if cleared := sessionCookie(res); cleared != nil {
				t.Error("a failed sign-out cleared the cookie while the session may still be live")
			}
			if live := s.liveSessions(t, account); live != 1 {
				t.Errorf("%d live sessions after a failed sign-out, want the session untouched", live)
			}
			if probe := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin}); probe.StatusCode != http.StatusOK {
				t.Errorf("the session stopped working after a failed sign-out: %d", probe.StatusCode)
			}
		})
	}

	// An absent, finished or already revoked session is idempotent success.
	if err := s.store.RevokeSession(context.Background(), sessionIDOf(t, s, account), s.clock.Now()); err != nil {
		t.Fatalf("revoking failed: %v", err)
	}
	for _, name := range []string{"already revoked", "repeat"} {
		res := s.send(t, request{
			method: http.MethodDelete, target: sessionRoute,
			cookie: in.token, csrf: in.csrf, origin: publicOrigin, fetchSite: "same-origin", contentType: "application/json"})
		if res.StatusCode != http.StatusNoContent {
			t.Fatalf("sign-out on an %s session returned %d, want 204", name, res.StatusCode)
		}
		if sessionCookie(res) == nil {
			t.Errorf("sign-out on an %s session did not clear the cookie", name)
		}
	}
}

// TestSignOutRequiresTheSameJSONShapeAsEveryOtherOperationWithEffect: a simple
// content type must not reach a revocation, valid origin and token notwithstanding.
func TestSignOutRequiresTheSameJSONShapeAsEveryOtherOperationWithEffect(t *testing.T) {
	shapes := map[string]request{
		"absent":                {noContentType: true},
		"text/plain":            {contentType: "text/plain"},
		"form-urlencoded":       {contentType: "application/x-www-form-urlencoded"},
		"multipart/form-data":   {contentType: "multipart/form-data; boundary=x"},
		"another non-JSON type": {contentType: "application/xml"},
	}
	for name, shape := range shapes {
		t.Run(name, func(t *testing.T) {
			s := newSurface(t)
			address, account := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
			in := s.signIn(t, address, probePassword)
			if in.response.StatusCode != http.StatusCreated {
				t.Fatalf("sign-in returned %d", in.response.StatusCode)
			}
			before := readSessionLedger(t, s)

			r := shape
			r.method, r.target = http.MethodDelete, sessionRoute
			r.cookie, r.csrf, r.origin, r.fetchSite = in.token, in.csrf, publicOrigin, "same-origin"
			res := s.send(t, r)

			if res.StatusCode != http.StatusUnsupportedMediaType {
				t.Fatalf("a %s sign-out returned %d, want 415", name, res.StatusCode)
			}
			if sessionCookie(res) != nil {
				t.Error("a refused sign-out emitted a clearing cookie")
			}
			if after := readSessionLedger(t, s); after != before {
				t.Errorf("the store changed: %+v, want %+v", after, before)
			}
			if live := s.liveSessions(t, account); live != 1 {
				t.Errorf("%d live sessions after a refused sign-out, want 1", live)
			}
			if probe := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin}); probe.StatusCode != http.StatusOK {
				t.Errorf("the session stopped working after a refused sign-out: %d", probe.StatusCode)
			}
		})
	}
}

// TestSignOutValidatesTheRequestShapeBeforeConcludingItIsDone: a malformed request
// is refused whether or not a session answers, never reported as already done.
func TestSignOutValidatesTheRequestShapeBeforeConcludingItIsDone(t *testing.T) {
	s := newSurface(t)
	address, account := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", in.response.StatusCode)
	}

	// No cookie at all.
	res := s.send(t, request{
		method: http.MethodDelete, target: sessionRoute,
		origin: publicOrigin, fetchSite: "same-origin", contentType: "text/plain",
	})
	if res.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("a shapeless sign-out without a cookie returned %d, want 415", res.StatusCode)
	}

	// A session that has already been revoked.
	if err := s.store.RevokeSession(context.Background(), sessionIDOf(t, s, account), s.clock.Now()); err != nil {
		t.Fatalf("revoking failed: %v", err)
	}
	res = s.send(t, request{
		method: http.MethodDelete, target: sessionRoute,
		cookie: in.token, csrf: in.csrf, origin: publicOrigin, fetchSite: "same-origin", contentType: "text/plain",
	})
	if res.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("a shapeless sign-out on a revoked session returned %d, want 415", res.StatusCode)
	}

	// The correctly shaped request still succeeds on that finished session.
	res = s.send(t, request{
		method: http.MethodDelete, target: sessionRoute,
		cookie: in.token, csrf: in.csrf, origin: publicOrigin, fetchSite: "same-origin", contentType: "application/json"})
	if res.StatusCode != http.StatusNoContent {
		t.Errorf("a well-shaped sign-out returned %d, want 204", res.StatusCode)
	}
}

// readSessionLedger counts what a refused sign-out must leave untouched.
func readSessionLedger(t *testing.T, s *surface) [2]int {
	t.Helper()
	var sessions, revoked int
	if err := s.pool.QueryRow(context.Background(), `
		SELECT (SELECT count(*) FROM account_sessions WHERE revoked_at IS NOT NULL),
		       (SELECT count(*) FROM account_security_events WHERE kind = 'session_revoked')`).
		Scan(&sessions, &revoked); err != nil {
		t.Fatalf("reading the ledger failed: %v", err)
	}
	return [2]int{sessions, revoked}
}
