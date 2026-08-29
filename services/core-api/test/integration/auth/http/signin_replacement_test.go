package integration_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

func (s *surface) allSessions(t *testing.T) int {
	t.Helper()
	var total int
	if err := s.pool.QueryRow(context.Background(), `SELECT count(*) FROM account_sessions`).Scan(&total); err != nil {
		t.Fatalf("counting sessions failed: %v", err)
	}
	return total
}

// TestAuthenticatingEndsTheSessionTheRequestArrivedWith keeps a second live token
// from surviving a sign-in, which a value planted beforehand would rely on.
func TestAuthenticatingEndsTheSessionTheRequestArrivedWith(t *testing.T) {
	s := newSurface(t)
	address, account := s.account(t, iam.KindViewer, iam.StatusActive, iam.RoleViewer)

	first := s.signIn(t, address, probePassword)
	if first.response.StatusCode != http.StatusCreated {
		t.Fatalf("the first sign-in returned %d", first.response.StatusCode)
	}

	// Sign in again while presenting the first cookie.
	res := s.send(t, request{
		method: http.MethodPost, target: sessionRoute,
		body:   map[string]string{"email": address, "password": probePassword},
		origin: publicOrigin, fetchSite: "same-origin", cookie: first.token,
	})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("the second sign-in returned %d: %s", res.StatusCode, bodyOf(t, res))
	}
	second := sessionCookie(res)
	if second == nil || second.Value == "" {
		t.Fatal("the second sign-in issued no session")
	}
	if second.Value == first.token {
		t.Fatal("the second sign-in reused the presented token")
	}

	// The presented token is finished; the new one works.
	if probe := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: first.token, origin: publicOrigin}); probe.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the presented session survived the sign-in: %d", probe.StatusCode)
	}
	if probe := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: second.Value, origin: publicOrigin}); probe.StatusCode != http.StatusOK {
		t.Fatalf("the new session was not usable: %d", probe.StatusCode)
	}

	var live int
	if err := s.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM account_sessions WHERE account_id = $1 AND revoked_at IS NULL AND rotated_to IS NULL`,
		account.ID.String()).Scan(&live); err != nil {
		t.Fatalf("counting sessions failed: %v", err)
	}
	if live != 1 {
		t.Fatalf("%d sessions are live after re-authentication, want exactly 1", live)
	}

	// A refused sign-in leaves the presented session alone.
	current := second.Value
	failed := s.send(t, request{
		method: http.MethodPost, target: sessionRoute,
		body:   map[string]string{"email": address, "password": "wrong-" + probePassword},
		origin: publicOrigin, fetchSite: "same-origin", cookie: current,
	})
	if failed.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the refused sign-in returned %d", failed.StatusCode)
	}
	if probe := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: current, origin: publicOrigin}); probe.StatusCode != http.StatusOK {
		t.Fatalf("a refused sign-in ended the existing session: %d", probe.StatusCode)
	}
}

// TestSessionReplacementIsAllOrNothing: under any storage failure the presented
// session stays usable with no replacement, or exactly one replaces it.
func TestSessionReplacementIsAllOrNothing(t *testing.T) {
	failures := map[string]func(*surface){
		"the presented session cannot be resolved": func(s *surface) { s.faults.resolve = func() error { return storeFailure() } },
		"the replacement cannot be written":        func(s *surface) { s.faults.replace = func() error { return storeFailure() } },
	}
	for name, breakIt := range failures {
		t.Run(name, func(t *testing.T) {
			s := newSurface(t)
			address, account := s.account(t, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
			first := s.signIn(t, address, probePassword)
			if first.response.StatusCode != http.StatusCreated {
				t.Fatalf("the first sign-in returned %d", first.response.StatusCode)
			}
			before := s.allSessions(t)

			breakIt(s)
			res := s.send(t, request{
				method: http.MethodPost, target: sessionRoute,
				body:   map[string]string{"email": address, "password": probePassword},
				origin: publicOrigin, fetchSite: "same-origin", cookie: first.token,
			})
			s.faults.resolve, s.faults.replace = nil, nil

			if res.StatusCode != http.StatusInternalServerError {
				t.Fatalf("the failed sign-in returned %d, want 500", res.StatusCode)
			}
			if sessionCookie(res) != nil {
				t.Error("a failed sign-in set a session cookie")
			}
			if after := s.allSessions(t); after != before {
				t.Errorf("%d session rows exist, want the %d from before the failure", after, before)
			}
			if live := s.liveSessions(t, account); live != 1 {
				t.Fatalf("%d live sessions after the failure, want exactly the original", live)
			}
			if probe := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: first.token, origin: publicOrigin}); probe.StatusCode != http.StatusOK {
				t.Errorf("the presented session stopped working after a failure that changed nothing: %d", probe.StatusCode)
			}
		})
	}

	t.Run("a successful replacement leaves exactly one live session", func(t *testing.T) {
		s := newSurface(t)
		address, account := s.account(t, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
		first := s.signIn(t, address, probePassword)
		if first.response.StatusCode != http.StatusCreated {
			t.Fatalf("the first sign-in returned %d", first.response.StatusCode)
		}
		res := s.send(t, request{
			method: http.MethodPost, target: sessionRoute,
			body:   map[string]string{"email": address, "password": probePassword},
			origin: publicOrigin, fetchSite: "same-origin", cookie: first.token,
		})
		if res.StatusCode != http.StatusCreated {
			t.Fatalf("the second sign-in returned %d", res.StatusCode)
		}
		if live := s.liveSessions(t, account); live != 1 {
			t.Fatalf("%d live sessions after a successful replacement, want 1", live)
		}
		if probe := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: first.token, origin: publicOrigin}); probe.StatusCode != http.StatusUnauthorized {
			t.Errorf("the replaced session still worked: %d", probe.StatusCode)
		}
		if probe := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: sessionCookie(res).Value, origin: publicOrigin}); probe.StatusCode != http.StatusOK {
			t.Errorf("the replacement was not usable: %d", probe.StatusCode)
		}
	})

	// The presented session may belong to somebody else entirely: it is still
	// ended, and the account that authenticated gets exactly one session.
	t.Run("the presented session belongs to another account", func(t *testing.T) {
		s := newSurface(t)
		otherAddress, otherAccount := s.account(t, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
		address, account := s.account(t, iam.KindViewer, iam.StatusActive, iam.RoleViewer)

		other := s.signIn(t, otherAddress, probePassword)
		if other.response.StatusCode != http.StatusCreated {
			t.Fatalf("the other account could not sign in: %d", other.response.StatusCode)
		}
		res := s.send(t, request{
			method: http.MethodPost, target: sessionRoute,
			body:   map[string]string{"email": address, "password": probePassword},
			origin: publicOrigin, fetchSite: "same-origin", cookie: other.token,
		})
		if res.StatusCode != http.StatusCreated {
			t.Fatalf("sign-in returned %d: %s", res.StatusCode, bodyOf(t, res))
		}
		if live := s.liveSessions(t, otherAccount); live != 0 {
			t.Errorf("%d live sessions remain for the other account, want 0", live)
		}
		if live := s.liveSessions(t, account); live != 1 {
			t.Errorf("%d live sessions for the account that authenticated, want 1", live)
		}
		if probe := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: other.token, origin: publicOrigin}); probe.StatusCode != http.StatusUnauthorized {
			t.Errorf("the other account's session survived: %d", probe.StatusCode)
		}
	})
}

// TestAnAccountSuspendedBeforeTheReplacementGetsTheOrdinaryRefusal: the account
// becomes unusable between the credential check and the transaction.
func TestAnAccountSuspendedBeforeTheReplacementGetsTheOrdinaryRefusal(t *testing.T) {
	s := newSurface(t)
	address, account := s.account(t, iam.KindViewer, iam.StatusActive, iam.RoleViewer)

	// A refusal with the wrong password gives the shape every refusal must match.
	reference := s.signIn(t, address, "wrong-"+probePassword)
	if reference.response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the reference refusal returned %d", reference.response.StatusCode)
	}

	// The suspension runs after the credential was read and verified, and before
	// the real replacement is delegated to PostgreSQL.
	var suspended bool
	s.faults.replace = func() error {
		if !suspended {
			suspended = true
			if err := s.store.Suspend(context.Background(), account.ID, s.clock.Now()); err != nil {
				t.Errorf("suspending failed: %v", err)
			}
		}
		return nil
	}
	in := s.signIn(t, address, probePassword)
	s.faults.replace = nil

	if in.response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a correct credential on a newly suspended account returned %d, want 401: %s",
			in.response.StatusCode, in.body)
	}
	normalise := func(body string) string { return requestIDPattern.ReplaceAllString(body, `"request_id":"x"`) }
	if normalise(in.body) != normalise(reference.body) {
		t.Errorf("the refusal reads %q, want it identical to %q", in.body, reference.body)
	}
	if sessionCookie(in.response) != nil {
		t.Error("a refused sign-in set a session cookie")
	}

	var sessions, created int
	if err := s.pool.QueryRow(context.Background(), `
		SELECT (SELECT count(*) FROM account_sessions),
		       (SELECT count(*) FROM account_security_events WHERE kind = 'session_created')`).
		Scan(&sessions, &created); err != nil {
		t.Fatalf("reading the ledger failed: %v", err)
	}
	if sessions != 0 || created != 0 {
		t.Fatalf("%d sessions and %d creation events were written for a refused sign-in", sessions, created)
	}

	// Applied to what the service actually said. Documents are decoded and the
	// opaque correlation identifier is excluded, so no scan depends on chance.
	forbidden := []string{
		"suspended", "account_sessions", "SQLSTATE", "42P01", driverDetail,
		address, account.ID.String(), probePassword,
	}
	for _, value := range decodedValues(t, in.body) {
		for _, secret := range forbidden {
			if strings.Contains(value, secret) {
				t.Errorf("the refusal carried %q in %q", secret, value)
			}
		}
	}

	// The reference refusal wrote records of its own, which must not satisfy an
	// assertion about this one. The identifier correlates; it is never scanned.
	requestID := requestIDOf(t, in.body)
	records := decodeRecords(t, s.logs.String())
	handled := 0
	correlated := 0
	for _, record := range records {
		// Every record of this scenario is read, on its decoded values.
		for _, value := range record.values {
			for _, secret := range forbidden {
				if strings.Contains(value, secret) {
					t.Errorf("a record carried %q in %q", secret, value)
				}
			}
		}
		if record.requestID != requestID {
			continue
		}
		correlated++
		if record.fields["msg"] != "request handled" {
			continue
		}
		handled++
		if record.fields["method"] != http.MethodPost {
			t.Errorf("the record names method %v, want POST", record.fields["method"])
		}
		if record.fields["route"] != sessionRoute {
			t.Errorf("the record names route %v, want %s", record.fields["route"], sessionRoute)
		}
		if status, _ := record.fields["status"].(float64); int(status) != http.StatusUnauthorized {
			t.Errorf("the record carries status %v, want 401", record.fields["status"])
		}
	}
	if correlated == 0 {
		t.Fatalf("no record was written for request %s", requestID)
	}
	if handled != 1 {
		t.Fatalf("%d handling records exist for request %s, want exactly 1", handled, requestID)
	}
}
