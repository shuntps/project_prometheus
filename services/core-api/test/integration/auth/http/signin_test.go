package integration_test

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

// requestIDPattern normalises the one field a uniform answer is allowed to vary.
var requestIDPattern = regexp.MustCompile(`"request_id":"[^"]*"`)

func TestASignedInAccountReceivesASessionAndItsCSRFToken(t *testing.T) {
	s := newSurface(t)
	address, account := s.account(t, iam.KindViewer, iam.StatusActive, iam.RoleViewer)

	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d: %s", in.response.StatusCode, in.body)
	}
	if in.token == "" {
		t.Fatal("no session cookie was set")
	}
	if in.csrf == "" {
		t.Fatal("no CSRF token was handed back")
	}
	if in.view["account_id"] != account.ID.String() {
		t.Errorf("the response names %v, want %s", in.view["account_id"], account.ID)
	}
	if in.view["surface"] != string(iam.SurfacePublic) {
		t.Errorf("the session opened on surface %v", in.view["surface"])
	}

	// The session is immediately usable and reports the same authority.
	res := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("resolving the session returned %d: %s", res.StatusCode, bodyOf(t, res))
	}
}

// TestEveryRefusedSignInIsIndistinguishable: an unknown address, a wrong password
// and an unusable account must all leave by exactly the same door.
func TestEveryRefusedSignInIsIndistinguishable(t *testing.T) {
	s := newSurface(t)
	known, _ := s.account(t, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
	pending, _ := s.account(t, iam.KindViewer, iam.StatusPending, iam.RoleViewer)
	suspended, _ := s.account(t, iam.KindViewer, iam.StatusSuspended, iam.RoleViewer)
	closed, _ := s.account(t, iam.KindViewer, iam.StatusClosed, iam.RoleViewer)
	operator, _ := s.account(t, iam.KindOperator, iam.StatusActive, iam.RoleOperatorSupport)

	cases := map[string][2]string{
		"unknown address":   {"nobody-here@example.com", probePassword},
		"wrong password":    {known, "wrong-" + probePassword},
		"pending account":   {pending, probePassword},
		"suspended account": {suspended, probePassword},
		"closed account":    {closed, probePassword},
		"operator account":  {operator, probePassword},
		"malformed address": {"not-an-address", probePassword},
		"empty address":     {"", probePassword},
		"empty password":    {known, ""},
	}

	var seen []string
	for name, pair := range cases {
		in := s.signIn(t, pair[0], pair[1])
		if in.response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s returned %d, want 401: %s", name, in.response.StatusCode, in.body)
		}
		if sessionCookie(in.response) != nil {
			t.Fatalf("%s set a session cookie", name)
		}
		// The request identifier differs per call and is the only field allowed to.
		normalised := requestIDPattern.ReplaceAllString(in.body, `"request_id":"x"`)
		seen = append(seen, name+"\x00"+normalised)
	}
	first := strings.SplitN(seen[0], "\x00", 2)[1]
	for _, entry := range seen {
		name, body, _ := strings.Cut(entry, "\x00")
		if body != first {
			t.Errorf("%s answered %q while another cause answered %q", name, body, first)
		}
	}
}

// TestAnOperatorAccountCannotOpenThePublicSurface keeps the operator journey
// unreachable through the public one, whatever the credential is.
func TestAnOperatorAccountCannotOpenThePublicSurface(t *testing.T) {
	s := newSurface(t)
	operator, account := s.account(t, iam.KindOperator, iam.StatusActive, iam.RoleOperatorSupport)

	in := s.signIn(t, operator, probePassword)
	if in.response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("an operator signed in through the public surface: %d %s", in.response.StatusCode, in.body)
	}
	var sessions int
	if err := s.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM account_sessions WHERE account_id = $1`, account.ID.String()).Scan(&sessions); err != nil {
		t.Fatalf("counting sessions failed: %v", err)
	}
	if sessions != 0 {
		t.Fatalf("%d session rows were written for a refused operator", sessions)
	}
}
