package integration_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

// stamps reads the two deadlines a session carries, which is where every claim
// about renewal has to be checked.
func (s *surface) stamps(t *testing.T, account iam.Account) (active, idle, absolute time.Time) {
	t.Helper()
	if err := s.pool.QueryRow(context.Background(),
		`SELECT last_active_at, idle_expires_at, absolute_expires_at FROM account_sessions
		 WHERE account_id = $1 ORDER BY created_at DESC LIMIT 1`, account.ID.String()).
		Scan(&active, &idle, &absolute); err != nil {
		t.Fatalf("reading the deadlines failed: %v", err)
	}
	return active, idle, absolute
}

// TestExplicitActivityExtendsOnlyTheInactivityDeadline is the behaviour the slice
// adds: without it the shorter deadline is a second absolute one.
func TestExplicitActivityExtendsOnlyTheInactivityDeadline(t *testing.T) {
	s := newSurface(t)
	address, account := s.account(t, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", in.response.StatusCode)
	}
	_, idleBefore, absoluteBefore := s.stamps(t, account)

	s.clock.advance(10 * time.Minute)
	res := s.send(t, request{
		method: http.MethodPost, target: activityRoute,
		body: map[string]string{}, origin: publicOrigin, fetchSite: "same-origin",
		cookie: in.token, csrf: in.csrf,
	})
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("the activity signal returned %d, want 204: %s", res.StatusCode, bodyOf(t, res))
	}

	activeAfter, idleAfter, absoluteAfter := s.stamps(t, account)
	if !idleAfter.After(idleBefore) {
		t.Errorf("the inactivity deadline stayed at %s, want it moved past %s", idleAfter, idleBefore)
	}
	if !absoluteAfter.Equal(absoluteBefore) {
		t.Errorf("the absolute deadline moved from %s to %s", absoluteBefore, absoluteAfter)
	}
	if !activeAfter.Equal(s.clock.Now()) {
		t.Errorf("the activity instant is %s, want the server's own %s", activeAfter, s.clock.Now())
	}
	// The session outlives what would have been its unrenewed deadline.
	s.clock.advance(25 * time.Minute)
	if probe := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin}); probe.StatusCode != http.StatusOK {
		t.Fatalf("the renewed session expired on its old schedule: %d", probe.StatusCode)
	}
}

// TestOnlyTheExplicitSignalRenewsTheInactivityDeadline separates the renewal from
// every request that merely happens to carry the cookie.
func TestOnlyTheExplicitSignalRenewsTheInactivityDeadline(t *testing.T) {
	s := newSurface(t)
	address, account := s.account(t, iam.KindCreator, iam.StatusActive, iam.RoleViewer, iam.RoleCreator)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", in.response.StatusCode)
	}
	activeBefore, idleBefore, _ := s.stamps(t, account)
	s.clock.advance(10 * time.Minute)

	passive := []request{
		{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin},
		{method: http.MethodGet, target: broadcastRoute, cookie: in.token, origin: publicOrigin},
		// A top-level navigation, which SameSite=Lax lets carry the cookie.
		{method: http.MethodGet, target: sessionRoute, cookie: in.token},
		{method: http.MethodGet, target: sessionRoute, cookie: in.token, fetchSite: "cross-site"},
	}
	for i, r := range passive {
		if res := s.send(t, r); res.StatusCode != http.StatusOK {
			t.Fatalf("passive read %d returned %d", i, res.StatusCode)
		}
		active, idle, _ := s.stamps(t, account)
		if !active.Equal(activeBefore) || !idle.Equal(idleBefore) {
			t.Fatalf("passive read %d renewed the session: %s / %s", i, active, idle)
		}
	}
	// The explicit signal, and only it, renews.
	if res := s.send(t, request{
		method: http.MethodPost, target: activityRoute, body: map[string]string{},
		origin: publicOrigin, fetchSite: "same-origin", cookie: in.token, csrf: in.csrf,
	}); res.StatusCode != http.StatusNoContent {
		t.Fatalf("the activity signal returned %d", res.StatusCode)
	}
	_, idle, _ := s.stamps(t, account)
	if !idle.After(idleBefore) {
		t.Fatal("the explicit signal did not renew the deadline")
	}
}

// TestTheActivitySignalIsGuardedLikeEveryOtherOperationWithEffect requires the
// same context, shape and token checks a sign-out passes.
func TestTheActivitySignalIsGuardedLikeEveryOtherOperationWithEffect(t *testing.T) {
	s := newSurface(t)
	address, account := s.account(t, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", in.response.StatusCode)
	}
	forged, err := session.NewCSRFToken(nil)
	if err != nil {
		t.Fatalf("drawing failed: %v", err)
	}
	base := request{
		method: http.MethodPost, target: activityRoute, body: map[string]string{},
		origin: publicOrigin, fetchSite: "same-origin", cookie: in.token, csrf: in.csrf,
	}
	refusals := map[string]struct {
		mutate func(*request)
		want   int
	}{
		"foreign origin":       {func(r *request) { r.origin = foreignOrigin }, http.StatusForbidden},
		"absent origin":        {func(r *request) { r.origin = "" }, http.StatusForbidden},
		"cross-site metadata":  {func(r *request) { r.fetchSite = "cross-site" }, http.StatusForbidden},
		"same-site metadata":   {func(r *request) { r.fetchSite = "same-site" }, http.StatusForbidden},
		"absent content type":  {func(r *request) { r.noContentType = true }, http.StatusUnsupportedMediaType},
		"form content type":    {func(r *request) { r.contentType = "application/x-www-form-urlencoded" }, http.StatusUnsupportedMediaType},
		"text content type":    {func(r *request) { r.contentType = "text/plain" }, http.StatusUnsupportedMediaType},
		"absent CSRF token":    {func(r *request) { r.csrf = "" }, http.StatusForbidden},
		"forged CSRF token":    {func(r *request) { r.csrf = forged.Reveal() }, http.StatusForbidden},
		"malformed CSRF token": {func(r *request) { r.csrf = "not-a-token" }, http.StatusForbidden},
		"no session cookie":    {func(r *request) { r.cookie = "" }, http.StatusUnauthorized},
		"unknown session":      {func(r *request) { r.cookie = drawnToken(t) }, http.StatusUnauthorized},
	}
	for name, c := range refusals {
		t.Run(name, func(t *testing.T) {
			activeBefore, idleBefore, _ := s.stamps(t, account)
			r := base
			c.mutate(&r)
			res := s.send(t, r)
			if res.StatusCode != c.want {
				t.Fatalf("returned %d, want %d: %s", res.StatusCode, c.want, bodyOf(t, res))
			}
			if got := res.Header.Get("Cache-Control"); got != "no-store" {
				t.Errorf("the refusal declared %q, want no-store", got)
			}
			active, idle, _ := s.stamps(t, account)
			if !active.Equal(activeBefore) || !idle.Equal(idleBefore) {
				t.Errorf("a refused signal renewed the session: %s / %s", active, idle)
			}
		})
	}
	// The well-formed request still works, so the refusals above were the checks.
	s.clock.advance(2 * time.Minute)
	if res := s.send(t, base); res.StatusCode != http.StatusNoContent {
		t.Fatalf("the well-formed signal returned %d", res.StatusCode)
	}
}

func drawnToken(t *testing.T) string {
	t.Helper()
	token, err := session.NewToken(nil)
	if err != nil {
		t.Fatalf("drawing failed: %v", err)
	}
	return token.Reveal()
}

// TestTheActivitySignalNeitherReplacesTheSessionNorLeaks keeps the operation to
// the one deadline it is for, and keeps its answers empty of anything sensitive.
func TestTheActivitySignalNeitherReplacesTheSessionNorLeaks(t *testing.T) {
	s := newSurface(t)
	address, account := s.account(t, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", in.response.StatusCode)
	}
	var sessionsBefore int
	if err := s.pool.QueryRow(context.Background(), `SELECT count(*) FROM account_sessions`).Scan(&sessionsBefore); err != nil {
		t.Fatalf("counting failed: %v", err)
	}

	s.clock.advance(5 * time.Minute)
	res := s.send(t, request{
		method: http.MethodPost, target: activityRoute, body: map[string]string{},
		origin: publicOrigin, fetchSite: "same-origin", cookie: in.token, csrf: in.csrf,
	})
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("the signal returned %d", res.StatusCode)
	}
	if sessionCookie(res) != nil {
		t.Error("the signal replaced or refreshed the session cookie")
	}
	if body := bodyOf(t, res); body != "" {
		t.Errorf("the signal answered with a body: %q", body)
	}
	var sessionsAfter int
	if err := s.pool.QueryRow(context.Background(), `SELECT count(*) FROM account_sessions`).Scan(&sessionsAfter); err != nil {
		t.Fatalf("counting failed: %v", err)
	}
	if sessionsAfter != sessionsBefore {
		t.Errorf("%d sessions after the signal, want the %d from before", sessionsAfter, sessionsBefore)
	}
	// The same token still resolves: nothing was rotated.
	if probe := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin}); probe.StatusCode != http.StatusOK {
		t.Fatalf("the token stopped working after the signal: %d", probe.StatusCode)
	}

	forbidden := []string{
		"suspended", "account_sessions", "SQLSTATE", "42P01", driverDetail,
		address, account.ID.String(), probePassword, in.token, in.csrf,
	}
	for _, record := range decodeRecords(t, s.logs.String()) {
		for _, value := range record.values {
			for _, secret := range forbidden {
				if strings.Contains(value, secret) {
					t.Errorf("a record carried %q in %q", secret, value)
				}
			}
		}
	}
}

// TestAStorageFailureOnTheActivitySignalIsNotAnAbsentSession keeps the two apart
// on this path as on every other.
func TestAStorageFailureOnTheActivitySignalIsNotAnAbsentSession(t *testing.T) {
	s := newSurface(t)
	address, account := s.account(t, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", in.response.StatusCode)
	}
	activeBefore, idleBefore, _ := s.stamps(t, account)
	s.clock.advance(5 * time.Minute)

	signal := request{
		method: http.MethodPost, target: activityRoute, body: map[string]string{},
		origin: publicOrigin, fetchSite: "same-origin", cookie: in.token, csrf: in.csrf,
	}
	s.faults.activity = func() error { return storeFailure() }
	res := s.send(t, signal)
	s.faults.activity = nil
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("a failed write returned %d, want 500: %s", res.StatusCode, bodyOf(t, res))
	}
	active, idle, _ := s.stamps(t, account)
	if !active.Equal(activeBefore) || !idle.Equal(idleBefore) {
		t.Errorf("a failed write changed the stamps to %s / %s", active, idle)
	}
	// The session is untouched and the signal works once the store answers again.
	if res := s.send(t, signal); res.StatusCode != http.StatusNoContent {
		t.Fatalf("the signal returned %d after the store recovered", res.StatusCode)
	}
}

// TestTheActivitySignalWritesAtMostOncePerInterval proves the bound through the
// HTTP boundary, by observing the stored instant rather than by timing.
func TestTheActivitySignalWritesAtMostOncePerInterval(t *testing.T) {
	s := newSurface(t)
	address, account := s.account(t, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", in.response.StatusCode)
	}
	signal := request{
		method: http.MethodPost, target: activityRoute, body: map[string]string{},
		origin: publicOrigin, fetchSite: "same-origin", cookie: in.token, csrf: in.csrf,
	}

	s.clock.advance(2 * time.Minute)
	if res := s.send(t, signal); res.StatusCode != http.StatusNoContent {
		t.Fatalf("the first signal returned %d", res.StatusCode)
	}
	activeAfterFirst, idleAfterFirst, _ := s.stamps(t, account)

	// A burst inside the same interval is accepted but persists nothing.
	for i := 0; i < 25; i++ {
		if res := s.send(t, signal); res.StatusCode != http.StatusNoContent {
			t.Fatalf("burst signal %d returned %d", i, res.StatusCode)
		}
	}
	active, idle, _ := s.stamps(t, account)
	if !active.Equal(activeAfterFirst) || !idle.Equal(idleAfterFirst) {
		t.Fatalf("a burst inside one interval wrote again: %s / %s", active, idle)
	}

	// Past the interval, one write happens again.
	s.clock.advance(2 * time.Minute)
	if res := s.send(t, signal); res.StatusCode != http.StatusNoContent {
		t.Fatalf("the later signal returned %d", res.StatusCode)
	}
	activeLater, idleLater, _ := s.stamps(t, account)
	if !activeLater.After(activeAfterFirst) || !idleLater.After(idleAfterFirst) {
		t.Fatalf("the deadline did not move past the interval: %s / %s", activeLater, idleLater)
	}
}
