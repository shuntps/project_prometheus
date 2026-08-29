package integration_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/browser"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
	"github.com/shuntps/project_prometheus/services/core-api/internal/ratelimit"
	"github.com/shuntps/project_prometheus/services/core-api/internal/testsupport/httpfixture"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi/authapi"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi/healthapi"
)

// TestThePartialAuthenticationSurfaceIsRefused keeps the service from starting
// with a surface missing any of the parts a defence depends on.
func TestThePartialAuthenticationSurfaceIsRefused(t *testing.T) {
	origin, err := browser.ParseOrigin(publicOrigin)
	if err != nil {
		t.Fatalf("parsing the origin failed: %v", err)
	}
	hasher, err := password.NewHasher(
		password.Params{MemoryKiB: password.FloorMemoryKiB, Iterations: password.FloorIterations, Lanes: password.FloorLanes},
		password.Policy{MinCodePoints: password.SingleFactorMinimum}, nil)
	if err != nil {
		t.Fatalf("building the hasher failed: %v", err)
	}
	limiter, err := ratelimit.NewAuthLimiter(ratelimit.AuthPolicy{
		ClientAttempts: 10, IdentityAttempts: 5, Window: time.Minute, Capacity: ratelimit.MinAuthCapacity,
	}, nil)
	if err != nil {
		t.Fatalf("building the limiter failed: %v", err)
	}
	lifetimes := session.Lifetimes{Absolute: time.Hour, Idle: 30 * time.Minute, ActivityInterval: time.Minute}
	repository := inertRepository{}
	signIn, err := auth.NewSignIn(auth.SignInOptions{
		Repository: repository, Hasher: hasher, Limiter: limiter, Lifetimes: lifetimes,
	})
	if err != nil {
		t.Fatalf("building the sign-in use case failed: %v", err)
	}
	sessions, err := auth.NewSessions(auth.SessionsOptions{
		Repository: repository, Lifetimes: lifetimes,
	})
	if err != nil {
		t.Fatalf("building the session use cases failed: %v", err)
	}
	complete := authapi.Options{SignIn: signIn, Sessions: sessions, Origin: origin}

	cases := map[string]func(*authapi.Options){
		"no sign-in":  func(o *authapi.Options) { o.SignIn = nil },
		"no sessions": func(o *authapi.Options) { o.Sessions = nil },
		"no origin":   func(o *authapi.Options) { o.Origin = browser.Origin{} },
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			opts := complete
			breakIt(&opts)
			app, err := httpapi.New(mountedWith(&opts))
			if err == nil || app != nil {
				t.Fatal("a partial authentication surface was mounted")
			}
		})
	}

	app, err := httpapi.New(mountedWith(&complete))
	if err != nil || app == nil {
		t.Fatalf("a complete surface was refused: %v", err)
	}
}

// TestEveryAuthenticationResponseForbidsCaching covers the success and the refusal
// paths alike, so no branch relies on a browser, proxy or CDN default.
func TestEveryAuthenticationResponseForbidsCaching(t *testing.T) {
	s := newSurface(t)
	address, _ := s.account(t, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", in.response.StatusCode)
	}
	if got := in.response.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("the sign-in response declared %q, want no-store", got)
	}

	cases := []struct {
		name    string
		request request
	}{
		{"session read", request{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin}},
		{"authorisation refused", request{method: http.MethodGet, target: broadcastRoute, cookie: in.token, origin: publicOrigin}},
		{"unauthenticated read", request{method: http.MethodGet, target: sessionRoute, origin: publicOrigin}},
		{"cross-site refusal", request{method: http.MethodPost, target: sessionRoute, body: map[string]string{"email": address, "password": probePassword}, origin: foreignOrigin}},
		{"wrong content type", request{method: http.MethodPost, target: sessionRoute, body: map[string]string{"email": address}, origin: publicOrigin, noJSON: true}},
		{"malformed body", request{method: http.MethodPost, target: sessionRoute, body: "not an object", origin: publicOrigin, fetchSite: "same-origin"}},
		{"missing CSRF token", request{method: http.MethodDelete, target: sessionRoute, cookie: in.token, origin: publicOrigin, fetchSite: "same-origin", contentType: "application/json"}},
		{"unknown route on the surface", request{method: http.MethodGet, target: "/api/v1/auth/nothing-here", origin: publicOrigin}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := s.send(t, c.request)
			if got := res.Header.Get("Cache-Control"); got != "no-store" {
				t.Errorf("the %s response (%d) declared %q, want no-store", c.name, res.StatusCode, got)
			}
		})
	}

	// A server error must carry it too, since the branch is written by the shared
	// error handler rather than by the surface.
	s.faults.resolve = func() error { return storeFailure() }
	broken := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin})
	s.faults.resolve = nil
	if broken.StatusCode != http.StatusInternalServerError {
		t.Fatalf("the failing read returned %d, want 500", broken.StatusCode)
	}
	if got := broken.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("the server-error response declared %q, want no-store", got)
	}

	// Sign-out ends with the cookie being cleared, so it is checked last.
	out := s.send(t, request{
		method: http.MethodDelete, target: sessionRoute,
		cookie: in.token, csrf: in.csrf, origin: publicOrigin, fetchSite: "same-origin", contentType: "application/json"})
	if out.StatusCode != http.StatusNoContent {
		t.Fatalf("sign-out returned %d", out.StatusCode)
	}
	if got := out.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("the sign-out response declared %q, want no-store", got)
	}
}

// TestAGlobalRefusalOnTheSurfaceStillForbidsCaching covers the branch no handler
// reaches: the shared limiter answers 429 before the surface ever runs.
func TestAGlobalRefusalOnTheSurfaceStillForbidsCaching(t *testing.T) {
	const globalMax = 3
	s := newSurface(t, func(c *authConfig) {
		// The specialised limiter keeps plenty of room, so the refusal below can
		// only come from the shared one.
		limiter, err := ratelimit.NewAuthLimiter(ratelimit.AuthPolicy{
			ClientAttempts: ratelimit.MaxAuthAttempts, IdentityAttempts: ratelimit.MaxAuthAttempts,
			Window: 15 * time.Minute, Capacity: ratelimit.MinAuthCapacity,
		}, nil)
		if err != nil {
			t.Fatalf("building the limiter failed: %v", err)
		}
		c.limiter = limiter
		c.global = httpfixture.DirectPolicy(globalMax)
	})

	var refused *http.Response
	for attempt := 1; attempt <= globalMax+3; attempt++ {
		res := s.send(t, request{method: http.MethodGet, target: sessionRoute, origin: publicOrigin})
		if res.StatusCode == http.StatusTooManyRequests {
			refused = res
			break
		}
	}
	if refused == nil {
		t.Fatalf("the shared limiter never refused within %d attempts", globalMax+3)
	}
	if got := refused.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("the shared limiter's 429 declared %q, want no-store", got)
	}
}

// inertRepository satisfies the ports this test must supply without standing in
// for PostgreSQL. Reaching it would mean the refusal under test stopped working.
type inertRepository struct{}

func (inertRepository) CredentialByEmail(context.Context, iam.EmailAddress) (auth.Credential, bool, error) {
	return auth.Credential{}, false, errUnexpectedRepositoryCall
}

func (inertRepository) ResolveSession(context.Context, session.Token, time.Time) (auth.Resolved, bool, error) {
	return auth.Resolved{}, false, errUnexpectedRepositoryCall
}

func (inertRepository) ReplaceSession(context.Context, *session.ID, session.Session, time.Time) (auth.Resolved, bool, error) {
	return auth.Resolved{}, false, errUnexpectedRepositoryCall
}

func (inertRepository) RevokeSession(context.Context, session.ID, time.Time) (bool, error) {
	return false, errUnexpectedRepositoryCall
}

func (inertRepository) RecordActivity(context.Context, session.ID, time.Time, session.Lifetimes) (bool, error) {
	return false, errUnexpectedRepositoryCall
}

var errUnexpectedRepositoryCall = errors.New("the surface policy test reached persistence")

// mountedWith supplies every dependency unrelated to the authentication surface,
// so a refusal can only come from the surface the case is actually proving.
func mountedWith(auth *authapi.Options) httpapi.Options {
	return httpapi.Options{
		Logger:       slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Readiness:    &healthapi.Readiness{},
		RateLimit:    httpfixture.DirectPolicy(100),
		Persistence:  httpfixture.NewStubStore(true),
		CheckTimeout: time.Second,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
		Auth:         auth,
	}
}
