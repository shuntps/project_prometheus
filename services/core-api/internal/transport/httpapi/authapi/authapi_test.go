package authapi_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/application"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/browser"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi/authapi"
)

var errNotReached = errors.New("the mounting test reached persistence")

// inert satisfies the ports the use cases need without standing in for a store.
type inert struct{}

func (inert) CredentialByEmail(context.Context, iam.EmailAddress) (application.Credential, bool, error) {
	return application.Credential{}, false, errNotReached
}

func (inert) ResolveSession(context.Context, session.Token, time.Time) (application.Resolved, bool, error) {
	return application.Resolved{}, false, errNotReached
}

func (inert) ReplaceSession(context.Context, *session.ID, session.Session, time.Time) (application.Resolved, bool, error) {
	return application.Resolved{}, false, errNotReached
}

func (inert) RevokeSession(context.Context, session.ID, time.Time) (bool, error) {
	return false, errNotReached
}

func (inert) RecordActivity(context.Context, session.ID, time.Time, session.Lifetimes) (bool, error) {
	return false, errNotReached
}

type verifier struct{}

func (verifier) Hash(string) (password.Encoded, error) { return password.NewEncoded("x"), nil }

func (verifier) Verify(password.Encoded, string) (bool, error) { return false, errNotReached }

type limiter struct{}

func (limiter) Allow(string, string, time.Time) bool { return true }

func completeOptions(t *testing.T) authapi.Options {
	t.Helper()
	lifetimes := session.Lifetimes{Absolute: time.Hour, Idle: 30 * time.Minute, ActivityInterval: time.Minute}
	signIn, err := application.NewSignIn(application.SignInOptions{
		Repository: inert{}, Hasher: verifier{}, Limiter: limiter{}, Lifetimes: lifetimes,
	})
	if err != nil {
		t.Fatalf("building the sign-in use case failed: %v", err)
	}
	sessions, err := application.NewSessions(application.SessionsOptions{Repository: inert{}, Lifetimes: lifetimes})
	if err != nil {
		t.Fatalf("building the session use cases failed: %v", err)
	}
	origin, err := browser.ParseOrigin("https://app.example.com")
	if err != nil {
		t.Fatalf("parsing the origin failed: %v", err)
	}
	return authapi.Options{SignIn: signIn, Sessions: sessions, Origin: origin}
}

// TestAPartialSurfaceIsRefusedAtRegistration keeps a subset of the defences from
// being served: every part is required, and a missing one mounts no route.
func TestAPartialSurfaceIsRefusedAtRegistration(t *testing.T) {
	complete := completeOptions(t)
	for name, breakIt := range map[string]func(*authapi.Options){
		"no sign-in":  func(o *authapi.Options) { o.SignIn = nil },
		"no sessions": func(o *authapi.Options) { o.Sessions = nil },
		"no origin":   func(o *authapi.Options) { o.Origin = browser.Origin{} },
	} {
		t.Run(name, func(t *testing.T) {
			opts := complete
			breakIt(&opts)
			app := fiber.New()
			if err := authapi.Register(app, opts); err == nil {
				t.Fatal("a partial surface was mounted")
			}
			res, testErr := app.Test(httptest.NewRequest(http.MethodPost, "/api/v1/auth/session", nil),
				fiber.TestConfig{Timeout: 5 * time.Second})
			if testErr != nil {
				t.Fatalf("the request failed: %v", testErr)
			}
			defer res.Body.Close()
			if res.StatusCode != http.StatusNotFound {
				t.Errorf("a route answered %d after a refused registration", res.StatusCode)
			}
		})
	}

	app := fiber.New()
	if err := authapi.Register(app, complete); err != nil {
		t.Fatalf("a complete surface was refused: %v", err)
	}
}

// TestNoStoreForbidsCachingOnEveryAnswer keeps an authentication answer out of a
// browser, proxy or CDN cache, including one decided before any handler ran.
func TestNoStoreForbidsCachingOnEveryAnswer(t *testing.T) {
	app := fiber.New()
	app.Use(authapi.PathPrefix, authapi.NoStore)
	app.Get(authapi.PathPrefix+"/probe", func(c fiber.Ctx) error { return c.SendString("ok") })
	app.Get("/elsewhere", func(c fiber.Ctx) error { return c.SendString("ok") })

	for path, want := range map[string]string{authapi.PathPrefix + "/probe": "no-store", "/elsewhere": ""} {
		res, err := app.Test(httptest.NewRequest(http.MethodGet, path, nil), fiber.TestConfig{Timeout: 5 * time.Second})
		if err != nil {
			t.Fatalf("the request failed: %v", err)
		}
		defer res.Body.Close()
		if got := res.Header.Get(fiber.HeaderCacheControl); got != want {
			t.Errorf("%s answered Cache-Control %q, want %q", path, got, want)
		}
	}
}
