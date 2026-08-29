// Package authapi is the HTTP adapter of the authentication surface: it
// translates requests and responses, and holds no application decision.
package authapi

import (
	"errors"

	"github.com/gofiber/fiber/v3"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
	"github.com/shuntps/project_prometheus/services/core-api/internal/browser"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

// Route patterns of the public authentication surface. They are the paths the
// browser uses: the edge routes /api here without rewriting, so none is rebuilt.
const (
	PathPrefix          = "/api/v1/auth"
	sessionPath         = "/api/v1/auth/session"
	broadcastAccessPath = "/api/v1/auth/broadcast-access"
	activityPath        = "/api/v1/auth/session/activity"
)

// Options carries everything the authentication surface runs on. Every field is
// required: the router refuses to mount the surface on a partial set.
type Options struct {
	SignIn   *auth.SignIn
	Sessions *auth.Sessions
	Origin   browser.Origin
}

type authSurface struct {
	signIns  *auth.SignIn
	sessions *auth.Sessions
	origin   browser.Origin
}

func newAuthSurface(opts Options) (*authSurface, error) {
	switch {
	case opts.SignIn == nil:
		return nil, errors.New("authentication surface requires the sign-in use case")
	case opts.Sessions == nil:
		return nil, errors.New("authentication surface requires the session use cases")
	case opts.Origin.IsZero():
		return nil, errors.New("authentication surface requires the public origin")
	}
	return &authSurface{signIns: opts.SignIn, sessions: opts.Sessions, origin: opts.Origin}, nil
}

// Register mounts the whole surface, refusing a partial one rather than serving
// a subset of the defences it depends on.
func Register(app *fiber.App, opts Options) error {
	surface, err := newAuthSurface(opts)
	if err != nil {
		return err
	}
	surface.register(app)
	return nil
}

func (s *authSurface) register(app *fiber.App) {
	app.Post(sessionPath, s.signIn)
	app.Delete(sessionPath, s.signOut)
	app.Get(sessionPath, s.requirePermission(iam.PermissionOwnSessionRead, s.currentSession))
	app.Get(broadcastAccessPath, s.requirePermission(iam.PermissionStreamBroadcast, grantedHandler))
	app.Post(activityPath, s.recordActivity)
}

// NoStore is mounted ahead of the abuse limiter, so a refusal decided before any
// handler carries it too, and scoped to this prefix so nothing else inherits it.
func NoStore(c fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "no-store")
	return c.Next()
}
