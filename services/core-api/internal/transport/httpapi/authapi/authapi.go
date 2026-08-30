// Package authapi is the HTTP adapter of the authentication surface: it
// translates requests and responses, and holds no application decision.
package authapi

import (
	"errors"
	"net/http"

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

// maxRequestBytes bounds this surface's own JSON far below what the server
// accepts elsewhere: the largest useful body is one password and one address.
const maxRequestBytes = 32 << 10

// oversizedBodyMessage names the limit and nothing the request carried.
const oversizedBodyMessage = "The request body exceeds the accepted size."

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
	// Mounted once for the whole surface, after the global limiter so a refusal
	// is still counted, and before every route so none of them can skip it.
	app.Use(PathPrefix, limitRequestBody)

	app.Post(sessionPath, s.signIn)
	app.Delete(sessionPath, s.signOut)
	app.Get(sessionPath, s.requireSession(s.currentSession))
	app.Get(broadcastAccessPath, s.requirePermission(iam.PermissionStreamBroadcast, grantedHandler))
	app.Post(activityPath, s.recordActivity)
}

// limitRequestBody refuses an oversized body before anything decodes it, so no
// use case, attempt counter, query or password hash is reached by one.
func limitRequestBody(c fiber.Ctx) error {
	if len(c.Body()) > maxRequestBytes {
		return fiber.NewError(http.StatusRequestEntityTooLarge, oversizedBodyMessage)
	}
	return c.Next()
}

// NoStore is mounted ahead of the abuse limiter, so a refusal decided before any
// handler carries it too, and scoped to this prefix so nothing else inherits it.
func NoStore(c fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "no-store")
	return c.Next()
}
