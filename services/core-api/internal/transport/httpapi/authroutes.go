package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/browser"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/authstore"
	"github.com/shuntps/project_prometheus/services/core-api/internal/ratelimit"
)

// Route patterns of the public authentication surface. They are the paths the
// browser uses: the edge routes /api here without rewriting, so none is rebuilt.
const (
	authPathPrefix      = "/api/v1/auth"
	sessionPath         = "/api/v1/auth/session"
	broadcastAccessPath = "/api/v1/auth/broadcast-access"
	activityPath        = "/api/v1/auth/session/activity"
)

// AuthStore is the persistence the authentication surface needs. It is stated
// here so the transport depends on the operations it calls and nothing wider.
type AuthStore interface {
	CredentialByEmail(ctx context.Context, email auth.EmailAddress) (authstore.Credential, error)
	ReplaceSession(ctx context.Context, previous *auth.SessionID, successor session.Session, now time.Time) (authstore.Resolved, error)
	Resolve(ctx context.Context, token session.Token, now time.Time) (authstore.Resolved, error)
	RevokeSession(ctx context.Context, id auth.SessionID, now time.Time) error
	RecordActivity(ctx context.Context, id auth.SessionID, now time.Time, lifetimes session.Lifetimes) (bool, error)
}

// PasswordVerifier is the credential check the sign-in path performs. Stating it
// here lets a test count the work and show both paths perform the same.
type PasswordVerifier interface {
	Hash(plaintext string) (password.Encoded, error)
	Verify(encoded password.Encoded, plaintext string) (rehash bool, err error)
}

// AuthOptions carries everything the authentication surface runs on. Every field
// is required: the router refuses to mount the surface on a partial set.
type AuthOptions struct {
	Store     AuthStore
	Hasher    PasswordVerifier
	Lifetimes session.Lifetimes
	Origin    browser.Origin
	Limiter   *ratelimit.AuthLimiter
	Now       func() time.Time
	Random    io.Reader
}

type authSurface struct {
	store     AuthStore
	hasher    PasswordVerifier
	lifetimes session.Lifetimes
	origin    browser.Origin
	limiter   *ratelimit.AuthLimiter
	now       func() time.Time
	random    io.Reader
	// decoy carries the configured parameters, so verifying against it costs the
	// same memory and passes as verifying a real credential.
	decoy password.Encoded
}

func newAuthSurface(opts AuthOptions) (*authSurface, error) {
	switch {
	case opts.Store == nil:
		return nil, errors.New("authentication surface requires a store")
	case opts.Hasher == nil:
		return nil, errors.New("authentication surface requires a password hasher")
	case opts.Limiter == nil:
		return nil, errors.New("authentication surface requires an attempt limiter")
	case opts.Origin.IsZero():
		return nil, errors.New("authentication surface requires the public origin")
	}
	if err := opts.Lifetimes.Validate(); err != nil {
		return nil, err
	}

	random := opts.Random
	if random == nil {
		random = rand.Reader
	}
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}

	// The decoy is hashed from a value drawn here and never stored, so no
	// deployment shares it and nothing can be matched against it.
	seed := make([]byte, 32)
	if _, err := io.ReadFull(random, seed); err != nil {
		return nil, errors.New("authentication surface could not prepare its verification path")
	}
	decoy, err := opts.Hasher.Hash(base64.RawURLEncoding.EncodeToString(seed))
	if err != nil {
		return nil, err
	}

	return &authSurface{
		store: opts.Store, hasher: opts.Hasher, lifetimes: opts.Lifetimes,
		origin: opts.Origin, limiter: opts.Limiter, now: now, random: random, decoy: decoy,
	}, nil
}

func (s *authSurface) register(app *fiber.App) {
	app.Post(sessionPath, s.signIn)
	app.Delete(sessionPath, s.signOut)
	app.Get(sessionPath, s.requirePermission(auth.PermissionOwnSessionRead, s.currentSession))
	app.Get(broadcastAccessPath, s.requirePermission(auth.PermissionStreamBroadcast, grantedHandler))
	app.Post(activityPath, s.recordActivity)
}

// noStore is mounted ahead of the abuse limiter, so a refusal decided before any
// handler carries it too, and scoped to this prefix so nothing else inherits it.
func noStore(c fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "no-store")
	return c.Next()
}
