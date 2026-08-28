package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/authstore"
	"github.com/shuntps/project_prometheus/services/core-api/internal/ratelimit"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/web"
)

// Route patterns of the public authentication surface. They are the paths the
// browser uses: the edge routes /api here without rewriting, so none is rebuilt.
const (
	authPathPrefix      = "/api/v1/auth"
	sessionPath         = "/api/v1/auth/session"
	broadcastAccessPath = "/api/v1/auth/broadcast-access"
)

// signInFailure is the one answer every unsuccessful sign-in produces: an unknown
// address, a wrong password and an unusable account are not distinguished.
const signInFailure = "The credentials were not accepted."

// authenticationRequired is the one answer a missing or finished session gets. A
// store failure never uses it: that would assert an absence nobody established.
const authenticationRequired = "Authentication is required."

// AuthStore is the persistence the authentication surface needs. It is stated
// here so the transport depends on the operations it calls and nothing wider.
type AuthStore interface {
	CredentialByEmail(ctx context.Context, email auth.EmailAddress) (authstore.Credential, error)
	ReplaceSession(ctx context.Context, previous *auth.SessionID, successor session.Session, now time.Time) (authstore.Resolved, error)
	Resolve(ctx context.Context, token session.Token, now time.Time) (authstore.Resolved, error)
	RevokeSession(ctx context.Context, id auth.SessionID, now time.Time) error
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
	Origin    web.Origin
	Limiter   *ratelimit.AuthLimiter
	Now       func() time.Time
	Random    io.Reader
}

type authSurface struct {
	store     AuthStore
	hasher    PasswordVerifier
	lifetimes session.Lifetimes
	origin    web.Origin
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
}

// noStore is mounted ahead of the abuse limiter, so a refusal decided before any
// handler carries it too, and scoped to this prefix so nothing else inherits it.
func noStore(c fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "no-store")
	return c.Next()
}

type signInRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type sessionView struct {
	CSRFToken string    `json:"csrf_token"`
	AccountID string    `json:"account_id"`
	Kind      string    `json:"kind"`
	Surface   string    `json:"surface"`
	Roles     []string  `json:"roles"`
	ExpiresAt time.Time `json:"expires_at"`
}

// signIn authenticates a public account. Every refusal leaves by the same door,
// and the cryptographic work happens whether or not the address is registered.
func (s *authSurface) signIn(c fiber.Ctx) error {
	if err := verifyRequestOrigin(c, s.origin); err != nil {
		return err
	}
	if err := requireJSONRequest(c); err != nil {
		return err
	}

	var req signInRequest
	if err := json.Unmarshal(c.Body(), &req); err != nil {
		return fiber.NewError(http.StatusBadRequest, "The request body is not valid JSON.")
	}
	if err := password.CheckResourceLimit(req.Password); err != nil {
		return fiber.NewError(http.StatusBadRequest, "The submitted values exceed the accepted size.")
	}

	now := s.now().UTC()
	// The limiter is charged on what was presented, before any lookup, so an
	// unregistered address consumes quota exactly as a registered one does.
	if !s.limiter.Allow(clientKey(c), req.Email, now) {
		return fiber.NewError(http.StatusTooManyRequests, "Too many authentication attempts.")
	}

	credential, found, err := s.lookup(c.Context(), req.Email)
	if err != nil {
		// The verification still runs, so a failure is not distinguishable from an
		// absence by the work done, and the answer is a server error, not a verdict.
		_, _ = s.hasher.Verify(s.decoy, req.Password)
		return fiber.NewError(http.StatusInternalServerError)
	}
	if !found {
		// The decoy makes the work independent of whether the address exists.
		// Parity of work, not of duration.
		_, _ = s.hasher.Verify(s.decoy, req.Password)
		return fiber.NewError(http.StatusUnauthorized, signInFailure)
	}

	if _, err := s.hasher.Verify(credential.Password, req.Password); err != nil {
		return fiber.NewError(http.StatusUnauthorized, signInFailure)
	}
	// Usability is decided after verification so that a suspended, closed or
	// pending account is indistinguishable from a wrong password.
	if !credential.Status.CanAuthenticate() {
		return fiber.NewError(http.StatusUnauthorized, signInFailure)
	}
	// The surface is fixed here, never taken from the request: an operator account
	// cannot obtain a public session, and no caller can ask for another surface.
	if err := auth.ValidateSurface(credential.Kind, auth.SurfacePublic); err != nil {
		return fiber.NewError(http.StatusUnauthorized, signInFailure)
	}

	// The session the request carried is identified before anything is written. A
	// store failure here stops the sign-in: continuing could leave two live tokens.
	previous, err := s.presentedSession(c, now)
	if err != nil {
		return err
	}
	// The successor exists before any irreversible write, so the transaction below
	// either ends the old session and creates this one, or changes nothing.
	successor, token, err := session.Issue(credential.Account, credential.Kind, auth.SurfacePublic, s.lifetimes, now, s.random)
	if err != nil {
		return fiber.NewError(http.StatusInternalServerError)
	}
	resolved, err := s.store.ReplaceSession(c.Context(), previous, successor, now)
	switch {
	case err == nil:
	case errors.Is(err, authstore.ErrNotFound):
		// The account stopped being usable meanwhile. That is an authentication
		// outcome, not a failure, and it leaves by the same door.
		return fiber.NewError(http.StatusUnauthorized, signInFailure)
	default:
		return fiber.NewError(http.StatusInternalServerError)
	}

	setSessionCookie(c, token, successor.AbsoluteExpiresAt)
	return c.Status(http.StatusCreated).JSON(viewOf(resolved.Session, resolved.Principal))
}

// presentedSession names the session the request arrived with. A store failure is
// reported rather than ignored: proceeding blind could leave two sessions alive.
func (s *authSurface) presentedSession(c fiber.Ctx, now time.Time) (*auth.SessionID, error) {
	token, held := sessionTokenFromRequest(c)
	if !held {
		return nil, nil
	}
	resolved, err := s.store.Resolve(c.Context(), token, now)
	switch {
	case err == nil:
		id := resolved.Session.ID
		return &id, nil
	case errors.Is(err, authstore.ErrNotFound):
		return nil, nil
	default:
		return nil, fiber.NewError(http.StatusInternalServerError)
	}
}

// lookup separates three outcomes the caller must not conflate: a credential, a
// genuine absence, and a store that failed. A malformed address is an absence.
func (s *authSurface) lookup(ctx context.Context, raw string) (authstore.Credential, bool, error) {
	email, err := auth.NormaliseEmail(raw)
	if err != nil {
		return authstore.Credential{}, false, nil
	}
	credential, err := s.store.CredentialByEmail(ctx, email)
	switch {
	case err == nil:
		return credential, true, nil
	case errors.Is(err, authstore.ErrNotFound):
		return authstore.Credential{}, false, nil
	default:
		return authstore.Credential{}, false, err
	}
}

// signOut is idempotent over an absent, expired or revoked session. A store that
// failed is not: the cookie is kept, because the session may still be live.
func (s *authSurface) signOut(c fiber.Ctx) error {
	if err := verifyRequestOrigin(c, s.origin); err != nil {
		return err
	}

	token, held := sessionTokenFromRequest(c)
	if !held {
		clearSessionCookie(c)
		return c.SendStatus(http.StatusNoContent)
	}

	resolved, err := s.store.Resolve(c.Context(), token, s.now().UTC())
	switch {
	case err == nil:
	case errors.Is(err, authstore.ErrNotFound):
		// Nothing usable answers to this token, so the caller is already signed out.
		clearSessionCookie(c)
		return c.SendStatus(http.StatusNoContent)
	default:
		return fiber.NewError(http.StatusInternalServerError)
	}

	// A live session is being ended, which is a state change: the synchronizer
	// token is required before anything is revoked.
	if err := verifyCSRFToken(c, resolved.Session.CSRF); err != nil {
		return err
	}
	if err := s.store.RevokeSession(c.Context(), resolved.Session.ID, s.now().UTC()); err != nil {
		if errors.Is(err, authstore.ErrNotFound) {
			// Revoked between the resolution and here: the outcome asked for holds.
			clearSessionCookie(c)
			return c.SendStatus(http.StatusNoContent)
		}
		return fiber.NewError(http.StatusInternalServerError)
	}
	clearSessionCookie(c)
	return c.SendStatus(http.StatusNoContent)
}

// currentSession writes nothing, so a top-level cross-site navigation carrying
// the cookie under SameSite=Lax cannot renew an idle window.
func (s *authSurface) currentSession(c fiber.Ctx, resolved authstore.Resolved) error {
	return c.JSON(viewOf(resolved.Session, resolved.Principal))
}

func grantedHandler(c fiber.Ctx, _ authstore.Resolved) error {
	return c.JSON(fiber.Map{"granted": true})
}

func viewOf(sess session.Session, principal auth.Principal) sessionView {
	roles := make([]string, 0, len(principal.Roles))
	for _, role := range principal.Roles {
		roles = append(roles, string(role))
	}
	return sessionView{
		CSRFToken: sess.CSRF.Reveal(),
		AccountID: principal.Account.String(),
		Kind:      string(principal.Kind),
		Surface:   string(principal.Surface),
		Roles:     roles,
		ExpiresAt: sess.AbsoluteExpiresAt,
	}
}

// requirePermission resolves the caller from the cookie alone, then puts that
// principal through the domain function. No header contributes to any of it.
func (s *authSurface) requirePermission(permission auth.Permission, next func(fiber.Ctx, authstore.Resolved) error) fiber.Handler {
	return func(c fiber.Ctx) error {
		token, held := sessionTokenFromRequest(c)
		if !held {
			return fiber.NewError(http.StatusUnauthorized, authenticationRequired)
		}
		resolved, err := s.store.Resolve(c.Context(), token, s.now().UTC())
		switch {
		case err == nil:
		case errors.Is(err, authstore.ErrNotFound):
			return fiber.NewError(http.StatusUnauthorized, authenticationRequired)
		default:
			// A store that failed says nothing about the caller. Answering 401 would
			// assert an absence that was never established.
			return fiber.NewError(http.StatusInternalServerError)
		}
		if err := auth.Authorize(resolved.Principal, permission); err != nil {
			return fiber.NewError(http.StatusForbidden, "The account may not perform this action.")
		}
		return next(c, resolved)
	}
}
