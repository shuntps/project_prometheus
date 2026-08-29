package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/authstore"
)

// signInFailure is the one answer every unsuccessful sign-in produces: an unknown
// address, a wrong password and an unusable account are not distinguished.
const signInFailure = "The credentials were not accepted."

type signInRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
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
