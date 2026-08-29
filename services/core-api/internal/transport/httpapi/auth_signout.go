package httpapi

import (
	"errors"
	"net/http"

	"github.com/gofiber/fiber/v3"

	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/authstore"
)

// signOut is idempotent over an absent, expired or revoked session. A store that
// failed is not: the cookie is kept, because the session may still be live.
func (s *authSurface) signOut(c fiber.Ctx) error {
	if err := verifyRequestOrigin(c, s.origin); err != nil {
		return err
	}
	// The shape is judged before the session is looked at, so a request no JSON
	// client could have sent is never reported as an accomplished sign-out.
	if err := requireJSONRequest(c); err != nil {
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
