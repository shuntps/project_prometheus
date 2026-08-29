package httpapi

import (
	"errors"
	"net/http"

	"github.com/gofiber/fiber/v3"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/authstore"
)

// recordActivity renews the inactivity deadline and nothing else. Whether the
// interaction was meaningful is the caller's judgement, not something to enforce.
func (s *authSurface) recordActivity(c fiber.Ctx) error {
	if err := verifyRequestOrigin(c, s.origin); err != nil {
		return err
	}
	if err := requireJSONRequest(c); err != nil {
		return err
	}

	token, held := sessionTokenFromRequest(c)
	if !held {
		return fiber.NewError(http.StatusUnauthorized, authenticationRequired)
	}
	now := s.now().UTC()
	resolved, err := s.store.Resolve(c.Context(), token, now)
	switch {
	case err == nil:
	case errors.Is(err, authstore.ErrNotFound):
		return fiber.NewError(http.StatusUnauthorized, authenticationRequired)
	default:
		return fiber.NewError(http.StatusInternalServerError)
	}
	if err := verifyCSRFToken(c, resolved.Session.CSRF); err != nil {
		return err
	}

	// The operation decides its own permission inside the write's transaction, so
	// nothing here can pick a more convenient rule or act on a stale authority.
	switch _, err := s.store.RecordActivity(c.Context(), resolved.Session.ID, now, s.lifetimes); {
	case err == nil:
	case errors.Is(err, auth.ErrDenied):
		return fiber.NewError(http.StatusForbidden, "The account may not perform this action.")
	case errors.Is(err, authstore.ErrNotFound):
		// The session stopped being usable between the resolution and the write.
		return fiber.NewError(http.StatusUnauthorized, authenticationRequired)
	default:
		return fiber.NewError(http.StatusInternalServerError)
	}
	// Whether the update was persisted or suppressed is a storage concern; the
	// answer is the same, so the frequency policy discloses nothing.
	return c.SendStatus(http.StatusNoContent)
}
