package authapi

import (
	"net/http"

	"github.com/gofiber/fiber/v3"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/application"
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
	authenticated, outcome, err := s.sessions.Authenticate(c.Context(), token)
	if err != nil {
		return fiber.NewError(http.StatusInternalServerError)
	}
	switch outcome {
	case application.OutcomeSucceeded:
	case application.OutcomeUnauthenticated:
		return fiber.NewError(http.StatusUnauthorized, authenticationRequired)
	default:
		return fiber.NewError(http.StatusInternalServerError)
	}
	if err := verifyCSRFToken(c, authenticated.Resolved.Session.CSRF); err != nil {
		return err
	}

	// The write is anchored to the instant the session was resolved at, and the
	// operation decides its own permission inside that write's transaction.
	renewed, err := s.sessions.RenewActivity(c.Context(), authenticated.Resolved.Session.ID, authenticated.At)
	if err != nil {
		return fiber.NewError(http.StatusInternalServerError)
	}
	switch renewed {
	// Whether the update was persisted or suppressed is a storage concern; the
	// answer is the same, so the frequency policy discloses nothing.
	case application.OutcomeSucceeded:
		return c.SendStatus(http.StatusNoContent)
	case application.OutcomeForbidden:
		return fiber.NewError(http.StatusForbidden, "The account may not perform this action.")
	case application.OutcomeUnauthenticated:
		// The session stopped being usable between the resolution and the write.
		return fiber.NewError(http.StatusUnauthorized, authenticationRequired)
	default:
		return fiber.NewError(http.StatusInternalServerError)
	}
}
