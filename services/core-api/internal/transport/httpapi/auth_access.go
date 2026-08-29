package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/authstore"
)

// authenticationRequired is the one answer a missing or finished session gets. A
// store failure never uses it: that would assert an absence nobody established.
const authenticationRequired = "Authentication is required."

type sessionView struct {
	CSRFToken string    `json:"csrf_token"`
	AccountID string    `json:"account_id"`
	Kind      string    `json:"kind"`
	Surface   string    `json:"surface"`
	Roles     []string  `json:"roles"`
	ExpiresAt time.Time `json:"expires_at"`
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
