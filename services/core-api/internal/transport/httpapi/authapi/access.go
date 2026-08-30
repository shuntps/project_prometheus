package authapi

import (
	"net/http"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
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
func (s *authSurface) currentSession(c fiber.Ctx, resolved auth.Resolved) error {
	return c.JSON(viewOf(resolved.Session, resolved.Principal))
}

func grantedHandler(c fiber.Ctx, _ auth.Resolved) error {
	return c.JSON(fiber.Map{"granted": true})
}

func viewOf(sess session.Session, principal iam.Principal) sessionView {
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

// requireSession resolves the caller's own session and nothing beyond it. A live
// session is sufficient to read its metadata; no role participates in the read.
func (s *authSurface) requireSession(next func(fiber.Ctx, auth.Resolved) error) fiber.Handler {
	return func(c fiber.Ctx) error {
		token, held := sessionTokenFromRequest(c)
		if !held {
			return fiber.NewError(http.StatusUnauthorized, authenticationRequired)
		}
		authenticated, outcome, err := s.sessions.Authenticate(c.Context(), token)
		if err != nil {
			// A store that failed says nothing about the caller, so it is never
			// reported as an absent session.
			return fiber.NewError(http.StatusInternalServerError)
		}
		switch outcome {
		case auth.OutcomeSucceeded:
			return next(c, authenticated.Resolved)
		case auth.OutcomeUnauthenticated:
			return fiber.NewError(http.StatusUnauthorized, authenticationRequired)
		default:
			return fiber.NewError(http.StatusInternalServerError)
		}
	}
}

// requirePermission resolves the caller from the cookie alone, then puts that
// principal through the domain function. No header contributes to any of it.
func (s *authSurface) requirePermission(permission iam.Permission, next func(fiber.Ctx, auth.Resolved) error) fiber.Handler {
	return func(c fiber.Ctx) error {
		token, held := sessionTokenFromRequest(c)
		if !held {
			return fiber.NewError(http.StatusUnauthorized, authenticationRequired)
		}
		authenticated, outcome, err := s.sessions.Authorise(c.Context(), token, permission)
		if err != nil {
			// A store that failed says nothing about the caller. Answering 401 would
			// assert an absence that was never established.
			return fiber.NewError(http.StatusInternalServerError)
		}
		switch outcome {
		case auth.OutcomeSucceeded:
			return next(c, authenticated.Resolved)
		case auth.OutcomeUnauthenticated:
			return fiber.NewError(http.StatusUnauthorized, authenticationRequired)
		case auth.OutcomeForbidden:
			return fiber.NewError(http.StatusForbidden, "The account may not perform this action.")
		default:
			return fiber.NewError(http.StatusInternalServerError)
		}
	}
}
