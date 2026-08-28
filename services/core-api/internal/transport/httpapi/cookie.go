package httpapi

import (
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/web"
)

// setSessionCookie sets every attribute explicitly. The __Host- prefix makes the
// browser reject the cookie if Secure, Path=/ or the absent Domain were dropped.
func setSessionCookie(c fiber.Ctx, token session.Token, expires time.Time) {
	c.Cookie(&fiber.Cookie{
		Name:     web.SessionCookieName,
		Value:    token.Reveal(),
		Path:     web.CookiePath,
		Domain:   "",
		Expires:  expires.UTC(),
		Secure:   true,
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
	})
}

// clearSessionCookie overwrites the cookie with an expired empty value. The
// attributes must match, or the browser keeps the original alongside it.
func clearSessionCookie(c fiber.Ctx) {
	c.Cookie(&fiber.Cookie{
		Name:     web.SessionCookieName,
		Value:    "",
		Path:     web.CookiePath,
		Domain:   "",
		Expires:  time.Unix(0, 0).UTC(),
		MaxAge:   -1,
		Secure:   true,
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
	})
}

// sessionTokenFromRequest reads the cookie and nothing else, so no URL, header or
// body carries a token and no record of a target can contain one.
func sessionTokenFromRequest(c fiber.Ctx) (session.Token, bool) {
	raw := c.Cookies(web.SessionCookieName)
	if raw == "" {
		return session.Token{}, false
	}
	token, err := session.ParseToken(raw)
	if err != nil {
		return session.Token{}, false
	}
	return token, true
}
