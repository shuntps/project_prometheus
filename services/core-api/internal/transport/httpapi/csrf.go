package httpapi

import (
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v3"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/browser"
)

const (
	crossSiteMessage  = "The request did not come from the application."
	csrfTokenMessage  = "The request did not carry a valid CSRF token."
	contentTypeJSON   = "application/json"
	contentTypeReason = "The request must be sent as application/json."
)

// verifyRequestOrigin runs before anything else is read. It compares against the
// configured origin, never a Host or forwarded header a client controls.
func verifyRequestOrigin(c fiber.Ctx, origin browser.Origin) error {
	// An absent Origin is a refusal, not a pass: browsers always send it here, so
	// its absence means a non-browser client or a stripped header.
	if !origin.Matches(c.Get(browser.OriginHeader)) {
		return fiber.NewError(http.StatusForbidden, crossSiteMessage)
	}
	// Fetch Metadata is defence in depth. It is enforced when the browser sends
	// it and never used to excuse the checks above.
	if site := c.Get(browser.FetchSiteHeader); site != "" && site != "same-origin" {
		return fiber.NewError(http.StatusForbidden, crossSiteMessage)
	}
	return nil
}

// requireJSONRequest keeps state-changing requests to a content type no cross-site
// form can produce, so a form post never reaches a handler.
func requireJSONRequest(c fiber.Ctx) error {
	declared := c.Get(fiber.HeaderContentType)
	if media, _, _ := strings.Cut(declared, ";"); !strings.EqualFold(strings.TrimSpace(media), contentTypeJSON) {
		return fiber.NewError(http.StatusUnsupportedMediaType, contentTypeReason)
	}
	return nil
}

// verifyCSRFToken compares the header against the token issued with the session.
// An absent or unmatched value is refused; there is no fallback.
func verifyCSRFToken(c fiber.Ctx, issued session.CSRFToken) error {
	presented, err := session.ParseCSRFToken(c.Get(browser.CSRFHeader))
	if err != nil || !issued.Equals(presented) {
		return fiber.NewError(http.StatusForbidden, csrfTokenMessage)
	}
	return nil
}
