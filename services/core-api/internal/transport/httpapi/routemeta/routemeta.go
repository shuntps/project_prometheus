// Package routemeta names the route a request matched. It is the one derivation
// every record uses, so no target, parameter or query value can reach one.
package routemeta

import (
	"github.com/gofiber/fiber/v3"
)

// RoutePattern returns the registered pattern of the resolved route, and nothing
// at all when the router matched none: the raw target must never stand in for it.
func RoutePattern(c fiber.Ctx) string {
	if !c.Matched() {
		return ""
	}
	return c.FullPath()
}
