// Package requestlimit applies the per-instance HTTP quota and owns the single
// derivation of the client identity every quota counts against.
package requestlimit

import (
	"net/http"
	"slices"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/limiter"

	"github.com/shuntps/project_prometheus/services/core-api/internal/ratelimit"
)

// RateLimiter applies the per-instance abuse policy, every value set explicitly.
// The unlimited paths are the probes, which must answer while the quota is spent.
func RateLimiter(policy ratelimit.Policy, unlimited ...string) fiber.Handler {
	var algorithm limiter.Handler = limiter.FixedWindow{}
	if policy.Algorithm == ratelimit.SlidingWindow {
		algorithm = limiter.SlidingWindow{}
	}
	return limiter.New(limiter.Config{
		Max:                    policy.Max,
		Expiration:             policy.Window,
		LimiterMiddleware:      algorithm,
		KeyGenerator:           ClientKey,
		LimitReached:           func(fiber.Ctx) error { return fiber.NewError(http.StatusTooManyRequests) },
		Next:                   func(c fiber.Ctx) bool { return slices.Contains(unlimited, c.Path()) },
		DisableHeaders:         false,
		SkipFailedRequests:     false,
		SkipSuccessfulRequests: false,
	})
}

// ClientKey falls back to the direct peer when the forwarded chain yields none,
// and is the one derivation every quota uses, global and specialised alike.
func ClientKey(c fiber.Ctx) string {
	if resolved := c.IP(); resolved != "" {
		return resolved
	}
	return c.RequestCtx().RemoteIP().String()
}
