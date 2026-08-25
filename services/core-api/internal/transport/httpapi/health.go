package httpapi

import (
	"net/http"
	"sync/atomic"

	"github.com/gofiber/fiber/v3"
)

// Readiness reports whether the service should receive traffic. It is set once
// startup completes and cleared as soon as shutdown begins.
type Readiness struct {
	ready atomic.Bool
}

func (r *Readiness) Set(ready bool) { r.ready.Store(ready) }

func (r *Readiness) Ready() bool { return r.ready.Load() }

type healthBody struct {
	Status string `json:"status"`
}

func liveHandler(c fiber.Ctx) error {
	return c.Status(http.StatusOK).JSON(healthBody{Status: "alive"})
}

func readyHandler(r *Readiness) fiber.Handler {
	return func(c fiber.Ctx) error {
		if !r.Ready() {
			return c.Status(http.StatusServiceUnavailable).JSON(healthBody{Status: "not_ready"})
		}
		return c.Status(http.StatusOK).JSON(healthBody{Status: "ready"})
	}
}
