package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/requestid"

	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence"
)

// Readiness reports whether the service should receive traffic. It is set once
// startup completes and cleared as soon as shutdown begins.
type Readiness struct {
	ready atomic.Bool
}

func (r *Readiness) Set(ready bool) { r.ready.Store(ready) }

func (r *Readiness) Ready() bool { return r.ready.Load() }

const (
	statusAlive                 = "alive"
	statusReady                 = "ready"
	statusNotReady              = "not_ready"
	statusDependencyUnavailable = "dependency_unavailable"
	dependencyPersistence       = "persistence"
)

type healthBody struct {
	Status string `json:"status"`
}

// liveHandler answers from the process alone. Liveness must stay independent of
// every dependency, or an outage downstream restarts a healthy process.
func liveHandler(c fiber.Ctx) error {
	return c.Status(http.StatusOK).JSON(healthBody{Status: statusAlive})
}

// readyHandler reports readiness only while the store answers, and recovers on
// its own once it answers again. The check is bounded so a probe never hangs.
func readyHandler(r *Readiness, store persistence.Checker, timeout time.Duration, logger *slog.Logger) fiber.Handler {
	return func(c fiber.Ctx) error {
		if !r.Ready() {
			return c.Status(http.StatusServiceUnavailable).JSON(healthBody{Status: statusNotReady})
		}

		ctx, cancel := context.WithTimeout(c.Context(), timeout)
		defer cancel()
		if err := store.Check(ctx); err != nil {
			// Only the dependency name is recorded: the driver's message carries
			// the host, the user and the database name.
			logger.Warn("readiness dependency unavailable",
				slog.String("request_id", requestid.FromContext(c)),
				slog.String("dependency", dependencyPersistence),
			)
			return c.Status(http.StatusServiceUnavailable).JSON(healthBody{Status: statusDependencyUnavailable})
		}
		return c.Status(http.StatusOK).JSON(healthBody{Status: statusReady})
	}
}
