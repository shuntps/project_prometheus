// Package requestlog owns the canonical request identifier, the request record
// and panic recovery, so nothing a client sent decides what is recorded.
package requestlog

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/requestid"

	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi/httperror"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi/routemeta"
)

const (
	RequestIDHeader = "X-Request-Id"
	routeUnmatched  = "unmatched"
	// routeRateLimited marks a refusal decided before the handler was resolved.
	routeRateLimited = "rate_limited"
)

// StripClientRequestID discards any identifier a public client presented, so the
// canonical one is always drawn server-side and public input is never echoed.
func StripClientRequestID(c fiber.Ctx) error {
	c.Request().Header.Del(RequestIDHeader)
	return c.Next()
}

// PanicHandler replaces the recovered value with a fixed internal error so that
// nothing carried by the panic can reach the client or the log.
func PanicHandler(logger *slog.Logger) func(fiber.Ctx, any) error {
	return func(c fiber.Ctx, _ any) error {
		logger.Error("recovered from panic",
			slog.String("request_id", requestid.FromContext(c)),
			slog.String("method", c.Method()),
			slog.String("route", routemeta.RoutePattern(c)),
			slog.String("error_code", "internal_error"),
		)
		return fiber.NewError(http.StatusInternalServerError)
	}
}

// RequestLogger records the route pattern rather than the raw target so that
// identifiers and query values never reach the log.
func RequestLogger(logger *slog.Logger) fiber.Handler {
	return func(c fiber.Ctx) error {
		started := time.Now()
		err := c.Next()

		status := c.Response().StatusCode()
		route := routemeta.RoutePattern(c)
		if err != nil {
			status = httperror.StatusFromError(err)
			switch {
			case status == http.StatusTooManyRequests:
				route = routeRateLimited
			case errors.Is(err, fiber.ErrNotFound):
				route = routeUnmatched
			}
		}

		logger.Info("request handled",
			slog.String("request_id", requestid.FromContext(c)),
			slog.String("method", c.Method()),
			slog.String("route", route),
			slog.Int("status", status),
			slog.Int64("duration_ms", time.Since(started).Milliseconds()),
		)
		return err
	}
}
