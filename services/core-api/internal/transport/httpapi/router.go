package httpapi

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/limiter"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/gofiber/fiber/v3/middleware/requestid"

	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence"
	"github.com/shuntps/project_prometheus/services/core-api/internal/ratelimit"
)

type Options struct {
	Logger       *slog.Logger
	Readiness    *Readiness
	RateLimit    ratelimit.Policy
	Persistence  persistence.Checker
	CheckTimeout time.Duration
	// Auth mounts the public authentication surface. When it is absent no
	// authentication route exists at all; a partial one is refused.
	Auth         *AuthOptions
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

const (
	requestIDHeader = "X-Request-Id"
	livenessPath    = "/healthz"
	readinessPath   = "/readyz"
	routeUnmatched  = "unmatched"
	// routeRateLimited marks a refusal decided before the handler was resolved.
	routeRateLimited = "rate_limited"
)

func New(opts Options) (*fiber.App, error) {
	if err := opts.RateLimit.Validate(); err != nil {
		return nil, err
	}
	// A nil store would leave readiness reporting on nothing, which is the one
	// shape that lets the service serve traffic with no persistence behind it.
	if opts.Persistence == nil {
		return nil, errors.New("http router requires a persistence checker")
	}
	if opts.CheckTimeout <= 0 {
		return nil, errors.New("http router requires a positive dependency check timeout")
	}

	cfg := fiber.Config{
		AppName:      "core-api",
		ReadTimeout:  opts.ReadTimeout,
		WriteTimeout: opts.WriteTimeout,
		IdleTimeout:  opts.IdleTimeout,
		ErrorHandler: NewErrorHandler(opts.Logger),
	}
	// Forwarded headers are read only for peers inside the allowlist, and only
	// with validation on, which walks the chain right to left and strips them.
	if opts.RateLimit.NetworkMode == ratelimit.BehindProxy {
		cfg.TrustProxy = true
		cfg.EnableIPValidation = true
		cfg.ProxyHeader = opts.RateLimit.ProxyHeader
		cfg.TrustProxyConfig = fiber.TrustProxyConfig{Proxies: opts.RateLimit.TrustedProxyStrings()}
	}
	app := fiber.New(cfg)

	app.Use(stripClientRequestID)
	app.Use(requestid.New(requestid.Config{Header: requestIDHeader}))
	app.Use(requestLogger(opts.Logger))
	app.Use(recover.New(recover.Config{PanicHandler: panicHandler(opts.Logger)}))
	if opts.Auth != nil {
		// Registered before the limiter so a refusal it decides still declares the
		// policy, and scoped to the authentication prefix so nothing else inherits it.
		app.Use(authPathPrefix, noStore)
	}
	app.Use(rateLimiter(opts.RateLimit))

	app.Get(livenessPath, liveHandler)
	app.Get(readinessPath, readyHandler(opts.Readiness, opts.Persistence, opts.CheckTimeout, opts.Logger))

	if opts.Auth != nil {
		surface, err := newAuthSurface(*opts.Auth)
		if err != nil {
			return nil, err
		}
		surface.register(app)
	}

	return app, nil
}

// stripClientRequestID discards any identifier a public client presented, so the
// canonical one is always drawn server-side and public input is never echoed.
func stripClientRequestID(c fiber.Ctx) error {
	c.Request().Header.Del(requestIDHeader)
	return c.Next()
}

// rateLimiter applies the per-instance abuse policy. Every value is set
// explicitly so no middleware default silently governs the service.
func rateLimiter(policy ratelimit.Policy) fiber.Handler {
	var algorithm limiter.Handler = limiter.FixedWindow{}
	if policy.Algorithm == ratelimit.SlidingWindow {
		algorithm = limiter.SlidingWindow{}
	}
	return limiter.New(limiter.Config{
		Max:                    policy.Max,
		Expiration:             policy.Window,
		LimiterMiddleware:      algorithm,
		KeyGenerator:           clientKey,
		LimitReached:           func(fiber.Ctx) error { return fiber.NewError(http.StatusTooManyRequests) },
		Next:                   func(c fiber.Ctx) bool { return c.Path() == livenessPath || c.Path() == readinessPath },
		DisableHeaders:         false,
		SkipFailedRequests:     false,
		SkipSuccessfulRequests: false,
	})
}

// clientKey falls back to the direct peer when the forwarded chain yields no
// usable client, so an unparsable header cannot create its own empty bucket.
func clientKey(c fiber.Ctx) string {
	if resolved := c.IP(); resolved != "" {
		return resolved
	}
	return c.RequestCtx().RemoteIP().String()
}

// panicHandler replaces the recovered value with a fixed internal error so that
// nothing carried by the panic can reach the client or the log.
func panicHandler(logger *slog.Logger) func(fiber.Ctx, any) error {
	return func(c fiber.Ctx, _ any) error {
		logger.Error("recovered from panic",
			slog.String("request_id", requestid.FromContext(c)),
			slog.String("method", c.Method()),
			slog.String("route", routePattern(c)),
			slog.String("error_code", "internal_error"),
		)
		return fiber.NewError(http.StatusInternalServerError)
	}
}

// requestLogger records the route pattern rather than the raw target so that
// identifiers and query values never reach the log.
func requestLogger(logger *slog.Logger) fiber.Handler {
	return func(c fiber.Ctx) error {
		started := time.Now()
		err := c.Next()

		status := c.Response().StatusCode()
		route := routePattern(c)
		if err != nil {
			status = StatusFromError(err)
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
