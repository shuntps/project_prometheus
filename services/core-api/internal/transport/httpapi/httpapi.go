// Package httpapi assembles the HTTP transport: it mounts the cross-cutting
// middleware and the route groups, and owns no handler of its own.
package httpapi

import (
	"errors"
	"log/slog"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/gofiber/fiber/v3/middleware/requestid"

	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence"
	"github.com/shuntps/project_prometheus/services/core-api/internal/ratelimit"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi/authapi"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi/healthapi"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi/httperror"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi/requestlimit"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi/requestlog"
)

type Options struct {
	Logger       *slog.Logger
	Readiness    *healthapi.Readiness
	RateLimit    ratelimit.Policy
	Persistence  persistence.Checker
	CheckTimeout time.Duration
	// Auth mounts the public authentication surface. When it is absent no
	// authentication route exists at all; a partial one is refused.
	Auth         *authapi.Options
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

func New(opts Options) (*fiber.App, error) {
	if err := opts.RateLimit.Validate(); err != nil {
		return nil, err
	}
	// Every dependency is required. A default supplied here would let the service
	// run on a posture no deployment chose, discovered only by a later request.
	if opts.Logger == nil {
		return nil, errors.New("http router requires a logger")
	}
	if opts.Readiness == nil {
		return nil, errors.New("http router requires a readiness reporter")
	}
	if opts.Persistence == nil {
		return nil, errors.New("http router requires a persistence checker")
	}
	if opts.CheckTimeout <= 0 {
		return nil, errors.New("http router requires a positive dependency check timeout")
	}
	// Fiber reads a non-positive bound as no bound at all, so an unset one would
	// leave a connection able to read, write or idle without limit.
	if opts.ReadTimeout <= 0 {
		return nil, errors.New("http router requires a positive read timeout")
	}
	if opts.WriteTimeout <= 0 {
		return nil, errors.New("http router requires a positive write timeout")
	}
	if opts.IdleTimeout <= 0 {
		return nil, errors.New("http router requires a positive idle timeout")
	}

	cfg := fiber.Config{
		AppName:      "core-api",
		ReadTimeout:  opts.ReadTimeout,
		WriteTimeout: opts.WriteTimeout,
		IdleTimeout:  opts.IdleTimeout,
		ErrorHandler: httperror.NewErrorHandler(opts.Logger),
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

	app.Use(requestlog.StripClientRequestID)
	app.Use(requestid.New(requestid.Config{Header: requestlog.RequestIDHeader}))
	app.Use(requestlog.RequestLogger(opts.Logger))
	app.Use(recover.New(recover.Config{PanicHandler: requestlog.PanicHandler(opts.Logger)}))
	if opts.Auth != nil {
		// Registered before the limiter so a refusal it decides still declares the
		// policy, and scoped to the authentication prefix so nothing else inherits it.
		app.Use(authapi.PathPrefix, authapi.NoStore)
	}
	app.Use(requestlimit.RateLimiter(opts.RateLimit, healthapi.LivenessPath, healthapi.ReadinessPath))

	app.Get(healthapi.LivenessPath, healthapi.LiveHandler)
	app.Get(healthapi.ReadinessPath, healthapi.ReadyHandler(opts.Readiness, opts.Persistence, opts.CheckTimeout, opts.Logger))

	if opts.Auth != nil {
		if err := authapi.Register(app, *opts.Auth); err != nil {
			return nil, err
		}
	}

	return app, nil
}
