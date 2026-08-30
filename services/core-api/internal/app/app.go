// Package app builds the running service from a validated configuration and
// owns its lifecycle, including graceful shutdown.
package app

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/gofiber/fiber/v3"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/config"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/authstore"
	"github.com/shuntps/project_prometheus/services/core-api/internal/ratelimit"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi/authapi"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi/healthapi"
)

type App struct {
	cfg       config.Config
	logger    *slog.Logger
	readiness *healthapi.Readiness
	server    *fiber.App
	store     *postgres.Pool
}

// New refuses to build a service whose store cannot be reached: the connection
// is established here, under the configured bound, not deferred to first use.
func New(ctx context.Context, cfg config.Config, logger *slog.Logger) (*App, error) {
	// Local settings are checked before an external resource is acquired, so a
	// refusal costs no connection.
	if err := cfg.RateLimit.Validate(); err != nil {
		return nil, err
	}
	if err := cfg.Database.Validate(); err != nil {
		return nil, err
	}
	if err := cfg.Auth.Validate(); err != nil {
		return nil, err
	}
	if cfg.PublicOrigin.IsZero() {
		return nil, errors.New("the public origin is required")
	}

	hasher, err := password.NewHasher(cfg.Auth.Password.Params, cfg.Auth.Password.Policy, nil)
	if err != nil {
		return nil, err
	}
	limiter, err := ratelimit.NewAuthLimiter(cfg.Auth.RateLimit)
	if err != nil {
		return nil, err
	}

	store, err := postgres.Open(ctx, cfg.DatabaseURL, cfg.Database)
	if err != nil {
		return nil, err
	}
	// The adapter is the one place the store's vocabulary is translated; the use
	// cases and the transport are wired to the ports, never to the driver.
	authTables, err := authstore.New(store.Unwrap())
	if err != nil {
		store.Close()
		return nil, err
	}
	repository, err := authstore.NewRepository(authTables)
	if err != nil {
		store.Close()
		return nil, err
	}
	signIn, err := auth.NewSignIn(auth.SignInOptions{
		Repository: repository, Hasher: hasher, Limiter: limiter, Lifetimes: cfg.Auth.Session,
	})
	if err != nil {
		store.Close()
		return nil, err
	}
	sessions, err := auth.NewSessions(auth.SessionsOptions{
		Repository: repository, Lifetimes: cfg.Auth.Session,
	})
	if err != nil {
		store.Close()
		return nil, err
	}

	readiness := &healthapi.Readiness{}
	server, err := httpapi.New(httpapi.Options{
		Logger:       logger,
		Readiness:    readiness,
		RateLimit:    cfg.RateLimit,
		Persistence:  store,
		CheckTimeout: cfg.Database.CheckTimeout,
		Auth: &authapi.Options{
			SignIn:   signIn,
			Sessions: sessions,
			Origin:   cfg.PublicOrigin,
		},
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	})
	if err != nil {
		store.Close()
		return nil, err
	}
	logger.Info("persistence connected")
	return &App{cfg: cfg, logger: logger, readiness: readiness, server: server, store: store}, nil
}

// Run serves until ctx is cancelled. Readiness is cleared before draining so
// traffic stops being routed here while in-flight requests finish.
func (a *App) Run(ctx context.Context) error {
	// The store is closed only once the server has stopped accepting and has
	// drained, so no in-flight request loses its connection mid-handler.
	defer func() {
		a.store.Close()
		a.logger.Info("persistence closed")
	}()

	listenErr := make(chan error, 1)
	go func() {
		a.readiness.Set(true)
		a.logger.Info("http server listening", slog.String("address", a.cfg.HTTPAddress))
		err := a.server.Listen(a.cfg.HTTPAddress, fiber.ListenConfig{DisableStartupMessage: true})
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			listenErr <- err
			return
		}
		listenErr <- nil
	}()

	select {
	case err := <-listenErr:
		a.readiness.Set(false)
		return err
	case <-ctx.Done():
	}

	a.readiness.Set(false)
	a.logger.Info("shutdown started", slog.String("timeout", a.cfg.ShutdownTimeout.String()))

	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.cfg.ShutdownTimeout)
	defer cancel()
	if err := a.server.ShutdownWithContext(shutdownCtx); err != nil {
		return err
	}

	a.logger.Info("shutdown complete")
	return <-listenErr
}
