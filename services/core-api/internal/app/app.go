// Package app builds the running service from a validated configuration and
// owns its lifecycle, including graceful shutdown.
package app

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/gofiber/fiber/v3"

	"github.com/shuntps/project_prometheus/services/core-api/internal/config"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi"
)

type App struct {
	cfg       config.Config
	logger    *slog.Logger
	readiness *httpapi.Readiness
	server    *fiber.App
}

func New(cfg config.Config, logger *slog.Logger) (*App, error) {
	readiness := &httpapi.Readiness{}
	server, err := httpapi.New(httpapi.Options{
		Logger:       logger,
		Readiness:    readiness,
		RateLimit:    cfg.RateLimit,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	})
	if err != nil {
		return nil, err
	}
	return &App{cfg: cfg, logger: logger, readiness: readiness, server: server}, nil
}

// Run serves until ctx is cancelled. Readiness is cleared before draining so
// traffic stops being routed here while in-flight requests finish.
func (a *App) Run(ctx context.Context) error {
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
