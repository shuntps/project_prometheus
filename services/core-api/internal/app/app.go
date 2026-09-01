// Package app builds the running service from a validated configuration and
// owns its lifecycle, including graceful shutdown.
package app

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/emailverification"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/config"
	"github.com/shuntps/project_prometheus/services/core-api/internal/notification/smtp"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/authstore"
	"github.com/shuntps/project_prometheus/services/core-api/internal/ratelimit"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi/authapi"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi/healthapi"
)

// maxDispatchFailures bounds how many consecutive undecided ticks the dispatcher
// may report before the service is brought down. Accepting registrations whose
// message nothing will carry is worse than stopping.
const maxDispatchFailures = 5

type App struct {
	cfg       config.Config
	logger    *slog.Logger
	readiness *healthapi.Readiness
	server    *fiber.App
	store     *postgres.Pool
	// deliveries drains the verification outbox. It is built here and started by
	// Run: New starts no goroutine of its own.
	deliveries *auth.Deliveries
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
	if err := cfg.Registration.Validate(); err != nil {
		return nil, err
	}
	if cfg.PublicOrigin.IsZero() {
		return nil, errors.New("the public origin is required")
	}

	hasher, err := password.NewHasher(cfg.Auth.Password.Params, cfg.Auth.Password.Policy)
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

	registrations, verifications, deliveries, err := buildRegistration(cfg, repository)
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
			SignIn:        signIn,
			Sessions:      sessions,
			Origin:        cfg.PublicOrigin,
			Registrations: registrations,
			Verifications: verifications,
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
	if deliveries == nil {
		logger.Info("public registration disabled", slog.String("email_transport", string(cfg.Registration.Transport)))
	}
	return &App{
		cfg: cfg, logger: logger, readiness: readiness,
		server: server, store: store, deliveries: deliveries,
	}, nil
}

// buildRegistration assembles public registration, or nothing at all. The three
// pieces are returned together: a surface that accepts a registration without a
// dispatcher would queue work nobody drains.
func buildRegistration(cfg config.Config, repository authstore.Repository) (
	*auth.Registrations, *auth.Verifications, *auth.Deliveries, error) {
	if !cfg.Registration.Enabled() {
		return nil, nil, nil, nil
	}

	registrationLimiter, err := ratelimit.NewAuthLimiter(cfg.Registration.RateLimit)
	if err != nil {
		return nil, nil, nil, err
	}
	verificationLimiter, err := ratelimit.NewClientLimiter(cfg.Registration.Verify)
	if err != nil {
		return nil, nil, nil, err
	}
	hasher, err := password.NewHasher(cfg.Auth.Password.Params, cfg.Auth.Password.Policy)
	if err != nil {
		return nil, nil, nil, err
	}

	registrations, err := auth.NewRegistrations(auth.RegistrationOptions{
		Repository: repository, Hasher: hasher, Limiter: registrationLimiter,
		Lifetimes: cfg.Registration.Verification,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	verifications, err := auth.NewVerifications(auth.VerificationOptions{
		Repository: repository, Limiter: verificationLimiter,
	})
	if err != nil {
		return nil, nil, nil, err
	}

	var sender auth.VerificationSender
	switch cfg.Registration.Transport {
	case config.EmailTransportSMTPDevelopment:
		sender, err = smtp.New(cfg.Registration.SMTPAddress, cfg.Registration.FromAddress)
		if err != nil {
			return nil, nil, nil, err
		}
	default:
		return nil, nil, nil, errors.New("no verification transport is configured")
	}

	// Built here from the one origin the browser sees. The token travels in the
	// fragment, which never reaches the server serving that page.
	link := func(token emailverification.Token) string {
		return cfg.PublicOrigin.VerificationLink(token.Reveal())
	}
	deliveries, err := auth.NewDeliveries(auth.DeliveryOptions{
		Repository: repository, Sender: sender, Link: link, Policy: cfg.Registration.Delivery,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	return registrations, verifications, deliveries, nil
}

// Run serves until ctx is cancelled. Readiness is cleared first, then the server
// drains so no request can still write to the outbox, then the dispatcher is
// stopped and joined, and the store is closed last.
func (a *App) Run(ctx context.Context) error {
	// The store is closed only once the server has drained and the dispatcher has
	// returned, so neither loses its connection mid-operation.
	defer func() {
		a.store.Close()
		a.logger.Info("persistence closed")
	}()

	// The dispatcher's cancellation is this function's to give, so a request that
	// cancelled its own context cannot stop it.
	dispatchCtx, stopDispatch := context.WithCancel(context.WithoutCancel(ctx))
	defer stopDispatch()
	dispatchErr := make(chan error, 1)
	if a.deliveries != nil {
		go func() { dispatchErr <- a.dispatch(dispatchCtx) }()
	}

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

	var fatal error
	select {
	case err := <-listenErr:
		a.readiness.Set(false)
		stopDispatch()
		if a.deliveries != nil {
			<-dispatchErr
		}
		return err
	case fatal = <-dispatchErr:
		// The dispatcher stopped on its own. The server is drained first anyway, so
		// nothing is accepted whose message would never leave.
		a.logger.Error("verification dispatcher stopped the service")
	case <-ctx.Done():
	}

	a.readiness.Set(false)
	a.logger.Info("shutdown started", slog.String("timeout", a.cfg.ShutdownTimeout.String()))

	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.cfg.ShutdownTimeout)
	defer cancel()
	shutdownErr := a.server.ShutdownWithContext(shutdownCtx)

	// The server has stopped accepting and has drained, so no handler can still
	// add work to the outbox. Only now is the dispatcher asked to stop.
	stopDispatch()
	if a.deliveries != nil && fatal == nil {
		fatal = <-dispatchErr
	}

	if shutdownErr != nil {
		return shutdownErr
	}
	if err := <-listenErr; err != nil {
		return err
	}
	a.logger.Info("shutdown complete")
	return fatal
}

// dispatch drains the verification outbox until it is cancelled. A transport
// failure never reaches here; only a store that could not decide does, and it is
// tolerated a bounded number of consecutive times.
func (a *App) dispatch(ctx context.Context) error {
	ticker := time.NewTicker(a.deliveries.Interval())
	defer ticker.Stop()

	failures := 0
	for {
		select {
		case <-ctx.Done():
			a.logger.Info("verification dispatcher stopped")
			return nil
		case <-ticker.C:
		}

		result, err := a.deliveries.Dispatch(ctx)
		if err != nil {
			if ctx.Err() != nil {
				a.logger.Info("verification dispatcher stopped")
				return nil
			}
			failures++
			a.logger.Warn("verification dispatch could not be decided",
				slog.Int("consecutive_failures", failures))
			if failures >= maxDispatchFailures {
				return errors.New("the verification dispatcher could not reach its store")
			}
			continue
		}
		failures = 0
		if result.Delivered+result.Discarded+result.Lost > 0 || result.Swept > 0 {
			a.logger.Info("verification deliveries dispatched",
				slog.Int("claimed", result.Claimed),
				slog.Int("delivered", result.Delivered),
				slog.Int("rescheduled", result.Rescheduled),
				slog.Int("discarded", result.Discarded),
				slog.Int("lost_lease", result.Lost),
				slog.Int64("swept", result.Swept))
		}
	}
}
