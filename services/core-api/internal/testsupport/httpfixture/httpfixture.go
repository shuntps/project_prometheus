// Package httpfixture builds the assembled HTTP application an integration suite
// drives, and the stub persistence it reports readiness on.
package httpfixture

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/shuntps/project_prometheus/services/core-api/internal/ratelimit"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi/healthapi"
)

// DirectPolicy is the quota a suite mounts when the limiter is not what it is
// proving: one window, no proxy, and the ceiling the caller asks for.
func DirectPolicy(max int) ratelimit.Policy {
	return ratelimit.Policy{Max: max, Window: time.Hour, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.Direct}
}

// StubStore reproduces an outage, a recovery and a check that never returns. The
// real adapter runs against a real server in the persistence and runtime suites.
type StubStore struct {
	available atomic.Bool
	calls     atomic.Int64
	hang      atomic.Bool
}

func NewStubStore(available bool) *StubStore {
	s := &StubStore{}
	s.available.Store(available)
	return s
}

func (s *StubStore) Check(ctx context.Context) error {
	s.calls.Add(1)
	if s.hang.Load() {
		<-ctx.Done()
		return ctx.Err()
	}
	if !s.available.Load() {
		return errors.New("store refused the check")
	}
	return nil
}

// SetAvailable decides whether the next check answers or refuses.
func (s *StubStore) SetAvailable(available bool) { s.available.Store(available) }

// SetHanging makes the check never answer, so a probe's own bound is exercised.
func (s *StubStore) SetHanging(hanging bool) { s.hang.Store(hanging) }

// Calls counts the checks reaching the store, which is how a suite proves a
// probe answered without consulting it.
func (s *StubStore) Calls() int64 { return s.calls.Load() }

// DefaultTimeout is what the fixture supplies for a bound the caller left unset
// or set to a value the router would refuse.
const DefaultTimeout = time.Second

// MustApp assembles the router, filling only what the caller left unset, and
// mounts one ordinary route. The options are read back through the pointer.
func MustApp(t *testing.T, opts *httpapi.Options) *fiber.App {
	t.Helper()
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	if opts.Readiness == nil {
		opts.Readiness = &healthapi.Readiness{}
		opts.Readiness.Set(true)
	}
	if opts.Persistence == nil {
		opts.Persistence = NewStubStore(true)
	}
	for _, bound := range []*time.Duration{&opts.CheckTimeout, &opts.ReadTimeout, &opts.WriteTimeout, &opts.IdleTimeout} {
		if *bound <= 0 {
			*bound = DefaultTimeout
		}
	}
	app, err := httpapi.New(*opts)
	if err != nil {
		t.Fatalf("building the application failed: %v", err)
	}
	app.Get("/resource", func(c fiber.Ctx) error { return c.SendString("ok") })
	return app
}
