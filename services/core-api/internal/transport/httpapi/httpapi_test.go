package httpapi_test

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/ratelimit"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi/healthapi"
)

type availableStore struct{}

func (availableStore) Check(context.Context) error { return nil }

// complete is a posture the constructor must accept, so a refusal below can only
// come from the one dependency the case removes.
func complete() httpapi.Options {
	return httpapi.Options{
		Logger:    slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Readiness: &healthapi.Readiness{},
		RateLimit: ratelimit.Policy{
			Max: 100, Window: time.Hour,
			Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.Direct,
		},
		Persistence:  availableStore{},
		CheckTimeout: time.Second,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
	}
}

// TestACompletePostureIsAccepted anchors every refusal below: without it, a case
// could pass because something else was missing too.
func TestACompletePostureIsAccepted(t *testing.T) {
	app, err := httpapi.New(complete())
	if err != nil || app == nil {
		t.Fatalf("a complete posture was refused: %v", err)
	}
}

// TestEveryMissingDependencyIsRefusedBeforeAssembly keeps the service from
// running on a posture no deployment chose, discovered only by a later request.
func TestEveryMissingDependencyIsRefusedBeforeAssembly(t *testing.T) {
	cases := map[string]struct {
		breakIt func(*httpapi.Options)
		names   string
	}{
		"no logger":              {func(o *httpapi.Options) { o.Logger = nil }, "logger"},
		"no readiness":           {func(o *httpapi.Options) { o.Readiness = nil }, "readiness"},
		"no persistence":         {func(o *httpapi.Options) { o.Persistence = nil }, "persistence"},
		"no check timeout":       {func(o *httpapi.Options) { o.CheckTimeout = 0 }, "timeout"},
		"unusable policy":        {func(o *httpapi.Options) { o.RateLimit = ratelimit.Policy{} }, ""},
		"no read timeout":        {func(o *httpapi.Options) { o.ReadTimeout = 0 }, "read timeout"},
		"negative read timeout":  {func(o *httpapi.Options) { o.ReadTimeout = -time.Second }, "read timeout"},
		"no write timeout":       {func(o *httpapi.Options) { o.WriteTimeout = 0 }, "write timeout"},
		"negative write timeout": {func(o *httpapi.Options) { o.WriteTimeout = -time.Second }, "write timeout"},
		"no idle timeout":        {func(o *httpapi.Options) { o.IdleTimeout = 0 }, "idle timeout"},
		"negative idle timeout":  {func(o *httpapi.Options) { o.IdleTimeout = -time.Second }, "idle timeout"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			opts := complete()
			c.breakIt(&opts)
			app, err := httpapi.New(opts)
			if err == nil {
				t.Fatal("an incomplete posture was assembled")
			}
			if app != nil {
				t.Error("the refused construction handed back an application")
			}
			if c.names != "" && !strings.Contains(err.Error(), c.names) {
				t.Errorf("the refusal %q does not name %q", err, c.names)
			}
		})
	}
}
