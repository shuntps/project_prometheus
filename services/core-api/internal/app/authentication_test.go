package app_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/goleak"

	"github.com/shuntps/project_prometheus/services/core-api/internal/app"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/config"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/migration"
	"github.com/shuntps/project_prometheus/services/core-api/internal/ratelimit"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/web"
)

const publicAuthOrigin = "https://app.example.com"

// TestTheRealServiceMountsTheAuthenticationSurface drives the running binary, not
// a router built in a test, so the wiring itself is the thing being proven.
func TestTheRealServiceMountsTheAuthenticationSurface(t *testing.T) {
	dsn, host := realPostgres(t)
	// Four HTTP-stack goroutines outlive a served request and expose no stop hook:
	// two collectors, and two timestamp updaters started on first use.
	options := []goleak.Option{
		goleak.IgnoreCurrent(),
		goleak.IgnoreAnyFunction("github.com/gofiber/fiber/v3/internal/memory.(*Storage).gc"),
		goleak.IgnoreAnyFunction("github.com/valyala/fasthttp.(*workerPool).Start.func2"),
		goleak.IgnoreAnyFunction("github.com/valyala/fasthttp.updateServerDate.func1"),
		goleak.IgnoreAnyFunction("github.com/gofiber/utils/v2.StartTimeStampUpdater.func1"),
	}
	t.Cleanup(func() { goleak.VerifyNone(t, options...) })

	target := dsnFor(t, dsn, host)
	// The schema is applied here, not by the service: cmd/api never migrates. It
	// also makes the refusal below a credential verdict rather than a store failure.
	applySchema(t, target)

	cfg := storeConfig(t, freeAddress(t), target)
	origin, err := web.ParseOrigin(publicAuthOrigin)
	if err != nil {
		t.Fatalf("parsing the origin failed: %v", err)
	}
	cfg.PublicOrigin = origin

	base, logs, stop := serve(t, cfg)
	defer func() {
		if err := stop(); err != nil {
			t.Fatalf("the service did not shut down cleanly: %v", err)
		}
	}()

	// A sign-in attempt reaches the surface: the answer is the authentication
	// refusal, not the router's unmatched-route answer.
	body, _ := json.Marshal(map[string]string{"email": "nobody@example.com", "password": "correct-horse-battery-staple"})
	req, err := http.NewRequest(http.MethodPost, base+"/api/v1/auth/session", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("building the request failed: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", publicAuthOrigin)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("the request failed: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(res.Body)
		t.Fatalf("sign-in returned %d, want 401: %s", res.StatusCode, raw)
	}

	// The unauthenticated read is refused rather than absent.
	probe, err := http.Get(base + "/api/v1/auth/session")
	if err != nil {
		t.Fatalf("the request failed: %v", err)
	}
	defer probe.Body.Close()
	if probe.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the session route returned %d, want 401", probe.StatusCode)
	}

	// Nothing the attempt carried reached the records.
	for _, record := range logs.messages() {
		if strings.Contains(record, "nobody@example.com") || strings.Contains(record, "correct-horse-battery-staple") {
			t.Fatalf("a record carried submitted credentials: %s", record)
		}
	}
}

// TestStartupIsRefusedOnAnUnusableAuthenticationPosture keeps a service that
// could not enforce one of its authentication controls from ever serving.
func TestStartupIsRefusedOnAnUnusableAuthenticationPosture(t *testing.T) {
	origin, err := web.ParseOrigin(publicAuthOrigin)
	if err != nil {
		t.Fatalf("parsing the origin failed: %v", err)
	}

	cases := map[string]func(*config.Config){
		"no public origin":         func(c *config.Config) { c.PublicOrigin = web.Origin{} },
		"no attempt policy":        func(c *config.Config) { c.Auth.RateLimit = ratelimit.AuthPolicy{} },
		"no client bound":          func(c *config.Config) { c.Auth.RateLimit.ClientAttempts = 0 },
		"no identity bound":        func(c *config.Config) { c.Auth.RateLimit.IdentityAttempts = 0 },
		"unbounded window":         func(c *config.Config) { c.Auth.RateLimit.Window = 0 },
		"unbounded counters":       func(c *config.Config) { c.Auth.RateLimit.Capacity = 0 },
		"hashing below the floor":  func(c *config.Config) { c.Auth.Password.Params.MemoryKiB = password.FloorMemoryKiB - 1 },
		"length below the floor":   func(c *config.Config) { c.Auth.Password.Policy.MinCodePoints = 1 },
		"no session lifetimes":     func(c *config.Config) { c.Auth.Session.Absolute, c.Auth.Session.Idle = 0, 0 },
		"idle beyond the absolute": func(c *config.Config) { c.Auth.Session.Idle = 2 * c.Auth.Session.Absolute },
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := config.Config{
				Environment: config.EnvDevelopment, LogLevel: "error", HTTPAddress: "127.0.0.1:0",
				PublicOrigin: origin, Auth: testAuthSettings(),
				RateLimit:   ratelimit.Policy{Max: 100, Window: time.Minute, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.Direct},
				ReadTimeout: time.Second, WriteTimeout: time.Second, IdleTimeout: time.Second, ShutdownTimeout: time.Second,
				Database: testSettings(),
			}
			breakIt(&cfg)
			service, err := app.New(context.Background(), cfg, slog.New(slog.NewJSONHandler(io.Discard, nil)))
			if err == nil {
				t.Fatal("the service started on an unusable authentication posture")
			}
			if service != nil {
				t.Error("a service was returned despite the refusal")
			}
			// The refusal costs no connection: it happens before the store is opened.
			if strings.Contains(err.Error(), "unavailable") {
				t.Errorf("the posture was checked after the store was reached: %v", err)
			}
		})
	}
}

// applySchema runs the controlled migration operation against the shared server,
// because other tests in this package deliberately drop the schema.
func applySchema(t *testing.T, target persistence.DSN) {
	t.Helper()
	parsed, err := url.Parse(target.Reveal())
	if err != nil {
		t.Fatalf("the connection string could not be inspected: %v", err)
	}
	values := parsed.Query()
	values.Set("sslmode", string(persistence.TLSDisable))
	parsed.RawQuery = values.Encode()

	pool, err := pgxpool.New(context.Background(), parsed.String())
	if err != nil {
		t.Fatalf("opening the pool failed: %v", err)
	}
	defer pool.Close()

	if _, err := pool.Exec(context.Background(), `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("resetting the schema failed: %v", err)
	}
	migrations, err := migration.Load()
	if err != nil {
		t.Fatalf("loading migrations failed: %v", err)
	}
	if _, err := migration.Apply(context.Background(), pool, migrations); err != nil {
		t.Fatalf("applying migrations failed: %v", err)
	}
}
