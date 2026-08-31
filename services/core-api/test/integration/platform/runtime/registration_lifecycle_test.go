package integration_test

import (
	"context"
	"log/slog"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/goleak"

	"github.com/shuntps/project_prometheus/services/core-api/internal/app"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/emailverification"
	"github.com/shuntps/project_prometheus/services/core-api/internal/config"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/migration"
	"github.com/shuntps/project_prometheus/services/core-api/internal/ratelimit"
)

// migrateRuntimeSchema applies the controlled migration operation, which the
// service itself never performs.
func migrateRuntimeSchema(t *testing.T, dsn string) {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), dsn)
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

// registrationConfig turns the registration surface on. The collector address is
// a port nothing listens on: what is being proven here is the lifecycle, not the
// transport.
func registrationConfig(t *testing.T, address string, dsn persistence.DSN, collector string) config.Config {
	t.Helper()
	cfg := storeConfig(t, address, dsn)
	cfg.Registration = config.RegistrationSettings{
		Transport:   config.EmailTransportSMTPDevelopment,
		SMTPAddress: collector,
		FromAddress: "no-reply@example.invalid",
		Verification: emailverification.Lifetimes{
			Lifetime: 8 * time.Hour, ResendInterval: time.Minute,
		},
		RateLimit: ratelimit.AuthPolicy{
			ClientAttempts: 5, IdentityAttempts: 3, Window: time.Hour, Capacity: ratelimit.MinAuthCapacity,
		},
		Verify: ratelimit.ClientPolicy{
			Attempts: 20, Window: 15 * time.Minute, Capacity: ratelimit.MinAuthCapacity,
		},
		Delivery: emailverification.DeliveryPolicy{
			Interval: 50 * time.Millisecond, Batch: 8, MaxAttempts: 3,
			Lease: 2 * time.Minute, SendTimeout: time.Second, Backoff: time.Second,
		},
	}
	return cfg
}

// TestBuildingTheServiceStartsNoGoroutine pins where the dispatcher may run: the
// constructor assembles it and starts nothing, so a service that is built and
// never run leaves nothing behind.
func TestBuildingTheServiceStartsNoGoroutine(t *testing.T) {
	dsn, host := realPostgres(t)
	migrateRuntimeSchema(t, dsn)
	cfg := registrationConfig(t, freeAddress(t), dsnFor(t, dsn, host), "127.0.0.1:1")
	service, err := app.New(context.Background(), cfg, slog.New(slog.NewJSONHandler(&syncBuffer{}, nil)))
	if err != nil {
		t.Fatalf("building the service failed: %v", err)
	}
	// Counting goroutines would conflate the pool's own; the claim is about this
	// one function, so the stacks are read and it must appear in none of them.
	time.Sleep(200 * time.Millisecond)
	if running(t, "internal/app.(*App).dispatch") {
		t.Fatal("the constructor started the verification dispatcher")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	waitForStatus(t, "http://"+cfg.HTTPAddress+"/healthz", http.StatusOK)
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("the run returned an error: %v", err)
	}
}

// TestShutdownDrainsTheServerBeforeStoppingTheDispatcher pins the order that
// makes the outbox safe to leave: nothing can still add work once the dispatcher
// is asked to stop, and the store outlives both.
func TestShutdownDrainsTheServerBeforeStoppingTheDispatcher(t *testing.T) {
	dsn, host := realPostgres(t)
	t.Cleanup(func() { goleak.VerifyNone(t, httpStackExceptions()...) })

	migrateRuntimeSchema(t, dsn)
	address := freeAddress(t)
	base, logs, stop := serve(t, registrationConfig(t, address, dsnFor(t, dsn, host), "127.0.0.1:1"))
	waitForStatus(t, base+"/readyz", http.StatusOK)
	// Long enough for several dispatcher ticks to have run and failed to reach a
	// collector nothing listens on.
	time.Sleep(300 * time.Millisecond)

	if err := stop(); err != nil {
		t.Fatalf("the run returned an error: %v", err)
	}
	want := []string{
		"shutdown started",
		"verification dispatcher stopped",
		"shutdown complete",
		"persistence closed",
	}
	if !ordered(logs.messages(), want) {
		t.Fatalf("shutdown records %v do not contain %v in order", logs.messages(), want)
	}
}

// TestADispatcherThatCannotReachItsStoreStopsTheService is the fail-closed
// branch: accepting registrations nothing could drain is worse than stopping.
// The schema is deliberately absent, so the dispatcher can decide nothing.
func TestADispatcherThatCannotReachItsStoreStopsTheService(t *testing.T) {
	dsn, host := realPostgres(t)
	emptySchema(t, dsn)
	t.Cleanup(func() { goleak.VerifyNone(t, httpStackExceptions()...) })

	address := freeAddress(t)
	base, logs, stop := serve(t, registrationConfig(t, address, dsnFor(t, dsn, host), "127.0.0.1:1"))
	waitForStatus(t, base+"/readyz", http.StatusOK)
	// Long enough for the tolerated run of undecided ticks to be exhausted.
	waitForRecord(t, logs, "verification dispatcher stopped the service", 20*time.Second)

	err := stop()
	if err == nil {
		t.Fatal("the service kept running with a dispatcher that could decide nothing")
	}
	// The shutdown still ran in order: the failure is reported, not taken as a
	// reason to skip draining.
	want := []string{"shutdown started", "shutdown complete", "persistence closed"}
	if !ordered(logs.messages(), want) {
		t.Fatalf("shutdown records %v do not contain %v in order", logs.messages(), want)
	}
}

// httpStackExceptions names the goroutines the HTTP stack starts and exposes no
// hook to stop: Fiber's limiter store collector, fasthttp's worker cleaner, its
// server-date updater and Fiber's timestamp updater.
func httpStackExceptions() []goleak.Option {
	return []goleak.Option{
		goleak.IgnoreCurrent(),
		goleak.IgnoreAnyFunction("github.com/gofiber/fiber/v3/internal/memory.(*Storage).gc"),
		goleak.IgnoreAnyFunction("github.com/valyala/fasthttp.(*workerPool).Start.func2"),
		goleak.IgnoreAnyFunction("github.com/valyala/fasthttp.updateServerDate"),
		goleak.IgnoreAnyFunction("github.com/gofiber/utils/v2.StartTimeStampUpdater.func1"),
	}
}

// waitForRecord blocks until the service wrote the record named, so a proof
// never rests on a delay chosen by the test.
func waitForRecord(t *testing.T, logs *syncBuffer, message string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		for _, record := range logs.messages() {
			if record == message {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the service never wrote %q", message)
}

// emptySchema leaves a reachable database with none of the service's tables.
func emptySchema(t *testing.T, dsn string) {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("opening the pool failed: %v", err)
	}
	defer pool.Close()
	if _, err := pool.Exec(context.Background(), `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("resetting the schema failed: %v", err)
	}
}

// running reports whether any goroutine is executing the named function.
func running(t *testing.T, name string) bool {
	t.Helper()
	buf := make([]byte, 1<<20)
	return strings.Contains(string(buf[:runtime.Stack(buf, true)]), name)
}

// TestRegistrationIsAbsentWithoutATransport keeps the surface from accepting work
// no dispatcher would ever drain.
func TestRegistrationIsAbsentWithoutATransport(t *testing.T) {
	dsn, host := realPostgres(t)
	migrateRuntimeSchema(t, dsn)
	cfg := storeConfig(t, freeAddress(t), dsnFor(t, dsn, host))
	cfg.Registration = config.RegistrationSettings{Transport: config.EmailTransportNone}

	base, _, stop := serve(t, cfg)
	res, err := http.Post(base+"/api/v1/auth/registration", "application/json", nil)
	if err != nil {
		t.Fatalf("the request failed: %v", err)
	}
	status := res.StatusCode
	_ = res.Body.Close()
	if status != http.StatusMethodNotAllowed && status != http.StatusNotFound {
		t.Fatalf("the registration route answered %d, want no route at all", status)
	}
	if err := stop(); err != nil {
		t.Fatalf("the run returned an error: %v", err)
	}
}
