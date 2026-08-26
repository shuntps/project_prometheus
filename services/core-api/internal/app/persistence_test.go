package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"go.uber.org/goleak"

	"github.com/shuntps/project_prometheus/services/core-api/internal/app"
	"github.com/shuntps/project_prometheus/services/core-api/internal/config"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence"
	"github.com/shuntps/project_prometheus/services/core-api/internal/ratelimit"
)

func storeConfig(t *testing.T, address string, dsn persistence.DSN) config.Config {
	t.Helper()
	return config.Config{
		Environment:     config.EnvDevelopment,
		LogLevel:        "info",
		HTTPAddress:     address,
		RateLimit:       ratelimit.Policy{Max: 1000, Window: time.Hour, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.Direct},
		ReadTimeout:     time.Second,
		WriteTimeout:    time.Second,
		IdleTimeout:     time.Second,
		ShutdownTimeout: 5 * time.Second,
		DatabaseURL:     dsn,
		Database:        testSettings(),
	}
}

// serve starts the service and returns its base URL, the records it wrote and a
// function that shuts it down and waits for the run to finish.
func serve(t *testing.T, cfg config.Config) (base string, logs *syncBuffer, stop func() error) {
	t.Helper()
	logs = &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, nil))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	service, err := app.New(ctx, cfg, logger)
	if err != nil {
		cancel()
		t.Fatalf("building the service failed: %v", err)
	}
	go func() { done <- service.Run(ctx) }()

	base = "http://" + cfg.HTTPAddress
	waitForStatus(t, base+"/healthz", http.StatusOK)
	return base, logs, func() error {
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(20 * time.Second):
			t.Fatal("the service never finished shutting down")
			return nil
		}
	}
}

type syncBuffer struct {
	mu      sync.Mutex
	records []string
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.records = append(b.records, string(p))
	return len(p), nil
}

func (b *syncBuffer) messages() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, 0, len(b.records))
	for _, record := range b.records {
		var parsed struct {
			Msg string `json:"msg"`
		}
		if err := json.Unmarshal([]byte(record), &parsed); err == nil {
			out = append(out, parsed.Msg)
		}
	}
	return out
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.Join(b.records, "")
}

func healthStatus(t *testing.T, url string) (int, string) {
	t.Helper()
	res, err := http.Get(url)
	if err != nil {
		t.Fatalf("probing %s failed: %v", url, err)
	}
	defer func() { _ = res.Body.Close() }()
	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decoding %s failed: %v", url, err)
	}
	return res.StatusCode, body.Status
}

func waitForHealth(t *testing.T, url string, wantStatus int, wantBody string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var status int
	var body string
	for time.Now().Before(deadline) {
		status, body = healthStatus(t, url)
		if status == wantStatus && body == wantBody {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s settled on %d %q, want %d %q", url, status, body, wantStatus, wantBody)
}

func TestServiceStartsAgainstARealStoreAndReportsReady(t *testing.T) {
	dsn, host := realPostgres(t)
	base, logs, stop := serve(t, storeConfig(t, freeAddress(t), dsnFor(t, dsn, host)))

	if status, body := healthStatus(t, base+"/readyz"); status != http.StatusOK || body != "ready" {
		t.Fatalf("got %d %q, want 200 \"ready\"", status, body)
	}
	if err := stop(); err != nil {
		t.Fatalf("the run returned an error: %v", err)
	}
	if !slices(logs.messages(), "persistence connected") {
		t.Errorf("the connection was never recorded: %v", logs.messages())
	}
	if strings.Contains(logs.String(), postgresPassword) {
		t.Error("a record exposed the store password")
	}
}

// TestStartupIsRefusedWhenTheStoreIsUnreachable proves the service never reaches
// a serving state with no persistence behind it.
func TestStartupIsRefusedWhenTheStoreIsUnreachable(t *testing.T) {
	dsn, host := realPostgres(t)
	gate := newGate(t, host)
	gate.down()

	cfg := storeConfig(t, freeAddress(t), dsnFor(t, dsn, gate.addr()))
	cfg.Database.ConnectTimeout = time.Second

	started := time.Now()
	service, err := app.New(context.Background(), cfg, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	elapsed := time.Since(started)

	if err == nil {
		t.Fatal("the service was built with an unreachable store")
	}
	if service != nil {
		t.Error("expected no service when the store cannot be reached")
	}
	if !errors.Is(err, persistence.ErrUnavailable) {
		t.Errorf("error is %v, want it to wrap ErrUnavailable", err)
	}
	if elapsed > 10*time.Second {
		t.Errorf("the attempt took %s, which is not bounded by the configured timeout", elapsed)
	}
	if _, err := http.Get("http://" + cfg.HTTPAddress + "/healthz"); err == nil {
		t.Error("the service is listening even though startup was refused")
	}
}

// TestReadinessFollowsARealOutageAndRecovers exercises the whole chain against a
// running server whose reachability is cut and restored.
func TestReadinessFollowsARealOutageAndRecovers(t *testing.T) {
	dsn, host := realPostgres(t)
	gate := newGate(t, host)
	base, _, stop := serve(t, storeConfig(t, freeAddress(t), dsnFor(t, dsn, gate.addr())))

	waitForHealth(t, base+"/readyz", http.StatusOK, "ready")

	gate.down()
	waitForHealth(t, base+"/readyz", http.StatusServiceUnavailable, "dependency_unavailable")

	// Liveness answers from the process alone, so the outage must not touch it.
	if status, body := healthStatus(t, base+"/healthz"); status != http.StatusOK || body != "alive" {
		t.Errorf("liveness during the outage: got %d %q, want 200 \"alive\"", status, body)
	}

	gate.raise()
	waitForHealth(t, base+"/readyz", http.StatusOK, "ready")

	if err := stop(); err != nil {
		t.Fatalf("the run returned an error: %v", err)
	}
}

// TestShutdownClearsReadinessDrainsThenClosesTheStore pins the order: traffic is
// refused first, in-flight work finishes next, and the pool is released last.
func TestShutdownClearsReadinessDrainsThenClosesTheStore(t *testing.T) {
	dsn, host := realPostgres(t)
	// Two HTTP-stack goroutines cannot be stopped from here: Fiber's limiter store
	// collector has no Close, and fasthttp's cleaner exits after its idle sleep.
	options := []goleak.Option{
		goleak.IgnoreCurrent(),
		goleak.IgnoreAnyFunction("github.com/gofiber/fiber/v3/internal/memory.(*Storage).gc"),
		goleak.IgnoreAnyFunction("github.com/valyala/fasthttp.(*workerPool).Start.func2"),
	}
	t.Cleanup(func() { goleak.VerifyNone(t, options...) })

	address := freeAddress(t)
	base, logs, stop := serve(t, storeConfig(t, address, dsnFor(t, dsn, host)))
	waitForHealth(t, base+"/readyz", http.StatusOK, "ready")

	if err := stop(); err != nil {
		t.Fatalf("the run returned an error: %v", err)
	}

	want := []string{"shutdown started", "shutdown complete", "persistence closed"}
	if got := ordered(logs.messages(), want); !got {
		t.Errorf("shutdown records %v do not contain %v in order", logs.messages(), want)
	}
	if remaining := backendCount(t, dsnFor(t, dsn, host)); remaining != 0 {
		t.Errorf("%d server-side connection(s) survived shutdown", remaining)
	}
}

func slices(haystack []string, needle string) bool {
	for _, value := range haystack {
		if value == needle {
			return true
		}
	}
	return false
}

func ordered(records, want []string) bool {
	index := 0
	for _, record := range records {
		if index < len(want) && record == want[index] {
			index++
		}
	}
	return index == len(want)
}

// backendCount asks the server how many backends the test database still holds,
// so the claim rests on the server rather than on the pool's own view.
func backendCount(t *testing.T, dsn persistence.DSN) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	parsed, err := url.Parse(dsn.Reveal())
	if err != nil {
		t.Fatal("the connection string could not be inspected")
	}
	database := strings.TrimPrefix(parsed.Path, "/")
	query := parsed.Query()
	query.Set("sslmode", string(persistence.TLSDisable))
	parsed.RawQuery = query.Encode()

	conn, err := pgx.Connect(ctx, parsed.String())
	if err != nil {
		t.Fatal("the observer could not reach the server")
	}
	defer func() { _ = conn.Close(ctx) }()

	const statement = `SELECT count(*) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`
	deadline := time.Now().Add(10 * time.Second)
	var count int
	for time.Now().Before(deadline) {
		if err := conn.QueryRow(ctx, statement, database).Scan(&count); err != nil {
			t.Fatal("counting backends failed")
		}
		if count == 0 {
			return 0
		}
		time.Sleep(50 * time.Millisecond)
	}
	return count
}
