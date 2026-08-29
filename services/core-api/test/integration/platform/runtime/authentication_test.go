package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/goleak"

	"github.com/shuntps/project_prometheus/services/core-api/internal/app"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/browser"
	"github.com/shuntps/project_prometheus/services/core-api/internal/config"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/authstore"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/migration"
	"github.com/shuntps/project_prometheus/services/core-api/internal/ratelimit"
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
	origin, err := browser.ParseOrigin(publicAuthOrigin)
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
	origin, err := browser.ParseOrigin(publicAuthOrigin)
	if err != nil {
		t.Fatalf("parsing the origin failed: %v", err)
	}

	cases := map[string]func(*config.Config){
		"no public origin":         func(c *config.Config) { c.PublicOrigin = browser.Origin{} },
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

// waitForGrantLockWait observes a backend actually blocked on a lock inside
// PostgreSQL, so the interleaving below is a state, not an elapsed delay.
func waitForGrantLockWait(t *testing.T, pool *pgxpool.Pool, fragment string) int {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		var pid int
		err := pool.QueryRow(context.Background(), `
			SELECT pid FROM pg_stat_activity
			WHERE state = 'active' AND wait_event_type = 'Lock' AND query LIKE $1
			LIMIT 1`, "%"+fragment+"%").Scan(&pid)
		if err == nil {
			return pid
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("inspecting server activity failed: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no backend ever waited on a lock for a statement matching %q", fragment)
	return 0
}

func poolOn(t *testing.T, target persistence.DSN) *pgxpool.Pool {
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
	t.Cleanup(pool.Close)
	return pool
}

// signedInClient signs an account in over HTTP and returns what a browser would
// hold afterwards: the session cookie and the synchronizer token.
func signedInClient(t *testing.T, base, address, plaintext string) (*http.Cookie, string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"email": address, "password": plaintext})
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
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d, want 201", res.StatusCode)
	}
	var view struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&view); err != nil {
		t.Fatalf("decoding the session view failed: %v", err)
	}
	for _, cookie := range res.Cookies() {
		if cookie.Name == browser.SessionCookieName {
			return cookie, view.CSRFToken
		}
	}
	t.Fatal("sign-in set no session cookie")
	return nil, ""
}

func activityRequest(t *testing.T, base string, cookie *http.Cookie, csrf string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+"/api/v1/auth/session/activity", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("building the request failed: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", publicAuthOrigin)
	req.Header.Set(browser.CSRFHeader, csrf)
	req.AddCookie(cookie)
	return req
}

// TestActivityIsRefusedByARoleWithdrawnMidRequest drives the running service against
// a real database and interleaves the withdrawal with the renewal it authorises.
func TestActivityIsRefusedByARoleWithdrawnMidRequest(t *testing.T) {
	dsn, host := realPostgres(t)
	target := dsnFor(t, dsn, host)
	applySchema(t, target)

	cfg := storeConfig(t, freeAddress(t), target)
	origin, err := browser.ParseOrigin(publicAuthOrigin)
	if err != nil {
		t.Fatalf("parsing the origin failed: %v", err)
	}
	cfg.PublicOrigin = origin

	pool := poolOn(t, target)
	store, err := authstore.New(pool)
	if err != nil {
		t.Fatalf("building the store failed: %v", err)
	}
	hasher, err := password.NewHasher(cfg.Auth.Password.Params, cfg.Auth.Password.Policy, nil)
	if err != nil {
		t.Fatalf("building the hasher failed: %v", err)
	}
	const address, plaintext = "holder@example.com", "correct-horse-battery-staple"
	encoded, err := hasher.Hash(plaintext)
	if err != nil {
		t.Fatalf("hashing failed: %v", err)
	}
	ctx := context.Background()
	email, err := iam.NormaliseEmail(address)
	if err != nil {
		t.Fatalf("normalising the address failed: %v", err)
	}
	account, err := store.CreateAccount(ctx, authstore.NewAccount{
		Kind:     iam.KindViewer,
		Status:   iam.StatusActive,
		Email:    email,
		Password: encoded,
		Roles:    []iam.Role{iam.RoleViewer},
	}, time.Now().UTC())
	if err != nil {
		t.Fatalf("creating the account failed: %v", err)
	}

	base, _, stop := serve(t, cfg)
	defer func() {
		if err := stop(); err != nil {
			t.Fatalf("the service did not shut down cleanly: %v", err)
		}
	}()

	cookie, csrf := signedInClient(t, base, address, plaintext)

	// The route works while the role is held, so the refusal below is the
	// withdrawal and not a misdirected request.
	granted, err := http.DefaultClient.Do(activityRequest(t, base, cookie, csrf))
	if err != nil {
		t.Fatalf("the request failed: %v", err)
	}
	granted.Body.Close()
	if granted.StatusCode != http.StatusNoContent {
		t.Fatalf("the renewal returned %d while the role was held, want 204", granted.StatusCode)
	}

	var sessionID string
	if err := pool.QueryRow(ctx,
		`SELECT id FROM account_sessions WHERE account_id = $1 AND revoked_at IS NULL`,
		account.ID.String()).Scan(&sessionID); err != nil {
		t.Fatalf("locating the session failed: %v", err)
	}
	var activeBefore, idleBefore time.Time
	stamps := func() (time.Time, time.Time) {
		var active, idle time.Time
		if err := pool.QueryRow(ctx,
			`SELECT last_active_at, idle_expires_at FROM account_sessions WHERE id = $1`,
			sessionID).Scan(&active, &idle); err != nil {
			t.Fatalf("reading the deadlines failed: %v", err)
		}
		return active, idle
	}
	activeBefore, idleBefore = stamps()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("beginning failed: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `DELETE FROM account_role_grants WHERE account_id = $1`, account.ID.String()); err != nil {
		t.Fatalf("withdrawing the role failed: %v", err)
	}

	answers := make(chan int, 1)
	go func() {
		res, err := http.DefaultClient.Do(activityRequest(t, base, cookie, csrf))
		if err != nil {
			answers <- 0
			return
		}
		defer res.Body.Close()
		answers <- res.StatusCode
	}()
	waitForGrantLockWait(t, pool, "account_role_grants")
	select {
	case status := <-answers:
		t.Fatalf("the request answered %d while it was reported waiting", status)
	default:
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("committing the withdrawal failed: %v", err)
	}
	if status := <-answers; status != http.StatusForbidden {
		t.Fatalf("the renewal returned %d after the withdrawal committed, want 403", status)
	}
	if active, idle := stamps(); !active.Equal(activeBefore) || !idle.Equal(idleBefore) {
		t.Errorf("a refused renewal moved the deadlines to %s / %s", active, idle)
	}
}
