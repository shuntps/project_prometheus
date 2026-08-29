package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/browser"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/authstore"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/migration"
	"github.com/shuntps/project_prometheus/services/core-api/internal/ratelimit"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi"
)

// The image is pinned by digest so this evidence is reproducible. The credentials
// are fictitious, live only in the throwaway container and are never production.
const (
	authPostgresImage    = "postgres:18.6-alpine@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2"
	authPostgresDatabase = "core_api_test"
	authPostgresUser     = "core_api_test"
	authPostgresPassword = "test-only-not-a-production-secret"

	publicOrigin  = "https://app.example.com"
	foreignOrigin = "https://attacker.example"
	// A password comfortably above the adopted single-factor minimum.
	probePassword  = "correct-horse-battery-staple-42"
	sessionRoute   = "/api/v1/auth/session"
	broadcastRoute = "/api/v1/auth/broadcast-access"
	activityRoute  = "/api/v1/auth/session/activity"
)

var (
	authOnce sync.Once
	authDSN  string
	authErr  error
	authStop func()
)

func TestMain(m *testing.M) {
	code := m.Run()
	if authStop != nil {
		authStop()
	}
	os.Exit(code)
}

func startAuthPostgres() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	container, err := tcpostgres.Run(ctx, authPostgresImage,
		tcpostgres.WithDatabase(authPostgresDatabase),
		tcpostgres.WithUsername(authPostgresUser),
		tcpostgres.WithPassword(authPostgresPassword),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(2*time.Minute),
		),
	)
	if err != nil {
		authErr = err
		return
	}
	authStop = func() { _ = testcontainers.TerminateContainer(container) }
	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		authErr = err
		return
	}
	authDSN = dsn
}

// surface is one running authentication surface and the pieces a test needs to
// drive it: the store behind it, the clock it reads and the records it wrote.
type surface struct {
	app    *fiber.App
	store  *authstore.Store
	pool   *pgxpool.Pool
	logs   *bytes.Buffer
	clock  *testClock
	limits ratelimit.AuthPolicy
	faults *faultyStore
}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newSurface(t *testing.T, tune ...func(*httpapi.Options)) *surface {
	t.Helper()
	authOnce.Do(startAuthPostgres)
	if authErr != nil {
		t.Fatalf("starting PostgreSQL failed: %v", authErr)
	}

	pool, err := pgxpool.New(context.Background(), authDSN)
	if err != nil {
		t.Fatalf("opening the pool failed: %v", err)
	}
	t.Cleanup(pool.Close)
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

	origin, err := browser.ParseOrigin(publicOrigin)
	if err != nil {
		t.Fatalf("parsing the origin failed: %v", err)
	}
	hasher, err := password.NewHasher(
		password.Params{MemoryKiB: password.FloorMemoryKiB, Iterations: password.FloorIterations, Lanes: password.FloorLanes},
		password.Policy{MinCodePoints: password.SingleFactorMinimum}, nil)
	if err != nil {
		t.Fatalf("building the hasher failed: %v", err)
	}
	limits := ratelimit.AuthPolicy{
		ClientAttempts: 1_000, IdentityAttempts: 1_000,
		Window: 15 * time.Minute, Capacity: ratelimit.MinAuthCapacity,
	}
	clock := &testClock{now: time.Now().UTC().Truncate(time.Second)}
	store := authstore.New(pool)

	auth := httpapi.AuthOptions{
		Store:     &faultyStore{inner: store},
		Hasher:    hasher,
		Lifetimes: session.Lifetimes{Absolute: 12 * time.Hour, Idle: 30 * time.Minute, ActivityInterval: time.Minute},
		Origin:    origin,
		Now:       clock.Now,
	}
	logs := &bytes.Buffer{}
	opts := httpapi.Options{
		Logger:    slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		RateLimit: directPolicy(100_000),
		Auth:      &auth,
	}
	for _, apply := range tune {
		apply(&opts)
	}
	faults, _ := opts.Auth.Store.(*faultyStore)
	if opts.Auth.Limiter == nil {
		limiter, err := ratelimit.NewAuthLimiter(limits, nil)
		if err != nil {
			t.Fatalf("building the limiter failed: %v", err)
		}
		opts.Auth.Limiter = limiter
	}
	limits = opts.Auth.Limiter.Policy()

	app := mustApp(t, opts)
	return &surface{app: app, store: store, pool: pool, logs: logs, clock: clock, limits: limits, faults: faults}
}

var accountCounter = struct {
	mu sync.Mutex
	n  int
}{}

func nextAddress() string {
	accountCounter.mu.Lock()
	defer accountCounter.mu.Unlock()
	accountCounter.n++
	return fmt.Sprintf("probe%d@example.com", accountCounter.n)
}

// account writes a real account with a real Argon2id credential, so every sign-in
// below verifies against material the production path would have produced.
func (s *surface) account(t *testing.T, kind auth.Kind, status auth.Status, roles ...auth.Role) (string, auth.Account) {
	t.Helper()
	raw := nextAddress()
	address, err := auth.NormaliseEmail(raw)
	if err != nil {
		t.Fatalf("normalising failed: %v", err)
	}
	hasher, err := password.NewHasher(
		password.Params{MemoryKiB: password.FloorMemoryKiB, Iterations: password.FloorIterations, Lanes: password.FloorLanes},
		password.Policy{MinCodePoints: password.SingleFactorMinimum}, nil)
	if err != nil {
		t.Fatalf("building the hasher failed: %v", err)
	}
	encoded, err := hasher.Hash(probePassword)
	if err != nil {
		t.Fatalf("hashing failed: %v", err)
	}
	created, err := s.store.CreateAccount(context.Background(), authstore.NewAccount{
		Kind: kind, Status: status, Email: address, Password: encoded, Roles: roles,
	}, s.clock.Now())
	if err != nil {
		t.Fatalf("creating the account failed: %v", err)
	}
	return raw, created
}

// request is one browser-shaped call. Every field a defence reads is set
// explicitly so a test can remove exactly one of them.
type request struct {
	method        string
	target        string
	body          any
	origin        string
	fetchSite     string
	noJSON        bool
	cookie        string
	csrf          string
	requestID     string
	contentType   string
	noContentType bool
}

func (s *surface) send(t *testing.T, r request) *http.Response {
	t.Helper()
	var body io.Reader
	if r.body != nil {
		encoded, err := json.Marshal(r.body)
		if err != nil {
			t.Fatalf("encoding the body failed: %v", err)
		}
		body = bytes.NewReader(encoded)
	}
	req := httptest.NewRequest(r.method, r.target, body)
	if r.body != nil && !r.noJSON {
		req.Header.Set(fiber.HeaderContentType, "application/json")
	}
	if r.noJSON {
		req.Header.Set(fiber.HeaderContentType, "application/x-www-form-urlencoded")
	}
	if r.contentType != "" {
		req.Header.Set(fiber.HeaderContentType, r.contentType)
	}
	if r.noContentType {
		req.Header.Del(fiber.HeaderContentType)
	}
	if r.origin != "" {
		req.Header.Set(browser.OriginHeader, r.origin)
	}
	if r.fetchSite != "" {
		req.Header.Set(browser.FetchSiteHeader, r.fetchSite)
	}
	if r.cookie != "" {
		req.AddCookie(&http.Cookie{Name: browser.SessionCookieName, Value: r.cookie})
	}
	if r.csrf != "" {
		req.Header.Set(browser.CSRFHeader, r.csrf)
	}
	if r.requestID != "" {
		req.Header.Set("X-Request-Id", r.requestID)
	}
	res, err := s.app.Test(req, fiber.TestConfig{Timeout: 30 * time.Second, FailOnTimeout: true})
	if err != nil {
		t.Fatalf("the request failed: %v", err)
	}
	t.Cleanup(func() { _ = res.Body.Close() })
	return res
}

type signedIn struct {
	response *http.Response
	body     string
	token    string
	csrf     string
	view     map[string]any
}

func (s *surface) signIn(t *testing.T, address, secret string) signedIn {
	t.Helper()
	res := s.send(t, request{
		method: http.MethodPost, target: sessionRoute,
		body:   map[string]string{"email": address, "password": secret},
		origin: publicOrigin, fetchSite: "same-origin",
	})
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading the body failed: %v", err)
	}
	out := signedIn{response: res, body: string(raw)}
	if res.StatusCode == http.StatusCreated {
		if err := json.Unmarshal(raw, &out.view); err != nil {
			t.Fatalf("decoding the body failed: %v", err)
		}
		out.csrf, _ = out.view["csrf_token"].(string)
		for _, cookie := range res.Cookies() {
			if cookie.Name == browser.SessionCookieName {
				out.token = cookie.Value
			}
		}
	}
	return out
}

func bodyOf(t *testing.T, res *http.Response) string {
	t.Helper()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading the body failed: %v", err)
	}
	return string(raw)
}

func sessionCookie(res *http.Response) *http.Cookie {
	for _, cookie := range res.Cookies() {
		if cookie.Name == browser.SessionCookieName {
			return cookie
		}
	}
	return nil
}

func sessionIDOf(t *testing.T, s *surface, account auth.Account) auth.SessionID {
	t.Helper()
	var raw string
	if err := s.pool.QueryRow(context.Background(),
		`SELECT id FROM account_sessions WHERE account_id = $1 AND revoked_at IS NULL AND rotated_to IS NULL
		 ORDER BY created_at DESC LIMIT 1`, account.ID.String()).Scan(&raw); err != nil {
		t.Fatalf("reading the session failed: %v", err)
	}
	id, err := auth.ParseAccountID(raw)
	if err != nil {
		t.Fatalf("parsing the session identifier failed: %v", err)
	}
	return auth.SessionID(id)
}

func (s *surface) liveSessions(t *testing.T, account auth.Account) int {
	t.Helper()
	var live int
	if err := s.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM account_sessions WHERE account_id = $1 AND revoked_at IS NULL AND rotated_to IS NULL`,
		account.ID.String()).Scan(&live); err != nil {
		t.Fatalf("counting sessions failed: %v", err)
	}
	return live
}
