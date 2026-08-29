package integration_test

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

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/browser"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/authstore"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/migration"
	"github.com/shuntps/project_prometheus/services/core-api/internal/ratelimit"
	"github.com/shuntps/project_prometheus/services/core-api/internal/testsupport/httpfixture"
	"github.com/shuntps/project_prometheus/services/core-api/internal/testsupport/postgresfixture"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi/authapi"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi/httperror"
)

// The image is pinned by digest so this evidence is reproducible. The credentials
// are fictitious, live only in the throwaway container and are never production.
const (
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

	instance, err := postgresfixture.Start(ctx, "sslmode=disable")
	authStop = instance.Terminate
	if err != nil {
		authErr = err
		return
	}
	authDSN = instance.DSN()
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

// authConfig is what a test may replace before the use cases are constructed.
type authConfig struct {
	hasher    auth.PasswordVerifier
	limiter   auth.AttemptLimiter
	lifetimes session.Lifetimes
	now       func() time.Time
	global    ratelimit.Policy
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

func newSurface(t *testing.T, tune ...func(*authConfig)) *surface {
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
	store, err := authstore.New(pool)
	if err != nil {
		t.Fatalf("building the store failed: %v", err)
	}

	// cfg gathers what a test may tune before the use cases are built, so the
	// wiring below stays the production one.
	cfg := authConfig{
		hasher:    hasher,
		lifetimes: session.Lifetimes{Absolute: 12 * time.Hour, Idle: 30 * time.Minute, ActivityInterval: time.Minute},
		now:       clock.Now,
		global:    httpfixture.DirectPolicy(100_000),
	}
	for _, apply := range tune {
		apply(&cfg)
	}
	if cfg.limiter == nil {
		limiter, err := ratelimit.NewAuthLimiter(limits, nil)
		if err != nil {
			t.Fatalf("building the limiter failed: %v", err)
		}
		cfg.limiter = limiter
	}
	if policy, ok := cfg.limiter.(interface{ Policy() ratelimit.AuthPolicy }); ok {
		limits = policy.Policy()
	}

	repository, err := authstore.NewRepository(store)
	if err != nil {
		t.Fatalf("building the repository failed: %v", err)
	}
	faults := &faultyStore{inner: repository}
	signIn, err := auth.NewSignIn(auth.SignInOptions{
		Repository: faults, Hasher: cfg.hasher, Limiter: cfg.limiter,
		Lifetimes: cfg.lifetimes, Now: cfg.now,
	})
	if err != nil {
		t.Fatalf("building the sign-in use case failed: %v", err)
	}
	sessions, err := auth.NewSessions(auth.SessionsOptions{
		Repository: faults, Lifetimes: cfg.lifetimes, Now: cfg.now,
	})
	if err != nil {
		t.Fatalf("building the session use cases failed: %v", err)
	}

	logs := &bytes.Buffer{}
	opts := httpapi.Options{
		Logger:    slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		RateLimit: cfg.global,
		Auth:      &authapi.Options{SignIn: signIn, Sessions: sessions, Origin: origin},
	}

	app := httpfixture.MustApp(t, &opts)
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
func (s *surface) account(t *testing.T, kind iam.Kind, status iam.Status, roles ...iam.Role) (string, iam.Account) {
	t.Helper()
	raw := nextAddress()
	address, err := iam.NormaliseEmail(raw)
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

func sessionIDOf(t *testing.T, s *surface, account iam.Account) session.ID {
	t.Helper()
	var raw string
	if err := s.pool.QueryRow(context.Background(),
		`SELECT id FROM account_sessions WHERE account_id = $1 AND revoked_at IS NULL AND rotated_to IS NULL
		 ORDER BY created_at DESC LIMIT 1`, account.ID.String()).Scan(&raw); err != nil {
		t.Fatalf("reading the session failed: %v", err)
	}
	id, err := iam.ParseAccountID(raw)
	if err != nil {
		t.Fatalf("parsing the session identifier failed: %v", err)
	}
	return session.ID(id)
}

func (s *surface) liveSessions(t *testing.T, account iam.Account) int {
	t.Helper()
	var live int
	if err := s.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM account_sessions WHERE account_id = $1 AND revoked_at IS NULL AND rotated_to IS NULL`,
		account.ID.String()).Scan(&live); err != nil {
		t.Fatalf("counting sessions failed: %v", err)
	}
	return live
}

// The public refusal messages of the authentication surface. They are pinned here
// rather than imported, so changing one in production turns these tests red.
const (
	crossSiteMessage  = "The request did not come from the application."
	csrfTokenMessage  = "The request did not carry a valid CSRF token."
	contentTypeReason = "The request must be sent as application/json."
)

// messageOf decodes the error contract and returns the message a client reads.
// It consumes the body, so a caller keeps the returned value rather than re-reading.
func messageOf(t *testing.T, res *http.Response) string {
	t.Helper()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading the body failed: %v", err)
	}
	var decoded httperror.ErrorResponse
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("the answer %q is not the error contract: %v", raw, err)
	}
	return decoded.Error.Message
}
