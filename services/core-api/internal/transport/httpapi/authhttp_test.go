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
	"regexp"
	"strings"
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
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/authstore"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/migration"
	"github.com/shuntps/project_prometheus/services/core-api/internal/ratelimit"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/web"
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

// requestIDPattern normalises the one field a uniform answer is allowed to vary.
var requestIDPattern = regexp.MustCompile(`"request_id":"[^"]*"`)

// serverIDPattern is the only shape the canonical identifier may have: the 43
// Base64URL characters of a 32-byte token the server drew itself.
var serverIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

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

	origin, err := web.ParseOrigin(publicOrigin)
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
		req.Header.Set(web.OriginHeader, r.origin)
	}
	if r.fetchSite != "" {
		req.Header.Set(web.FetchSiteHeader, r.fetchSite)
	}
	if r.cookie != "" {
		req.AddCookie(&http.Cookie{Name: web.SessionCookieName, Value: r.cookie})
	}
	if r.csrf != "" {
		req.Header.Set(web.CSRFHeader, r.csrf)
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
			if cookie.Name == web.SessionCookieName {
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
		if cookie.Name == web.SessionCookieName {
			return cookie
		}
	}
	return nil
}

func TestASignedInAccountReceivesASessionAndItsCSRFToken(t *testing.T) {
	s := newSurface(t)
	address, account := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)

	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d: %s", in.response.StatusCode, in.body)
	}
	if in.token == "" {
		t.Fatal("no session cookie was set")
	}
	if in.csrf == "" {
		t.Fatal("no CSRF token was handed back")
	}
	if in.view["account_id"] != account.ID.String() {
		t.Errorf("the response names %v, want %s", in.view["account_id"], account.ID)
	}
	if in.view["surface"] != string(auth.SurfacePublic) {
		t.Errorf("the session opened on surface %v", in.view["surface"])
	}

	// The session is immediately usable and reports the same authority.
	res := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("resolving the session returned %d: %s", res.StatusCode, bodyOf(t, res))
	}
}

// TestEveryRefusedSignInIsIndistinguishable: an unknown address, a wrong password
// and an unusable account must all leave by exactly the same door.
func TestEveryRefusedSignInIsIndistinguishable(t *testing.T) {
	s := newSurface(t)
	known, _ := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	pending, _ := s.account(t, auth.KindViewer, auth.StatusPending, auth.RoleViewer)
	suspended, _ := s.account(t, auth.KindViewer, auth.StatusSuspended, auth.RoleViewer)
	closed, _ := s.account(t, auth.KindViewer, auth.StatusClosed, auth.RoleViewer)
	operator, _ := s.account(t, auth.KindOperator, auth.StatusActive, auth.RoleOperatorSupport)

	cases := map[string][2]string{
		"unknown address":   {"nobody-here@example.com", probePassword},
		"wrong password":    {known, "wrong-" + probePassword},
		"pending account":   {pending, probePassword},
		"suspended account": {suspended, probePassword},
		"closed account":    {closed, probePassword},
		"operator account":  {operator, probePassword},
		"malformed address": {"not-an-address", probePassword},
		"empty address":     {"", probePassword},
		"empty password":    {known, ""},
	}

	var seen []string
	for name, pair := range cases {
		in := s.signIn(t, pair[0], pair[1])
		if in.response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s returned %d, want 401: %s", name, in.response.StatusCode, in.body)
		}
		if sessionCookie(in.response) != nil {
			t.Fatalf("%s set a session cookie", name)
		}
		// The request identifier differs per call and is the only field allowed to.
		normalised := requestIDPattern.ReplaceAllString(in.body, `"request_id":"x"`)
		seen = append(seen, name+"\x00"+normalised)
	}
	first := strings.SplitN(seen[0], "\x00", 2)[1]
	for _, entry := range seen {
		name, body, _ := strings.Cut(entry, "\x00")
		if body != first {
			t.Errorf("%s answered %q while another cause answered %q", name, body, first)
		}
	}
}

// TestAnOperatorAccountCannotOpenThePublicSurface keeps the operator journey
// unreachable through the public one, whatever the credential is.
func TestAnOperatorAccountCannotOpenThePublicSurface(t *testing.T) {
	s := newSurface(t)
	operator, account := s.account(t, auth.KindOperator, auth.StatusActive, auth.RoleOperatorSupport)

	in := s.signIn(t, operator, probePassword)
	if in.response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("an operator signed in through the public surface: %d %s", in.response.StatusCode, in.body)
	}
	var sessions int
	if err := s.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM account_sessions WHERE account_id = $1`, account.ID.String()).Scan(&sessions); err != nil {
		t.Fatalf("counting sessions failed: %v", err)
	}
	if sessions != 0 {
		t.Fatalf("%d session rows were written for a refused operator", sessions)
	}
}

func TestTheSessionCookieCarriesEveryAdoptedAttribute(t *testing.T) {
	s := newSurface(t)
	address, _ := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)

	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d: %s", in.response.StatusCode, in.body)
	}
	cookie := sessionCookie(in.response)
	if cookie == nil {
		t.Fatal("no session cookie was set")
	}
	if !strings.HasPrefix(cookie.Name, "__Host-") {
		t.Errorf("the cookie is named %q, without the __Host- prefix", cookie.Name)
	}
	if !cookie.Secure {
		t.Error("the cookie is not Secure, which the __Host- prefix requires")
	}
	if !cookie.HttpOnly {
		t.Error("the cookie is not HttpOnly, so a script could read it")
	}
	if cookie.Path != "/" {
		t.Errorf("the cookie path is %q, want / as the __Host- prefix requires", cookie.Path)
	}
	if cookie.Domain != "" {
		t.Errorf("the cookie declares Domain=%q, which the __Host- prefix forbids", cookie.Domain)
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("the cookie declares SameSite=%v, want Lax", cookie.SameSite)
	}
	raw := in.response.Header.Get("Set-Cookie")
	if strings.Contains(strings.ToLower(raw), "domain=") {
		t.Errorf("the Set-Cookie header carries a Domain attribute: %q", raw)
	}
}

// TestTheSessionTokenNeverLeavesTheCookie keeps the one bearer secret out of the
// body, the errors, the headers and the records.
func TestTheSessionTokenNeverLeavesTheCookie(t *testing.T) {
	s := newSurface(t)
	address, _ := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)

	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d: %s", in.response.StatusCode, in.body)
	}
	token := in.token
	if len(token) < 20 {
		t.Fatalf("the token is implausibly short: %q", token)
	}

	if strings.Contains(in.body, token) {
		t.Error("the sign-in body carried the session token")
	}
	for name, values := range in.response.Header {
		if strings.EqualFold(name, "Set-Cookie") {
			continue
		}
		for _, value := range values {
			if strings.Contains(value, token) {
				t.Errorf("header %s carried the session token", name)
			}
		}
	}

	// A later authenticated call must not echo it either.
	res := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: token, origin: publicOrigin})
	if body := bodyOf(t, res); strings.Contains(body, token) {
		t.Error("the session body carried the session token")
	}

	// Neither the whole token nor a prefix of it may appear in the records.
	logs := s.logs.String()
	if strings.Contains(logs, token) {
		t.Error("the records carried the session token")
	}
	if prefix := token[:20]; strings.Contains(logs, prefix) {
		t.Error("the records carried a prefix of the session token")
	}
	if strings.Contains(logs, address) || strings.Contains(logs, probePassword) {
		t.Error("the records carried the address or the password")
	}
}

// TestNoStoredMaterialReproducesTheToken proves the database holds only an
// irreversible fingerprint, so a read of it cannot be replayed as a cookie.
func TestNoStoredMaterialReproducesTheToken(t *testing.T) {
	s := newSurface(t)
	address, _ := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", in.response.StatusCode)
	}

	var fingerprint []byte
	var storedCSRF string
	if err := s.pool.QueryRow(context.Background(),
		`SELECT token_fingerprint, csrf_token FROM account_sessions`).Scan(&fingerprint, &storedCSRF); err != nil {
		t.Fatalf("reading the row failed: %v", err)
	}
	if strings.Contains(string(fingerprint), in.token) {
		t.Error("the stored fingerprint contains the token")
	}
	// The CSRF token is stored as issued, which is deliberate: the server has to
	// hand it back. It must not be the session token.
	if storedCSRF != in.csrf {
		t.Error("the stored CSRF token is not the one handed to the client")
	}
	if storedCSRF == in.token {
		t.Error("the CSRF token and the session token are the same value")
	}
}

func TestAnUnusableTokenNeverResolves(t *testing.T) {
	s := newSurface(t)
	address, account := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", in.response.StatusCode)
	}

	valid, err := session.ParseToken(in.token)
	if err != nil {
		t.Fatalf("the issued token does not parse: %v", err)
	}
	drawn, err := session.NewToken(nil)
	if err != nil {
		t.Fatalf("drawing failed: %v", err)
	}

	cases := map[string]string{
		"absent":                  "",
		"malformed":               "not-a-token",
		"truncated":               in.token[:len(in.token)-1],
		"well-formed but unknown": drawn.Reveal(),
	}
	for name, token := range cases {
		res := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: token, origin: publicOrigin})
		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("a %s token returned %d, want 401", name, res.StatusCode)
		}
	}

	// Revoked.
	if err := s.store.RevokeSession(context.Background(), sessionIDOf(t, s, account), s.clock.Now()); err != nil {
		t.Fatalf("revoking failed: %v", err)
	}
	res := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: valid.Reveal(), origin: publicOrigin})
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("a revoked session returned %d, want 401", res.StatusCode)
	}
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

// TestAnExpiredSessionCannotBeExtendedByTheBrowser: a cookie the browser still
// holds cannot revive a session, and using it pushes neither expiry out.
func TestAnExpiredSessionCannotBeExtendedByTheBrowser(t *testing.T) {
	s := newSurface(t)
	address, _ := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", in.response.StatusCode)
	}

	// Usable while inside the idle window.
	s.clock.advance(29 * time.Minute)
	res := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("an active session returned %d", res.StatusCode)
	}

	// Past the idle expiry the cookie is inert, and stays inert on every retry.
	s.clock.advance(31 * time.Minute)
	for attempt := 1; attempt <= 3; attempt++ {
		res := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin})
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d on an expired session returned %d", attempt, res.StatusCode)
		}
	}

	var idle, absolute time.Time
	if err := s.pool.QueryRow(context.Background(),
		`SELECT idle_expires_at, absolute_expires_at FROM account_sessions`).Scan(&idle, &absolute); err != nil {
		t.Fatalf("reading the row failed: %v", err)
	}
	if !idle.Before(s.clock.Now()) {
		t.Error("a refused request moved the idle expiry forward")
	}
	if !absolute.After(s.clock.Now()) {
		t.Fatal("the absolute expiry was reached, so the idle expiry is not what refused the request")
	}
}

func TestSignOutRevokesTheSessionAndClearsTheCookie(t *testing.T) {
	s := newSurface(t)
	address, _ := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", in.response.StatusCode)
	}

	res := s.send(t, request{
		method: http.MethodDelete, target: sessionRoute,
		cookie: in.token, csrf: in.csrf, origin: publicOrigin, fetchSite: "same-origin", contentType: "application/json"})
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("sign-out returned %d: %s", res.StatusCode, bodyOf(t, res))
	}
	cleared := sessionCookie(res)
	if cleared == nil {
		t.Fatal("sign-out did not write a replacement cookie")
	}
	if cleared.Value != "" || cleared.MaxAge >= 0 {
		t.Errorf("the cookie was not cleared: value=%q max-age=%d", cleared.Value, cleared.MaxAge)
	}
	if !cleared.Secure || !cleared.HttpOnly || cleared.Path != "/" || cleared.Domain != "" {
		t.Error("the clearing cookie does not match the attributes it must replace")
	}

	// The token is inert immediately, and every repeat stays successful without
	// restoring anything.
	for attempt := 1; attempt <= 3; attempt++ {
		res := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin})
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("the session still resolved after sign-out (attempt %d): %d", attempt, res.StatusCode)
		}
		repeat := s.send(t, request{
			method: http.MethodDelete, target: sessionRoute,
			cookie: in.token, csrf: in.csrf, origin: publicOrigin, fetchSite: "same-origin", contentType: "application/json"})
		if repeat.StatusCode != http.StatusNoContent {
			t.Fatalf("repeat %d of sign-out returned %d", attempt, repeat.StatusCode)
		}
	}

	// Signing out with no cookie at all is the same successful answer.
	empty := s.send(t, request{method: http.MethodDelete, target: sessionRoute, origin: publicOrigin, fetchSite: "same-origin", contentType: "application/json"})
	if empty.StatusCode != http.StatusNoContent {
		t.Fatalf("sign-out without a session returned %d", empty.StatusCode)
	}
}

func TestSignOutRequiresTheSynchronizerToken(t *testing.T) {
	s := newSurface(t)
	address, _ := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", in.response.StatusCode)
	}
	forged, err := session.NewCSRFToken(nil)
	if err != nil {
		t.Fatalf("drawing failed: %v", err)
	}

	cases := map[string]string{
		"absent":    "",
		"forged":    forged.Reveal(),
		"malformed": "not-a-token",
		"truncated": in.csrf[:len(in.csrf)-1],
	}
	for name, token := range cases {
		res := s.send(t, request{
			method: http.MethodDelete, target: sessionRoute,
			cookie: in.token, csrf: token, origin: publicOrigin, fetchSite: "same-origin", contentType: "application/json"})
		if res.StatusCode != http.StatusForbidden {
			t.Errorf("a %s CSRF token returned %d, want 403", name, res.StatusCode)
		}
		// The session must survive a refused sign-out.
		check := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin})
		if check.StatusCode != http.StatusOK {
			t.Fatalf("a refused sign-out (%s) ended the session anyway: %d", name, check.StatusCode)
		}
	}

	// The genuine token still works, so the refusals above were the token's doing.
	res := s.send(t, request{
		method: http.MethodDelete, target: sessionRoute,
		cookie: in.token, csrf: in.csrf, origin: publicOrigin, fetchSite: "same-origin", contentType: "application/json"})
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("the genuine CSRF token was refused: %d", res.StatusCode)
	}
}

// TestACrossSiteContextIsRefusedBeforeAnythingHappens covers login CSRF too: with
// no session yet, the origin check and the request shape are the whole defence.
func TestACrossSiteContextIsRefusedBeforeAnythingHappens(t *testing.T) {
	s := newSurface(t)
	address, account := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)

	cases := []struct {
		name    string
		request request
		want    int
	}{
		{"foreign origin", request{method: http.MethodPost, target: sessionRoute, origin: foreignOrigin, fetchSite: "cross-site"}, http.StatusForbidden},
		{"absent origin", request{method: http.MethodPost, target: sessionRoute}, http.StatusForbidden},
		{"null origin", request{method: http.MethodPost, target: sessionRoute, origin: "null"}, http.StatusForbidden},
		{"sibling host", request{method: http.MethodPost, target: sessionRoute, origin: "https://app.example.com.attacker.example"}, http.StatusForbidden},
		{"plain-text origin", request{method: http.MethodPost, target: sessionRoute, origin: "http://app.example.com"}, http.StatusForbidden},
		{"cross-site fetch metadata", request{method: http.MethodPost, target: sessionRoute, origin: publicOrigin, fetchSite: "cross-site"}, http.StatusForbidden},
		{"same-site fetch metadata", request{method: http.MethodPost, target: sessionRoute, origin: publicOrigin, fetchSite: "same-site"}, http.StatusForbidden},
		{"form content type", request{method: http.MethodPost, target: sessionRoute, origin: publicOrigin, fetchSite: "same-origin", noJSON: true}, http.StatusUnsupportedMediaType},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := c.request
			r.body = map[string]string{"email": address, "password": probePassword}
			res := s.send(t, r)
			if res.StatusCode != c.want {
				t.Fatalf("returned %d, want %d: %s", res.StatusCode, c.want, bodyOf(t, res))
			}
			if sessionCookie(res) != nil {
				t.Error("a refused request still set a session cookie")
			}
		})
	}

	var sessions int
	if err := s.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM account_sessions WHERE account_id = $1`, account.ID.String()).Scan(&sessions); err != nil {
		t.Fatalf("counting sessions failed: %v", err)
	}
	if sessions != 0 {
		t.Fatalf("%d sessions were created by refused cross-site requests", sessions)
	}
}

// TestAuthorisationIsGrantedOnlyByAnExplicitRule drives the real principal through
// the domain function and proves both outcomes on the same running surface.
func TestAuthorisationIsGrantedOnlyByAnExplicitRule(t *testing.T) {
	s := newSurface(t)

	viewerAddress, _ := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	creatorAddress, _ := s.account(t, auth.KindCreator, auth.StatusActive, auth.RoleViewer, auth.RoleCreator)
	bareAddress, _ := s.account(t, auth.KindViewer, auth.StatusActive)

	viewer := s.signIn(t, viewerAddress, probePassword)
	creator := s.signIn(t, creatorAddress, probePassword)
	bare := s.signIn(t, bareAddress, probePassword)
	for name, in := range map[string]signedIn{"viewer": viewer, "creator": creator, "bare": bare} {
		if in.response.StatusCode != http.StatusCreated {
			t.Fatalf("%s could not sign in: %d %s", name, in.response.StatusCode, in.body)
		}
	}

	// Only the role that explicitly carries the permission is granted it.
	if res := s.send(t, request{method: http.MethodGet, target: broadcastRoute, cookie: creator.token, origin: publicOrigin}); res.StatusCode != http.StatusOK {
		t.Errorf("a creator was refused the broadcast permission: %d", res.StatusCode)
	}
	if res := s.send(t, request{method: http.MethodGet, target: broadcastRoute, cookie: viewer.token, origin: publicOrigin}); res.StatusCode != http.StatusForbidden {
		t.Errorf("a viewer was granted the broadcast permission: %d", res.StatusCode)
	}
	// An account holding no role at all is granted nothing, not even the read every
	// named role carries.
	if res := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: bare.token, origin: publicOrigin}); res.StatusCode != http.StatusForbidden {
		t.Errorf("an account with no role read its own session: %d", res.StatusCode)
	}
	if res := s.send(t, request{method: http.MethodGet, target: broadcastRoute, cookie: bare.token, origin: publicOrigin}); res.StatusCode != http.StatusForbidden {
		t.Errorf("an account with no role was granted the broadcast permission: %d", res.StatusCode)
	}
}

// TestNoClientHeaderDecidesTheIdentity keeps the resolved session the only source
// of the account, the kind, the roles and the surface.
func TestNoClientHeaderDecidesTheIdentity(t *testing.T) {
	s := newSurface(t)
	viewerAddress, viewerAccount := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	_, creatorAccount := s.account(t, auth.KindCreator, auth.StatusActive, auth.RoleViewer, auth.RoleCreator)

	viewer := s.signIn(t, viewerAddress, probePassword)
	if viewer.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", viewer.response.StatusCode)
	}

	spoofed := []struct{ header, value string }{
		{"X-Account-Id", creatorAccount.ID.String()},
		{"X-Account-Kind", string(auth.KindCreator)},
		{"X-Role", string(auth.RoleCreator)},
		{"X-Roles", string(auth.RoleOperatorFinance)},
		{"X-Surface", string(auth.SurfaceOperator)},
		{"X-Permission", string(auth.PermissionStreamBroadcast)},
		{"X-Forwarded-User", creatorAccount.ID.String()},
	}
	req := httptest.NewRequest(http.MethodGet, sessionRoute, nil)
	req.Header.Set(web.OriginHeader, publicOrigin)
	req.AddCookie(&http.Cookie{Name: web.SessionCookieName, Value: viewer.token})
	for _, h := range spoofed {
		req.Header.Set(h.header, h.value)
	}
	res, err := s.app.Test(req, fiber.TestConfig{Timeout: 30 * time.Second, FailOnTimeout: true})
	if err != nil {
		t.Fatalf("the request failed: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("the request returned %d", res.StatusCode)
	}
	var view map[string]any
	if err := json.NewDecoder(res.Body).Decode(&view); err != nil {
		t.Fatalf("decoding failed: %v", err)
	}
	if view["account_id"] != viewerAccount.ID.String() {
		t.Errorf("the identity resolved to %v, want the cookie's account %s", view["account_id"], viewerAccount.ID)
	}
	if view["kind"] != string(auth.KindViewer) || view["surface"] != string(auth.SurfacePublic) {
		t.Errorf("headers changed the kind or the surface: %v", view)
	}

	// The escalated permission is still refused with the same headers present.
	broadcast := httptest.NewRequest(http.MethodGet, broadcastRoute, nil)
	broadcast.Header.Set(web.OriginHeader, publicOrigin)
	broadcast.AddCookie(&http.Cookie{Name: web.SessionCookieName, Value: viewer.token})
	for _, h := range spoofed {
		broadcast.Header.Set(h.header, h.value)
	}
	escalated, err := s.app.Test(broadcast, fiber.TestConfig{Timeout: 30 * time.Second, FailOnTimeout: true})
	if err != nil {
		t.Fatalf("the request failed: %v", err)
	}
	defer escalated.Body.Close()
	if escalated.StatusCode != http.StatusForbidden {
		t.Fatalf("spoofed headers granted the broadcast permission: %d", escalated.StatusCode)
	}
}

// TestTheSpecialisedLimitBoundsAuthenticationUnderConcurrency drives the real
// surface, so the limiter is proven where it is actually mounted.
func TestTheSpecialisedLimitBoundsAuthenticationUnderConcurrency(t *testing.T) {
	const allowed = 4
	s := newSurface(t, func(o *httpapi.Options) {
		limiter, err := ratelimit.NewAuthLimiter(ratelimit.AuthPolicy{
			ClientAttempts: allowed, IdentityAttempts: 1_000,
			Window: 15 * time.Minute, Capacity: ratelimit.MinAuthCapacity,
		}, nil)
		if err != nil {
			t.Fatalf("building the limiter failed: %v", err)
		}
		o.Auth.Limiter = limiter
	})
	address, _ := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		statuses = map[int]int{}
	)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			in := s.signIn(t, fmt.Sprintf("attempt%d@example.com", i), "wrong-"+probePassword)
			mu.Lock()
			statuses[in.response.StatusCode]++
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	if statuses[http.StatusUnauthorized] != allowed {
		t.Errorf("%d attempts reached verification, want exactly %d", statuses[http.StatusUnauthorized], allowed)
	}
	if statuses[http.StatusTooManyRequests] != 20-allowed {
		t.Errorf("%d attempts were limited, want %d", statuses[http.StatusTooManyRequests], 20-allowed)
	}
	// The genuine credential is refused too: the client, not the address, is spent.
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusTooManyRequests {
		t.Errorf("a correct credential bypassed the exhausted client bound: %d", in.response.StatusCode)
	}
}

// TestUsingRevokingAndRotatingRaceWithoutRestoringASession runs the three session
// operations against one record at once and requires the outcome to stay closed.
func TestUsingRevokingAndRotatingRaceWithoutRestoringASession(t *testing.T) {
	s := newSurface(t)
	address, account := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", in.response.StatusCode)
	}
	current := sessionIDOf(t, s, account)

	successor, _, err := session.Issue(account.ID, auth.KindViewer, auth.SurfacePublic,
		session.Lifetimes{Absolute: 12 * time.Hour, Idle: 30 * time.Minute, ActivityInterval: time.Minute}, s.clock.Now(), nil)
	if err != nil {
		t.Fatalf("issuing a successor failed: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin})
		}()
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = s.store.RevokeSession(context.Background(), current, s.clock.Now())
	}()
	go func() {
		defer wg.Done()
		_ = s.store.Rotate(context.Background(), current, successor, s.clock.Now())
	}()
	wg.Wait()

	// However the race resolved, the original token is finished and stays finished.
	for attempt := 1; attempt <= 3; attempt++ {
		res := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin})
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("the original token still resolved after the race (attempt %d): %d", attempt, res.StatusCode)
		}
	}
}

// countingVerifier records every credential check the surface performs.
type countingVerifier struct {
	inner *password.Hasher
	mu    sync.Mutex
	seen  []password.Encoded
}

func (v *countingVerifier) Hash(plaintext string) (password.Encoded, error) {
	return v.inner.Hash(plaintext)
}

func (v *countingVerifier) Verify(encoded password.Encoded, plaintext string) (bool, error) {
	v.mu.Lock()
	v.seen = append(v.seen, encoded)
	v.mu.Unlock()
	return v.inner.Verify(encoded, plaintext)
}

func (v *countingVerifier) calls() []password.Encoded {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]password.Encoded(nil), v.seen...)
}

func (v *countingVerifier) reset() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.seen = nil
}

// TestAnUnknownAddressPerformsTheSameCryptographicWork proves parity of the
// intended work and no early return, never equality of wall-clock duration.
func TestAnUnknownAddressPerformsTheSameCryptographicWork(t *testing.T) {
	inner, err := password.NewHasher(
		password.Params{MemoryKiB: password.FloorMemoryKiB, Iterations: password.FloorIterations, Lanes: password.FloorLanes},
		password.Policy{MinCodePoints: password.SingleFactorMinimum}, nil)
	if err != nil {
		t.Fatalf("building the hasher failed: %v", err)
	}
	verifier := &countingVerifier{inner: inner}
	s := newSurface(t, func(o *httpapi.Options) { o.Auth.Hasher = verifier })
	address, account := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)

	var stored string
	if err := s.pool.QueryRow(context.Background(),
		`SELECT encoded_hash FROM account_password_credentials WHERE account_id = $1`,
		account.ID.String()).Scan(&stored); err != nil {
		t.Fatalf("reading the credential failed: %v", err)
	}

	suspended, _ := s.account(t, auth.KindViewer, auth.StatusSuspended, auth.RoleViewer)
	closed, _ := s.account(t, auth.KindViewer, auth.StatusClosed, auth.RoleViewer)
	operator, _ := s.account(t, auth.KindOperator, auth.StatusActive, auth.RoleOperatorSupport)

	cases := []struct {
		name    string
		address string
	}{
		{"registered address", address},
		{"unregistered address", "nobody-here@example.com"},
		{"malformed address", "not-an-address"},
		// An unusable account must not short-circuit ahead of the verification:
		// skipping the work there would make its state measurable from outside.
		{"suspended account", suspended},
		{"closed account", closed},
		{"operator account", operator},
	}
	for _, c := range cases {
		verifier.reset()
		in := s.signIn(t, c.address, "wrong-"+probePassword)
		if in.response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s returned %d, want 401", c.name, in.response.StatusCode)
		}
		calls := verifier.calls()
		if len(calls) != 1 {
			t.Fatalf("%s performed %d verifications, want exactly 1", c.name, len(calls))
		}

		checked := calls[0].Reveal()
		params, ok := strings.CutPrefix(checked, "$argon2id$v=19$")
		if !ok {
			t.Fatalf("%s verified against a value that is not an Argon2id encoding", c.name)
		}
		wantParams := fmt.Sprintf("m=%d,t=%d,p=%d$", password.FloorMemoryKiB, password.FloorIterations, password.FloorLanes)
		if !strings.HasPrefix(params, wantParams) {
			t.Errorf("%s verified against parameters %q, want the configured %q", c.name, params, wantParams)
		}
		known := c.name != "unregistered address" && c.name != "malformed address"
		if !known && checked == stored {
			t.Errorf("%s was verified against a registered credential", c.name)
		}
		if c.address == address && checked != stored {
			t.Errorf("%s was not verified against its own credential", c.name)
		}
	}
}

// TestThePartialAuthenticationSurfaceIsRefused keeps the service from starting
// with a surface missing any of the parts a defence depends on.
func TestThePartialAuthenticationSurfaceIsRefused(t *testing.T) {
	origin, err := web.ParseOrigin(publicOrigin)
	if err != nil {
		t.Fatalf("parsing the origin failed: %v", err)
	}
	hasher, err := password.NewHasher(
		password.Params{MemoryKiB: password.FloorMemoryKiB, Iterations: password.FloorIterations, Lanes: password.FloorLanes},
		password.Policy{MinCodePoints: password.SingleFactorMinimum}, nil)
	if err != nil {
		t.Fatalf("building the hasher failed: %v", err)
	}
	limiter, err := ratelimit.NewAuthLimiter(ratelimit.AuthPolicy{
		ClientAttempts: 10, IdentityAttempts: 5, Window: time.Minute, Capacity: ratelimit.MinAuthCapacity,
	}, nil)
	if err != nil {
		t.Fatalf("building the limiter failed: %v", err)
	}
	complete := httpapi.AuthOptions{
		Store: authstore.New(nil), Hasher: hasher, Origin: origin, Limiter: limiter,
		Lifetimes: session.Lifetimes{Absolute: time.Hour, Idle: 30 * time.Minute, ActivityInterval: time.Minute},
	}

	cases := map[string]func(*httpapi.AuthOptions){
		"no store":      func(o *httpapi.AuthOptions) { o.Store = nil },
		"no hasher":     func(o *httpapi.AuthOptions) { o.Hasher = nil },
		"no limiter":    func(o *httpapi.AuthOptions) { o.Limiter = nil },
		"no origin":     func(o *httpapi.AuthOptions) { o.Origin = web.Origin{} },
		"no lifetimes":  func(o *httpapi.AuthOptions) { o.Lifetimes = session.Lifetimes{} },
		"idle too long": func(o *httpapi.AuthOptions) { o.Lifetimes.Idle = 2 * o.Lifetimes.Absolute },
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			opts := complete
			breakIt(&opts)
			app, err := httpapi.New(httpapi.Options{
				RateLimit: directPolicy(100), Persistence: newStubStore(true),
				CheckTimeout: time.Second, Auth: &opts,
			})
			if err == nil || app != nil {
				t.Fatal("a partial authentication surface was mounted")
			}
		})
	}

	app, err := httpapi.New(httpapi.Options{
		RateLimit: directPolicy(100), Persistence: newStubStore(true),
		CheckTimeout: time.Second, Auth: &complete,
	})
	if err != nil || app == nil {
		t.Fatalf("a complete surface was refused: %v", err)
	}
}

// TestAuthorityIsReReadOnEveryRequestRatherThanFrozenInTheCookie changes the
// account behind a live session and requires every decision to follow at once.
func TestAuthorityIsReReadOnEveryRequestRatherThanFrozenInTheCookie(t *testing.T) {
	s := newSurface(t)
	address, account := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d: %s", in.response.StatusCode, in.body)
	}
	if roles, _ := in.view["roles"].([]any); len(roles) != 1 {
		t.Fatalf("the session opened with roles %v, want exactly the viewer role", in.view["roles"])
	}

	// A role granted after the cookie was issued is honoured on the next request,
	// which is only possible if the grants are read again rather than carried.
	if res := s.send(t, request{method: http.MethodGet, target: broadcastRoute, cookie: in.token, origin: publicOrigin}); res.StatusCode != http.StatusForbidden {
		t.Fatalf("a viewer already held the broadcast permission: %d", res.StatusCode)
	}
	if _, err := s.pool.Exec(context.Background(),
		`INSERT INTO account_role_grants (account_id, role, granted_at) VALUES ($1, $2, now())`,
		account.ID.String(), string(auth.RoleCreator)); err != nil {
		t.Fatalf("granting the role failed: %v", err)
	}
	// The account kind still refuses it: a viewer may not hold the creator role.
	if res := s.send(t, request{method: http.MethodGet, target: broadcastRoute, cookie: in.token, origin: publicOrigin}); res.StatusCode != http.StatusForbidden {
		t.Fatalf("a viewer kind exercised a creator role: %d", res.StatusCode)
	}
	if _, err := s.pool.Exec(context.Background(),
		`UPDATE accounts SET kind = $2 WHERE id = $1`, account.ID.String(), string(auth.KindCreator)); err != nil {
		t.Fatalf("changing the kind failed: %v", err)
	}
	if res := s.send(t, request{method: http.MethodGet, target: broadcastRoute, cookie: in.token, origin: publicOrigin}); res.StatusCode != http.StatusOK {
		t.Fatalf("a granted role was not honoured on the established session: %d", res.StatusCode)
	}

	// Withdrawing the grant withdraws the permission on the very next request.
	if _, err := s.pool.Exec(context.Background(),
		`DELETE FROM account_role_grants WHERE account_id = $1 AND role = $2`,
		account.ID.String(), string(auth.RoleCreator)); err != nil {
		t.Fatalf("withdrawing the role failed: %v", err)
	}
	if res := s.send(t, request{method: http.MethodGet, target: broadcastRoute, cookie: in.token, origin: publicOrigin}); res.StatusCode != http.StatusForbidden {
		t.Fatalf("a withdrawn role was still honoured: %d", res.StatusCode)
	}

	// A status change alone, with the session left untouched, ends every decision.
	for _, status := range []auth.Status{auth.StatusSuspended, auth.StatusClosed, auth.StatusPending} {
		if _, err := s.pool.Exec(context.Background(),
			`UPDATE accounts SET status = $2 WHERE id = $1`, account.ID.String(), string(status)); err != nil {
			t.Fatalf("changing the status failed: %v", err)
		}
		var live int
		if err := s.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM account_sessions WHERE account_id = $1 AND revoked_at IS NULL`,
			account.ID.String()).Scan(&live); err != nil {
			t.Fatalf("counting sessions failed: %v", err)
		}
		if live == 0 {
			t.Fatalf("the %s status revoked the session, so the re-read is not what refused it", status)
		}
		res := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin})
		if res.StatusCode == http.StatusOK {
			t.Fatalf("a %s account still used its established session", status)
		}
	}
}

// TestOneSessionsCSRFTokenIsWorthlessAgainstAnother: the token is bound to one
// session, so obtaining one by signing up buys nothing against anybody else.
func TestOneSessionsCSRFTokenIsWorthlessAgainstAnother(t *testing.T) {
	s := newSurface(t)
	victimAddress, _ := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	attackerAddress, _ := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)

	victim := s.signIn(t, victimAddress, probePassword)
	attacker := s.signIn(t, attackerAddress, probePassword)
	if victim.response.StatusCode != http.StatusCreated || attacker.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in failed: %d and %d", victim.response.StatusCode, attacker.response.StatusCode)
	}
	if victim.csrf == "" || attacker.csrf == "" {
		t.Fatal("a session was issued without a CSRF token")
	}
	if victim.csrf == attacker.csrf {
		t.Fatal("two sessions were issued the same CSRF token")
	}

	// A second session for the same account gets its own token too, so the value
	// is not a per-account constant either.
	again := s.signIn(t, victimAddress, probePassword)
	if again.response.StatusCode != http.StatusCreated {
		t.Fatalf("the second sign-in returned %d", again.response.StatusCode)
	}
	if again.csrf == victim.csrf {
		t.Fatal("two sessions of one account share a CSRF token")
	}

	var distinct int
	if err := s.pool.QueryRow(context.Background(),
		`SELECT count(DISTINCT csrf_token) FROM account_sessions`).Scan(&distinct); err != nil {
		t.Fatalf("counting tokens failed: %v", err)
	}
	if distinct != 3 {
		t.Fatalf("%d distinct CSRF tokens were stored for 3 sessions", distinct)
	}

	// Holding a token from one session authorises nothing on another.
	res := s.send(t, request{
		method: http.MethodDelete, target: sessionRoute,
		cookie: victim.token, csrf: attacker.csrf, origin: publicOrigin, fetchSite: "same-origin", contentType: "application/json"})
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("another session's CSRF token was accepted: %d", res.StatusCode)
	}
	check := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: victim.token, origin: publicOrigin})
	if check.StatusCode != http.StatusOK {
		t.Fatalf("the victim session was ended by a foreign token: %d", check.StatusCode)
	}
}

// TestAuthenticatingEndsTheSessionTheRequestArrivedWith keeps a second live token
// from surviving a sign-in, which a value planted beforehand would rely on.
func TestAuthenticatingEndsTheSessionTheRequestArrivedWith(t *testing.T) {
	s := newSurface(t)
	address, account := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)

	first := s.signIn(t, address, probePassword)
	if first.response.StatusCode != http.StatusCreated {
		t.Fatalf("the first sign-in returned %d", first.response.StatusCode)
	}

	// Sign in again while presenting the first cookie.
	res := s.send(t, request{
		method: http.MethodPost, target: sessionRoute,
		body:   map[string]string{"email": address, "password": probePassword},
		origin: publicOrigin, fetchSite: "same-origin", cookie: first.token,
	})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("the second sign-in returned %d: %s", res.StatusCode, bodyOf(t, res))
	}
	second := sessionCookie(res)
	if second == nil || second.Value == "" {
		t.Fatal("the second sign-in issued no session")
	}
	if second.Value == first.token {
		t.Fatal("the second sign-in reused the presented token")
	}

	// The presented token is finished; the new one works.
	if probe := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: first.token, origin: publicOrigin}); probe.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the presented session survived the sign-in: %d", probe.StatusCode)
	}
	if probe := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: second.Value, origin: publicOrigin}); probe.StatusCode != http.StatusOK {
		t.Fatalf("the new session was not usable: %d", probe.StatusCode)
	}

	var live int
	if err := s.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM account_sessions WHERE account_id = $1 AND revoked_at IS NULL AND rotated_to IS NULL`,
		account.ID.String()).Scan(&live); err != nil {
		t.Fatalf("counting sessions failed: %v", err)
	}
	if live != 1 {
		t.Fatalf("%d sessions are live after re-authentication, want exactly 1", live)
	}

	// A refused sign-in leaves the presented session alone.
	current := second.Value
	failed := s.send(t, request{
		method: http.MethodPost, target: sessionRoute,
		body:   map[string]string{"email": address, "password": "wrong-" + probePassword},
		origin: publicOrigin, fetchSite: "same-origin", cookie: current,
	})
	if failed.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the refused sign-in returned %d", failed.StatusCode)
	}
	if probe := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: current, origin: publicOrigin}); probe.StatusCode != http.StatusOK {
		t.Fatalf("a refused sign-in ended the existing session: %d", probe.StatusCode)
	}
}

// faultyStore makes exactly one operation fail while every other call reaches
// PostgreSQL. The injected message imitates driver detail that must not travel.
type faultyStore struct {
	inner      *authstore.Store
	credential func() error
	resolve    func() error
	replace    func() error
	revoke     func() error
	activity   func() error
}

// driverDetail stands in for what a driver error could carry. Scans decode the
// document, so the original string is recovered rather than its escaped form.
const driverDetail = `ERROR: relation "account_sessions" does not exist (SQLSTATE 42P01) host=db.internal user=core_api`

func (f *faultyStore) CredentialByEmail(ctx context.Context, email auth.EmailAddress) (authstore.Credential, error) {
	if f.credential != nil {
		if err := f.credential(); err != nil {
			return authstore.Credential{}, err
		}
	}
	return f.inner.CredentialByEmail(ctx, email)
}

func (f *faultyStore) ReplaceSession(ctx context.Context, previous *auth.SessionID, successor session.Session, now time.Time) (authstore.Resolved, error) {
	if f.replace != nil {
		if err := f.replace(); err != nil {
			return authstore.Resolved{}, err
		}
	}
	return f.inner.ReplaceSession(ctx, previous, successor, now)
}

func (f *faultyStore) Resolve(ctx context.Context, token session.Token, now time.Time) (authstore.Resolved, error) {
	if f.resolve != nil {
		if err := f.resolve(); err != nil {
			return authstore.Resolved{}, err
		}
	}
	return f.inner.Resolve(ctx, token, now)
}

func (f *faultyStore) RecordActivity(ctx context.Context, id auth.SessionID, now time.Time, lifetimes session.Lifetimes) (bool, error) {
	if f.activity != nil {
		if err := f.activity(); err != nil {
			return false, err
		}
	}
	return f.inner.RecordActivity(ctx, id, now, lifetimes)
}

func (f *faultyStore) RevokeSession(ctx context.Context, id auth.SessionID, now time.Time) error {
	if f.revoke != nil {
		if err := f.revoke(); err != nil {
			return err
		}
	}
	return f.inner.RevokeSession(ctx, id, now)
}

// storeFailure is what the adapter reports when the driver fails: the sentinel,
// wrapping detail that must never travel.
func storeFailure() error {
	return fmt.Errorf("%w: %s", authstore.ErrStore, driverDetail)
}

// once returns a hook that fails only the nth call, so a test can let a sign-in
// reach a chosen step before the store breaks.
func once(n int) func() error {
	var calls int
	var mu sync.Mutex
	return func() error {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls == n {
			return storeFailure()
		}
		return nil
	}
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

func (s *surface) allSessions(t *testing.T) int {
	t.Helper()
	var total int
	if err := s.pool.QueryRow(context.Background(), `SELECT count(*) FROM account_sessions`).Scan(&total); err != nil {
		t.Fatalf("counting sessions failed: %v", err)
	}
	return total
}

// TestAStoreFailureIsNeverReportedAsACredentialVerdict separates a genuine
// absence from a store that could not say. The work happens on both.
func TestAStoreFailureIsNeverReportedAsACredentialVerdict(t *testing.T) {
	inner, err := password.NewHasher(
		password.Params{MemoryKiB: password.FloorMemoryKiB, Iterations: password.FloorIterations, Lanes: password.FloorLanes},
		password.Policy{MinCodePoints: password.SingleFactorMinimum}, nil)
	if err != nil {
		t.Fatalf("building the hasher failed: %v", err)
	}
	verifier := &countingVerifier{inner: inner}
	s := newSurface(t, func(o *httpapi.Options) { o.Auth.Hasher = verifier })
	address, account := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)

	// A genuine absence keeps the uniform answer.
	verifier.reset()
	absent := s.signIn(t, "nobody-here@example.com", probePassword)
	if absent.response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("an absent address returned %d, want 401", absent.response.StatusCode)
	}
	if calls := len(verifier.calls()); calls != 1 {
		t.Fatalf("an absent address performed %d verifications, want 1", calls)
	}

	// A store that failed is a server error, and the same work still happens.
	s.faults.credential = func() error { return storeFailure() }
	verifier.reset()
	broken := s.signIn(t, address, probePassword)
	s.faults.credential = nil
	if broken.response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("a failed lookup returned %d, want 500: %s", broken.response.StatusCode, broken.body)
	}
	if calls := len(verifier.calls()); calls != 1 {
		t.Fatalf("a failed lookup performed %d verifications, want 1", calls)
	}
	if sessionCookie(broken.response) != nil {
		t.Error("a failed lookup set a session cookie")
	}
	if live := s.liveSessions(t, account); live != 0 {
		t.Errorf("%d sessions exist after a failed lookup", live)
	}
	// The correct credential still works once the store answers again.
	if in := s.signIn(t, address, probePassword); in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d after the store recovered", in.response.StatusCode)
	}
}

// TestAStoreFailureOnAProtectedRouteIsNotAFalseUnauthorized keeps the server from
// asserting an absence it never established.
func TestAStoreFailureOnAProtectedRouteIsNotAFalseUnauthorized(t *testing.T) {
	s := newSurface(t)
	address, _ := s.account(t, auth.KindCreator, auth.StatusActive, auth.RoleViewer, auth.RoleCreator)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", in.response.StatusCode)
	}

	for _, route := range []string{sessionRoute, broadcastRoute} {
		s.faults.resolve = func() error { return storeFailure() }
		res := s.send(t, request{method: http.MethodGet, target: route, cookie: in.token, origin: publicOrigin})
		s.faults.resolve = nil
		if res.StatusCode != http.StatusInternalServerError {
			t.Errorf("%s returned %d on a store failure, want 500", route, res.StatusCode)
		}
	}
	// A genuinely unknown token still gets the uniform refusal.
	drawn, err := session.NewToken(nil)
	if err != nil {
		t.Fatalf("drawing failed: %v", err)
	}
	if res := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: drawn.Reveal(), origin: publicOrigin}); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("an unknown token returned %d, want 401", res.StatusCode)
	}
}

// TestSignOutNeverAnnouncesASignOutItDidNotPerform keeps a failure from producing
// a cleared cookie and a success code while the server session is still live.
func TestSignOutNeverAnnouncesASignOutItDidNotPerform(t *testing.T) {
	s := newSurface(t)
	address, account := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", in.response.StatusCode)
	}

	failures := map[string]func(){
		"resolution fails": func() { s.faults.resolve = func() error { return storeFailure() } },
		"revocation fails": func() { s.faults.revoke = func() error { return storeFailure() } },
	}
	for name, breakIt := range failures {
		t.Run(name, func(t *testing.T) {
			breakIt()
			res := s.send(t, request{
				method: http.MethodDelete, target: sessionRoute,
				cookie: in.token, csrf: in.csrf, origin: publicOrigin, fetchSite: "same-origin", contentType: "application/json"})
			s.faults.resolve, s.faults.revoke = nil, nil

			if res.StatusCode != http.StatusInternalServerError {
				t.Fatalf("sign-out returned %d, want 500", res.StatusCode)
			}
			if cleared := sessionCookie(res); cleared != nil {
				t.Error("a failed sign-out cleared the cookie while the session may still be live")
			}
			if live := s.liveSessions(t, account); live != 1 {
				t.Errorf("%d live sessions after a failed sign-out, want the session untouched", live)
			}
			if probe := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin}); probe.StatusCode != http.StatusOK {
				t.Errorf("the session stopped working after a failed sign-out: %d", probe.StatusCode)
			}
		})
	}

	// An absent, finished or already revoked session is idempotent success.
	if err := s.store.RevokeSession(context.Background(), sessionIDOf(t, s, account), s.clock.Now()); err != nil {
		t.Fatalf("revoking failed: %v", err)
	}
	for _, name := range []string{"already revoked", "repeat"} {
		res := s.send(t, request{
			method: http.MethodDelete, target: sessionRoute,
			cookie: in.token, csrf: in.csrf, origin: publicOrigin, fetchSite: "same-origin", contentType: "application/json"})
		if res.StatusCode != http.StatusNoContent {
			t.Fatalf("sign-out on an %s session returned %d, want 204", name, res.StatusCode)
		}
		if sessionCookie(res) == nil {
			t.Errorf("sign-out on an %s session did not clear the cookie", name)
		}
	}
}

// TestNoStoreDetailReachesTheResponseOrTheRecords keeps driver text, host names,
// identifiers and SQLSTATE codes out of everything the caller or an operator sees.
func TestNoStoreDetailReachesTheResponseOrTheRecords(t *testing.T) {
	s := newSurface(t)
	address, account := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", in.response.StatusCode)
	}

	var bodies []string
	s.faults.credential = func() error { return storeFailure() }
	bodies = append(bodies, s.signIn(t, address, probePassword).body)
	s.faults.credential = nil

	s.faults.resolve = func() error { return storeFailure() }
	bodies = append(bodies, bodyOf(t, s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin})))
	s.faults.resolve = nil

	s.faults.replace = func() error { return storeFailure() }
	bodies = append(bodies, s.signIn(t, address, probePassword).body)
	s.faults.replace = nil

	forbidden := []string{
		driverDetail, "42P01", "SQLSTATE", "account_sessions", "db.internal", "core_api",
		address, probePassword, in.token, in.csrf, account.ID.String(),
	}
	for i, body := range bodies {
		for _, secret := range forbidden {
			if strings.Contains(body, secret) {
				t.Errorf("response %d carried %q", i, secret)
			}
		}
	}
	logs := s.logs.String()
	for _, secret := range forbidden {
		if strings.Contains(logs, secret) {
			t.Errorf("the records carried %q", secret)
		}
	}
	// The class of failure is still recorded, so an operator is not left blind.
	if !strings.Contains(logs, `"error_code":"internal_error"`) {
		t.Error("no record identified the failure class")
	}
}

// TestSessionReplacementIsAllOrNothing: under any storage failure the presented
// session stays usable with no replacement, or exactly one replaces it.
func TestSessionReplacementIsAllOrNothing(t *testing.T) {
	failures := map[string]func(*surface){
		"the presented session cannot be resolved": func(s *surface) { s.faults.resolve = func() error { return storeFailure() } },
		"the replacement cannot be written":        func(s *surface) { s.faults.replace = func() error { return storeFailure() } },
	}
	for name, breakIt := range failures {
		t.Run(name, func(t *testing.T) {
			s := newSurface(t)
			address, account := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
			first := s.signIn(t, address, probePassword)
			if first.response.StatusCode != http.StatusCreated {
				t.Fatalf("the first sign-in returned %d", first.response.StatusCode)
			}
			before := s.allSessions(t)

			breakIt(s)
			res := s.send(t, request{
				method: http.MethodPost, target: sessionRoute,
				body:   map[string]string{"email": address, "password": probePassword},
				origin: publicOrigin, fetchSite: "same-origin", cookie: first.token,
			})
			s.faults.resolve, s.faults.replace = nil, nil

			if res.StatusCode != http.StatusInternalServerError {
				t.Fatalf("the failed sign-in returned %d, want 500", res.StatusCode)
			}
			if sessionCookie(res) != nil {
				t.Error("a failed sign-in set a session cookie")
			}
			if after := s.allSessions(t); after != before {
				t.Errorf("%d session rows exist, want the %d from before the failure", after, before)
			}
			if live := s.liveSessions(t, account); live != 1 {
				t.Fatalf("%d live sessions after the failure, want exactly the original", live)
			}
			if probe := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: first.token, origin: publicOrigin}); probe.StatusCode != http.StatusOK {
				t.Errorf("the presented session stopped working after a failure that changed nothing: %d", probe.StatusCode)
			}
		})
	}

	t.Run("a successful replacement leaves exactly one live session", func(t *testing.T) {
		s := newSurface(t)
		address, account := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
		first := s.signIn(t, address, probePassword)
		if first.response.StatusCode != http.StatusCreated {
			t.Fatalf("the first sign-in returned %d", first.response.StatusCode)
		}
		res := s.send(t, request{
			method: http.MethodPost, target: sessionRoute,
			body:   map[string]string{"email": address, "password": probePassword},
			origin: publicOrigin, fetchSite: "same-origin", cookie: first.token,
		})
		if res.StatusCode != http.StatusCreated {
			t.Fatalf("the second sign-in returned %d", res.StatusCode)
		}
		if live := s.liveSessions(t, account); live != 1 {
			t.Fatalf("%d live sessions after a successful replacement, want 1", live)
		}
		if probe := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: first.token, origin: publicOrigin}); probe.StatusCode != http.StatusUnauthorized {
			t.Errorf("the replaced session still worked: %d", probe.StatusCode)
		}
		if probe := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: sessionCookie(res).Value, origin: publicOrigin}); probe.StatusCode != http.StatusOK {
			t.Errorf("the replacement was not usable: %d", probe.StatusCode)
		}
	})

	// The presented session may belong to somebody else entirely: it is still
	// ended, and the account that authenticated gets exactly one session.
	t.Run("the presented session belongs to another account", func(t *testing.T) {
		s := newSurface(t)
		otherAddress, otherAccount := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
		address, account := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)

		other := s.signIn(t, otherAddress, probePassword)
		if other.response.StatusCode != http.StatusCreated {
			t.Fatalf("the other account could not sign in: %d", other.response.StatusCode)
		}
		res := s.send(t, request{
			method: http.MethodPost, target: sessionRoute,
			body:   map[string]string{"email": address, "password": probePassword},
			origin: publicOrigin, fetchSite: "same-origin", cookie: other.token,
		})
		if res.StatusCode != http.StatusCreated {
			t.Fatalf("sign-in returned %d: %s", res.StatusCode, bodyOf(t, res))
		}
		if live := s.liveSessions(t, otherAccount); live != 0 {
			t.Errorf("%d live sessions remain for the other account, want 0", live)
		}
		if live := s.liveSessions(t, account); live != 1 {
			t.Errorf("%d live sessions for the account that authenticated, want 1", live)
		}
		if probe := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: other.token, origin: publicOrigin}); probe.StatusCode != http.StatusUnauthorized {
			t.Errorf("the other account's session survived: %d", probe.StatusCode)
		}
	})
}

// TestEveryAuthenticationResponseForbidsCaching covers the success and the refusal
// paths alike, so no branch relies on a browser, proxy or CDN default.
func TestEveryAuthenticationResponseForbidsCaching(t *testing.T) {
	s := newSurface(t)
	address, _ := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", in.response.StatusCode)
	}
	if got := in.response.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("the sign-in response declared %q, want no-store", got)
	}

	cases := []struct {
		name    string
		request request
	}{
		{"session read", request{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin}},
		{"authorisation refused", request{method: http.MethodGet, target: broadcastRoute, cookie: in.token, origin: publicOrigin}},
		{"unauthenticated read", request{method: http.MethodGet, target: sessionRoute, origin: publicOrigin}},
		{"cross-site refusal", request{method: http.MethodPost, target: sessionRoute, body: map[string]string{"email": address, "password": probePassword}, origin: foreignOrigin}},
		{"wrong content type", request{method: http.MethodPost, target: sessionRoute, body: map[string]string{"email": address}, origin: publicOrigin, noJSON: true}},
		{"malformed body", request{method: http.MethodPost, target: sessionRoute, body: "not an object", origin: publicOrigin, fetchSite: "same-origin"}},
		{"missing CSRF token", request{method: http.MethodDelete, target: sessionRoute, cookie: in.token, origin: publicOrigin, fetchSite: "same-origin", contentType: "application/json"}},
		{"unknown route on the surface", request{method: http.MethodGet, target: "/api/v1/auth/nothing-here", origin: publicOrigin}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := s.send(t, c.request)
			if got := res.Header.Get("Cache-Control"); got != "no-store" {
				t.Errorf("the %s response (%d) declared %q, want no-store", c.name, res.StatusCode, got)
			}
		})
	}

	// A server error must carry it too, since the branch is written by the shared
	// error handler rather than by the surface.
	s.faults.resolve = func() error { return storeFailure() }
	broken := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin})
	s.faults.resolve = nil
	if broken.StatusCode != http.StatusInternalServerError {
		t.Fatalf("the failing read returned %d, want 500", broken.StatusCode)
	}
	if got := broken.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("the server-error response declared %q, want no-store", got)
	}

	// Sign-out ends with the cookie being cleared, so it is checked last.
	out := s.send(t, request{
		method: http.MethodDelete, target: sessionRoute,
		cookie: in.token, csrf: in.csrf, origin: publicOrigin, fetchSite: "same-origin", contentType: "application/json"})
	if out.StatusCode != http.StatusNoContent {
		t.Fatalf("sign-out returned %d", out.StatusCode)
	}
	if got := out.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("the sign-out response declared %q, want no-store", got)
	}
}

// TestASessionReadWritesNothing: a top-level navigation carries the cookie under
// SameSite=Lax, so a read that renewed the idle window would hand it away.
func TestASessionReadWritesNothing(t *testing.T) {
	s := newSurface(t)
	address, account := s.account(t, auth.KindCreator, auth.StatusActive, auth.RoleViewer, auth.RoleCreator)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", in.response.StatusCode)
	}

	stamps := func() (time.Time, time.Time) {
		t.Helper()
		var active, idle time.Time
		if err := s.pool.QueryRow(context.Background(),
			`SELECT last_active_at, idle_expires_at FROM account_sessions WHERE account_id = $1`,
			account.ID.String()).Scan(&active, &idle); err != nil {
			t.Fatalf("reading the row failed: %v", err)
		}
		return active, idle
	}
	activeBefore, idleBefore := stamps()

	// Time moves on, so a renewal would be visible if one happened.
	s.clock.advance(10 * time.Minute)

	reads := []request{
		{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin},
		{method: http.MethodGet, target: broadcastRoute, cookie: in.token, origin: publicOrigin},
		// A top-level navigation: no Origin, no Fetch Metadata, cookie carried.
		{method: http.MethodGet, target: sessionRoute, cookie: in.token},
		{method: http.MethodGet, target: sessionRoute, cookie: in.token, fetchSite: "cross-site"},
	}
	for i, r := range reads {
		if res := s.send(t, r); res.StatusCode != http.StatusOK {
			t.Fatalf("read %d returned %d", i, res.StatusCode)
		}
		activeAfter, idleAfter := stamps()
		if !activeAfter.Equal(activeBefore) {
			t.Fatalf("read %d moved last_active_at from %s to %s", i, activeBefore, activeAfter)
		}
		if !idleAfter.Equal(idleBefore) {
			t.Fatalf("read %d moved idle_expires_at from %s to %s", i, idleBefore, idleAfter)
		}
	}

	// The idle expiry therefore still ends the session on its original schedule.
	s.clock.advance(21 * time.Minute)
	if res := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin}); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the session outlived its unrenewed idle window: %d", res.StatusCode)
	}
}

// TestAGlobalRefusalOnTheSurfaceStillForbidsCaching covers the branch no handler
// reaches: the shared limiter answers 429 before the surface ever runs.
func TestAGlobalRefusalOnTheSurfaceStillForbidsCaching(t *testing.T) {
	const globalMax = 3
	s := newSurface(t, func(o *httpapi.Options) {
		// The specialised limiter keeps plenty of room, so the refusal below can
		// only come from the shared one.
		limiter, err := ratelimit.NewAuthLimiter(ratelimit.AuthPolicy{
			ClientAttempts: ratelimit.MaxAuthAttempts, IdentityAttempts: ratelimit.MaxAuthAttempts,
			Window: 15 * time.Minute, Capacity: ratelimit.MinAuthCapacity,
		}, nil)
		if err != nil {
			t.Fatalf("building the limiter failed: %v", err)
		}
		o.Auth.Limiter = limiter
		o.RateLimit = directPolicy(globalMax)
	})

	var refused *http.Response
	for attempt := 1; attempt <= globalMax+3; attempt++ {
		res := s.send(t, request{method: http.MethodGet, target: sessionRoute, origin: publicOrigin})
		if res.StatusCode == http.StatusTooManyRequests {
			refused = res
			break
		}
	}
	if refused == nil {
		t.Fatalf("the shared limiter never refused within %d attempts", globalMax+3)
	}
	if got := refused.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("the shared limiter's 429 declared %q, want no-store", got)
	}
}

// TestAnAccountSuspendedBeforeTheReplacementGetsTheOrdinaryRefusal: the account
// becomes unusable between the credential check and the transaction.
func TestAnAccountSuspendedBeforeTheReplacementGetsTheOrdinaryRefusal(t *testing.T) {
	s := newSurface(t)
	address, account := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)

	// A refusal with the wrong password gives the shape every refusal must match.
	reference := s.signIn(t, address, "wrong-"+probePassword)
	if reference.response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the reference refusal returned %d", reference.response.StatusCode)
	}

	// The suspension runs after the credential was read and verified, and before
	// the real replacement is delegated to PostgreSQL.
	var suspended bool
	s.faults.replace = func() error {
		if !suspended {
			suspended = true
			if err := s.store.Suspend(context.Background(), account.ID, s.clock.Now()); err != nil {
				t.Errorf("suspending failed: %v", err)
			}
		}
		return nil
	}
	in := s.signIn(t, address, probePassword)
	s.faults.replace = nil

	if in.response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a correct credential on a newly suspended account returned %d, want 401: %s",
			in.response.StatusCode, in.body)
	}
	normalise := func(body string) string { return requestIDPattern.ReplaceAllString(body, `"request_id":"x"`) }
	if normalise(in.body) != normalise(reference.body) {
		t.Errorf("the refusal reads %q, want it identical to %q", in.body, reference.body)
	}
	if sessionCookie(in.response) != nil {
		t.Error("a refused sign-in set a session cookie")
	}

	var sessions, created int
	if err := s.pool.QueryRow(context.Background(), `
		SELECT (SELECT count(*) FROM account_sessions),
		       (SELECT count(*) FROM account_security_events WHERE kind = 'session_created')`).
		Scan(&sessions, &created); err != nil {
		t.Fatalf("reading the ledger failed: %v", err)
	}
	if sessions != 0 || created != 0 {
		t.Fatalf("%d sessions and %d creation events were written for a refused sign-in", sessions, created)
	}

	// Applied to what the service actually said. Documents are decoded and the
	// opaque correlation identifier is excluded, so no scan depends on chance.
	forbidden := []string{
		"suspended", "account_sessions", "SQLSTATE", "42P01", driverDetail,
		address, account.ID.String(), probePassword,
	}
	for _, value := range decodedValues(t, in.body) {
		for _, secret := range forbidden {
			if strings.Contains(value, secret) {
				t.Errorf("the refusal carried %q in %q", secret, value)
			}
		}
	}

	// The reference refusal wrote records of its own, which must not satisfy an
	// assertion about this one. The identifier correlates; it is never scanned.
	requestID := requestIDOf(t, in.body)
	records := decodeRecords(t, s.logs.String())
	handled := 0
	correlated := 0
	for _, record := range records {
		// Every record of this scenario is read, on its decoded values.
		for _, value := range record.values {
			for _, secret := range forbidden {
				if strings.Contains(value, secret) {
					t.Errorf("a record carried %q in %q", secret, value)
				}
			}
		}
		if record.requestID != requestID {
			continue
		}
		correlated++
		if record.fields["msg"] != "request handled" {
			continue
		}
		handled++
		if record.fields["method"] != http.MethodPost {
			t.Errorf("the record names method %v, want POST", record.fields["method"])
		}
		if record.fields["route"] != sessionRoute {
			t.Errorf("the record names route %v, want %s", record.fields["route"], sessionRoute)
		}
		if status, _ := record.fields["status"].(float64); int(status) != http.StatusUnauthorized {
			t.Errorf("the record carries status %v, want 401", record.fields["status"])
		}
	}
	if correlated == 0 {
		t.Fatalf("no record was written for request %s", requestID)
	}
	if handled != 1 {
		t.Fatalf("%d handling records exist for request %s, want exactly 1", handled, requestID)
	}
}

// TestTheCanonicalIdentifierIsAlwaysServerGenerated: a value a public client puts
// in the header is never adopted, echoed or logged, whatever it carries.
func TestTheCanonicalIdentifierIsAlwaysServerGenerated(t *testing.T) {
	s := newSurface(t)
	address, _ := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)

	// The client's value carries exactly what must never travel: an address, a
	// password and a realistic driver message.
	crafted := "sent-by-the-client " + address + " " + probePassword + " " + driverDetail
	forbidden := []string{"sent-by-the-client", address, probePassword, driverDetail, "SQLSTATE", "42P01", "account_sessions"}

	var ids []string
	for attempt := 1; attempt <= 2; attempt++ {
		res := s.send(t, request{
			method: http.MethodPost, target: sessionRoute,
			body:   map[string]string{"email": address, "password": "wrong-" + probePassword},
			origin: publicOrigin, fetchSite: "same-origin", requestID: crafted,
		})
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("the refusal returned %d", res.StatusCode)
		}
		body := bodyOf(t, res)
		id := requestIDOf(t, body)
		if id == crafted {
			t.Fatal("the client's value became the canonical identifier")
		}
		if echoed := res.Header.Get("X-Request-Id"); echoed != id {
			t.Fatalf("the response header carries %q, want the canonical %q", echoed, id)
		}
		for _, value := range decodedValues(t, body) {
			for _, secret := range forbidden {
				if strings.Contains(value, secret) {
					t.Errorf("the response carried %q in %q", secret, value)
				}
			}
		}
		ids = append(ids, id)
	}
	// Two requests sharing one client value get two distinct server identifiers.
	if ids[0] == ids[1] {
		t.Fatalf("two requests sharing a client value shared the identifier %s", ids[0])
	}

	records := decodeRecords(t, s.logs.String())
	for _, id := range ids {
		handled := 0
		for _, record := range records {
			if record.requestID == id && record.fields["msg"] == "request handled" {
				handled++
			}
		}
		// Each response correlates to exactly its own handling record.
		if handled != 1 {
			t.Fatalf("%d handling records for %s, want exactly 1", handled, id)
		}
	}
	for _, record := range records {
		if record.requestID == crafted {
			t.Fatal("a record adopted the client's value as its identifier")
		}
		for _, value := range record.values {
			for _, secret := range forbidden {
				if strings.Contains(value, secret) {
					t.Errorf("a record carried %q in %q", secret, value)
				}
			}
		}
	}

	// An empty, oversized or syntactically unusual client value never changes the
	// canonical shape either; requestIDOf enforces that shape.
	weirdness := map[string]string{
		"empty":     "",
		"oversized": strings.Repeat("A", 2048),
		"spaced":    "  leading and trailing spaces  ",
		"non-ascii": "h\u00e9llo-\u00ff-identifier",
	}
	for name, weird := range weirdness {
		req := httptest.NewRequest(http.MethodGet, sessionRoute, nil)
		req.Header.Set(web.OriginHeader, publicOrigin)
		req.Header.Set("X-Request-Id", weird)
		res, err := s.app.Test(req, fiber.TestConfig{Timeout: 30 * time.Second, FailOnTimeout: true})
		if err != nil {
			t.Fatalf("the %s request failed: %v", name, err)
		}
		body := bodyOf(t, res)
		_ = res.Body.Close()
		id := requestIDOf(t, body)
		if weird != "" && id == weird {
			t.Errorf("the %s client value became the canonical identifier", name)
		}
	}
}

type logRecord struct {
	requestID string
	fields    map[string]any
	// values holds every string the record carries except the correlation
	// identifier, which is opaque and not something the service disclosed.
	values []string
}

// collectStrings gathers the text a decoded document carries, skipping the
// correlation identifier wherever it appears.
func collectStrings(node any, into *[]string) {
	switch typed := node.(type) {
	case map[string]any:
		for key, value := range typed {
			// The identifier is excluded only once it has the server's shape;
			// anything else in that field is scanned like every other value.
			if key == "request_id" {
				if id, ok := value.(string); ok && serverIDPattern.MatchString(id) {
					continue
				}
			}
			collectStrings(value, into)
		}
	case []any:
		for _, value := range typed {
			collectStrings(value, into)
		}
	case string:
		*into = append(*into, typed)
	}
}

// decodedValues returns what a JSON document actually says, identifier excluded,
// so a scan reads the service's own text rather than the encoding around it.
func decodedValues(t *testing.T, document string) []string {
	t.Helper()
	var node any
	if err := json.Unmarshal([]byte(document), &node); err != nil {
		t.Fatalf("decoding failed: %v", err)
	}
	var values []string
	collectStrings(node, &values)
	return values
}

// requestIDOf reads the identifier the response carries, used only to correlate.
func requestIDOf(t *testing.T, body string) string {
	t.Helper()
	var parsed struct {
		Error struct {
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("decoding the response failed: %v", err)
	}
	if !serverIDPattern.MatchString(parsed.Error.RequestID) {
		t.Fatalf("the response identifier %q is not of the server's shape", parsed.Error.RequestID)
	}
	return parsed.Error.RequestID
}

// decodeRecords parses every record the surface wrote.
func decodeRecords(t *testing.T, logs string) []logRecord {
	t.Helper()
	var records []logRecord
	for _, line := range strings.Split(logs, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := map[string]any{}
		if err := json.Unmarshal([]byte(line), &fields); err != nil {
			t.Fatalf("a record is not JSON: %v", err)
		}
		id, _ := fields["request_id"].(string)
		var values []string
		collectStrings(fields, &values)
		records = append(records, logRecord{requestID: id, fields: fields, values: values})
	}
	return records
}

// TestSignOutRequiresTheSameJSONShapeAsEveryOtherOperationWithEffect: a simple
// content type must not reach a revocation, valid origin and token notwithstanding.
func TestSignOutRequiresTheSameJSONShapeAsEveryOtherOperationWithEffect(t *testing.T) {
	shapes := map[string]request{
		"absent":                {noContentType: true},
		"text/plain":            {contentType: "text/plain"},
		"form-urlencoded":       {contentType: "application/x-www-form-urlencoded"},
		"multipart/form-data":   {contentType: "multipart/form-data; boundary=x"},
		"another non-JSON type": {contentType: "application/xml"},
	}
	for name, shape := range shapes {
		t.Run(name, func(t *testing.T) {
			s := newSurface(t)
			address, account := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
			in := s.signIn(t, address, probePassword)
			if in.response.StatusCode != http.StatusCreated {
				t.Fatalf("sign-in returned %d", in.response.StatusCode)
			}
			before := readSessionLedger(t, s)

			r := shape
			r.method, r.target = http.MethodDelete, sessionRoute
			r.cookie, r.csrf, r.origin, r.fetchSite = in.token, in.csrf, publicOrigin, "same-origin"
			res := s.send(t, r)

			if res.StatusCode != http.StatusUnsupportedMediaType {
				t.Fatalf("a %s sign-out returned %d, want 415", name, res.StatusCode)
			}
			if sessionCookie(res) != nil {
				t.Error("a refused sign-out emitted a clearing cookie")
			}
			if after := readSessionLedger(t, s); after != before {
				t.Errorf("the store changed: %+v, want %+v", after, before)
			}
			if live := s.liveSessions(t, account); live != 1 {
				t.Errorf("%d live sessions after a refused sign-out, want 1", live)
			}
			if probe := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin}); probe.StatusCode != http.StatusOK {
				t.Errorf("the session stopped working after a refused sign-out: %d", probe.StatusCode)
			}
		})
	}
}

// TestSignOutValidatesTheRequestShapeBeforeConcludingItIsDone: a malformed request
// is refused whether or not a session answers, never reported as already done.
func TestSignOutValidatesTheRequestShapeBeforeConcludingItIsDone(t *testing.T) {
	s := newSurface(t)
	address, account := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", in.response.StatusCode)
	}

	// No cookie at all.
	res := s.send(t, request{
		method: http.MethodDelete, target: sessionRoute,
		origin: publicOrigin, fetchSite: "same-origin", contentType: "text/plain",
	})
	if res.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("a shapeless sign-out without a cookie returned %d, want 415", res.StatusCode)
	}

	// A session that has already been revoked.
	if err := s.store.RevokeSession(context.Background(), sessionIDOf(t, s, account), s.clock.Now()); err != nil {
		t.Fatalf("revoking failed: %v", err)
	}
	res = s.send(t, request{
		method: http.MethodDelete, target: sessionRoute,
		cookie: in.token, csrf: in.csrf, origin: publicOrigin, fetchSite: "same-origin", contentType: "text/plain",
	})
	if res.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("a shapeless sign-out on a revoked session returned %d, want 415", res.StatusCode)
	}

	// The correctly shaped request still succeeds on that finished session.
	res = s.send(t, request{
		method: http.MethodDelete, target: sessionRoute,
		cookie: in.token, csrf: in.csrf, origin: publicOrigin, fetchSite: "same-origin", contentType: "application/json"})
	if res.StatusCode != http.StatusNoContent {
		t.Errorf("a well-shaped sign-out returned %d, want 204", res.StatusCode)
	}
}

// readSessionLedger counts what a refused sign-out must leave untouched.
func readSessionLedger(t *testing.T, s *surface) [2]int {
	t.Helper()
	var sessions, revoked int
	if err := s.pool.QueryRow(context.Background(), `
		SELECT (SELECT count(*) FROM account_sessions WHERE revoked_at IS NOT NULL),
		       (SELECT count(*) FROM account_security_events WHERE kind = 'session_revoked')`).
		Scan(&sessions, &revoked); err != nil {
		t.Fatalf("reading the ledger failed: %v", err)
	}
	return [2]int{sessions, revoked}
}

// stamps reads the two deadlines a session carries, which is where every claim
// about renewal has to be checked.
func (s *surface) stamps(t *testing.T, account auth.Account) (active, idle, absolute time.Time) {
	t.Helper()
	if err := s.pool.QueryRow(context.Background(),
		`SELECT last_active_at, idle_expires_at, absolute_expires_at FROM account_sessions
		 WHERE account_id = $1 ORDER BY created_at DESC LIMIT 1`, account.ID.String()).
		Scan(&active, &idle, &absolute); err != nil {
		t.Fatalf("reading the deadlines failed: %v", err)
	}
	return active, idle, absolute
}

// TestExplicitActivityExtendsOnlyTheInactivityDeadline is the behaviour the slice
// adds: without it the shorter deadline is a second absolute one.
func TestExplicitActivityExtendsOnlyTheInactivityDeadline(t *testing.T) {
	s := newSurface(t)
	address, account := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", in.response.StatusCode)
	}
	_, idleBefore, absoluteBefore := s.stamps(t, account)

	s.clock.advance(10 * time.Minute)
	res := s.send(t, request{
		method: http.MethodPost, target: activityRoute,
		body: map[string]string{}, origin: publicOrigin, fetchSite: "same-origin",
		cookie: in.token, csrf: in.csrf,
	})
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("the activity signal returned %d, want 204: %s", res.StatusCode, bodyOf(t, res))
	}

	activeAfter, idleAfter, absoluteAfter := s.stamps(t, account)
	if !idleAfter.After(idleBefore) {
		t.Errorf("the inactivity deadline stayed at %s, want it moved past %s", idleAfter, idleBefore)
	}
	if !absoluteAfter.Equal(absoluteBefore) {
		t.Errorf("the absolute deadline moved from %s to %s", absoluteBefore, absoluteAfter)
	}
	if !activeAfter.Equal(s.clock.Now()) {
		t.Errorf("the activity instant is %s, want the server's own %s", activeAfter, s.clock.Now())
	}
	// The session outlives what would have been its unrenewed deadline.
	s.clock.advance(25 * time.Minute)
	if probe := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin}); probe.StatusCode != http.StatusOK {
		t.Fatalf("the renewed session expired on its old schedule: %d", probe.StatusCode)
	}
}

// TestOnlyTheExplicitSignalRenewsTheInactivityDeadline separates the renewal from
// every request that merely happens to carry the cookie.
func TestOnlyTheExplicitSignalRenewsTheInactivityDeadline(t *testing.T) {
	s := newSurface(t)
	address, account := s.account(t, auth.KindCreator, auth.StatusActive, auth.RoleViewer, auth.RoleCreator)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", in.response.StatusCode)
	}
	activeBefore, idleBefore, _ := s.stamps(t, account)
	s.clock.advance(10 * time.Minute)

	passive := []request{
		{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin},
		{method: http.MethodGet, target: broadcastRoute, cookie: in.token, origin: publicOrigin},
		// A top-level navigation, which SameSite=Lax lets carry the cookie.
		{method: http.MethodGet, target: sessionRoute, cookie: in.token},
		{method: http.MethodGet, target: sessionRoute, cookie: in.token, fetchSite: "cross-site"},
	}
	for i, r := range passive {
		if res := s.send(t, r); res.StatusCode != http.StatusOK {
			t.Fatalf("passive read %d returned %d", i, res.StatusCode)
		}
		active, idle, _ := s.stamps(t, account)
		if !active.Equal(activeBefore) || !idle.Equal(idleBefore) {
			t.Fatalf("passive read %d renewed the session: %s / %s", i, active, idle)
		}
	}
	// The explicit signal, and only it, renews.
	if res := s.send(t, request{
		method: http.MethodPost, target: activityRoute, body: map[string]string{},
		origin: publicOrigin, fetchSite: "same-origin", cookie: in.token, csrf: in.csrf,
	}); res.StatusCode != http.StatusNoContent {
		t.Fatalf("the activity signal returned %d", res.StatusCode)
	}
	_, idle, _ := s.stamps(t, account)
	if !idle.After(idleBefore) {
		t.Fatal("the explicit signal did not renew the deadline")
	}
}

// TestTheActivitySignalIsGuardedLikeEveryOtherOperationWithEffect requires the
// same context, shape and token checks a sign-out passes.
func TestTheActivitySignalIsGuardedLikeEveryOtherOperationWithEffect(t *testing.T) {
	s := newSurface(t)
	address, account := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", in.response.StatusCode)
	}
	forged, err := session.NewCSRFToken(nil)
	if err != nil {
		t.Fatalf("drawing failed: %v", err)
	}
	base := request{
		method: http.MethodPost, target: activityRoute, body: map[string]string{},
		origin: publicOrigin, fetchSite: "same-origin", cookie: in.token, csrf: in.csrf,
	}
	refusals := map[string]struct {
		mutate func(*request)
		want   int
	}{
		"foreign origin":       {func(r *request) { r.origin = foreignOrigin }, http.StatusForbidden},
		"absent origin":        {func(r *request) { r.origin = "" }, http.StatusForbidden},
		"cross-site metadata":  {func(r *request) { r.fetchSite = "cross-site" }, http.StatusForbidden},
		"same-site metadata":   {func(r *request) { r.fetchSite = "same-site" }, http.StatusForbidden},
		"absent content type":  {func(r *request) { r.noContentType = true }, http.StatusUnsupportedMediaType},
		"form content type":    {func(r *request) { r.contentType = "application/x-www-form-urlencoded" }, http.StatusUnsupportedMediaType},
		"text content type":    {func(r *request) { r.contentType = "text/plain" }, http.StatusUnsupportedMediaType},
		"absent CSRF token":    {func(r *request) { r.csrf = "" }, http.StatusForbidden},
		"forged CSRF token":    {func(r *request) { r.csrf = forged.Reveal() }, http.StatusForbidden},
		"malformed CSRF token": {func(r *request) { r.csrf = "not-a-token" }, http.StatusForbidden},
		"no session cookie":    {func(r *request) { r.cookie = "" }, http.StatusUnauthorized},
		"unknown session":      {func(r *request) { r.cookie = drawnToken(t) }, http.StatusUnauthorized},
	}
	for name, c := range refusals {
		t.Run(name, func(t *testing.T) {
			activeBefore, idleBefore, _ := s.stamps(t, account)
			r := base
			c.mutate(&r)
			res := s.send(t, r)
			if res.StatusCode != c.want {
				t.Fatalf("returned %d, want %d: %s", res.StatusCode, c.want, bodyOf(t, res))
			}
			if got := res.Header.Get("Cache-Control"); got != "no-store" {
				t.Errorf("the refusal declared %q, want no-store", got)
			}
			active, idle, _ := s.stamps(t, account)
			if !active.Equal(activeBefore) || !idle.Equal(idleBefore) {
				t.Errorf("a refused signal renewed the session: %s / %s", active, idle)
			}
		})
	}
	// The well-formed request still works, so the refusals above were the checks.
	s.clock.advance(2 * time.Minute)
	if res := s.send(t, base); res.StatusCode != http.StatusNoContent {
		t.Fatalf("the well-formed signal returned %d", res.StatusCode)
	}
}

func drawnToken(t *testing.T) string {
	t.Helper()
	token, err := session.NewToken(nil)
	if err != nil {
		t.Fatalf("drawing failed: %v", err)
	}
	return token.Reveal()
}

// TestTheActivitySignalNeitherReplacesTheSessionNorLeaks keeps the operation to
// the one deadline it is for, and keeps its answers empty of anything sensitive.
func TestTheActivitySignalNeitherReplacesTheSessionNorLeaks(t *testing.T) {
	s := newSurface(t)
	address, account := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", in.response.StatusCode)
	}
	var sessionsBefore int
	if err := s.pool.QueryRow(context.Background(), `SELECT count(*) FROM account_sessions`).Scan(&sessionsBefore); err != nil {
		t.Fatalf("counting failed: %v", err)
	}

	s.clock.advance(5 * time.Minute)
	res := s.send(t, request{
		method: http.MethodPost, target: activityRoute, body: map[string]string{},
		origin: publicOrigin, fetchSite: "same-origin", cookie: in.token, csrf: in.csrf,
	})
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("the signal returned %d", res.StatusCode)
	}
	if sessionCookie(res) != nil {
		t.Error("the signal replaced or refreshed the session cookie")
	}
	if body := bodyOf(t, res); body != "" {
		t.Errorf("the signal answered with a body: %q", body)
	}
	var sessionsAfter int
	if err := s.pool.QueryRow(context.Background(), `SELECT count(*) FROM account_sessions`).Scan(&sessionsAfter); err != nil {
		t.Fatalf("counting failed: %v", err)
	}
	if sessionsAfter != sessionsBefore {
		t.Errorf("%d sessions after the signal, want the %d from before", sessionsAfter, sessionsBefore)
	}
	// The same token still resolves: nothing was rotated.
	if probe := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin}); probe.StatusCode != http.StatusOK {
		t.Fatalf("the token stopped working after the signal: %d", probe.StatusCode)
	}

	forbidden := []string{
		"suspended", "account_sessions", "SQLSTATE", "42P01", driverDetail,
		address, account.ID.String(), probePassword, in.token, in.csrf,
	}
	for _, record := range decodeRecords(t, s.logs.String()) {
		for _, value := range record.values {
			for _, secret := range forbidden {
				if strings.Contains(value, secret) {
					t.Errorf("a record carried %q in %q", secret, value)
				}
			}
		}
	}
}

// TestAStorageFailureOnTheActivitySignalIsNotAnAbsentSession keeps the two apart
// on this path as on every other.
func TestAStorageFailureOnTheActivitySignalIsNotAnAbsentSession(t *testing.T) {
	s := newSurface(t)
	address, account := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", in.response.StatusCode)
	}
	activeBefore, idleBefore, _ := s.stamps(t, account)
	s.clock.advance(5 * time.Minute)

	signal := request{
		method: http.MethodPost, target: activityRoute, body: map[string]string{},
		origin: publicOrigin, fetchSite: "same-origin", cookie: in.token, csrf: in.csrf,
	}
	s.faults.activity = func() error { return storeFailure() }
	res := s.send(t, signal)
	s.faults.activity = nil
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("a failed write returned %d, want 500: %s", res.StatusCode, bodyOf(t, res))
	}
	active, idle, _ := s.stamps(t, account)
	if !active.Equal(activeBefore) || !idle.Equal(idleBefore) {
		t.Errorf("a failed write changed the stamps to %s / %s", active, idle)
	}
	// The session is untouched and the signal works once the store answers again.
	if res := s.send(t, signal); res.StatusCode != http.StatusNoContent {
		t.Fatalf("the signal returned %d after the store recovered", res.StatusCode)
	}
}

// TestTheActivitySignalWritesAtMostOncePerInterval proves the bound through the
// HTTP boundary, by observing the stored instant rather than by timing.
func TestTheActivitySignalWritesAtMostOncePerInterval(t *testing.T) {
	s := newSurface(t)
	address, account := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", in.response.StatusCode)
	}
	signal := request{
		method: http.MethodPost, target: activityRoute, body: map[string]string{},
		origin: publicOrigin, fetchSite: "same-origin", cookie: in.token, csrf: in.csrf,
	}

	s.clock.advance(2 * time.Minute)
	if res := s.send(t, signal); res.StatusCode != http.StatusNoContent {
		t.Fatalf("the first signal returned %d", res.StatusCode)
	}
	activeAfterFirst, idleAfterFirst, _ := s.stamps(t, account)

	// A burst inside the same interval is accepted but persists nothing.
	for i := 0; i < 25; i++ {
		if res := s.send(t, signal); res.StatusCode != http.StatusNoContent {
			t.Fatalf("burst signal %d returned %d", i, res.StatusCode)
		}
	}
	active, idle, _ := s.stamps(t, account)
	if !active.Equal(activeAfterFirst) || !idle.Equal(idleAfterFirst) {
		t.Fatalf("a burst inside one interval wrote again: %s / %s", active, idle)
	}

	// Past the interval, one write happens again.
	s.clock.advance(2 * time.Minute)
	if res := s.send(t, signal); res.StatusCode != http.StatusNoContent {
		t.Fatalf("the later signal returned %d", res.StatusCode)
	}
	activeLater, idleLater, _ := s.stamps(t, account)
	if !activeLater.After(activeAfterFirst) || !idleLater.After(idleAfterFirst) {
		t.Fatalf("the deadline did not move past the interval: %s / %s", activeLater, idleLater)
	}
}
