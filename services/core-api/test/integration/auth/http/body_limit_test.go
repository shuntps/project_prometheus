package integration_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
	"github.com/shuntps/project_prometheus/services/core-api/internal/ratelimit"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi/authapi"
)

// The bound the authentication surface applies to its own JSON. It is unexported
// there, so the boundary is restated here and the tests below hold it to it.
const authBodyLimit = 32 << 10

// watchedLimiter records what actually reached the attempt limiter, so a refusal
// decided earlier can be told from one the limiter itself made.
type watchedLimiter struct {
	inner *ratelimit.AuthLimiter
	mu    sync.Mutex
	seen  []string
}

func (w *watchedLimiter) Allow(client, identifier string, now time.Time) bool {
	w.mu.Lock()
	w.seen = append(w.seen, identifier)
	w.mu.Unlock()
	return w.inner.Allow(client, identifier, now)
}

func (w *watchedLimiter) attempts() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.seen)
}

// paddedAuthBody renders a sign-in body of exactly size bytes carrying only the
// two fields the request declares, padded with JSON whitespace after the object.
func paddedAuthBody(t *testing.T, address, secret string, size int) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]string{"email": address, "password": secret})
	if err != nil {
		t.Fatalf("encoding the body failed: %v", err)
	}
	if len(body) > size {
		t.Fatalf("the credentials alone are %d bytes, above the requested %d", len(body), size)
	}
	padded := append(body, strings.Repeat(" ", size-len(body))...)
	var probe map[string]string
	if err := json.Unmarshal(padded, &probe); err != nil {
		t.Fatalf("the padded body stopped being valid JSON: %v", err)
	}
	if len(padded) != size {
		t.Fatalf("the body is %d bytes, want exactly %d", len(padded), size)
	}
	return padded
}

// TestAnOversizedAuthenticationBodyIsRefusedBeforeItIsDecoded pins the public
// boundary: past the limit nothing decodes, counts, queries or hashes the body.
func TestAnOversizedAuthenticationBodyIsRefusedBeforeItIsDecoded(t *testing.T) {
	watched := &watchedLimiter{}
	s := newSurface(t, func(c *authConfig) {
		inner, err := ratelimit.NewAuthLimiter(ratelimit.AuthPolicy{
			ClientAttempts: 1_000, IdentityAttempts: 1_000,
			Window: 15 * time.Minute, Capacity: ratelimit.MinAuthCapacity,
		})
		if err != nil {
			t.Fatalf("building the limiter failed: %v", err)
		}
		watched.inner = inner
		c.limiter = watched
	})
	address, account := s.account(t, iam.KindViewer, iam.StatusActive, iam.RoleViewer)

	res := s.send(t, request{
		method: http.MethodPost, target: sessionRoute,
		raw:    paddedAuthBody(t, address, probePassword, authBodyLimit),
		origin: publicOrigin, fetchSite: "same-origin",
	})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("a body of %d bytes answered %d, want %d", authBodyLimit, res.StatusCode, http.StatusCreated)
	}
	if watched.attempts() != 1 {
		t.Fatalf("the limiter saw %d attempts for the body at the limit, want 1", watched.attempts())
	}
	sessionsAfterSuccess := s.liveSessions(t, account)
	eventsAfterSuccess := s.securityEvents(t, account)

	oversized := paddedAuthBody(t, address, probePassword, authBodyLimit+1)
	over := s.send(t, request{
		method: http.MethodPost, target: sessionRoute,
		raw:    oversized,
		origin: publicOrigin, fetchSite: "same-origin",
	})
	if over.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("a body of %d bytes answered %d, want %d", len(oversized), over.StatusCode, http.StatusRequestEntityTooLarge)
	}
	// The same credentials succeeded one byte earlier, so anything below having
	// moved would mean the body was decoded and acted on.
	if watched.attempts() != 1 {
		t.Errorf("the limiter saw %d attempts, want the oversized request never to reach it", watched.attempts())
	}
	if len(over.Cookies()) != 0 {
		t.Errorf("the refusal set %d cookie(s)", len(over.Cookies()))
	}
	if live := s.liveSessions(t, account); live != sessionsAfterSuccess {
		t.Errorf("live sessions went from %d to %d on a refused request", sessionsAfterSuccess, live)
	}
	if events := s.securityEvents(t, account); events != eventsAfterSuccess {
		t.Errorf("security events went from %d to %d on a refused request", eventsAfterSuccess, events)
	}

	raw, err := io.ReadAll(over.Body)
	if err != nil {
		t.Fatalf("reading the body failed: %v", err)
	}
	for _, leak := range []string{address, probePassword} {
		if strings.Contains(string(raw), leak) {
			t.Error("the refusal carries a value the request supplied")
		}
		if strings.Contains(s.logs.String(), leak) {
			t.Error("the log carries a value the request supplied")
		}
	}
}

// TestTheGlobalQuotaStillCountsARefusedBody keeps the surface bound from sitting
// ahead of the shared limiter, which would make a refusal free to repeat.
func TestTheGlobalQuotaStillCountsARefusedBody(t *testing.T) {
	s := newSurface(t)
	address, _ := s.account(t, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
	oversized := paddedAuthBody(t, address, probePassword, authBodyLimit+1)

	remaining := func(res *http.Response) int {
		t.Helper()
		raw := res.Header.Get("X-Ratelimit-Remaining")
		if raw == "" {
			t.Fatal("the global quota reported nothing")
		}
		value, err := strconv.Atoi(raw)
		if err != nil {
			t.Fatalf("the global quota reported %q, which is not an integer: %v", raw, err)
		}
		return value
	}

	first := s.send(t, request{
		method: http.MethodPost, target: sessionRoute, raw: oversized,
		origin: publicOrigin, fetchSite: "same-origin",
	})
	second := s.send(t, request{
		method: http.MethodPost, target: sessionRoute, raw: oversized,
		origin: publicOrigin, fetchSite: "same-origin",
	})
	before, after := remaining(first), remaining(second)
	if after != before-1 {
		t.Fatalf("the global quota went from %d to %d, want exactly one less", before, after)
	}
}

// TestEveryAuthenticationRouteIsBounded drives the routes the surface actually
// registered, read from the router, so a new one cannot escape the bound.
func TestEveryAuthenticationRouteIsBounded(t *testing.T) {
	s := newSurface(t)
	oversized := []byte("{}" + strings.Repeat(" ", authBodyLimit))

	var registered []fiber.Route
	for _, route := range s.app.GetRoutes(true) {
		if strings.HasPrefix(route.Path, authapi.PathPrefix) {
			registered = append(registered, route)
		}
	}
	if len(registered) != 5 {
		t.Fatalf("the router holds %d authentication routes, want the 5 the surface registers: %v", len(registered), registered)
	}
	for _, route := range registered {
		res := s.send(t, request{
			method: route.Method, target: route.Path, raw: oversized,
			origin: publicOrigin, fetchSite: "same-origin",
		})
		if res.StatusCode != http.StatusRequestEntityTooLarge {
			t.Errorf("%s %s answered %d for %d bytes, want %d",
				route.Method, route.Path, res.StatusCode, len(oversized), http.StatusRequestEntityTooLarge)
		}
	}
}

func (s *surface) securityEvents(t *testing.T, account iam.Account) int {
	t.Helper()
	var count int
	if err := s.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM account_security_events WHERE account_id = $1`,
		account.ID.String()).Scan(&count); err != nil {
		t.Fatalf("counting security events failed: %v", err)
	}
	return count
}
