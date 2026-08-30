package integration_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/shuntps/project_prometheus/services/core-api/internal/ratelimit"
	"github.com/shuntps/project_prometheus/services/core-api/internal/testsupport/httpfixture"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi/healthapi"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi/httperror"
)

const testProxyHeader = "X-Forwarded-For"

// proxyPolicy trusts the peer address the test harness presents, so the
// forwarded chain becomes authoritative for the key.
func proxyPolicy(max int) ratelimit.Policy {
	return ratelimit.Policy{
		Max:         max,
		Window:      time.Hour,
		Algorithm:   ratelimit.FixedWindow,
		NetworkMode: ratelimit.BehindProxy,
		ProxyHeader: testProxyHeader,
	}.WithTrustedProxies(netip.MustParsePrefix("0.0.0.0/32"), netip.MustParsePrefix("10.0.0.0/8"))
}

func statusWithHeader(t *testing.T, app *fiber.App, target, header, value string) int {
	t.Helper()
	req := newRequest(http.MethodGet, target)
	if header != "" {
		req.Header.Set(header, value)
	}
	res, err := app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	return res.StatusCode
}

func TestConstructorRefusesAPolicyThatWouldFallBackToLibraryDefaults(t *testing.T) {
	proxies := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	cases := map[string]ratelimit.Policy{
		"empty policy":                    {},
		"zero maximum":                    {Window: time.Hour, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.Direct},
		"negative maximum":                {Max: -1, Window: time.Hour, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.Direct},
		"zero window":                     {Max: 5, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.Direct},
		"unknown algorithm":               {Max: 5, Window: time.Hour, Algorithm: "token_bucket", NetworkMode: ratelimit.Direct},
		"empty algorithm":                 {Max: 5, Window: time.Hour, NetworkMode: ratelimit.Direct},
		"unset network mode":              {Max: 5, Window: time.Hour, Algorithm: ratelimit.FixedWindow},
		"unknown network mode":            {Max: 5, Window: time.Hour, Algorithm: ratelimit.FixedWindow, NetworkMode: "edge"},
		"proxies without the mode":        ratelimit.Policy{Max: 5, Window: time.Hour, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.Direct}.WithTrustedProxies(proxies...),
		"header without the mode":         {Max: 5, Window: time.Hour, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.Direct, ProxyHeader: testProxyHeader},
		"proxy mode without a list":       {Max: 5, Window: time.Hour, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.BehindProxy, ProxyHeader: testProxyHeader},
		"proxy mode without header":       ratelimit.Policy{Max: 5, Window: time.Hour, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.BehindProxy}.WithTrustedProxies(proxies...),
		"zero-value prefix":               ratelimit.Policy{Max: 5, Window: time.Hour, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.BehindProxy, ProxyHeader: testProxyHeader}.WithTrustedProxies(netip.Prefix{}),
		"invalid prefix among valid ones": ratelimit.Policy{Max: 5, Window: time.Hour, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.BehindProxy, ProxyHeader: testProxyHeader}.WithTrustedProxies(netip.MustParsePrefix("10.0.0.0/8"), netip.Prefix{}),
		"unsupported header":              ratelimit.Policy{Max: 5, Window: time.Hour, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.BehindProxy, ProxyHeader: "X-Client-Ip"}.WithTrustedProxies(proxies...),
		"non canonical header":            ratelimit.Policy{Max: 5, Window: time.Hour, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.BehindProxy, ProxyHeader: "x-forwarded-for"}.WithTrustedProxies(proxies...),
		"empty header string":             ratelimit.Policy{Max: 5, Window: time.Hour, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.BehindProxy, ProxyHeader: "   "}.WithTrustedProxies(proxies...),
	}
	for name, policy := range cases {
		t.Run(name, func(t *testing.T) {
			app, err := httpapi.New(completeExcept(policy))
			if err == nil {
				t.Fatal("expected the constructor to refuse the policy instead of serving library defaults")
			}
			if app != nil {
				t.Error("expected no application when the policy is refused")
			}
		})
	}
}

func TestConstructorAcceptsACompletePolicy(t *testing.T) {
	for name, policy := range map[string]ratelimit.Policy{"direct": httpfixture.DirectPolicy(5), "behind proxy": proxyPolicy(5)} {
		t.Run(name, func(t *testing.T) {
			if _, err := httpapi.New(completeExcept(policy)); err != nil {
				t.Errorf("complete policy was refused: %v", err)
			}
		})
	}
}

func TestEachAlgorithmAcceptsExactlyMaxRequests(t *testing.T) {
	const (
		max      = 5
		attempts = 40
	)
	for name, algorithm := range map[string]ratelimit.Algorithm{"fixed window": ratelimit.FixedWindow, "sliding window": ratelimit.SlidingWindow} {
		t.Run(name, func(t *testing.T) {
			policy := httpfixture.DirectPolicy(max)
			policy.Algorithm = algorithm
			app := httpfixture.MustApp(t, &httpapi.Options{RateLimit: policy})

			var mu sync.Mutex
			counts := map[int]int{}
			var failures []error
			var wg sync.WaitGroup
			for i := 0; i < attempts; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					res, err := app.Test(newRequest(http.MethodGet, "/resource"))
					mu.Lock()
					defer mu.Unlock()
					if err != nil {
						failures = append(failures, err)
						return
					}
					counts[res.StatusCode]++
					_ = res.Body.Close()
				}()
			}
			wg.Wait()

			if len(failures) > 0 {
				t.Fatalf("%d attempts returned a transport error: %v", len(failures), failures[0])
			}
			total := 0
			for _, n := range counts {
				total += n
			}
			if total != attempts {
				t.Fatalf("accounted for %d attempts, want %d", total, attempts)
			}
			if counts[http.StatusOK] != max {
				t.Errorf("accepted %d requests, want exactly %d", counts[http.StatusOK], max)
			}
			if counts[http.StatusTooManyRequests] != attempts-max {
				t.Errorf("refused %d requests, want %d", counts[http.StatusTooManyRequests], attempts-max)
			}
			if len(counts) != 2 {
				t.Errorf("unexpected status codes returned: %v", counts)
			}
		})
	}
}

func TestRefusalCarriesConsistentIdentifiersAndHeaders(t *testing.T) {
	var logs strings.Builder
	app := httpfixture.MustApp(t, &httpapi.Options{
		Logger:    slog.New(slog.NewJSONHandler(&logs, nil)),
		RateLimit: httpfixture.DirectPolicy(1),
	})
	do(t, app, http.MethodGet, "/resource")

	res := do(t, app, http.MethodGet, "/resource")
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", res.StatusCode)
	}

	var payload httperror.ErrorResponse
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatalf("refusal is not the error contract: %v", err)
	}
	headerID := res.Header.Get("X-Request-Id")
	if headerID == "" || payload.Error.RequestID != headerID {
		t.Errorf("header identifier %q and body identifier %q must match and be non-empty", headerID, payload.Error.RequestID)
	}
	if payload.Error.Code != "too_many_requests" {
		t.Errorf("code = %q, want too_many_requests", payload.Error.Code)
	}

	// The middleware emits Retry-After on refusal; the X-RateLimit family is
	// emitted on served responses, where its remaining count is meaningful.
	retry := res.Header.Get("Retry-After")
	retrySeconds, err := strconv.Atoi(retry)
	if err != nil || retrySeconds <= 0 {
		t.Errorf("Retry-After = %q, want a positive number of seconds", retry)
	}
	for _, absent := range []string{"X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"} {
		if value := res.Header.Get(absent); value != "" {
			t.Errorf("%s = %q on a refusal; this middleware does not emit it there", absent, value)
		}
	}

	record := lastLogRecord(t, logs.String())
	assertRequestLogFields(t, record, headerID, "rate_limited", 429)
}

func TestServedResponseCarriesCoherentRateLimitHeaders(t *testing.T) {
	const max = 3
	app := httpfixture.MustApp(t, &httpapi.Options{RateLimit: httpfixture.DirectPolicy(max)})

	for served := 1; served <= max; served++ {
		res := do(t, app, http.MethodGet, "/resource")
		if res.StatusCode != http.StatusOK {
			t.Fatalf("request %d = %d, want 200", served, res.StatusCode)
		}
		if got := res.Header.Get("X-RateLimit-Limit"); got != strconv.Itoa(max) {
			t.Errorf("X-RateLimit-Limit = %q, want %d", got, max)
		}
		remaining, err := strconv.Atoi(res.Header.Get("X-RateLimit-Remaining"))
		if err != nil {
			t.Fatalf("X-RateLimit-Remaining is not a number: %v", err)
		}
		if want := max - served; remaining != want {
			t.Errorf("after request %d, X-RateLimit-Remaining = %d, want %d", served, remaining, want)
		}
		reset, err := strconv.Atoi(res.Header.Get("X-RateLimit-Reset"))
		if err != nil || reset <= 0 {
			t.Errorf("X-RateLimit-Reset = %q, want a positive number of seconds", res.Header.Get("X-RateLimit-Reset"))
		}
	}
}

func TestHealthEndpointsAreNotRefusedByTheApplicationQuota(t *testing.T) {
	app := httpfixture.MustApp(t, &httpapi.Options{RateLimit: httpfixture.DirectPolicy(1)})
	do(t, app, http.MethodGet, "/resource")
	do(t, app, http.MethodGet, "/resource")

	for _, target := range []string{"/healthz", "/readyz"} {
		res := do(t, app, http.MethodGet, target)
		if res.StatusCode != http.StatusOK {
			t.Errorf("%s returned %d once the quota was exhausted, want 200", target, res.StatusCode)
		}
	}
}

func TestUnknownRoutesAreLimited(t *testing.T) {
	const max = 2
	app := httpfixture.MustApp(t, &httpapi.Options{RateLimit: httpfixture.DirectPolicy(max)})
	for i := 0; i < max; i++ {
		do(t, app, http.MethodGet, "/scan-"+strconv.Itoa(i))
	}
	res := do(t, app, http.MethodGet, "/scan-final")
	if res.StatusCode != http.StatusTooManyRequests {
		t.Errorf("unknown route returned %d after the quota, want 429", res.StatusCode)
	}
}

// completeExcept supplies every dependency unrelated to the quota, so a refusal
// can only come from the policy the case is actually proving.
func completeExcept(policy ratelimit.Policy) httpapi.Options {
	return httpapi.Options{
		Logger:       slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Readiness:    &healthapi.Readiness{},
		RateLimit:    policy,
		Persistence:  httpfixture.NewStubStore(true),
		CheckTimeout: time.Second,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
	}
}
