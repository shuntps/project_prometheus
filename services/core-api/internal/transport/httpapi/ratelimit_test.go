package httpapi_test

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
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi"
)

const testProxyHeader = "X-Forwarded-For"

func mustApp(t *testing.T, opts httpapi.Options) *fiber.App {
	t.Helper()
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	if opts.Readiness == nil {
		opts.Readiness = &httpapi.Readiness{}
		opts.Readiness.Set(true)
	}
	opts.ReadTimeout, opts.WriteTimeout, opts.IdleTimeout = time.Second, time.Second, time.Second
	app, err := httpapi.New(opts)
	if err != nil {
		t.Fatalf("building the application failed: %v", err)
	}
	app.Get("/resource", func(c fiber.Ctx) error { return c.SendString("ok") })
	return app
}

func directPolicy(max int) ratelimit.Policy {
	return ratelimit.Policy{Max: max, Window: time.Hour, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.Direct}
}

// proxyPolicy trusts the peer address the test harness presents, so the
// forwarded chain becomes authoritative for the key.
func proxyPolicy(max int) ratelimit.Policy {
	return ratelimit.Policy{
		Max:            max,
		Window:         time.Hour,
		Algorithm:      ratelimit.FixedWindow,
		NetworkMode:    ratelimit.BehindProxy,
		ProxyHeader:    testProxyHeader,
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/32"), netip.MustParsePrefix("10.0.0.0/8")},
	}
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

// ---------- constructor refuses implicit defaults ----------

func TestConstructorRefusesAPolicyThatWouldFallBackToLibraryDefaults(t *testing.T) {
	proxies := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	cases := map[string]ratelimit.Policy{
		"empty policy":              {},
		"zero maximum":              {Window: time.Hour, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.Direct},
		"negative maximum":          {Max: -1, Window: time.Hour, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.Direct},
		"zero window":               {Max: 5, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.Direct},
		"unknown algorithm":         {Max: 5, Window: time.Hour, Algorithm: "token_bucket", NetworkMode: ratelimit.Direct},
		"empty algorithm":           {Max: 5, Window: time.Hour, NetworkMode: ratelimit.Direct},
		"unset network mode":        {Max: 5, Window: time.Hour, Algorithm: ratelimit.FixedWindow},
		"unknown network mode":      {Max: 5, Window: time.Hour, Algorithm: ratelimit.FixedWindow, NetworkMode: "edge"},
		"proxies without the mode":  {Max: 5, Window: time.Hour, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.Direct, TrustedProxies: proxies},
		"header without the mode":   {Max: 5, Window: time.Hour, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.Direct, ProxyHeader: testProxyHeader},
		"proxy mode without a list": {Max: 5, Window: time.Hour, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.BehindProxy, ProxyHeader: testProxyHeader},
		"proxy mode without header": {Max: 5, Window: time.Hour, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.BehindProxy, TrustedProxies: proxies},
		"zero-value prefix":         {Max: 5, Window: time.Hour, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.BehindProxy, ProxyHeader: testProxyHeader, TrustedProxies: []netip.Prefix{{}}},
		"invalid prefix among valid ones": {Max: 5, Window: time.Hour, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.BehindProxy, ProxyHeader: testProxyHeader,
			TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), {}}},
		"unsupported header":   {Max: 5, Window: time.Hour, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.BehindProxy, ProxyHeader: "X-Client-Ip", TrustedProxies: proxies},
		"non canonical header": {Max: 5, Window: time.Hour, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.BehindProxy, ProxyHeader: "x-forwarded-for", TrustedProxies: proxies},
		"empty header string":  {Max: 5, Window: time.Hour, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.BehindProxy, ProxyHeader: "   ", TrustedProxies: proxies},
	}
	for name, policy := range cases {
		t.Run(name, func(t *testing.T) {
			app, err := httpapi.New(httpapi.Options{RateLimit: policy})
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
	for name, policy := range map[string]ratelimit.Policy{"direct": directPolicy(5), "behind proxy": proxyPolicy(5)} {
		t.Run(name, func(t *testing.T) {
			if _, err := httpapi.New(httpapi.Options{RateLimit: policy}); err != nil {
				t.Errorf("complete policy was refused: %v", err)
			}
		})
	}
}

// ---------- proxy chain resolution ----------

func TestChainOfTrustedProxiesResolvesTheRightmostUntrustedClient(t *testing.T) {
	app := mustApp(t, httpapi.Options{RateLimit: proxyPolicy(1)})

	// 203.0.113.5 is the client; 10.0.0.7 and 10.0.0.8 are trusted hops.
	if status := statusWithHeader(t, app, "/resource", testProxyHeader, "203.0.113.5, 10.0.0.7, 10.0.0.8"); status != http.StatusOK {
		t.Fatalf("first request through the chain = %d, want 200", status)
	}
	if status := statusWithHeader(t, app, "/resource", testProxyHeader, "203.0.113.5, 10.0.0.7, 10.0.0.8"); status != http.StatusTooManyRequests {
		t.Fatalf("second request from the same client = %d, want 429", status)
	}
	// A different client behind the very same hops must not inherit the quota.
	if status := statusWithHeader(t, app, "/resource", testProxyHeader, "203.0.113.6, 10.0.0.7, 10.0.0.8"); status != http.StatusOK {
		t.Error("a different client behind the same proxies inherited the exhausted quota")
	}
}

func TestValuePrependedByAMaliciousClientDoesNotChangeTheKey(t *testing.T) {
	app := mustApp(t, httpapi.Options{RateLimit: proxyPolicy(1)})

	if status := statusWithHeader(t, app, "/resource", testProxyHeader, "203.0.113.5, 10.0.0.7"); status != http.StatusOK {
		t.Fatalf("first request = %d, want 200", status)
	}
	// The client controls only what it prepends; the proxy appends its own view.
	for _, spoof := range []string{"198.51.100.1", "198.51.100.2, 198.51.100.3"} {
		status := statusWithHeader(t, app, "/resource", testProxyHeader, spoof+", 203.0.113.5, 10.0.0.7")
		if status != http.StatusTooManyRequests {
			t.Errorf("prepending %q reset the quota: status %d", spoof, status)
		}
	}
}

func TestUnusableForwardedValuesShareThePeerBucketExactly(t *testing.T) {
	const max = 3
	app := mustApp(t, httpapi.Options{RateLimit: proxyPolicy(max)})

	unusable := []string{"not-an-address", "999.999.999.999", "", "   ,  ,", "%%%", "::gg", "1.2.3", "abc, def"}
	counts := map[int]int{}
	for _, value := range unusable {
		req := newRequest(http.MethodGet, "/resource")
		req.Header.Set(testProxyHeader, value)
		res, err := app.Test(req)
		if err != nil {
			t.Fatalf("request carrying %q returned a transport error: %v", value, err)
		}
		counts[res.StatusCode]++
		_ = res.Body.Close()
	}

	total := 0
	for _, n := range counts {
		total += n
	}
	if total != len(unusable) {
		t.Fatalf("accounted for %d attempts, want %d", total, len(unusable))
	}
	if counts[http.StatusOK] != max {
		t.Errorf("served %d unusable-header requests, want exactly %d from the shared peer bucket", counts[http.StatusOK], max)
	}
	if counts[http.StatusTooManyRequests] != len(unusable)-max {
		t.Errorf("refused %d unusable-header requests, want %d", counts[http.StatusTooManyRequests], len(unusable)-max)
	}
	if len(counts) != 2 {
		t.Errorf("unexpected status codes returned: %v", counts)
	}

	// A client presenting a valid chain keeps a bucket of its own.
	for i := 1; i <= max; i++ {
		if status := statusWithHeader(t, app, "/resource", testProxyHeader, "203.0.113.5, 10.0.0.7"); status != http.StatusOK {
			t.Fatalf("valid client request %d = %d, want 200 from its own bucket", i, status)
		}
	}
	if status := statusWithHeader(t, app, "/resource", testProxyHeader, "203.0.113.5, 10.0.0.7"); status != http.StatusTooManyRequests {
		t.Errorf("valid client was not refused after its own quota: status %d", status)
	}
}

// Direct mode reads no forwarded header. The stronger boundary, proxy trust on
// with a peer outside the allowlist, is proven against a real peer in package app.
func TestDirectModeIgnoresForwardedHeaders(t *testing.T) {
	app := mustApp(t, httpapi.Options{RateLimit: directPolicy(1)})
	if status := statusWithHeader(t, app, "/resource", "", ""); status != http.StatusOK {
		t.Fatalf("first request = %d, want 200", status)
	}
	for _, header := range []string{"X-Forwarded-For", "X-Real-Ip", "Forwarded"} {
		if status := statusWithHeader(t, app, "/resource", header, "203.0.113.99"); status != http.StatusTooManyRequests {
			t.Errorf("%s reset the quota in direct mode: status %d", header, status)
		}
	}
}

// ---------- limit behaviour ----------

func TestEachAlgorithmAcceptsExactlyMaxRequests(t *testing.T) {
	const (
		max      = 5
		attempts = 40
	)
	for name, algorithm := range map[string]ratelimit.Algorithm{"fixed window": ratelimit.FixedWindow, "sliding window": ratelimit.SlidingWindow} {
		t.Run(name, func(t *testing.T) {
			policy := directPolicy(max)
			policy.Algorithm = algorithm
			app := mustApp(t, httpapi.Options{RateLimit: policy})

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
	app := mustApp(t, httpapi.Options{
		Logger:    slog.New(slog.NewJSONHandler(&logs, nil)),
		RateLimit: directPolicy(1),
	})
	do(t, app, http.MethodGet, "/resource")

	res := do(t, app, http.MethodGet, "/resource")
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", res.StatusCode)
	}

	var payload httpapi.ErrorResponse
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
	app := mustApp(t, httpapi.Options{RateLimit: directPolicy(max)})

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

// ---------- log shape ----------

func lastLogRecord(t *testing.T, logs string) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(logs), "\n")
	if len(lines) == 0 || lines[0] == "" {
		t.Fatal("no log record was written")
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &record); err != nil {
		t.Fatalf("log line is not JSON: %v", err)
	}
	return record
}

var allowedRequestLogFields = map[string]bool{
	"time": true, "level": true, "msg": true,
	"request_id": true, "method": true, "route": true, "status": true, "duration_ms": true,
}

func assertRequestLogFields(t *testing.T, record map[string]any, wantID, wantRoute string, wantStatus int) {
	t.Helper()
	for field := range record {
		if !allowedRequestLogFields[field] {
			t.Errorf("log record carries unexpected field %q: %v", field, record[field])
		}
	}
	if got, _ := record["request_id"].(string); got != wantID {
		t.Errorf("log request_id = %q, want %q", got, wantID)
	}
	if got, _ := record["route"].(string); got != wantRoute {
		t.Errorf("log route = %q, want %q", got, wantRoute)
	}
	if got, _ := record["status"].(float64); int(got) != wantStatus {
		t.Errorf("log status = %v, want %d", record["status"], wantStatus)
	}
	if got, _ := record["method"].(string); got == "" {
		t.Error("log record carries no method")
	}
}

func TestNoLogRecordExposesClientIdentity(t *testing.T) {
	var logs strings.Builder
	app := mustApp(t, httpapi.Options{Logger: slog.New(slog.NewJSONHandler(&logs, nil)), RateLimit: proxyPolicy(1)})
	statusWithHeader(t, app, "/resource", testProxyHeader, "203.0.113.5, 10.0.0.7")
	statusWithHeader(t, app, "/resource", testProxyHeader, "203.0.113.5, 10.0.0.7")

	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("log line is not JSON: %v", err)
		}
		for field := range record {
			if !allowedRequestLogFields[field] {
				t.Errorf("log record carries unexpected field %q", field)
			}
		}
		if strings.Contains(line, "203.0.113.5") || strings.Contains(line, "10.0.0.7") || strings.Contains(line, "0.0.0.0") {
			t.Errorf("log record exposes a client address: %s", line)
		}
	}
}

// ---------- scope preserved from the previous pass ----------

func TestHealthEndpointsAreNotRefusedByTheApplicationQuota(t *testing.T) {
	app := mustApp(t, httpapi.Options{RateLimit: directPolicy(1)})
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
	app := mustApp(t, httpapi.Options{RateLimit: directPolicy(max)})
	for i := 0; i < max; i++ {
		do(t, app, http.MethodGet, "/scan-"+strconv.Itoa(i))
	}
	res := do(t, app, http.MethodGet, "/scan-final")
	if res.StatusCode != http.StatusTooManyRequests {
		t.Errorf("unknown route returned %d after the quota, want 429", res.StatusCode)
	}
}
