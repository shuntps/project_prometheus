package integration_test

import (
	"net/http"
	"testing"

	"github.com/shuntps/project_prometheus/services/core-api/internal/testsupport/httpfixture"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi"
)

func TestChainOfTrustedProxiesResolvesTheRightmostUntrustedClient(t *testing.T) {
	app := httpfixture.MustApp(t, &httpapi.Options{RateLimit: proxyPolicy(1)})

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
	app := httpfixture.MustApp(t, &httpapi.Options{RateLimit: proxyPolicy(1)})

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
	app := httpfixture.MustApp(t, &httpapi.Options{RateLimit: proxyPolicy(max)})

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
	app := httpfixture.MustApp(t, &httpapi.Options{RateLimit: httpfixture.DirectPolicy(1)})
	if status := statusWithHeader(t, app, "/resource", "", ""); status != http.StatusOK {
		t.Fatalf("first request = %d, want 200", status)
	}
	for _, header := range []string{"X-Forwarded-For", "X-Real-Ip", "Forwarded"} {
		if status := statusWithHeader(t, app, "/resource", header, "203.0.113.99"); status != http.StatusTooManyRequests {
			t.Errorf("%s reset the quota in direct mode: status %d", header, status)
		}
	}
}
