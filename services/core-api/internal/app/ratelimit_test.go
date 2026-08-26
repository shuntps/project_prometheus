package app_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/app"
	"github.com/shuntps/project_prometheus/services/core-api/internal/config"
	"github.com/shuntps/project_prometheus/services/core-api/internal/ratelimit"
)

// clientFrom dials from a specific loopback source address so each client
// presents a distinct peer address to the server.
func clientFrom(t *testing.T, source string) *http.Client {
	t.Helper()
	addr, err := net.ResolveTCPAddr("tcp", source+":0")
	if err != nil {
		t.Fatalf("could not resolve source %s: %v", source, err)
	}
	dialer := &net.Dialer{LocalAddr: addr}
	return &http.Client{Transport: &http.Transport{DialContext: dialer.DialContext, DisableKeepAlives: true}}
}

func TestDistinctPeerAddressesDoNotShareTheQuota(t *testing.T) {
	const max = 2
	address := freeAddress(t)
	dsn, host := realPostgres(t)
	cfg := config.Config{
		Environment:     config.EnvProduction,
		LogLevel:        "error",
		HTTPAddress:     address,
		RateLimit:       ratelimit.Policy{Max: max, Window: time.Hour, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.Direct},
		ReadTimeout:     time.Second,
		WriteTimeout:    time.Second,
		IdleTimeout:     time.Second,
		ShutdownTimeout: 5 * time.Second,
		DatabaseURL:     dsnFor(t, dsn, host),
		Database:        testSettings(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		service, err := app.New(ctx, cfg, slog.New(slog.NewJSONHandler(io.Discard, nil)))
		if err != nil {
			done <- err
			return
		}
		done <- service.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	base := "http://" + address
	waitForStatus(t, base+"/readyz", http.StatusOK)

	first := clientFrom(t, "127.0.0.2")
	for i := 1; i <= max; i++ {
		if status := statusFrom(t, first, base+"/nothing-here"); status == http.StatusTooManyRequests {
			t.Fatalf("first client was refused on request %d, before reaching the limit", i)
		}
	}
	if status := statusFrom(t, first, base+"/nothing-here"); status != http.StatusTooManyRequests {
		t.Fatalf("first client status = %d after the quota, want 429", status)
	}

	second := clientFrom(t, "127.0.0.3")
	if status := statusFrom(t, second, base+"/nothing-here"); status == http.StatusTooManyRequests {
		t.Error("a different peer address inherited the exhausted quota")
	}
}

func statusFrom(t *testing.T, client *http.Client, url string) int {
	t.Helper()
	res, err := client.Get(url)
	if err != nil {
		t.Fatalf("request to %s failed: %v", url, err)
	}
	defer func() { _ = res.Body.Close() }()
	return res.StatusCode
}

// Proxy trust and IP validation are both on here, and the peer is a genuine TCP
// client whose address sits outside the allowlist.
func TestUntrustedPeerBehindProxyModeCannotForgeIdentity(t *testing.T) {
	const (
		max        = 2
		peerSource = "127.0.0.4"
	)
	allowlist := netip.MustParsePrefix("10.0.0.0/8")
	peer := netip.MustParseAddr(peerSource)
	if allowlist.Contains(peer) {
		t.Fatalf("test premise broken: peer %s is inside the allowlist %s", peer, allowlist)
	}

	address := freeAddress(t)
	dsn, host := realPostgres(t)
	cfg := config.Config{
		Environment: config.EnvProduction,
		LogLevel:    "error",
		HTTPAddress: address,
		RateLimit: ratelimit.Policy{
			Max: max, Window: time.Hour, Algorithm: ratelimit.FixedWindow,
			NetworkMode: ratelimit.BehindProxy, ProxyHeader: "X-Forwarded-For",
			TrustedProxies: []netip.Prefix{allowlist},
		},
		ReadTimeout: time.Second, WriteTimeout: time.Second, IdleTimeout: time.Second,
		ShutdownTimeout: 5 * time.Second,
		DatabaseURL:     dsnFor(t, dsn, host),
		Database:        testSettings(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		service, err := app.New(ctx, cfg, slog.New(slog.NewJSONHandler(io.Discard, nil)))
		if err != nil {
			done <- err
			return
		}
		done <- service.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	base := "http://" + address
	waitForStatus(t, base+"/readyz", http.StatusOK)

	client := clientFrom(t, peerSource)
	get := func(forwarded string) int {
		req, err := http.NewRequest(http.MethodGet, base+"/nothing-here", nil)
		if err != nil {
			t.Fatalf("building the request failed: %v", err)
		}
		if forwarded != "" {
			req.Header.Set("X-Forwarded-For", forwarded)
			req.Header.Set("X-Real-Ip", forwarded)
			req.Header.Set("Forwarded", "for="+forwarded)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = res.Body.Close() }()
		return res.StatusCode
	}

	for i := 1; i <= max; i++ {
		if status := get(""); status == http.StatusTooManyRequests {
			t.Fatalf("the untrusted peer was refused on request %d, before reaching its own limit", i)
		}
	}
	if status := get(""); status != http.StatusTooManyRequests {
		t.Fatalf("the untrusted peer was not refused after its quota: status %d", status)
	}

	for _, forged := range []string{"203.0.113.1", "203.0.113.2, 10.0.0.9", "10.0.0.9", "198.51.100.7"} {
		if status := get(forged); status != http.StatusTooManyRequests {
			t.Errorf("forging %q gave the untrusted peer a fresh quota: status %d", forged, status)
		}
	}
}

func TestUnsupportedProxyHeaderIsRefusedAtStartup(t *testing.T) {
	cfg := config.Config{
		Environment: config.EnvProduction,
		LogLevel:    "error",
		HTTPAddress: "127.0.0.1:0",
		RateLimit: ratelimit.Policy{
			Max: 5, Window: time.Hour, Algorithm: ratelimit.FixedWindow,
			NetworkMode: ratelimit.BehindProxy, ProxyHeader: "X-Client-Ip",
			TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		},
		ReadTimeout: time.Second, WriteTimeout: time.Second, IdleTimeout: time.Second,
		ShutdownTimeout: time.Second,
	}
	service, err := app.New(context.Background(), cfg, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err == nil {
		t.Fatal("expected startup to be refused for an unsupported proxy header")
	}
	if service != nil {
		t.Error("expected no service when the header is refused")
	}
}
