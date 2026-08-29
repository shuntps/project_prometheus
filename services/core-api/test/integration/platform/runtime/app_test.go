package integration_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/app"
	"github.com/shuntps/project_prometheus/services/core-api/internal/config"
	"github.com/shuntps/project_prometheus/services/core-api/internal/ratelimit"
)

func freeAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not reserve a port: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("could not release the reserved port: %v", err)
	}
	return address
}

func waitForStatus(t *testing.T, url string, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		res, err := http.Get(url)
		if err == nil {
			status := res.StatusCode
			_ = res.Body.Close()
			if status == want {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s never returned %d", url, want)
}

func TestRunServesThenShutsDownGracefully(t *testing.T) {
	dsn, host := realPostgres(t)
	address := freeAddress(t)
	cfg := config.Config{
		Environment:     config.EnvDevelopment,
		PublicOrigin:    testPublicOrigin,
		Auth:            testAuthSettings(),
		LogLevel:        "error",
		HTTPAddress:     address,
		RateLimit:       ratelimit.Policy{Max: 1000, Window: time.Hour, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.Direct},
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

	base := "http://" + address
	waitForStatus(t, base+"/readyz", http.StatusOK)
	waitForStatus(t, base+"/healthz", http.StatusOK)

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned an error on shutdown: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after the context was cancelled")
	}

	if _, err := http.Get(base + "/healthz"); err == nil {
		t.Error("expected the listener to be closed after shutdown")
	}
}
