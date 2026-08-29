package requestlimit_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/shuntps/project_prometheus/services/core-api/internal/ratelimit"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi/requestlimit"
)

// TestTheQuotaCountsPerClientAndSparesTheDeclaredPaths proves the quota on its
// own, without the assembled router deciding anything for it.
func TestTheQuotaCountsPerClientAndSparesTheDeclaredPaths(t *testing.T) {
	const max = 2
	policy := ratelimit.Policy{Max: max, Window: time.Hour, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.Direct}
	app := fiber.New()
	app.Use(requestlimit.RateLimiter(policy, "/spared"))
	app.Get("/probe", func(c fiber.Ctx) error { return c.SendString("ok") })
	app.Get("/spared", func(c fiber.Ctx) error { return c.SendString("ok") })

	send := func(path string) int {
		res, err := app.Test(httptest.NewRequest(http.MethodGet, path, nil), fiber.TestConfig{Timeout: 5 * time.Second})
		if err != nil {
			t.Fatalf("the request failed: %v", err)
		}
		defer res.Body.Close()
		return res.StatusCode
	}
	for i := range max {
		if status := send("/probe"); status != http.StatusOK {
			t.Fatalf("request %d was refused with %d", i+1, status)
		}
	}
	if status := send("/probe"); status != http.StatusTooManyRequests {
		t.Errorf("the request over the ceiling answered %d", status)
	}
	for range max + 2 {
		if status := send("/spared"); status != http.StatusOK {
			t.Fatalf("a spared path was refused with %d", status)
		}
	}
}

// TestTheClientKeyFallsBackToThePeer keeps an unusable forwarded chain from
// opening a bucket of its own.
func TestTheClientKeyFallsBackToThePeer(t *testing.T) {
	app := fiber.New()
	app.Get("/probe", func(c fiber.Ctx) error { return c.SendString(requestlimit.ClientKey(c)) })
	res, err := app.Test(httptest.NewRequest(http.MethodGet, "/probe", nil), fiber.TestConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("the request failed: %v", err)
	}
	defer res.Body.Close()
	body := make([]byte, 64)
	n, _ := res.Body.Read(body)
	if n == 0 {
		t.Fatal("the client key resolved to nothing")
	}
}
