package routemeta_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi/routemeta"
)

const (
	secretSegment = "2f8a-account-identifier"
	secretQuery   = "session-token-value"
)

// TestAResolvedRouteIsNamedByItsRegisteredPattern keeps a parameter and a query
// value out of the name every record is built from.
func TestAResolvedRouteIsNamedByItsRegisteredPattern(t *testing.T) {
	seen := make(chan string, 1)
	app := fiber.New()
	app.Get("/resource/:id", func(c fiber.Ctx) error {
		seen <- routemeta.RoutePattern(c)
		return c.SendString("ok")
	})

	target := "/resource/" + secretSegment + "?token=" + secretQuery
	if _, err := app.Test(httptest.NewRequest(http.MethodGet, target, nil),
		fiber.TestConfig{Timeout: 5 * time.Second}); err != nil {
		t.Fatalf("the request failed: %v", err)
	}
	got := <-seen
	if got != "/resource/:id" {
		t.Fatalf("the resolved route was named %q, want %q", got, "/resource/:id")
	}
	if got == target {
		t.Error("the raw target became the name")
	}
}

// TestATargetTheRouterResolvedToNothingNamesNothing exercises a genuinely unknown
// target through the error handler, which is where an unresolved request lands.
// No Use handler is registered: one would itself become the route "/" and hide
// what the derivation does on its own.
func TestATargetTheRouterResolvedToNothingNamesNothing(t *testing.T) {
	seen := make(chan string, 1)
	matched := make(chan bool, 1)
	app := fiber.New(fiber.Config{ErrorHandler: func(c fiber.Ctx, _ error) error {
		matched <- c.Matched()
		seen <- routemeta.RoutePattern(c)
		return c.SendStatus(http.StatusNotFound)
	}})
	app.Get("/resource/:id", func(c fiber.Ctx) error { return c.SendString("ok") })

	target := "/nowhere/" + secretSegment + "?token=" + secretQuery
	res, err := app.Test(httptest.NewRequest(http.MethodGet, target, nil),
		fiber.TestConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("the request failed: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("the unknown target answered %d", res.StatusCode)
	}
	if wasMatched := <-matched; wasMatched {
		t.Fatal("the router reported the unknown target as matched")
	}
	got := <-seen
	if got != "" {
		t.Errorf("an unresolved target was named %q, want nothing", got)
	}
	for _, leak := range []string{secretSegment, secretQuery, "/nowhere"} {
		if strings.Contains(got, leak) {
			t.Errorf("the name %q carries %q", got, leak)
		}
	}
}
