package requestlog_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/gofiber/fiber/v3/middleware/requestid"

	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi/requestlog"
)

const forged = "forged-by-the-client"

func record(logs *bytes.Buffer) map[string]any {
	lines := bytes.Split(bytes.TrimSpace(logs.Bytes()), []byte("\n"))
	var last map[string]any
	_ = json.Unmarshal(lines[len(lines)-1], &last)
	return last
}

// TestTheClientIdentifierIsAlwaysReplaced keeps public input from being echoed
// back as the canonical identifier of a request.
func TestTheClientIdentifierIsAlwaysReplaced(t *testing.T) {
	app := fiber.New()
	app.Use(requestlog.StripClientRequestID)
	app.Use(requestid.New(requestid.Config{Header: requestlog.RequestIDHeader}))
	app.Get("/probe", func(c fiber.Ctx) error { return c.SendString(requestid.FromContext(c)) })

	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set(requestlog.RequestIDHeader, forged)
	res, err := app.Test(req, fiber.TestConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("the request failed: %v", err)
	}
	defer res.Body.Close()
	if got := res.Header.Get(requestlog.RequestIDHeader); got == forged || got == "" {
		t.Fatalf("the answer carried %q", got)
	}
}

// TestTheRecordNamesTheRouteAndTheStatusActuallyReturned keeps a log line from
// carrying a target, and from disagreeing with what the client received.
func TestTheRecordNamesTheRouteAndTheStatusActuallyReturned(t *testing.T) {
	logs := &bytes.Buffer{}
	app := fiber.New()
	app.Use(requestid.New(requestid.Config{Header: requestlog.RequestIDHeader}))
	app.Use(requestlog.RequestLogger(slog.New(slog.NewJSONHandler(logs, nil))))
	app.Get("/probe/:id", func(fiber.Ctx) error { return fiber.NewError(http.StatusTooManyRequests) })

	if _, err := app.Test(httptest.NewRequest(http.MethodGet, "/probe/secret-value?token=leak", nil),
		fiber.TestConfig{Timeout: 5 * time.Second}); err != nil {
		t.Fatalf("the request failed: %v", err)
	}
	last := record(logs)
	if last["route"] != "rate_limited" {
		t.Errorf("the record named the route %v", last["route"])
	}
	if last["status"] != float64(http.StatusTooManyRequests) {
		t.Errorf("the record reported status %v", last["status"])
	}
	if bytes.Contains(logs.Bytes(), []byte("secret-value")) || bytes.Contains(logs.Bytes(), []byte("leak")) {
		t.Error("the raw target reached the record")
	}
	if last["request_id"] == "" || last["request_id"] == nil {
		t.Error("the record carries no correlation identifier")
	}
}

// TestARecoveredPanicCarriesNothingItHeld keeps the recovered value out of both
// the answer and the record.
func TestARecoveredPanicCarriesNothingItHeld(t *testing.T) {
	logs := &bytes.Buffer{}
	app := fiber.New()
	app.Use(requestid.New(requestid.Config{Header: requestlog.RequestIDHeader}))
	app.Use(recover.New(recover.Config{PanicHandler: requestlog.PanicHandler(slog.New(slog.NewJSONHandler(logs, nil)))}))
	app.Get("/probe", func(fiber.Ctx) error { panic("the database password is hunter2") })

	res, err := app.Test(httptest.NewRequest(http.MethodGet, "/probe", nil), fiber.TestConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("the request failed: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("the recovered panic answered %d", res.StatusCode)
	}
	if bytes.Contains(logs.Bytes(), []byte("hunter2")) {
		t.Error("the panic value reached the record")
	}
}
