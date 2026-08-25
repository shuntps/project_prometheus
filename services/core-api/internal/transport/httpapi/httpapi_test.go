package httpapi_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi"
)

func newTestApp(t *testing.T, ready bool) *fiber.App {
	t.Helper()
	readiness := &httpapi.Readiness{}
	readiness.Set(ready)
	app, err := httpapi.New(httpapi.Options{
		Logger:       slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Readiness:    readiness,
		RateLimit:    directPolicy(1000),
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
		IdleTimeout:  time.Second,
	})
	if err != nil {
		t.Fatalf("building the application failed: %v", err)
	}
	return app
}

func newRequest(method, target string) *http.Request {
	return httptest.NewRequest(method, target, nil)
}

func do(t *testing.T, app *fiber.App, method, target string) *http.Response {
	t.Helper()
	res, err := app.Test(httptest.NewRequest(method, target, nil))
	if err != nil {
		t.Fatalf("request %s %s failed: %v", method, target, err)
	}
	t.Cleanup(func() { _ = res.Body.Close() })
	return res
}

func TestLivenessAlwaysReportsAlive(t *testing.T) {
	for _, ready := range []bool{true, false} {
		res := do(t, newTestApp(t, ready), http.MethodGet, "/healthz")
		if res.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200 when readiness is %v", res.StatusCode, ready)
		}
		body, _ := io.ReadAll(res.Body)
		if !strings.Contains(string(body), `"alive"`) {
			t.Errorf("body = %s, want it to report alive", body)
		}
	}
}

func TestReadinessReflectsServingState(t *testing.T) {
	res := do(t, newTestApp(t, true), http.MethodGet, "/readyz")
	if res.StatusCode != http.StatusOK {
		t.Errorf("ready status = %d, want 200", res.StatusCode)
	}

	res = do(t, newTestApp(t, false), http.MethodGet, "/readyz")
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("not-ready status = %d, want 503", res.StatusCode)
	}
}

func TestUnknownRouteUsesTheErrorContract(t *testing.T) {
	res := do(t, newTestApp(t, true), http.MethodGet, "/does-not-exist")
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", res.StatusCode)
	}
	if got := res.Header.Get("Content-Type"); !strings.HasPrefix(got, fiber.MIMEApplicationJSON) {
		t.Errorf("content type = %q, want JSON", got)
	}

	var payload httpapi.ErrorResponse
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatalf("body is not the error contract: %v", err)
	}
	if payload.Error.Code != "not_found" {
		t.Errorf("code = %q, want not_found", payload.Error.Code)
	}
	if payload.Error.RequestID == "" {
		t.Error("expected the error body to carry a request identifier")
	}
}

func TestEveryResponseCarriesARequestIdentifier(t *testing.T) {
	res := do(t, newTestApp(t, true), http.MethodGet, "/healthz")
	if res.Header.Get("X-Request-Id") == "" {
		t.Error("expected an X-Request-Id response header")
	}
}

func TestPanicIsRecoveredWithoutLeakingDetail(t *testing.T) {
	app := newTestApp(t, true)
	app.Get("/boom", func(fiber.Ctx) error { panic("database password hunter2") })

	res := do(t, app, http.MethodGet, "/boom")
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", res.StatusCode)
	}

	body, _ := io.ReadAll(res.Body)
	if strings.Contains(string(body), "hunter2") {
		t.Fatalf("panic detail leaked to the client: %s", body)
	}

	var payload httpapi.ErrorResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("body is not the error contract: %v", err)
	}
	if payload.Error.Code != "internal_error" {
		t.Errorf("code = %q, want internal_error", payload.Error.Code)
	}
}

func TestClientErrorMessageIsPreservedButServerErrorIsNot(t *testing.T) {
	app := newTestApp(t, true)
	app.Get("/client", func(fiber.Ctx) error { return fiber.NewError(http.StatusBadRequest, "field is required") })
	app.Get("/server", func(fiber.Ctx) error {
		return fiber.NewError(http.StatusInternalServerError, "connection string leaked")
	})

	var client httpapi.ErrorResponse
	_ = json.NewDecoder(do(t, app, http.MethodGet, "/client").Body).Decode(&client)
	if client.Error.Message != "field is required" {
		t.Errorf("client message = %q, want it preserved", client.Error.Message)
	}

	var server httpapi.ErrorResponse
	_ = json.NewDecoder(do(t, app, http.MethodGet, "/server").Body).Decode(&server)
	if strings.Contains(server.Error.Message, "connection string") {
		t.Errorf("server message leaked internal detail: %q", server.Error.Message)
	}
}

func TestRequestLogRecordsTheStatusActuallyReturned(t *testing.T) {
	var captured strings.Builder
	readiness := &httpapi.Readiness{}
	readiness.Set(true)
	app := mustApp(t, httpapi.Options{Logger: slog.New(slog.NewJSONHandler(&captured, nil)), Readiness: readiness, RateLimit: directPolicy(1000)})

	do(t, app, http.MethodGet, "/does-not-exist")

	logged := captured.String()
	if !strings.Contains(logged, `"status":404`) {
		t.Errorf("log does not record the returned status: %s", logged)
	}
	if !strings.Contains(logged, `"route":"unmatched"`) {
		t.Errorf("log does not mark the request as unmatched: %s", logged)
	}
}
