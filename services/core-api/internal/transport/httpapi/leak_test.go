package httpapi_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"

	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi"
)

const (
	panicSentinel  = "PANIC-SENTINEL-7f3a9c2e"
	serverSentinel = "ERR-SENTINEL-b41d8e60"
)

func appWithCapturedLogs(t *testing.T, logs *strings.Builder) *fiber.App {
	t.Helper()
	readiness := &httpapi.Readiness{}
	readiness.Set(true)
	return mustApp(t, httpapi.Options{Logger: slog.New(slog.NewJSONHandler(logs, nil)), Readiness: readiness, RateLimit: directPolicy(1000)})
}

func assertSafeMetadata(t *testing.T, logs, body, route string) {
	t.Helper()
	for _, want := range []string{
		`"request_id"`,
		`"method":"GET"`,
		`"route":"` + route + `"`,
		`"status":500`,
		`"error_code":"internal_error"`,
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("log record is missing safe metadata %s\nlogs: %s", want, logs)
		}
	}

	var payload httpapi.ErrorResponse
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("response is not the error contract: %v", err)
	}
	if payload.Error.Code != "internal_error" {
		t.Errorf("response code = %q, want internal_error", payload.Error.Code)
	}
	if payload.Error.RequestID == "" {
		t.Error("response is missing the request identifier")
	}
}

func TestPanicValueReachesNeitherResponseNorLogs(t *testing.T) {
	var logs strings.Builder
	app := appWithCapturedLogs(t, &logs)
	app.Get("/panic", func(fiber.Ctx) error { panic("credential " + panicSentinel) })

	res := do(t, app, http.MethodGet, "/panic")
	raw, _ := io.ReadAll(res.Body)
	body := string(raw)

	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", res.StatusCode)
	}
	if strings.Contains(body, panicSentinel) {
		t.Errorf("panic value leaked into the response: %s", body)
	}
	if strings.Contains(logs.String(), panicSentinel) {
		t.Errorf("panic value leaked into the logs: %s", logs.String())
	}
	assertSafeMetadata(t, logs.String(), body, "/panic")
}

func TestServerErrorDetailReachesNeitherResponseNorLogs(t *testing.T) {
	var logs strings.Builder
	app := appWithCapturedLogs(t, &logs)
	app.Get("/server", func(fiber.Ctx) error {
		return fiber.NewError(http.StatusInternalServerError, "dsn "+serverSentinel)
	})

	res := do(t, app, http.MethodGet, "/server")
	raw, _ := io.ReadAll(res.Body)
	body := string(raw)

	if strings.Contains(body, serverSentinel) {
		t.Errorf("server error detail leaked into the response: %s", body)
	}
	if strings.Contains(logs.String(), serverSentinel) {
		t.Errorf("server error detail leaked into the logs: %s", logs.String())
	}
	assertSafeMetadata(t, logs.String(), body, "/server")
}

func TestRequestIdentifierOnEveryApplicationResponse(t *testing.T) {
	var logs strings.Builder
	app := appWithCapturedLogs(t, &logs)
	app.Get("/client", func(fiber.Ctx) error { return fiber.NewError(http.StatusBadRequest, "field is required") })
	app.Get("/server", func(fiber.Ctx) error { return fiber.NewError(http.StatusInternalServerError) })

	cases := map[string]string{
		"health":        "/healthz",
		"unknown route": "/does-not-exist",
		"client error":  "/client",
		"server error":  "/server",
	}
	for name, target := range cases {
		t.Run(name, func(t *testing.T) {
			res := do(t, app, http.MethodGet, target)
			if res.Header.Get("X-Request-Id") == "" {
				t.Errorf("%s response carries no X-Request-Id header", target)
			}
		})
	}

	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		if !strings.Contains(line, `"request_id"`) {
			t.Errorf("request-scoped log record carries no request identifier: %s", line)
		}
	}
}
