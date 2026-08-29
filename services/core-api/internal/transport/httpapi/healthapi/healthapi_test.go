package healthapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi/healthapi"
)

type checker struct {
	err  error
	hang bool
}

func (c checker) Check(ctx context.Context) error {
	if c.hang {
		<-ctx.Done()
		return ctx.Err()
	}
	return c.err
}

func probe(t *testing.T, handler fiber.Handler, path string) (int, string) {
	t.Helper()
	app := fiber.New()
	app.Get(path, handler)
	res, err := app.Test(httptest.NewRequest(http.MethodGet, path, nil), fiber.TestConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("the probe failed: %v", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading the body failed: %v", err)
	}
	var decoded struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("the probe answered %q, which is not the expected document", body)
	}
	return res.StatusCode, decoded.Status
}

// TestReadinessStartsClosed keeps a process from being routed traffic before its
// startup declared itself finished.
func TestReadinessStartsClosed(t *testing.T) {
	var readiness healthapi.Readiness
	if readiness.Ready() {
		t.Fatal("the zero value reported itself ready")
	}
	readiness.Set(true)
	if !readiness.Ready() {
		t.Error("readiness did not follow the value set")
	}
	readiness.Set(false)
	if readiness.Ready() {
		t.Error("readiness did not follow the clearing")
	}
}

// TestLivenessAnswersFromTheProcessAlone keeps a downstream outage from
// restarting a healthy process.
func TestLivenessAnswersFromTheProcessAlone(t *testing.T) {
	status, body := probe(t, healthapi.LiveHandler, healthapi.LivenessPath)
	if status != http.StatusOK || body != "alive" {
		t.Fatalf("liveness answered %d %q", status, body)
	}
}

func TestReadinessReportsDrainingThenTheStore(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	cases := map[string]struct {
		ready   bool
		store   checker
		status  int
		reports string
	}{
		"draining":      {false, checker{}, http.StatusServiceUnavailable, "not_ready"},
		"store down":    {true, checker{err: errors.New("refused")}, http.StatusServiceUnavailable, "dependency_unavailable"},
		"store hangs":   {true, checker{hang: true}, http.StatusServiceUnavailable, "dependency_unavailable"},
		"store answers": {true, checker{}, http.StatusOK, "ready"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			readiness := &healthapi.Readiness{}
			readiness.Set(c.ready)
			handler := healthapi.ReadyHandler(readiness, c.store, 50*time.Millisecond, logger)
			status, body := probe(t, handler, healthapi.ReadinessPath)
			if status != c.status || body != c.reports {
				t.Fatalf("readiness answered %d %q, want %d %q", status, body, c.status, c.reports)
			}
		})
	}
}
