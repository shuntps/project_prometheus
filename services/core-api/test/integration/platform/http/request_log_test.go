package integration_test

import (
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/shuntps/project_prometheus/services/core-api/internal/testsupport/httpfixture"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi"
)

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
	app := httpfixture.MustApp(t, &httpapi.Options{Logger: slog.New(slog.NewJSONHandler(&logs, nil)), RateLimit: proxyPolicy(1)})
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
