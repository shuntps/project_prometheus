package httpapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/web"
)

// serverIDPattern is the only shape the canonical identifier may have: the 43
// Base64URL characters of a 32-byte token the server drew itself.
var serverIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// TestTheCanonicalIdentifierIsAlwaysServerGenerated: a value a public client puts
// in the header is never adopted, echoed or logged, whatever it carries.
func TestTheCanonicalIdentifierIsAlwaysServerGenerated(t *testing.T) {
	s := newSurface(t)
	address, _ := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)

	// The client's value carries exactly what must never travel: an address, a
	// password and a realistic driver message.
	crafted := "sent-by-the-client " + address + " " + probePassword + " " + driverDetail
	forbidden := []string{"sent-by-the-client", address, probePassword, driverDetail, "SQLSTATE", "42P01", "account_sessions"}

	var ids []string
	for attempt := 1; attempt <= 2; attempt++ {
		res := s.send(t, request{
			method: http.MethodPost, target: sessionRoute,
			body:   map[string]string{"email": address, "password": "wrong-" + probePassword},
			origin: publicOrigin, fetchSite: "same-origin", requestID: crafted,
		})
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("the refusal returned %d", res.StatusCode)
		}
		body := bodyOf(t, res)
		id := requestIDOf(t, body)
		if id == crafted {
			t.Fatal("the client's value became the canonical identifier")
		}
		if echoed := res.Header.Get("X-Request-Id"); echoed != id {
			t.Fatalf("the response header carries %q, want the canonical %q", echoed, id)
		}
		for _, value := range decodedValues(t, body) {
			for _, secret := range forbidden {
				if strings.Contains(value, secret) {
					t.Errorf("the response carried %q in %q", secret, value)
				}
			}
		}
		ids = append(ids, id)
	}
	// Two requests sharing one client value get two distinct server identifiers.
	if ids[0] == ids[1] {
		t.Fatalf("two requests sharing a client value shared the identifier %s", ids[0])
	}

	records := decodeRecords(t, s.logs.String())
	for _, id := range ids {
		handled := 0
		for _, record := range records {
			if record.requestID == id && record.fields["msg"] == "request handled" {
				handled++
			}
		}
		// Each response correlates to exactly its own handling record.
		if handled != 1 {
			t.Fatalf("%d handling records for %s, want exactly 1", handled, id)
		}
	}
	for _, record := range records {
		if record.requestID == crafted {
			t.Fatal("a record adopted the client's value as its identifier")
		}
		for _, value := range record.values {
			for _, secret := range forbidden {
				if strings.Contains(value, secret) {
					t.Errorf("a record carried %q in %q", secret, value)
				}
			}
		}
	}

	// An empty, oversized or syntactically unusual client value never changes the
	// canonical shape either; requestIDOf enforces that shape.
	weirdness := map[string]string{
		"empty":     "",
		"oversized": strings.Repeat("A", 2048),
		"spaced":    "  leading and trailing spaces  ",
		"non-ascii": "h\u00e9llo-\u00ff-identifier",
	}
	for name, weird := range weirdness {
		req := httptest.NewRequest(http.MethodGet, sessionRoute, nil)
		req.Header.Set(web.OriginHeader, publicOrigin)
		req.Header.Set("X-Request-Id", weird)
		res, err := s.app.Test(req, fiber.TestConfig{Timeout: 30 * time.Second, FailOnTimeout: true})
		if err != nil {
			t.Fatalf("the %s request failed: %v", name, err)
		}
		body := bodyOf(t, res)
		_ = res.Body.Close()
		id := requestIDOf(t, body)
		if weird != "" && id == weird {
			t.Errorf("the %s client value became the canonical identifier", name)
		}
	}
}

type logRecord struct {
	requestID string
	fields    map[string]any
	// values holds every string the record carries except the correlation
	// identifier, which is opaque and not something the service disclosed.
	values []string
}

// collectStrings gathers the text a decoded document carries, skipping the
// correlation identifier wherever it appears.
func collectStrings(node any, into *[]string) {
	switch typed := node.(type) {
	case map[string]any:
		for key, value := range typed {
			// The identifier is excluded only once it has the server's shape;
			// anything else in that field is scanned like every other value.
			if key == "request_id" {
				if id, ok := value.(string); ok && serverIDPattern.MatchString(id) {
					continue
				}
			}
			collectStrings(value, into)
		}
	case []any:
		for _, value := range typed {
			collectStrings(value, into)
		}
	case string:
		*into = append(*into, typed)
	}
}

// decodedValues returns what a JSON document actually says, identifier excluded,
// so a scan reads the service's own text rather than the encoding around it.
func decodedValues(t *testing.T, document string) []string {
	t.Helper()
	var node any
	if err := json.Unmarshal([]byte(document), &node); err != nil {
		t.Fatalf("decoding failed: %v", err)
	}
	var values []string
	collectStrings(node, &values)
	return values
}

// requestIDOf reads the identifier the response carries, used only to correlate.
func requestIDOf(t *testing.T, body string) string {
	t.Helper()
	var parsed struct {
		Error struct {
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("decoding the response failed: %v", err)
	}
	if !serverIDPattern.MatchString(parsed.Error.RequestID) {
		t.Fatalf("the response identifier %q is not of the server's shape", parsed.Error.RequestID)
	}
	return parsed.Error.RequestID
}

// decodeRecords parses every record the surface wrote.
func decodeRecords(t *testing.T, logs string) []logRecord {
	t.Helper()
	var records []logRecord
	for _, line := range strings.Split(logs, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := map[string]any{}
		if err := json.Unmarshal([]byte(line), &fields); err != nil {
			t.Fatalf("a record is not JSON: %v", err)
		}
		id, _ := fields["request_id"].(string)
		var values []string
		collectStrings(fields, &values)
		records = append(records, logRecord{requestID: id, fields: fields, values: values})
	}
	return records
}
