package integration_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/shuntps/project_prometheus/services/core-api/internal/testsupport/httpfixture"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi/healthapi"
)

func appWithStore(t *testing.T, store *httpfixture.StubStore, logs *bytes.Buffer) *fiber.App {
	t.Helper()
	logger := slog.New(slog.NewJSONHandler(logs, nil))
	readiness := &healthapi.Readiness{}
	readiness.Set(true)
	app, err := httpapi.New(httpapi.Options{
		Logger:       logger,
		Readiness:    readiness,
		RateLimit:    httpfixture.DirectPolicy(1000),
		Persistence:  store,
		CheckTimeout: 200 * time.Millisecond,
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
		IdleTimeout:  time.Second,
	})
	if err != nil {
		t.Fatalf("building the application failed: %v", err)
	}
	return app
}

func statusAndBody(t *testing.T, app *fiber.App, target string) (int, string) {
	t.Helper()
	res := do(t, app, http.MethodGet, target)
	var body healthPayload
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decoding %s failed: %v", target, err)
	}
	return res.StatusCode, body.Status
}

type healthPayload struct {
	Status string `json:"status"`
}

func TestReadinessFollowsTheStoreAndRecoversOnItsOwn(t *testing.T) {
	store := httpfixture.NewStubStore(true)
	var logs bytes.Buffer
	app := appWithStore(t, store, &logs)

	if status, body := statusAndBody(t, app, "/readyz"); status != http.StatusOK || body != "ready" {
		t.Fatalf("with the store available: got %d %q, want 200 \"ready\"", status, body)
	}

	store.SetAvailable(false)
	if status, body := statusAndBody(t, app, "/readyz"); status != http.StatusServiceUnavailable || body != "dependency_unavailable" {
		t.Fatalf("during the outage: got %d %q, want 503 \"dependency_unavailable\"", status, body)
	}

	store.SetAvailable(true)
	if status, body := statusAndBody(t, app, "/readyz"); status != http.StatusOK || body != "ready" {
		t.Fatalf("after recovery: got %d %q, want 200 \"ready\"", status, body)
	}
}

// TestLivenessIgnoresTheStoreEntirely keeps an outage downstream from restarting
// a process that is running perfectly well.
func TestLivenessIgnoresTheStoreEntirely(t *testing.T) {
	store := httpfixture.NewStubStore(false)
	var logs bytes.Buffer
	app := appWithStore(t, store, &logs)

	if status, body := statusAndBody(t, app, "/healthz"); status != http.StatusOK || body != "alive" {
		t.Fatalf("during the outage: got %d %q, want 200 \"alive\"", status, body)
	}
	if calls := store.Calls(); calls != 0 {
		t.Errorf("liveness consulted the store %d time(s)", calls)
	}
}

// TestAStoreThatNeverAnswersStillYieldsAProbeResult keeps a probe from hanging
// on an unresponsive dependency until the orchestrator's own timeout fires.
func TestAStoreThatNeverAnswersStillYieldsAProbeResult(t *testing.T) {
	store := httpfixture.NewStubStore(true)
	store.SetHanging(true)
	var logs bytes.Buffer
	app := appWithStore(t, store, &logs)

	started := time.Now()
	status, body := statusAndBody(t, app, "/readyz")
	elapsed := time.Since(started)

	if status != http.StatusServiceUnavailable || body != "dependency_unavailable" {
		t.Fatalf("got %d %q, want 503 \"dependency_unavailable\"", status, body)
	}
	if elapsed > 2*time.Second {
		t.Errorf("the probe took %s, which is not bounded by the configured timeout", elapsed)
	}
}

// TestDrainingReportsNotReadyWithoutConsultingTheStore keeps shutdown from
// depending on a dependency that may already be gone.
func TestDrainingReportsNotReadyWithoutConsultingTheStore(t *testing.T) {
	store := httpfixture.NewStubStore(true)
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	readiness := &healthapi.Readiness{}
	app, err := httpapi.New(httpapi.Options{
		Logger: logger, Readiness: readiness, RateLimit: httpfixture.DirectPolicy(1000),
		Persistence: store, CheckTimeout: 200 * time.Millisecond,
		ReadTimeout: time.Second, WriteTimeout: time.Second, IdleTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("building the application failed: %v", err)
	}

	if status, body := statusAndBody(t, app, "/readyz"); status != http.StatusServiceUnavailable || body != "not_ready" {
		t.Fatalf("got %d %q, want 503 \"not_ready\"", status, body)
	}
	if calls := store.Calls(); calls != 0 {
		t.Errorf("a draining service consulted the store %d time(s)", calls)
	}
}

func TestTheUnavailableDependencyRecordCarriesNoConnectionDetail(t *testing.T) {
	store := httpfixture.NewStubStore(false)
	var logs bytes.Buffer
	app := appWithStore(t, store, &logs)

	if status, _ := statusAndBody(t, app, "/readyz"); status != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503", status)
	}
	record := logs.String()
	if !strings.Contains(record, "readiness dependency unavailable") {
		t.Fatalf("the outage was not recorded: %s", record)
	}
	for _, fragment := range []string{"store refused the check", "postgres", "sslmode", "password", "host="} {
		if strings.Contains(record, fragment) {
			t.Errorf("the record exposed %q: %s", fragment, record)
		}
	}
}

// TestTheConstructorRefusesAServiceWithNoStoreBehindIt closes the one shape that
// would let the service serve traffic with persistence silently switched off.
func TestTheConstructorRefusesAServiceWithNoStoreBehindIt(t *testing.T) {
	base := httpapi.Options{
		Logger: slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)), Readiness: &healthapi.Readiness{},
		RateLimit: httpfixture.DirectPolicy(10), Persistence: httpfixture.NewStubStore(true), CheckTimeout: time.Second,
		ReadTimeout: time.Second, WriteTimeout: time.Second, IdleTimeout: time.Second,
	}
	if _, err := httpapi.New(base); err != nil {
		t.Fatalf("complete options were refused: %v", err)
	}

	missingStore := base
	missingStore.Persistence = nil
	if _, err := httpapi.New(missingStore); err == nil {
		t.Error("the constructor accepted options with no store")
	}

	for _, timeout := range []time.Duration{0, -time.Second} {
		unbounded := base
		unbounded.CheckTimeout = timeout
		if _, err := httpapi.New(unbounded); err == nil {
			t.Errorf("the constructor accepted an unbounded check timeout %s", timeout)
		}
	}
}
