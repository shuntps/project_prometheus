package httperror_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi/httperror"
)

const internalDetail = "connection to db.internal as core_api failed"

func render(t *testing.T, logs io.Writer, err error) (int, httperror.ErrorResponse) {
	t.Helper()
	app := fiber.New(fiber.Config{ErrorHandler: httperror.NewErrorHandler(slog.New(slog.NewJSONHandler(logs, nil)))})
	app.Get("/probe", func(fiber.Ctx) error { return err })
	res, testErr := app.Test(httptest.NewRequest(http.MethodGet, "/probe", nil), fiber.TestConfig{Timeout: 5 * time.Second})
	if testErr != nil {
		t.Fatalf("the request failed: %v", testErr)
	}
	defer res.Body.Close()
	body, readErr := io.ReadAll(res.Body)
	if readErr != nil {
		t.Fatalf("reading the body failed: %v", readErr)
	}
	var decoded httperror.ErrorResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("the answer %q is not the error contract", body)
	}
	return res.StatusCode, decoded
}

// TestStatusFromErrorIsTheSingleMapping keeps a response and its log record from
// ever disagreeing about what happened.
func TestStatusFromErrorIsTheSingleMapping(t *testing.T) {
	if got := httperror.StatusFromError(nil); got != http.StatusOK {
		t.Errorf("no error resolved to %d, want 200", got)
	}
	if got := httperror.StatusFromError(errors.New("plain")); got != http.StatusInternalServerError {
		t.Errorf("an ordinary error resolved to %d, want 500", got)
	}
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests} {
		if got := httperror.StatusFromError(fiber.NewError(status)); got != status {
			t.Errorf("a %d error resolved to %d", status, got)
		}
	}
}

// TestTheContractCarriesAStableCodeForEveryStatus keeps a client from having to
// parse a message to tell one refusal from another.
func TestTheContractCarriesAStableCodeForEveryStatus(t *testing.T) {
	for status, code := range map[int]string{
		http.StatusBadRequest: "bad_request", http.StatusUnauthorized: "unauthorized",
		http.StatusForbidden: "forbidden", http.StatusNotFound: "not_found",
		http.StatusMethodNotAllowed: "method_not_allowed", http.StatusRequestTimeout: "request_timeout",
		http.StatusTooManyRequests: "too_many_requests", http.StatusServiceUnavailable: "service_unavailable",
		http.StatusInternalServerError: "internal_error", http.StatusBadGateway: "internal_error",
		http.StatusPaymentRequired: "request_error",
	} {
		got, body := render(t, io.Discard, fiber.NewError(status))
		if got != status || body.Error.Code != code {
			t.Errorf("status %d rendered %d %q, want %q", status, got, body.Error.Code, code)
		}
	}
}

// TestAClientMessageSurvivesWhileAServerOneNeverDoes keeps caller-supplied detail
// out of an answer the caller never provided.
func TestAClientMessageSurvivesWhileAServerOneNeverDoes(t *testing.T) {
	_, client := render(t, io.Discard, fiber.NewError(http.StatusBadRequest, "The request body is not valid JSON."))
	if client.Error.Message != "The request body is not valid JSON." {
		t.Errorf("the client message became %q", client.Error.Message)
	}

	logs := &bytes.Buffer{}
	status, server := render(t, logs, fiber.NewError(http.StatusInternalServerError, internalDetail))
	if status != http.StatusInternalServerError {
		t.Fatalf("the server error rendered %d", status)
	}
	if server.Error.Message == internalDetail {
		t.Error("the internal message reached the client")
	}
	if bytes.Contains(logs.Bytes(), []byte(internalDetail)) {
		t.Error("the internal message reached the log record")
	}
	if !bytes.Contains(logs.Bytes(), []byte(`"error_code":"internal_error"`)) {
		t.Error("the log record carries no stable failure class")
	}
}
