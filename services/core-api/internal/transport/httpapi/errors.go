// Package httpapi is the HTTP transport adapter: routing, middleware and the
// error contract every response outside the success path follows.
package httpapi

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/requestid"
)

type ErrorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
}

type ErrorResponse struct {
	Error ErrorBody `json:"error"`
}

const genericServerMessage = "The server could not process the request."

// NewErrorHandler renders every unhandled error as the same JSON contract and
// never lets an internal message reach the client.
func NewErrorHandler(logger *slog.Logger) fiber.ErrorHandler {
	return func(c fiber.Ctx, err error) error {
		status := StatusFromError(err)
		message := genericServerMessage

		var fiberErr *fiber.Error
		if errors.As(err, &fiberErr) && status < http.StatusInternalServerError {
			message = fiberErr.Message
		}

		if status >= http.StatusInternalServerError {
			// The error message can carry caller-supplied detail, so only its Go
			// type is recorded; the stable code identifies the failure class.
			logger.Error("request failed",
				slog.String("request_id", requestid.FromContext(c)),
				slog.String("method", c.Method()),
				slog.String("route", routePattern(c)),
				slog.Int("status", status),
				slog.String("error_code", codeFor(status)),
				slog.String("error_type", fmt.Sprintf("%T", err)),
			)
		}

		return c.Status(status).JSON(ErrorResponse{Error: ErrorBody{
			Code:      codeFor(status),
			Message:   message,
			RequestID: requestid.FromContext(c),
		}})
	}
}

// StatusFromError is the single mapping from a handler error to a status code,
// so that a response and its log record can never disagree.
func StatusFromError(err error) int {
	if err == nil {
		return http.StatusOK
	}
	var fiberErr *fiber.Error
	if errors.As(err, &fiberErr) {
		return fiberErr.Code
	}
	return http.StatusInternalServerError
}

func codeFor(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "bad_request"
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusMethodNotAllowed:
		return "method_not_allowed"
	case http.StatusRequestTimeout:
		return "request_timeout"
	case http.StatusTooManyRequests:
		return "too_many_requests"
	case http.StatusServiceUnavailable:
		return "service_unavailable"
	default:
		if status >= http.StatusInternalServerError {
			return "internal_error"
		}
		return "request_error"
	}
}

func routePattern(c fiber.Ctx) string {
	if route := c.Route(); route != nil {
		return route.Path
	}
	return ""
}
