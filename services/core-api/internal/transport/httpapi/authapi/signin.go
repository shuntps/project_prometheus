package authapi

import (
	"encoding/json"
	"net/http"

	"github.com/gofiber/fiber/v3"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/application"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi/requestlimit"
)

// signInFailure is the one answer every unsuccessful sign-in produces: an unknown
// address, a wrong password and an unusable account are not distinguished.
const signInFailure = "The credentials were not accepted."

type signInRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// signIn reads the request, hands the extracted values to the use case and
// translates its outcome. Every decision about the caller is made behind it.
func (s *authSurface) signIn(c fiber.Ctx) error {
	if err := verifyRequestOrigin(c, s.origin); err != nil {
		return err
	}
	if err := requireJSONRequest(c); err != nil {
		return err
	}

	var req signInRequest
	if err := json.Unmarshal(c.Body(), &req); err != nil {
		return fiber.NewError(http.StatusBadRequest, "The request body is not valid JSON.")
	}
	if err := password.CheckResourceLimit(req.Password); err != nil {
		return fiber.NewError(http.StatusBadRequest, "The submitted values exceed the accepted size.")
	}

	in := application.SignInRequest{
		ClientKey: requestlimit.ClientKey(c),
		Email:     req.Email,
		Password:  req.Password,
	}
	if token, held := sessionTokenFromRequest(c); held {
		in.Presented = &token
	}

	result, err := s.signIns.Execute(c.Context(), in)
	if err != nil {
		return fiber.NewError(http.StatusInternalServerError)
	}
	switch result.Outcome {
	case application.OutcomeSucceeded:
		setSessionCookie(c, result.Token, result.Session.AbsoluteExpiresAt)
		return c.Status(http.StatusCreated).JSON(viewOf(result.Session, result.Principal))
	case application.OutcomeRateLimited:
		return fiber.NewError(http.StatusTooManyRequests, "Too many authentication attempts.")
	case application.OutcomeRejected:
		return fiber.NewError(http.StatusUnauthorized, signInFailure)
	default:
		// An outcome this transport does not map is a refusal, never a session.
		return fiber.NewError(http.StatusInternalServerError)
	}
}
