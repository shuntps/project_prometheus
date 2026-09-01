package authapi

import (
	"encoding/json"
	"net/http"

	"github.com/gofiber/fiber/v3"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi/requestlimit"
)

// registrationAccepted is the one answer every admitted registration produces.
// A new address, one already registered and one belonging to an account that
// may not be touched are not distinguished, so no caller learns which it was.
const (
	registrationInvalid = "The submitted values are not acceptable."
	verificationInvalid = "The verification link is not valid."
	registrationBusy    = "Too many registration attempts."
	verificationBusy    = "Too many verification attempts."
)

type registrationRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type reissueRequest struct {
	Email string `json:"email"`
}

type verificationRequest struct {
	Token string `json:"token"`
}

func (s *authSurface) registerAccount(c fiber.Ctx) error {
	if err := verifyRequestOrigin(c, s.origin); err != nil {
		return err
	}
	if err := requireJSONRequest(c); err != nil {
		return err
	}

	var req registrationRequest
	if err := json.Unmarshal(c.Body(), &req); err != nil {
		return fiber.NewError(http.StatusBadRequest, "The request body is not valid JSON.")
	}
	if err := password.CheckResourceLimit(req.Password); err != nil {
		return fiber.NewError(http.StatusBadRequest, "The submitted values exceed the accepted size.")
	}

	outcome, err := s.registrations.Execute(c.Context(), auth.RegistrationRequest{
		ClientKey: requestlimit.ClientKey(c),
		Email:     req.Email,
		Password:  req.Password,
	})
	if err != nil {
		return fiber.NewError(http.StatusInternalServerError)
	}
	return acceptedOr(c, outcome, registrationInvalid, registrationBusy)
}

// resendVerification asks for another message. It carries no password, so no
// value here can change a credential.
func (s *authSurface) resendVerification(c fiber.Ctx) error {
	if err := verifyRequestOrigin(c, s.origin); err != nil {
		return err
	}
	if err := requireJSONRequest(c); err != nil {
		return err
	}

	var req reissueRequest
	if err := json.Unmarshal(c.Body(), &req); err != nil {
		return fiber.NewError(http.StatusBadRequest, "The request body is not valid JSON.")
	}

	outcome, err := s.registrations.Reissue(c.Context(), auth.ReissueRequest{
		ClientKey: requestlimit.ClientKey(c),
		Email:     req.Email,
	})
	if err != nil {
		return fiber.NewError(http.StatusInternalServerError)
	}
	return acceptedOr(c, outcome, registrationInvalid, registrationBusy)
}

// verifyEmail consumes a verification token read from the request body. No route
// reads one from a path, a query string or a GET, so nothing this service
// records can contain it.
func (s *authSurface) verifyEmail(c fiber.Ctx) error {
	if err := verifyRequestOrigin(c, s.origin); err != nil {
		return err
	}
	if err := requireJSONRequest(c); err != nil {
		return err
	}

	var req verificationRequest
	if err := json.Unmarshal(c.Body(), &req); err != nil {
		return fiber.NewError(http.StatusBadRequest, "The request body is not valid JSON.")
	}

	outcome, err := s.verifications.Execute(c.Context(), auth.VerificationRequest{
		ClientKey: requestlimit.ClientKey(c),
		Token:     req.Token,
	})
	if err != nil {
		return fiber.NewError(http.StatusInternalServerError)
	}
	switch outcome {
	// A first consumption and a coherent second presentation of the same token
	// are answered alike: neither leaves anything for the caller to compare.
	case auth.OutcomeSucceeded:
		return c.SendStatus(http.StatusNoContent)
	case auth.OutcomeRateLimited:
		return fiber.NewError(http.StatusTooManyRequests, verificationBusy)
	case auth.OutcomeRejected:
		return fiber.NewError(http.StatusBadRequest, verificationInvalid)
	default:
		return fiber.NewError(http.StatusInternalServerError)
	}
}

func acceptedOr(c fiber.Ctx, outcome auth.Outcome, invalid, busy string) error {
	switch outcome {
	case auth.OutcomeSucceeded:
		// Status only: a body would be one more thing that could differ between two
		// answers this surface must keep identical.
		return c.Status(http.StatusAccepted).Send(nil)
	case auth.OutcomeRateLimited:
		return fiber.NewError(http.StatusTooManyRequests, busy)
	case auth.OutcomeRejected:
		return fiber.NewError(http.StatusBadRequest, invalid)
	default:
		return fiber.NewError(http.StatusInternalServerError)
	}
}
