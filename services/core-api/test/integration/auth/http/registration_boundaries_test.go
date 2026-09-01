package integration_test

import (
	"context"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/emailverification"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
	"github.com/shuntps/project_prometheus/services/core-api/internal/ratelimit"
)

// TestTheRegistrationRouteJudgesItsOwnFields covers what this route carries and
// nothing else: an address and a password.
func TestTheRegistrationRouteJudgesItsOwnFields(t *testing.T) {
	s := newSurface(t)

	cases := map[string]struct {
		request request
		want    int
	}{
		"malformed address": {request{method: http.MethodPost, target: registrationRoute,
			body:   map[string]string{"email": "not-an-address", "password": registrationSecret},
			origin: publicOrigin, fetchSite: "same-origin"}, http.StatusBadRequest},
		"password under the policy": {request{method: http.MethodPost, target: registrationRoute,
			body:   map[string]string{"email": nextAddress(), "password": "short"},
			origin: publicOrigin, fetchSite: "same-origin"}, http.StatusBadRequest},
		"password past the resource limit": {request{method: http.MethodPost, target: registrationRoute,
			body:   map[string]string{"email": nextAddress(), "password": strings.Repeat("p", password.MaxBytes+1)},
			origin: publicOrigin, fetchSite: "same-origin"}, http.StatusBadRequest},
		"body past the surface limit": {request{method: http.MethodPost, target: registrationRoute,
			raw:    []byte(`{"email":"` + strings.Repeat("a", 33<<10) + `@example.com","password":"x"}`),
			origin: publicOrigin, fetchSite: "same-origin"}, http.StatusRequestEntityTooLarge},
		"not JSON": {request{method: http.MethodPost, target: registrationRoute,
			body:   map[string]string{"email": nextAddress(), "password": registrationSecret},
			origin: publicOrigin, fetchSite: "same-origin", noJSON: true}, http.StatusUnsupportedMediaType},
		"malformed JSON": {request{method: http.MethodPost, target: registrationRoute,
			raw: []byte(`{"email":`), origin: publicOrigin, fetchSite: "same-origin"}, http.StatusBadRequest},
		"foreign origin": {request{method: http.MethodPost, target: registrationRoute,
			body:   map[string]string{"email": nextAddress(), "password": registrationSecret},
			origin: foreignOrigin, fetchSite: "cross-site"}, http.StatusForbidden},
		"no origin at all": {request{method: http.MethodPost, target: registrationRoute,
			body: map[string]string{"email": nextAddress(), "password": registrationSecret}}, http.StatusForbidden},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			res := s.send(t, c.request)
			if res.StatusCode != c.want {
				t.Fatalf("status = %d, want %d: %s", res.StatusCode, c.want, bodyOf(t, res))
			}
		})
	}
}

// TestTheResendRouteJudgesItsOwnField covers the route that carries an address
// and no credential at all.
func TestTheResendRouteJudgesItsOwnField(t *testing.T) {
	s := newSurface(t)

	cases := map[string]struct {
		request request
		want    int
	}{
		"malformed address": {request{method: http.MethodPost, target: resendRoute,
			body:   map[string]string{"email": "not-an-address"},
			origin: publicOrigin, fetchSite: "same-origin"}, http.StatusBadRequest},
		"address past the domain limit": {request{method: http.MethodPost, target: resendRoute,
			body:   map[string]string{"email": strings.Repeat("a", 250) + "@example.com"},
			origin: publicOrigin, fetchSite: "same-origin"}, http.StatusBadRequest},
		"body past the surface limit": {request{method: http.MethodPost, target: resendRoute,
			raw:    []byte(`{"email":"` + strings.Repeat("a", 33<<10) + `@example.com"}`),
			origin: publicOrigin, fetchSite: "same-origin"}, http.StatusRequestEntityTooLarge},
		"not JSON": {request{method: http.MethodPost, target: resendRoute,
			body:   map[string]string{"email": nextAddress()},
			origin: publicOrigin, fetchSite: "same-origin", noJSON: true}, http.StatusUnsupportedMediaType},
		"malformed JSON": {request{method: http.MethodPost, target: resendRoute,
			raw: []byte(`{`), origin: publicOrigin, fetchSite: "same-origin"}, http.StatusBadRequest},
		"foreign origin": {request{method: http.MethodPost, target: resendRoute,
			body:   map[string]string{"email": nextAddress()},
			origin: foreignOrigin, fetchSite: "cross-site"}, http.StatusForbidden},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			res := s.send(t, c.request)
			if res.StatusCode != c.want {
				t.Fatalf("status = %d, want %d: %s", res.StatusCode, c.want, bodyOf(t, res))
			}
		})
	}
}

// TestTheVerificationRouteJudgesItsOwnField covers the route that carries a
// token and nothing else, and never reads one from anywhere but the body.
func TestTheVerificationRouteJudgesItsOwnField(t *testing.T) {
	s := newSurface(t)
	address := nextAddress()
	if got := s.register(t, address, registrationSecret).StatusCode; got != http.StatusAccepted {
		t.Fatalf("registering returned %d", got)
	}
	token := s.pendingToken(t, address)

	cases := map[string]struct {
		request request
		want    int
	}{
		"token in the query string": {request{method: http.MethodPost,
			target: verificationRoute + "?token=" + token, body: map[string]string{},
			origin: publicOrigin, fetchSite: "same-origin"}, http.StatusBadRequest},
		"body past the surface limit": {request{method: http.MethodPost, target: verificationRoute,
			raw:    []byte(`{"token":"` + strings.Repeat("a", 33<<10) + `"}`),
			origin: publicOrigin, fetchSite: "same-origin"}, http.StatusRequestEntityTooLarge},
		"not JSON": {request{method: http.MethodPost, target: verificationRoute,
			body:   map[string]string{"token": token},
			origin: publicOrigin, fetchSite: "same-origin", noJSON: true}, http.StatusUnsupportedMediaType},
		"malformed JSON": {request{method: http.MethodPost, target: verificationRoute,
			raw: []byte(`{"token":`), origin: publicOrigin, fetchSite: "same-origin"}, http.StatusBadRequest},
		"foreign origin": {request{method: http.MethodPost, target: verificationRoute,
			body:   map[string]string{"token": token},
			origin: foreignOrigin, fetchSite: "cross-site"}, http.StatusForbidden},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			res := s.send(t, c.request)
			if res.StatusCode != c.want {
				t.Fatalf("status = %d, want %d: %s", res.StatusCode, c.want, bodyOf(t, res))
			}
		})
	}
	// The token in the query string changed nothing: it is still consumable.
	if got := s.verify(t, token).StatusCode; got != http.StatusNoContent {
		t.Fatalf("the token was spent by a request that never carried it in its body: %d", got)
	}
}

// TestNoGetReachesTheRegistrationSurface keeps a top-level cross-site navigation,
// which SameSite=Lax deliberately lets carry the cookie, from writing anything.
func TestNoGetReachesTheRegistrationSurface(t *testing.T) {
	s := newSurface(t)
	for _, route := range []string{registrationRoute, verificationRoute, resendRoute} {
		t.Run(route, func(t *testing.T) {
			res := s.send(t, request{method: http.MethodGet, target: route,
				origin: publicOrigin, fetchSite: "same-origin"})
			if res.StatusCode != http.StatusMethodNotAllowed && res.StatusCode != http.StatusNotFound {
				t.Fatalf("GET %s answered %d, want no route at all", route, res.StatusCode)
			}
		})
	}
}

// TestTheThreeJourneysHoldSeparateAllowances is what the separate limiters buy:
// exhausting one leaves the others untouched.
func TestTheThreeJourneysHoldSeparateAllowances(t *testing.T) {
	registrationLimiter, err := ratelimit.NewAuthLimiter(ratelimit.AuthPolicy{
		ClientAttempts: 1, IdentityAttempts: 1, Window: time.Hour, Capacity: ratelimit.MinAuthCapacity,
	})
	if err != nil {
		t.Fatalf("building the registration limiter failed: %v", err)
	}
	s := newSurface(t, func(c *authConfig) { c.registrationLimiter = registrationLimiter })
	address, _ := s.account(t, iam.KindViewer, iam.StatusActive, iam.RoleViewer)

	if got := s.register(t, nextAddress(), registrationSecret).StatusCode; got != http.StatusAccepted {
		t.Fatalf("the first registration answered %d", got)
	}
	if got := s.register(t, nextAddress(), registrationSecret).StatusCode; got != http.StatusTooManyRequests {
		t.Fatalf("the second registration answered %d, want a refusal", got)
	}
	// The resend route shares that allowance, being the same journey.
	if got := s.resend(t, address).StatusCode; got != http.StatusTooManyRequests {
		t.Fatalf("a resend answered %d, want the shared registration allowance", got)
	}

	// Signing in and verifying hold their own, and neither was consumed.
	if in := s.signIn(t, address, probePassword); in.response.StatusCode != http.StatusCreated {
		t.Fatalf("signing in answered %d, want its own allowance intact", in.response.StatusCode)
	}
	if got := s.verify(t, "not-a-token").StatusCode; got != http.StatusBadRequest {
		t.Fatalf("verifying answered %d, want its own allowance intact", got)
	}
}

// TestAStoreFailureIsNeverAnAcceptedRegistration keeps an undecided operation
// from being reported as accepted work.
func TestAStoreFailureIsNeverAnAcceptedRegistration(t *testing.T) {
	s := newSurface(t)
	address := nextAddress()
	if got := s.register(t, address, registrationSecret).StatusCode; got != http.StatusAccepted {
		t.Fatalf("seeding failed with %d", got)
	}
	token := s.pendingToken(t, address)

	s.faults.register = func() error { return storeFailure() }
	if got := s.register(t, nextAddress(), registrationSecret).StatusCode; got != http.StatusInternalServerError {
		t.Fatalf("a broken store answered %d, want a server error", got)
	}
	s.faults.register = nil

	s.faults.reissue = func() error { return storeFailure() }
	if got := s.resend(t, address).StatusCode; got != http.StatusInternalServerError {
		t.Fatalf("a broken store answered %d, want a server error", got)
	}
	s.faults.reissue = nil

	s.faults.consume = func() error { return storeFailure() }
	res := s.verify(t, token)
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("a broken store answered %d, want a server error", res.StatusCode)
	}
	if strings.Contains(bodyOf(t, res), "SQLSTATE") {
		t.Fatal("driver detail reached the response")
	}
	s.faults.consume = nil

	// Nothing was decided about the address: the token still works.
	if got := s.verify(t, token).StatusCode; got != http.StatusNoContent {
		t.Fatalf("the token stopped working after a store failure: %d", got)
	}
}

// TestNoSecretReachesAnObservableSurface searches every value this journey
// handles, in the responses and in the records the service wrote.
func TestNoSecretReachesAnObservableSurface(t *testing.T) {
	s := newSurface(t)
	address := nextAddress()

	bodies := []string{bodyOf(t, s.register(t, address, registrationSecret))}
	token := s.pendingToken(t, address)
	bodies = append(bodies, bodyOf(t, s.resend(t, address)))
	bodies = append(bodies, bodyOf(t, s.verify(t, token)))
	bodies = append(bodies, bodyOf(t, s.verify(t, "not-a-token")))

	parsed, err := emailverification.ParseToken(token)
	if err != nil {
		t.Fatalf("the stored token is not of the issued shape: %v", err)
	}
	normalised, err := iam.NormaliseEmail(address)
	if err != nil {
		t.Fatalf("normalising failed: %v", err)
	}
	forbidden := map[string]string{
		"the verification token":  token,
		"its fingerprint":         hex.EncodeToString(parsed.Fingerprint().Bytes()),
		"the login address":       normalised.Reveal(),
		"the password":            registrationSecret,
		"driver detail":           "SQLSTATE",
		"a stored representation": "$argon2id$",
	}
	for name, secret := range forbidden {
		t.Run("response: "+name, func(t *testing.T) {
			for _, body := range bodies {
				if strings.Contains(body, secret) {
					t.Fatalf("a response carried %s", name)
				}
			}
		})
		t.Run("record: "+name, func(t *testing.T) {
			if strings.Contains(s.logs.String(), secret) {
				t.Fatalf("a record carried %s", name)
			}
		})
	}

	// The stored fingerprint is what the database holds, and it is not the token.
	var stored []byte
	if err := s.pool.QueryRow(context.Background(),
		`SELECT token_fingerprint FROM account_email_verifications LIMIT 1`).Scan(&stored); err != nil {
		t.Fatalf("reading the fingerprint failed: %v", err)
	}
	if strings.Contains(string(stored), token) {
		t.Fatal("the stored fingerprint carries the token")
	}
}

var _ auth.ClientLimiter = (*ratelimit.ClientLimiter)(nil)
