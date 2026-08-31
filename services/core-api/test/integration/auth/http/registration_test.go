package integration_test

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/emailverification"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

// registrationSecret is comfortably above the adopted single-factor minimum.
const registrationSecret = "correct-horse-battery-staple-42"

func (s *surface) register(t *testing.T, address, secret string) *http.Response {
	t.Helper()
	return s.send(t, request{
		method: http.MethodPost, target: registrationRoute,
		body:   map[string]string{"email": address, "password": secret},
		origin: publicOrigin, fetchSite: "same-origin",
	})
}

func (s *surface) resend(t *testing.T, address string) *http.Response {
	t.Helper()
	return s.send(t, request{
		method: http.MethodPost, target: resendRoute,
		body:   map[string]string{"email": address},
		origin: publicOrigin, fetchSite: "same-origin",
	})
}

func (s *surface) verify(t *testing.T, token string) *http.Response {
	t.Helper()
	return s.send(t, request{
		method: http.MethodPost, target: verificationRoute,
		body:   map[string]string{"token": token},
		origin: publicOrigin, fetchSite: "same-origin",
	})
}

// pendingToken takes the token the way the dispatcher would: out of the outbox,
// which is the only place it exists once the transaction has committed.
func (s *surface) pendingToken(t *testing.T, address string) string {
	t.Helper()
	normalised, err := iam.NormaliseEmail(address)
	if err != nil {
		t.Fatalf("normalising failed: %v", err)
	}
	var token string
	const query = `SELECT d.token FROM account_email_deliveries d
		JOIN account_email_verifications v ON v.id = d.challenge_id
		JOIN account_email_identities e ON e.id = v.identity_id
		WHERE e.address = $1 AND v.consumed_at IS NULL AND v.superseded_at IS NULL`
	if err := s.pool.QueryRow(context.Background(), query, normalised.Reveal()).Scan(&token); err != nil {
		t.Fatalf("reading the pending token failed: %v", err)
	}
	return token
}

func (s *surface) statusOf(t *testing.T, address string) (string, bool) {
	t.Helper()
	normalised, err := iam.NormaliseEmail(address)
	if err != nil {
		t.Fatalf("normalising failed: %v", err)
	}
	var status string
	var verified *time.Time
	const query = `SELECT a.status, e.verified_at FROM account_email_identities e
		JOIN accounts a ON a.id = e.account_id WHERE e.address = $1`
	if err := s.pool.QueryRow(context.Background(), query, normalised.Reveal()).Scan(&status, &verified); err != nil {
		t.Fatalf("reading the account failed: %v", err)
	}
	return status, verified != nil
}

// generic is one answer reduced to what a caller could actually compare.
type generic struct {
	status  int
	body    string
	headers string
}

func genericOf(t *testing.T, res *http.Response) generic {
	t.Helper()
	// The request identifier is the one value the server varies by design; it is
	// normalised in the body and dropped from the headers before comparing.
	body := requestIDPattern.ReplaceAllString(bodyOf(t, res), `"request_id":"<normalised>"`)

	var stable []string
	for name, values := range res.Header {
		// Dropped because the server varies them by design and by traffic, never by
		// what the request was about: the instant, the request identifier, and the
		// shared limiter's remaining allowance, which every call moves.
		switch canonical := http.CanonicalHeaderKey(name); {
		case canonical == "Date", canonical == "X-Request-Id",
			strings.HasPrefix(canonical, "X-Ratelimit-"):
			continue
		}
		stable = append(stable, http.CanonicalHeaderKey(name)+": "+strings.Join(values, ","))
	}
	slices.Sort(stable)
	return generic{status: res.StatusCode, body: body, headers: strings.Join(stable, "\n")}
}

// TestEveryAddressStateProducesOneAnswer is the enumeration defence: every
// address state, including one belonging to an account no public request may
// touch, is answered identically once the request identifier is normalised.
func TestEveryAddressStateProducesOneAnswer(t *testing.T) {
	s := newSurface(t)

	pending := nextAddress()
	if got := s.register(t, pending, registrationSecret).StatusCode; got != http.StatusAccepted {
		t.Fatalf("seeding the pending address returned %d", got)
	}
	activeAddress, _ := s.account(t, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
	suspendedAddress, _ := s.account(t, iam.KindViewer, iam.StatusSuspended, iam.RoleViewer)
	closedAddress, _ := s.account(t, iam.KindViewer, iam.StatusClosed)
	creatorAddress, _ := s.account(t, iam.KindCreator, iam.StatusPending, iam.RoleCreator)
	operatorAddress, _ := s.account(t, iam.KindOperator, iam.StatusPending, iam.RoleOperatorSupport)

	answers := map[string]generic{}
	for name, address := range map[string]string{
		"unknown address":  nextAddress(),
		"pending viewer":   pending,
		"active viewer":    activeAddress,
		"suspended viewer": suspendedAddress,
		"closed viewer":    closedAddress,
		"pending creator":  creatorAddress,
		"pending operator": operatorAddress,
	} {
		answers[name] = genericOf(t, s.register(t, address, registrationSecret))
	}

	var reference generic
	var referenceName string
	for name, answer := range answers {
		if referenceName == "" {
			reference, referenceName = answer, name
			continue
		}
		if answer != reference {
			t.Errorf("%q answered %#v\n%q answered %#v", name, answer, referenceName, reference)
		}
	}
	if reference.status != http.StatusAccepted || reference.body != "" {
		t.Fatalf("the shared answer is %d with body %q, want 202 and no body", reference.status, reference.body)
	}

	// The answer being identical is not the whole guarantee: nothing may have
	// changed on the accounts a public request must not touch.
	for name, address := range map[string]string{
		"active viewer": activeAddress, "suspended viewer": suspendedAddress,
		"closed viewer": closedAddress, "pending creator": creatorAddress,
		"pending operator": operatorAddress,
	} {
		status, verified := s.statusOf(t, address)
		if verified {
			t.Errorf("%q was marked verified by a registration", name)
		}
		if status == string(iam.StatusPending) && name == "active viewer" {
			t.Errorf("%q changed status", name)
		}
	}
	for _, address := range []string{creatorAddress, operatorAddress, activeAddress, suspendedAddress, closedAddress} {
		normalised, err := iam.NormaliseEmail(address)
		if err != nil {
			t.Fatalf("normalising failed: %v", err)
		}
		var queued int
		if err := s.pool.QueryRow(context.Background(), `SELECT count(*) FROM account_email_deliveries d
			JOIN account_email_verifications v ON v.id = d.challenge_id
			JOIN account_email_identities e ON e.id = v.identity_id WHERE e.address = $1`,
			normalised.Reveal()).Scan(&queued); err != nil {
			t.Fatalf("counting the queued work failed: %v", err)
		}
		if queued != 0 {
			t.Errorf("a registration queued %d messages for an address it may not touch", queued)
		}
	}
}

// TestAResendAnswersTheSameWhateverTheAddress covers the second route on its own
// terms: it carries an address and no password.
func TestAResendAnswersTheSameWhateverTheAddress(t *testing.T) {
	s := newSurface(t)
	pending := nextAddress()
	if got := s.register(t, pending, registrationSecret).StatusCode; got != http.StatusAccepted {
		t.Fatalf("seeding failed with %d", got)
	}
	activeAddress, _ := s.account(t, iam.KindViewer, iam.StatusActive, iam.RoleViewer)

	answers := map[string]generic{}
	for name, address := range map[string]string{
		"never registered": nextAddress(),
		"pending viewer":   pending,
		"active viewer":    activeAddress,
	} {
		answers[name] = genericOf(t, s.resend(t, address))
	}
	var reference generic
	var referenceName string
	for name, answer := range answers {
		if referenceName == "" {
			reference, referenceName = answer, name
			continue
		}
		if answer != reference {
			t.Errorf("%q answered %#v\n%q answered %#v", name, answer, referenceName, reference)
		}
	}
	if reference.status != http.StatusAccepted {
		t.Fatalf("the shared answer is %d, want 202", reference.status)
	}
}

// TestAVerifiedAddressActivatesAndOpensNoSession is the whole point of the
// separation: control of a mailbox activates the account and authenticates
// nobody.
func TestAVerifiedAddressActivatesAndOpensNoSession(t *testing.T) {
	s := newSurface(t)
	address := nextAddress()
	if got := s.register(t, address, registrationSecret).StatusCode; got != http.StatusAccepted {
		t.Fatalf("registering returned %d", got)
	}

	// Pending: the credential is real but the account may not authenticate yet.
	before := s.signIn(t, address, registrationSecret)
	if before.response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a pending account signed in with %d", before.response.StatusCode)
	}

	res := s.verify(t, s.pendingToken(t, address))
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("verifying returned %d: %s", res.StatusCode, bodyOf(t, res))
	}
	if body := bodyOf(t, res); body != "" {
		t.Fatalf("the verification answered with a body: %q", body)
	}
	if cookie := sessionCookie(res); cookie != nil {
		t.Fatal("verifying an address opened a session")
	}
	if status, verified := s.statusOf(t, address); status != string(iam.StatusActive) || !verified {
		t.Fatalf("status=%q verified=%v, want an active account with a verified address", status, verified)
	}

	after := s.signIn(t, address, registrationSecret)
	if after.response.StatusCode != http.StatusCreated {
		t.Fatalf("a verified account could not sign in: %d %s", after.response.StatusCode, after.body)
	}
	roles, _ := after.view["roles"].([]any)
	if len(roles) != 1 || roles[0] != string(iam.RoleViewer) {
		t.Fatalf("roles = %v, want the viewer grant alone", roles)
	}

	// The session it opens carries no adult capability.
	broadcast := s.send(t, request{
		method: http.MethodGet, target: broadcastRoute,
		origin: publicOrigin, fetchSite: "same-origin", cookie: after.token,
	})
	if broadcast.StatusCode != http.StatusForbidden {
		t.Fatalf("broadcast access answered %d, want a refusal", broadcast.StatusCode)
	}
}

// TestASecondPresentationOfTheSameTokenAnswersAlike keeps a repeated submission
// from reading as a broken link, while writing nothing.
func TestASecondPresentationOfTheSameTokenAnswersAlike(t *testing.T) {
	s := newSurface(t)
	address := nextAddress()
	if got := s.register(t, address, registrationSecret).StatusCode; got != http.StatusAccepted {
		t.Fatalf("registering returned %d", got)
	}
	token := s.pendingToken(t, address)

	first := genericOf(t, s.verify(t, token))
	second := genericOf(t, s.verify(t, token))
	if first != second {
		t.Fatalf("first %#v\nsecond %#v", first, second)
	}
	if first.status != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", first.status)
	}

	var completions int
	if err := s.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM account_security_events WHERE kind = 'email_verification_completed'`).
		Scan(&completions); err != nil {
		t.Fatalf("counting the completions failed: %v", err)
	}
	if completions != 1 {
		t.Fatalf("completion events = %d, want one", completions)
	}
}

// TestEveryUnusableTokenAnswersAlike keeps the refusal from saying which reason
// applied.
func TestEveryUnusableTokenAnswersAlike(t *testing.T) {
	s := newSurface(t)

	superseded := nextAddress()
	if got := s.register(t, superseded, registrationSecret).StatusCode; got != http.StatusAccepted {
		t.Fatalf("registering returned %d", got)
	}
	supersededToken := s.pendingToken(t, superseded)
	s.clock.advance(time.Minute)
	if got := s.resend(t, superseded).StatusCode; got != http.StatusAccepted {
		t.Fatalf("resending returned %d", got)
	}

	consumed := nextAddress()
	if got := s.register(t, consumed, registrationSecret).StatusCode; got != http.StatusAccepted {
		t.Fatalf("registering returned %d", got)
	}
	consumedToken := s.pendingToken(t, consumed)
	if got := s.verify(t, consumedToken).StatusCode; got != http.StatusNoContent {
		t.Fatalf("verifying returned %d", got)
	}
	// Consumed once and then the address is verified: a further address is needed
	// for a token whose account never became usable.
	expired := nextAddress()
	if got := s.register(t, expired, registrationSecret).StatusCode; got != http.StatusAccepted {
		t.Fatalf("registering returned %d", got)
	}
	expiredToken := s.pendingToken(t, expired)
	s.clock.advance(9 * time.Hour)

	identity, err := iam.NewIdentityID()
	if err != nil {
		t.Fatalf("drawing an identity identifier failed: %v", err)
	}
	_, stray, err := emailverification.Issue(identity,
		emailverification.Lifetimes{Lifetime: 8 * time.Hour, ResendInterval: time.Minute}, time.Now().UTC())
	if err != nil {
		t.Fatalf("issuing failed: %v", err)
	}

	answers := map[string]generic{}
	for name, token := range map[string]string{
		"never issued here": stray.Reveal(),
		"superseded":        supersededToken,
		"expired":           expiredToken,
		"not of the shape":  "not-a-token",
		"empty":             "",
	} {
		answers[name] = genericOf(t, s.verify(t, token))
	}
	var reference generic
	var referenceName string
	for name, answer := range answers {
		if referenceName == "" {
			reference, referenceName = answer, name
			continue
		}
		if answer != reference {
			t.Errorf("%q answered %#v\n%q answered %#v", name, answer, referenceName, reference)
		}
	}
	if reference.status != http.StatusBadRequest {
		t.Fatalf("the shared refusal is %d, want 400", reference.status)
	}
}
