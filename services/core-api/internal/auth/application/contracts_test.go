package application_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/application"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

var (
	fixedNow  = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	lifetimes = session.Lifetimes{Absolute: 12 * time.Hour, Idle: time.Hour, ActivityInterval: time.Minute}
	storeDown = errors.New("the store refused")
)

func clock() func() time.Time { return func() time.Time { return fixedNow } }

// entropy is deterministic so a failing case never depends on the machine.
func entropy() *bytes.Reader { return bytes.NewReader(bytes.Repeat([]byte{7}, 4096)) }

// hasher counts what was verified, so work parity is asserted on calls rather
// than on elapsed time, which no test can measure reliably.
type hasher struct {
	hashed   int
	verified []password.Encoded
	fail     bool
}

func (h *hasher) Hash(string) (password.Encoded, error) {
	h.hashed++
	return password.NewEncoded("decoy-hash"), nil
}

func (h *hasher) Verify(encoded password.Encoded, _ string) (bool, error) {
	h.verified = append(h.verified, encoded)
	if h.fail || encoded.Reveal() == "decoy-hash" {
		return false, errors.New("mismatch")
	}
	return false, nil
}

type limiter struct {
	allow bool
	calls int
}

func (l *limiter) Allow(string, string, time.Time) bool { l.calls++; return l.allow }

type repository struct {
	credential      application.Credential
	credentialFound bool
	credentialErr   error
	credentialCalls int

	resolved     application.Resolved
	resolveFound bool
	resolveErr   error
	resolveCalls int

	replaced      application.Resolved
	replaceFound  bool
	replaceErr    error
	replaceCalls  int
	replacedAfter *session.ID

	revokeFound bool
	revokeErr   error
	revokeCalls int

	activityFound bool
	activityErr   error
	activityCalls int
	activityAt    time.Time
}

func (r *repository) CredentialByEmail(context.Context, iam.EmailAddress) (application.Credential, bool, error) {
	r.credentialCalls++
	return r.credential, r.credentialFound, r.credentialErr
}

func (r *repository) ResolveSession(context.Context, session.Token, time.Time) (application.Resolved, bool, error) {
	r.resolveCalls++
	return r.resolved, r.resolveFound, r.resolveErr
}

func (r *repository) ReplaceSession(_ context.Context, previous *session.ID, _ session.Session, _ time.Time) (application.Resolved, bool, error) {
	r.replaceCalls++
	r.replacedAfter = previous
	return r.replaced, r.replaceFound, r.replaceErr
}

func (r *repository) RevokeSession(context.Context, session.ID, time.Time) (bool, error) {
	r.revokeCalls++
	return r.revokeFound, r.revokeErr
}

func (r *repository) RecordActivity(_ context.Context, _ session.ID, now time.Time, _ session.Lifetimes) (bool, error) {
	r.activityCalls++
	r.activityAt = now
	return r.activityFound, r.activityErr
}

func usableCredential(t *testing.T) application.Credential {
	t.Helper()
	account, err := iam.NewAccountID()
	if err != nil {
		t.Fatalf("drawing an account failed: %v", err)
	}
	return application.Credential{
		Account: account, Kind: iam.KindViewer, Status: iam.StatusActive,
		Password: password.NewEncoded("real-hash"),
	}
}

func newSignIn(t *testing.T, repo *repository, h *hasher, l *limiter) *application.SignIn {
	t.Helper()
	use, err := application.NewSignIn(application.SignInOptions{
		Repository: repo, Hasher: h, Limiter: l, Lifetimes: lifetimes,
		Now: clock(), Random: entropy(),
	})
	if err != nil {
		t.Fatalf("building the use case failed: %v", err)
	}
	return use
}

// TestTheZeroOutcomeIsNeverASuccess keeps an unset or unknown decision from ever
// being served: the zero value must be refused by whoever reads it.
func TestTheZeroOutcomeIsNeverASuccess(t *testing.T) {
	var zero application.SignInResult
	if zero.Outcome != application.OutcomeUnknown {
		t.Fatalf("the zero result carries %d, want OutcomeUnknown", zero.Outcome)
	}
	if application.OutcomeUnknown == application.OutcomeSucceeded {
		t.Fatal("the unknown outcome must not equal the success outcome")
	}
	if application.OutcomeUnknown != 0 {
		t.Fatalf("the unknown outcome must be the zero value, got %d", application.OutcomeUnknown)
	}
}

// TestARefusedLimitStopsBeforeAnyLookup keeps an unregistered address from being
// distinguishable by the work the service performs on its behalf.
func TestARefusedLimitStopsBeforeAnyLookup(t *testing.T) {
	repo := &repository{}
	h := &hasher{}
	l := &limiter{allow: false}
	result, err := newSignIn(t, repo, h, l).Execute(context.Background(), application.SignInRequest{Email: "a@example.com"})
	if err != nil {
		t.Fatalf("a refused attempt reported a failure: %v", err)
	}
	if result.Outcome != application.OutcomeRateLimited {
		t.Errorf("outcome %d, want OutcomeRateLimited", result.Outcome)
	}
	if repo.credentialCalls != 0 || repo.resolveCalls != 0 || repo.replaceCalls != 0 {
		t.Errorf("the repository was consulted %d/%d/%d times", repo.credentialCalls, repo.resolveCalls, repo.replaceCalls)
	}
	if l.calls != 1 {
		t.Errorf("the limiter was charged %d times", l.calls)
	}
}

// TestEveryUndecidedOrAbsentAddressPerformsTheSameWork covers the three paths that
// must not be told apart by the cryptographic work performed.
func TestEveryUndecidedOrAbsentAddressPerformsTheSameWork(t *testing.T) {
	cases := map[string]struct {
		repo    *repository
		outcome application.Outcome
		failed  bool
	}{
		"malformed address": {&repository{}, application.OutcomeRejected, false},
		"absent address":    {&repository{credentialFound: false}, application.OutcomeRejected, false},
		"store failure":     {&repository{credentialErr: storeDown}, application.OutcomeUnknown, true},
	}
	email := map[string]string{"malformed address": "not-an-address", "absent address": "a@example.com", "store failure": "a@example.com"}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h := &hasher{}
			result, err := newSignIn(t, c.repo, h, &limiter{allow: true}).
				Execute(context.Background(), application.SignInRequest{Email: email[name], Password: "presented"})
			if c.failed {
				if !errors.Is(err, application.ErrUnavailable) {
					t.Fatalf("a store failure reported %v", err)
				}
			} else if err != nil {
				t.Fatalf("unexpected failure: %v", err)
			}
			if result.Outcome != c.outcome {
				t.Errorf("outcome %d, want %d", result.Outcome, c.outcome)
			}
			if len(h.verified) != 1 {
				t.Fatalf("the verification ran %d times, want exactly one", len(h.verified))
			}
			if h.verified[0].Reveal() != "decoy-hash" {
				t.Errorf("the work was not performed against the decoy")
			}
		})
	}
}

// TestAnAbsenceIsNotAFailure keeps the two apart at the boundary: one is a verdict
// on the caller, the other is the absence of any verdict at all.
func TestAnAbsenceIsNotAFailure(t *testing.T) {
	absent, err := newSignIn(t, &repository{credentialFound: false}, &hasher{}, &limiter{allow: true}).
		Execute(context.Background(), application.SignInRequest{Email: "a@example.com"})
	if err != nil || absent.Outcome != application.OutcomeRejected {
		t.Fatalf("an absence produced (%d, %v)", absent.Outcome, err)
	}
	failed, err := newSignIn(t, &repository{credentialErr: storeDown}, &hasher{}, &limiter{allow: true}).
		Execute(context.Background(), application.SignInRequest{Email: "a@example.com"})
	if !errors.Is(err, application.ErrUnavailable) {
		t.Fatalf("a failure produced %v", err)
	}
	if failed.Outcome == application.OutcomeRejected {
		t.Fatal("a failure was reported as a verdict on the credentials")
	}
}

// TestThePresentedSessionReachesTheReplacement keeps a sign-in from leaving the
// session the request arrived with alive beside the new one.
func TestThePresentedSessionReachesTheReplacement(t *testing.T) {
	id, err := session.NewID()
	if err != nil {
		t.Fatalf("drawing a session identifier failed: %v", err)
	}
	credential := usableCredential(t)
	repo := &repository{
		credential: credential, credentialFound: true,
		resolved:     application.Resolved{Session: session.Session{ID: id}},
		resolveFound: true,
		replaced: application.Resolved{
			Session:   session.Session{ID: id},
			Principal: iam.Principal{Account: credential.Account, Kind: iam.KindViewer},
		},
		replaceFound: true,
	}
	token, err := session.NewToken(entropy())
	if err != nil {
		t.Fatalf("drawing a token failed: %v", err)
	}
	result, err := newSignIn(t, repo, &hasher{}, &limiter{allow: true}).
		Execute(context.Background(), application.SignInRequest{Email: "a@example.com", Presented: &token})
	if err != nil {
		t.Fatalf("the sign-in failed: %v", err)
	}
	if result.Outcome != application.OutcomeSucceeded {
		t.Fatalf("outcome %d, want OutcomeSucceeded", result.Outcome)
	}
	if repo.replacedAfter == nil || *repo.replacedAfter != id {
		t.Errorf("the replacement did not receive the presented session")
	}
	if repo.resolveCalls != 1 {
		t.Errorf("the presented session was resolved %d times", repo.resolveCalls)
	}
}

// TestAnUnusableAccountLeavesByTheOrdinaryDoor keeps a suspended account and an
// operator account from being distinguishable from a wrong password.
func TestAnUnusableAccountLeavesByTheOrdinaryDoor(t *testing.T) {
	for name, mutate := range map[string]func(*application.Credential){
		"suspended": func(c *application.Credential) { c.Status = iam.StatusSuspended },
		"closed":    func(c *application.Credential) { c.Status = iam.StatusClosed },
		"pending":   func(c *application.Credential) { c.Status = iam.StatusPending },
		"operator":  func(c *application.Credential) { c.Kind = iam.KindOperator },
	} {
		t.Run(name, func(t *testing.T) {
			credential := usableCredential(t)
			mutate(&credential)
			result, err := newSignIn(t, &repository{credential: credential, credentialFound: true}, &hasher{}, &limiter{allow: true}).
				Execute(context.Background(), application.SignInRequest{Email: "a@example.com"})
			if err != nil {
				t.Fatalf("unexpected failure: %v", err)
			}
			if result.Outcome != application.OutcomeRejected {
				t.Errorf("outcome %d, want OutcomeRejected", result.Outcome)
			}
		})
	}
}

// TestAReplacementRefusedIsNotAFailure keeps an account that stopped being usable
// mid-flight on the authentication door rather than the server error one.
func TestAReplacementRefusedIsNotAFailure(t *testing.T) {
	credential := usableCredential(t)
	result, err := newSignIn(t, &repository{credential: credential, credentialFound: true, replaceFound: false}, &hasher{}, &limiter{allow: true}).
		Execute(context.Background(), application.SignInRequest{Email: "a@example.com"})
	if err != nil {
		t.Fatalf("unexpected failure: %v", err)
	}
	if result.Outcome != application.OutcomeRejected {
		t.Errorf("outcome %d, want OutcomeRejected", result.Outcome)
	}
}

// TestAPartialUseCaseIsRefused keeps the guarantee the transport used to hold:
// a surface missing a hasher, a limiter or a usable pair of lifetimes never runs.
func TestAPartialUseCaseIsRefused(t *testing.T) {
	complete := application.SignInOptions{
		Repository: &repository{}, Hasher: &hasher{}, Limiter: &limiter{allow: true},
		Lifetimes: lifetimes, Now: clock(), Random: entropy(),
	}
	for name, breakIt := range map[string]func(*application.SignInOptions){
		"no repository": func(o *application.SignInOptions) { o.Repository = nil },
		"no hasher":     func(o *application.SignInOptions) { o.Hasher = nil },
		"no limiter":    func(o *application.SignInOptions) { o.Limiter = nil },
		"no lifetimes":  func(o *application.SignInOptions) { o.Lifetimes = session.Lifetimes{} },
		"idle too long": func(o *application.SignInOptions) { o.Lifetimes.Idle = 2 * o.Lifetimes.Absolute },
	} {
		t.Run(name, func(t *testing.T) {
			opts := complete
			breakIt(&opts)
			if use, err := application.NewSignIn(opts); err == nil || use != nil {
				t.Fatal("a partial sign-in use case was built")
			}
		})
	}

	for name, opts := range map[string]application.SessionsOptions{
		"no repository": {Lifetimes: lifetimes, Now: clock()},
		"no lifetimes":  {Repository: &repository{}, Now: clock()},
		"idle too long": {Repository: &repository{}, Now: clock(),
			Lifetimes: session.Lifetimes{Absolute: time.Hour, Idle: 2 * time.Hour, ActivityInterval: time.Minute}},
	} {
		t.Run("sessions/"+name, func(t *testing.T) {
			if use, err := application.NewSessions(opts); err == nil || use != nil {
				t.Fatal("a partial set of session use cases was built")
			}
		})
	}
}
