package auth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

func usableCredential(t *testing.T) auth.Credential {
	t.Helper()
	account, err := iam.NewAccountID()
	if err != nil {
		t.Fatalf("drawing an account failed: %v", err)
	}
	return auth.Credential{
		Account: account, Kind: iam.KindViewer, Status: iam.StatusActive,
		Password: password.NewEncoded("real-hash"),
		Revision: fixtureRevision,
	}
}

// fixtureRevision is neither zero nor the first revision, so a replacement handed
// a constant instead of what was verified cannot match it by chance.
const fixtureRevision password.Revision = 7

func newSignIn(t *testing.T, repo *repository, h *hasher, l *limiter) *auth.SignIn {
	t.Helper()
	use, err := auth.NewSignIn(auth.SignInOptions{
		Repository: repo, Hasher: h, Limiter: l, Lifetimes: lifetimes,
		Now: clock(),
	})
	if err != nil {
		t.Fatalf("building the use case failed: %v", err)
	}
	return use
}

// TestARefusedLimitStopsBeforeAnyLookup keeps an unregistered address from being
// distinguishable by the work the service performs on its behalf.
func TestARefusedLimitStopsBeforeAnyLookup(t *testing.T) {
	repo := &repository{}
	h := &hasher{}
	l := &limiter{allow: false}
	result, err := newSignIn(t, repo, h, l).Execute(context.Background(), auth.SignInRequest{Email: "a@example.com"})
	if err != nil {
		t.Fatalf("a refused attempt reported a failure: %v", err)
	}
	if result.Outcome != auth.OutcomeRateLimited {
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
		outcome auth.Outcome
		failed  bool
	}{
		"malformed address": {&repository{}, auth.OutcomeRejected, false},
		"absent address":    {&repository{credentialFound: false}, auth.OutcomeRejected, false},
		"store failure":     {&repository{credentialErr: storeDown}, auth.OutcomeUnknown, true},
	}
	email := map[string]string{"malformed address": "not-an-address", "absent address": "a@example.com", "store failure": "a@example.com"}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h := &hasher{}
			result, err := newSignIn(t, c.repo, h, &limiter{allow: true}).
				Execute(context.Background(), auth.SignInRequest{Email: email[name], Password: "presented"})
			if c.failed {
				if !errors.Is(err, auth.ErrUnavailable) {
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
		Execute(context.Background(), auth.SignInRequest{Email: "a@example.com"})
	if err != nil || absent.Outcome != auth.OutcomeRejected {
		t.Fatalf("an absence produced (%d, %v)", absent.Outcome, err)
	}
	failed, err := newSignIn(t, &repository{credentialErr: storeDown}, &hasher{}, &limiter{allow: true}).
		Execute(context.Background(), auth.SignInRequest{Email: "a@example.com"})
	if !errors.Is(err, auth.ErrUnavailable) {
		t.Fatalf("a failure produced %v", err)
	}
	if failed.Outcome == auth.OutcomeRejected {
		t.Fatal("a failure was reported as a verdict on the credentials")
	}
}

// TestTheVerifiedRevisionReachesTheReplacement keeps the precondition tied to the
// credential this sign-in actually verified, rather than to any constant.
func TestTheVerifiedRevisionReachesTheReplacement(t *testing.T) {
	credential := usableCredential(t)
	repo := &repository{
		credential: credential, credentialFound: true,
		replaced: auth.Resolved{
			Principal: iam.Principal{Account: credential.Account, Kind: iam.KindViewer},
		},
		replaceFound: true,
	}
	result, err := newSignIn(t, repo, &hasher{}, &limiter{allow: true}).
		Execute(context.Background(), auth.SignInRequest{Email: "a@example.com", Password: "secret"})
	if err != nil {
		t.Fatalf("the sign-in failed: %v", err)
	}
	if result.Outcome != auth.OutcomeSucceeded {
		t.Fatalf("outcome %d, want OutcomeSucceeded", result.Outcome)
	}
	if repo.credentialCalls != 1 || repo.replaceCalls != 1 {
		t.Fatalf("%d lookup(s) and %d replacement(s), want one of each",
			repo.credentialCalls, repo.replaceCalls)
	}
	// Exactly what the lookup returned. Zero, the first revision or any other
	// constant would leave the replacement deciding on something else.
	if repo.replacedOn != credential.Revision {
		t.Errorf("the replacement was handed revision %d, want the verified %d",
			repo.replacedOn, credential.Revision)
	}
}

// TestThePresentedSessionReachesTheReplacement keeps a sign-in from leaving the
// session the request arrived with alive beside the new one.
func TestThePresentedSessionReachesTheReplacement(t *testing.T) {
	sess, _ := drawn(t)
	id := sess.ID
	credential := usableCredential(t)
	repo := &repository{
		credential: credential, credentialFound: true,
		resolved:     auth.Resolved{Session: session.Session{ID: id}},
		resolveFound: true,
		replaced: auth.Resolved{
			Session:   session.Session{ID: id},
			Principal: iam.Principal{Account: credential.Account, Kind: iam.KindViewer},
		},
		replaceFound: true,
	}
	_, token := drawn(t)
	result, err := newSignIn(t, repo, &hasher{}, &limiter{allow: true}).
		Execute(context.Background(), auth.SignInRequest{Email: "a@example.com", Presented: &token})
	if err != nil {
		t.Fatalf("the sign-in failed: %v", err)
	}
	if result.Outcome != auth.OutcomeSucceeded {
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
	for name, mutate := range map[string]func(*auth.Credential){
		"suspended": func(c *auth.Credential) { c.Status = iam.StatusSuspended },
		"closed":    func(c *auth.Credential) { c.Status = iam.StatusClosed },
		"pending":   func(c *auth.Credential) { c.Status = iam.StatusPending },
		"operator":  func(c *auth.Credential) { c.Kind = iam.KindOperator },
	} {
		t.Run(name, func(t *testing.T) {
			credential := usableCredential(t)
			mutate(&credential)
			result, err := newSignIn(t, &repository{credential: credential, credentialFound: true}, &hasher{}, &limiter{allow: true}).
				Execute(context.Background(), auth.SignInRequest{Email: "a@example.com"})
			if err != nil {
				t.Fatalf("unexpected failure: %v", err)
			}
			if result.Outcome != auth.OutcomeRejected {
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
		Execute(context.Background(), auth.SignInRequest{Email: "a@example.com"})
	if err != nil {
		t.Fatalf("unexpected failure: %v", err)
	}
	if result.Outcome != auth.OutcomeRejected {
		t.Errorf("outcome %d, want OutcomeRejected", result.Outcome)
	}
}

// TestAPartialSignInUseCaseIsRefused keeps the guarantee the transport used to
// hold: a sign-in missing a port or a usable pair of lifetimes never runs.
func TestAPartialSignInUseCaseIsRefused(t *testing.T) {
	complete := auth.SignInOptions{
		Repository: &repository{}, Hasher: &hasher{}, Limiter: &limiter{allow: true},
		Lifetimes: lifetimes, Now: clock(),
	}
	for name, breakIt := range map[string]func(*auth.SignInOptions){
		"no repository": func(o *auth.SignInOptions) { o.Repository = nil },
		"no hasher":     func(o *auth.SignInOptions) { o.Hasher = nil },
		"no limiter":    func(o *auth.SignInOptions) { o.Limiter = nil },
		"no lifetimes":  func(o *auth.SignInOptions) { o.Lifetimes = session.Lifetimes{} },
		"idle too long": func(o *auth.SignInOptions) { o.Lifetimes.Idle = 2 * o.Lifetimes.Absolute },
	} {
		t.Run(name, func(t *testing.T) {
			opts := complete
			breakIt(&opts)
			if use, err := auth.NewSignIn(opts); err == nil || use != nil {
				t.Fatal("a partial sign-in use case was built")
			}
		})
	}
}
