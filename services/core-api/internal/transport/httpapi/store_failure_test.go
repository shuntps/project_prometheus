package httpapi_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/authstore"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi"
)

// faultyStore makes exactly one operation fail while every other call reaches
// PostgreSQL. The injected message imitates driver detail that must not travel.
type faultyStore struct {
	inner      *authstore.Store
	credential func() error
	resolve    func() error
	replace    func() error
	revoke     func() error
	activity   func() error
}

// driverDetail stands in for what a driver error could carry. Scans decode the
// document, so the original string is recovered rather than its escaped form.
const driverDetail = `ERROR: relation "account_sessions" does not exist (SQLSTATE 42P01) host=db.internal user=core_api`

func (f *faultyStore) CredentialByEmail(ctx context.Context, email auth.EmailAddress) (authstore.Credential, error) {
	if f.credential != nil {
		if err := f.credential(); err != nil {
			return authstore.Credential{}, err
		}
	}
	return f.inner.CredentialByEmail(ctx, email)
}

func (f *faultyStore) ReplaceSession(ctx context.Context, previous *auth.SessionID, successor session.Session, now time.Time) (authstore.Resolved, error) {
	if f.replace != nil {
		if err := f.replace(); err != nil {
			return authstore.Resolved{}, err
		}
	}
	return f.inner.ReplaceSession(ctx, previous, successor, now)
}

func (f *faultyStore) Resolve(ctx context.Context, token session.Token, now time.Time) (authstore.Resolved, error) {
	if f.resolve != nil {
		if err := f.resolve(); err != nil {
			return authstore.Resolved{}, err
		}
	}
	return f.inner.Resolve(ctx, token, now)
}

func (f *faultyStore) RecordActivity(ctx context.Context, id auth.SessionID, now time.Time, lifetimes session.Lifetimes) (bool, error) {
	if f.activity != nil {
		if err := f.activity(); err != nil {
			return false, err
		}
	}
	return f.inner.RecordActivity(ctx, id, now, lifetimes)
}

func (f *faultyStore) RevokeSession(ctx context.Context, id auth.SessionID, now time.Time) error {
	if f.revoke != nil {
		if err := f.revoke(); err != nil {
			return err
		}
	}
	return f.inner.RevokeSession(ctx, id, now)
}

// storeFailure is what the adapter reports when the driver fails: the sentinel,
// wrapping detail that must never travel.
func storeFailure() error {
	return fmt.Errorf("%w: %s", authstore.ErrStore, driverDetail)
}

// once returns a hook that fails only the nth call, so a test can let a sign-in
// reach a chosen step before the store breaks.
func once(n int) func() error {
	var calls int
	var mu sync.Mutex
	return func() error {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls == n {
			return storeFailure()
		}
		return nil
	}
}

// TestAStoreFailureIsNeverReportedAsACredentialVerdict separates a genuine
// absence from a store that could not say. The work happens on both.
func TestAStoreFailureIsNeverReportedAsACredentialVerdict(t *testing.T) {
	inner, err := password.NewHasher(
		password.Params{MemoryKiB: password.FloorMemoryKiB, Iterations: password.FloorIterations, Lanes: password.FloorLanes},
		password.Policy{MinCodePoints: password.SingleFactorMinimum}, nil)
	if err != nil {
		t.Fatalf("building the hasher failed: %v", err)
	}
	verifier := &countingVerifier{inner: inner}
	s := newSurface(t, func(o *httpapi.Options) { o.Auth.Hasher = verifier })
	address, account := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)

	// A genuine absence keeps the uniform answer.
	verifier.reset()
	absent := s.signIn(t, "nobody-here@example.com", probePassword)
	if absent.response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("an absent address returned %d, want 401", absent.response.StatusCode)
	}
	if calls := len(verifier.calls()); calls != 1 {
		t.Fatalf("an absent address performed %d verifications, want 1", calls)
	}

	// A store that failed is a server error, and the same work still happens.
	s.faults.credential = func() error { return storeFailure() }
	verifier.reset()
	broken := s.signIn(t, address, probePassword)
	s.faults.credential = nil
	if broken.response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("a failed lookup returned %d, want 500: %s", broken.response.StatusCode, broken.body)
	}
	if calls := len(verifier.calls()); calls != 1 {
		t.Fatalf("a failed lookup performed %d verifications, want 1", calls)
	}
	if sessionCookie(broken.response) != nil {
		t.Error("a failed lookup set a session cookie")
	}
	if live := s.liveSessions(t, account); live != 0 {
		t.Errorf("%d sessions exist after a failed lookup", live)
	}
	// The correct credential still works once the store answers again.
	if in := s.signIn(t, address, probePassword); in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d after the store recovered", in.response.StatusCode)
	}
}

// TestAStoreFailureOnAProtectedRouteIsNotAFalseUnauthorized keeps the server from
// asserting an absence it never established.
func TestAStoreFailureOnAProtectedRouteIsNotAFalseUnauthorized(t *testing.T) {
	s := newSurface(t)
	address, _ := s.account(t, auth.KindCreator, auth.StatusActive, auth.RoleViewer, auth.RoleCreator)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", in.response.StatusCode)
	}

	for _, route := range []string{sessionRoute, broadcastRoute} {
		s.faults.resolve = func() error { return storeFailure() }
		res := s.send(t, request{method: http.MethodGet, target: route, cookie: in.token, origin: publicOrigin})
		s.faults.resolve = nil
		if res.StatusCode != http.StatusInternalServerError {
			t.Errorf("%s returned %d on a store failure, want 500", route, res.StatusCode)
		}
	}
	// A genuinely unknown token still gets the uniform refusal.
	drawn, err := session.NewToken(nil)
	if err != nil {
		t.Fatalf("drawing failed: %v", err)
	}
	if res := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: drawn.Reveal(), origin: publicOrigin}); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("an unknown token returned %d, want 401", res.StatusCode)
	}
}

// TestNoStoreDetailReachesTheResponseOrTheRecords keeps driver text, host names,
// identifiers and SQLSTATE codes out of everything the caller or an operator sees.
func TestNoStoreDetailReachesTheResponseOrTheRecords(t *testing.T) {
	s := newSurface(t)
	address, account := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", in.response.StatusCode)
	}

	var bodies []string
	s.faults.credential = func() error { return storeFailure() }
	bodies = append(bodies, s.signIn(t, address, probePassword).body)
	s.faults.credential = nil

	s.faults.resolve = func() error { return storeFailure() }
	bodies = append(bodies, bodyOf(t, s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin})))
	s.faults.resolve = nil

	s.faults.replace = func() error { return storeFailure() }
	bodies = append(bodies, s.signIn(t, address, probePassword).body)
	s.faults.replace = nil

	forbidden := []string{
		driverDetail, "42P01", "SQLSTATE", "account_sessions", "db.internal", "core_api",
		address, probePassword, in.token, in.csrf, account.ID.String(),
	}
	for i, body := range bodies {
		for _, secret := range forbidden {
			if strings.Contains(body, secret) {
				t.Errorf("response %d carried %q", i, secret)
			}
		}
	}
	logs := s.logs.String()
	for _, secret := range forbidden {
		if strings.Contains(logs, secret) {
			t.Errorf("the records carried %q", secret)
		}
	}
	// The class of failure is still recorded, so an operator is not left blind.
	if !strings.Contains(logs, `"error_code":"internal_error"`) {
		t.Error("no record identified the failure class")
	}
}
