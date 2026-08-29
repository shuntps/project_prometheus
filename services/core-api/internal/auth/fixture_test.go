package auth_test

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
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
	credential      auth.Credential
	credentialFound bool
	credentialErr   error
	credentialCalls int

	resolved     auth.Resolved
	resolveFound bool
	resolveErr   error
	resolveCalls int

	replaced      auth.Resolved
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

func (r *repository) CredentialByEmail(context.Context, iam.EmailAddress) (auth.Credential, bool, error) {
	r.credentialCalls++
	return r.credential, r.credentialFound, r.credentialErr
}

func (r *repository) ResolveSession(context.Context, session.Token, time.Time) (auth.Resolved, bool, error) {
	r.resolveCalls++
	return r.resolved, r.resolveFound, r.resolveErr
}

func (r *repository) ReplaceSession(_ context.Context, previous *session.ID, _ session.Session, _ time.Time) (auth.Resolved, bool, error) {
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
