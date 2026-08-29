// Package application holds the authentication use cases. It depends on the
// domain and on the ports it declares, and on no transport, framework or driver.
package application

import (
	"errors"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

// Outcome is a decision a use case reached. The zero value is deliberately not a
// success: an unset or unknown outcome must be refused, never served.
type Outcome uint8

const (
	OutcomeUnknown Outcome = iota
	OutcomeSucceeded
	OutcomeRateLimited
	OutcomeRejected
	OutcomeUnauthenticated
	OutcomeForbidden
)

// ErrUnavailable reports that nothing was decided about the caller. It carries no
// store, driver or SQLSTATE detail, so nothing about the failure can travel.
var ErrUnavailable = errors.New("the operation could not be decided")

// Credential is what a login attempt needs in order to decide, and nothing more.
type Credential struct {
	Account  iam.AccountID
	Kind     iam.Kind
	Status   iam.Status
	Password password.Encoded
}

// Resolved is a session and the authority its account carries right now. Status
// and roles are read on every resolution, never carried inside the token.
type Resolved struct {
	Session   session.Session
	Principal iam.Principal
}

// Authenticated is a resolved session and the instant it was decided at. An
// operation that must not observe a later clock is anchored to that instant.
type Authenticated struct {
	Resolved Resolved
	At       time.Time
}

// PasswordVerifier is the credential check. Hashing is required too: the decoy is
// built with the very parameters a real credential is verified against.
type PasswordVerifier interface {
	Hash(plaintext string) (password.Encoded, error)
	Verify(encoded password.Encoded, plaintext string) (rehash bool, err error)
}

// AttemptLimiter bounds attempts on a client dimension and an identifier
// dimension at once; both must permit an attempt.
type AttemptLimiter interface {
	Allow(client, identifier string, now time.Time) bool
}
