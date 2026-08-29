// Package auth holds the authentication use cases. It depends on the domain and
// on the ports it declares, and on no transport, framework or driver.
package auth

import "errors"

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
