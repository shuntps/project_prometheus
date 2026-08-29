package session

import (
	"fmt"
	"strings"
	"time"
)

// Lifetimes bounds how long a session may live and how long it may sit idle.
type Lifetimes struct {
	Absolute time.Duration
	Idle     time.Duration
	// ActivityInterval is the shortest spacing between two persisted activity
	// updates, so a burst of user events costs one write rather than one per event.
	ActivityInterval time.Duration
}

const (
	MinIdle             = time.Minute
	MinAbsolute         = 5 * time.Minute
	MaxAbsolute         = 30 * 24 * time.Hour
	MinActivityInterval = time.Second
)

// Validate keeps the two expiries distinct and ordered.
func (l Lifetimes) Validate() error {
	var problems []string
	if l.Idle < MinIdle {
		problems = append(problems, fmt.Sprintf("the idle lifetime must be at least %s", MinIdle))
	}
	if l.Absolute < MinAbsolute || l.Absolute > MaxAbsolute {
		problems = append(problems, fmt.Sprintf("the absolute lifetime must be between %s and %s", MinAbsolute, MaxAbsolute))
	}
	if l.Idle >= MinIdle && l.Absolute >= MinAbsolute && l.Idle > l.Absolute {
		problems = append(problems, "the idle lifetime must not exceed the absolute lifetime")
	}
	if l.ActivityInterval < MinActivityInterval {
		problems = append(problems, fmt.Sprintf("the activity interval must be at least %s", MinActivityInterval))
	}
	// An interval at or above the idle lifetime would let a session expire between
	// two updates the policy permits, which is the opposite of what it is for.
	if l.ActivityInterval >= MinActivityInterval && l.Idle >= MinIdle && l.ActivityInterval >= l.Idle {
		problems = append(problems, "the activity interval must be shorter than the idle lifetime")
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalid, strings.Join(problems, "; "))
	}
	return nil
}
