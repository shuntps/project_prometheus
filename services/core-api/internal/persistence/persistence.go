// Package persistence defines the boundary the service reaches its durable store
// through, and is the single authority on usable store settings. It names no vendor.
package persistence

import (
	"context"
	"errors"
	"log/slog"
)

// Checker reports whether the durable store can serve traffic right now. The
// context bounds the attempt so a probe can never hang on an unresponsive peer.
type Checker interface {
	Check(ctx context.Context) error
}

var (
	// ErrUnavailable reports a store that did not answer. It carries no
	// connection detail and is therefore safe to log and to return.
	ErrUnavailable = errors.New("persistence unavailable")
	// ErrConfiguration reports settings the service refuses to open a store with.
	ErrConfiguration = errors.New("invalid persistence configuration")
)

const redacted = "[redacted]"

// Secret carries a value that must never be rendered. Every rendering path is
// overridden, so it cannot reach a record, an error or a test failure.
type Secret struct {
	raw string
}

func NewSecret(raw string) Secret { return Secret{raw: raw} }

// Reveal returns the value. Only the adapter that consumes it may call this.
func (s Secret) Reveal() string { return s.raw }

func (s Secret) IsZero() bool { return s.raw == "" }

func (s Secret) String() string { return redacted }

func (s Secret) GoString() string { return redacted }

func (s Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

func (s Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

func (s Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
