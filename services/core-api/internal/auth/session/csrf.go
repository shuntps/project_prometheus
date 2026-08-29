package session

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

// CSRFTokenBytes matches the session token: the value is a bearer secret for the
// request that carries it, so it is drawn at the same strength.
const CSRFTokenBytes = 32

// CSRFToken is the synchronizer token bound to one session. Unlike the session
// token it is stored as issued, because the server has to hand it back.
type CSRFToken struct {
	raw string
}

// NewCSRFToken draws a token from the injected CSPRNG.
func NewCSRFToken(random io.Reader) (CSRFToken, error) {
	if random == nil {
		random = rand.Reader
	}
	raw := make([]byte, CSRFTokenBytes)
	if _, err := io.ReadFull(random, raw); err != nil {
		return CSRFToken{}, fmt.Errorf("%w: no CSRF token could be drawn", ErrInvalid)
	}
	return CSRFToken{raw: base64.RawURLEncoding.EncodeToString(raw)}, nil
}

// ParseCSRFToken accepts only a value of the exact shape this package issues.
func ParseCSRFToken(raw string) (CSRFToken, error) {
	trimmed := strings.TrimSpace(raw)
	decoded, err := base64.RawURLEncoding.DecodeString(trimmed)
	if err != nil || len(decoded) != CSRFTokenBytes {
		return CSRFToken{}, fmt.Errorf("%w: the CSRF token is not of the issued shape", ErrInvalid)
	}
	return CSRFToken{raw: trimmed}, nil
}

// Reveal returns the value. Only the transport that hands the token to the client
// and the comparison that checks it back may call this.
func (c CSRFToken) Reveal() string { return c.raw }

// Equals compares in constant time, so a mismatch discloses nothing about how far
// a forged value matched.
func (c CSRFToken) Equals(other CSRFToken) bool {
	if c.IsZero() || other.IsZero() {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.raw), []byte(other.raw)) == 1
}

func (c CSRFToken) IsZero() bool { return c.raw == "" }

func (c CSRFToken) String() string { return iam.Redacted }

func (c CSRFToken) GoString() string { return iam.Redacted }

func (c CSRFToken) LogValue() slog.Value { return slog.StringValue(iam.Redacted) }

func (c CSRFToken) MarshalText() ([]byte, error) { return []byte(iam.Redacted), nil }

func (c CSRFToken) MarshalJSON() ([]byte, error) { return []byte(`"` + iam.Redacted + `"`), nil }
