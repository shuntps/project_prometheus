package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

// TokenBytes gives 256 bits of entropy, comfortably above the 128 bits ASVS
// v5.0.0-7.2.3 requires, at no interoperability cost for an opaque cookie value.
const TokenBytes = 32

// Token is the value the browser holds. Every rendering path is overridden so it
// cannot reach a record, an error, a metric or a test failure.
type Token struct {
	raw string
}

// NewToken draws a token from the injected CSPRNG.
func NewToken(random io.Reader) (Token, error) {
	if random == nil {
		random = rand.Reader
	}
	raw := make([]byte, TokenBytes)
	if _, err := io.ReadFull(random, raw); err != nil {
		return Token{}, fmt.Errorf("%w: no token could be drawn", ErrInvalid)
	}
	return Token{raw: base64.RawURLEncoding.EncodeToString(raw)}, nil
}

// ParseToken accepts only a value of the exact shape this package issues.
func ParseToken(raw string) (Token, error) {
	trimmed := strings.TrimSpace(raw)
	decoded, err := base64.RawURLEncoding.DecodeString(trimmed)
	if err != nil || len(decoded) != TokenBytes {
		return Token{}, fmt.Errorf("%w: the token is not of the issued shape", ErrInvalid)
	}
	return Token{raw: trimmed}, nil
}

// Reveal returns the value. Only the transport that sets the cookie and the
// lookup that fingerprints it may call this.
func (t Token) Reveal() string { return t.raw }

func (t Token) IsZero() bool { return t.raw == "" }

func (t Token) String() string { return iam.Redacted }

func (t Token) GoString() string { return iam.Redacted }

func (t Token) LogValue() slog.Value { return slog.StringValue(iam.Redacted) }

func (t Token) MarshalText() ([]byte, error) { return []byte(iam.Redacted), nil }

func (t Token) MarshalJSON() ([]byte, error) { return []byte(`"` + iam.Redacted + `"`), nil }

// Fingerprint is what the database holds. SHA-256 fits and a password hash does
// not: the token already carries full entropy, so there is nothing to slow down.
type Fingerprint struct {
	value [sha256.Size]byte
}

// Fingerprint derives the stored value. The token cannot be recovered from it.
func (t Token) Fingerprint() Fingerprint {
	return Fingerprint{value: sha256.Sum256([]byte(t.raw))}
}

// Bytes returns a copy for the store. It is the only path to the value.
func (f Fingerprint) Bytes() []byte {
	out := make([]byte, len(f.value))
	copy(out, f.value[:])
	return out
}

// FingerprintFrom rebuilds a fingerprint read back from the store.
func FingerprintFrom(raw []byte) (Fingerprint, error) {
	if len(raw) != sha256.Size {
		return Fingerprint{}, fmt.Errorf("%w: the fingerprint is not of the stored size", ErrInvalid)
	}
	var f Fingerprint
	copy(f.value[:], raw)
	return f, nil
}

func (f Fingerprint) IsZero() bool { return f == Fingerprint{} }

func (f Fingerprint) String() string { return iam.Redacted }

func (f Fingerprint) GoString() string { return iam.Redacted }

func (f Fingerprint) LogValue() slog.Value { return slog.StringValue(iam.Redacted) }

func (f Fingerprint) MarshalText() ([]byte, error) { return []byte(iam.Redacted), nil }

func (f Fingerprint) MarshalJSON() ([]byte, error) { return []byte(`"` + iam.Redacted + `"`), nil }
