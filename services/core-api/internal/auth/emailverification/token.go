package emailverification

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"

	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

// tokenBytes gives 256 bits of entropy. OWASP asks for a securely generated
// value of at least 32 characters; the encoding below writes 43.
const tokenBytes = 32

// EncodedTokenLength is the character count this package's encoder always
// writes. The store constrains the stored value to exactly it.
const EncodedTokenLength = 43

// Token is the value the verification link carries. Every rendering path is
// overridden so it cannot reach a record, an error, a metric or a test failure.
type Token struct {
	raw string
}

// newToken draws a token from the entropy source Issue was built with.
func newToken(random io.Reader) (Token, error) {
	raw := make([]byte, tokenBytes)
	if _, err := io.ReadFull(random, raw); err != nil {
		return Token{}, fmt.Errorf("%w: no verification token could be drawn", ErrInvalid)
	}
	return Token{raw: base64.RawURLEncoding.EncodeToString(raw)}, nil
}

// ParseToken accepts only a value of the exact shape this package issues: the
// input decoded as given, of the expected size, and re-encoding to the input.
func ParseToken(raw string) (Token, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || len(decoded) != tokenBytes {
		return Token{}, fmt.Errorf("%w: the verification token is not of the issued shape", ErrInvalid)
	}
	if base64.RawURLEncoding.EncodeToString(decoded) != raw {
		return Token{}, fmt.Errorf("%w: the verification token is not of the issued shape", ErrInvalid)
	}
	return Token{raw: raw}, nil
}

// Reveal returns the value. Only the delivery that carries it to the address and
// the lookup that fingerprints it may call this.
func (t Token) Reveal() string { return t.raw }

func (t Token) IsZero() bool { return t.raw == "" }

func (t Token) String() string { return iam.Redacted }

func (t Token) GoString() string { return iam.Redacted }

func (t Token) LogValue() slog.Value { return slog.StringValue(iam.Redacted) }

func (t Token) MarshalText() ([]byte, error) { return []byte(iam.Redacted), nil }

func (t Token) MarshalJSON() ([]byte, error) { return []byte(`"` + iam.Redacted + `"`), nil }

// Fingerprint is what the challenge table holds. SHA-256 fits and a password
// hash does not: the token already carries full entropy.
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

func (f Fingerprint) IsZero() bool { return f == Fingerprint{} }

func (f Fingerprint) String() string { return iam.Redacted }

func (f Fingerprint) GoString() string { return iam.Redacted }

func (f Fingerprint) LogValue() slog.Value { return slog.StringValue(iam.Redacted) }

func (f Fingerprint) MarshalText() ([]byte, error) { return []byte(iam.Redacted), nil }

func (f Fingerprint) MarshalJSON() ([]byte, error) { return []byte(`"` + iam.Redacted + `"`), nil }
