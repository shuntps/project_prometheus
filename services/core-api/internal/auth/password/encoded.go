package password

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Encoded is a stored password representation. It redacts itself; the store that
// persists it and the verifier that reads it reach the value explicitly.
type Encoded struct {
	value string
}

// NewEncoded wraps a representation read back from storage.
func NewEncoded(raw string) Encoded { return Encoded{value: raw} }

// Reveal returns the representation. Only storage and verification call this.
func (e Encoded) Reveal() string { return e.value }

func (e Encoded) IsZero() bool { return e.value == "" }

func (e Encoded) String() string { return redacted }

func (e Encoded) GoString() string { return redacted }

func (e Encoded) LogValue() slog.Value { return slog.StringValue(redacted) }

func (e Encoded) MarshalText() ([]byte, error) { return []byte(redacted), nil }

func (e Encoded) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

const redacted = "[redacted]"

var encoding = base64.RawStdEncoding

// encode writes the PHC string format, which carries the algorithm, the
// algorithm version and every parameter needed to verify and to detect a rehash.
func encode(p Params, salt, key []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.MemoryKiB, p.Iterations, p.Lanes,
		encoding.EncodeToString(salt), encoding.EncodeToString(key))
}

func decode(encoded string) (Params, []byte, []byte, error) {
	fields := strings.Split(encoded, "$")
	if len(fields) != 6 || fields[0] != "" || fields[1] != "argon2id" {
		return Params{}, nil, nil, fmt.Errorf("%w: the representation is not an argon2id PHC string", ErrMalformed)
	}

	var version int
	if _, err := fmt.Sscanf(fields[2], "v=%d", &version); err != nil || fields[2] != fmt.Sprintf("v=%d", version) {
		return Params{}, nil, nil, fmt.Errorf("%w: the algorithm version is unreadable", ErrMalformed)
	}
	if version != argon2.Version {
		return Params{}, nil, nil, fmt.Errorf("%w: algorithm version %d is not supported", ErrMalformed, version)
	}

	var p Params
	if _, err := fmt.Sscanf(fields[3], "m=%d,t=%d,p=%d", &p.MemoryKiB, &p.Iterations, &p.Lanes); err != nil ||
		fields[3] != fmt.Sprintf("m=%d,t=%d,p=%d", p.MemoryKiB, p.Iterations, p.Lanes) {
		return Params{}, nil, nil, fmt.Errorf("%w: the parameters are unreadable", ErrMalformed)
	}
	if err := p.Validate(); err != nil {
		return Params{}, nil, nil, fmt.Errorf("%w: the stored parameters are not acceptable", ErrMalformed)
	}

	// The canonical sizes are required exactly, not as a lower bound.
	salt, err := encoding.DecodeString(fields[4])
	if err != nil || len(salt) != int(SaltLength) {
		return Params{}, nil, nil, fmt.Errorf("%w: the salt is not of the canonical size", ErrMalformed)
	}
	key, err := encoding.DecodeString(fields[5])
	if err != nil || len(key) != int(KeyLength) {
		return Params{}, nil, nil, fmt.Errorf("%w: the derived key is not of the canonical size", ErrMalformed)
	}
	return p, salt, key, nil
}
