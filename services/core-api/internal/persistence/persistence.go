// Package persistence defines the boundary the service reaches its durable store
// through, and is the single authority on usable store settings. It names no vendor.
package persistence

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"
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

// TLSMode is the transport posture of a store connection. The three values the
// service accepts are defined here; the driver's other modes are not.
type TLSMode string

const (
	TLSDisable    TLSMode = "disable"
	TLSVerifyCA   TLSMode = "verify-ca"
	TLSVerifyFull TLSMode = "verify-full"
)

// ParseTLSMode resolves no default. An unset value must be refused rather than
// inherited: the driver's own default negotiates plaintext without reporting it.
func ParseTLSMode(raw string) (TLSMode, bool) {
	switch mode := TLSMode(strings.ToLower(strings.TrimSpace(raw))); mode {
	case TLSDisable, TLSVerifyCA, TLSVerifyFull:
		return mode, true
	default:
		return "", false
	}
}

// AuthenticatesServer reports whether the mode proves the peer's identity.
func (m TLSMode) AuthenticatesServer() bool {
	return m == TLSVerifyCA || m == TLSVerifyFull
}

// SupportedTLSModes is the admissible set. disable encrypts nothing, allow and
// prefer fall back to plaintext, and require verifies nothing without a root CA.
var SupportedTLSModes = []TLSMode{TLSDisable, TLSVerifyCA, TLSVerifyFull}

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

// DSN carries a connection string. It is a Secret, so it redacts itself the same
// way, and only the adapter that opens the connection reveals it.
type DSN struct {
	Secret
}

func NewDSN(raw string) DSN { return DSN{Secret: NewSecret(strings.TrimSpace(raw))} }

// DefaultPort is the port a connection string that names none resolves to.
const DefaultPort = 5432

// Target is the destination a connection string names. Every field that the
// normative rule keeps out of records and errors is opaque, not only the password.
type Target struct {
	Host     Secret
	Port     uint16
	User     Secret
	Password Secret
	Database Secret
}

// ParseTarget is the single authority on a usable connection string. It completes
// nothing: a missing element is refused, because a driver would supply its own.
func ParseTarget(dsn DSN) (Target, error) {
	if dsn.IsZero() {
		return Target{}, fmt.Errorf("%w: the connection string is empty", ErrConfiguration)
	}
	parsed, err := url.Parse(dsn.Reveal())
	if err != nil {
		// The parse error embeds the whole connection string.
		return Target{}, fmt.Errorf("%w: the connection string is not a valid URL", ErrConfiguration)
	}

	var problems []string
	if scheme := strings.ToLower(parsed.Scheme); scheme != "postgres" && scheme != "postgresql" {
		problems = append(problems, "the scheme must be postgres or postgresql")
	}
	if len(parsed.Query()) > 0 {
		problems = append(problems, "no connection parameter may be carried; the typed settings are the only authority")
	}

	host := parsed.Hostname()
	database := strings.TrimPrefix(parsed.Path, "/")
	target := Target{Host: NewSecret(host), Port: DefaultPort, Database: NewSecret(database)}
	if host == "" {
		problems = append(problems, "a host is required")
	}
	if raw := parsed.Port(); raw != "" {
		number, err := strconv.ParseUint(raw, 10, 16)
		if err != nil || number == 0 {
			problems = append(problems, "the port must be between 1 and 65535")
		} else {
			target.Port = uint16(number)
		}
	}
	if database == "" || strings.Contains(database, "/") {
		problems = append(problems, "exactly one database name is required")
	}
	if parsed.User == nil || parsed.User.Username() == "" {
		problems = append(problems, "a user is required; a driver would otherwise fall back to the local account")
	} else {
		target.User = NewSecret(parsed.User.Username())
		password, set := parsed.User.Password()
		if !set || password == "" {
			problems = append(problems, "a password is required; a driver would otherwise consult a password file")
		}
		target.Password = NewSecret(password)
	}

	if len(problems) > 0 {
		return Target{}, fmt.Errorf("%w: %s", ErrConfiguration, strings.Join(problems, "; "))
	}
	return target, nil
}

// TLSRoot names where the certificate authorities come from. There is no
// implicit source: the driver would otherwise take one from the account's home.
type TLSRoot string

// TLSRootSystem uses the host's certificate pool. The driver rewrites the mode
// to verify-full when it is selected, so verify-ca may not be paired with it.
const TLSRootSystem TLSRoot = "system"

// ParseTLSRoot accepts the system pool or an absolute path, and nothing else.
func ParseTLSRoot(raw string) (TLSRoot, bool) {
	value := strings.TrimSpace(raw)
	switch {
	case value == string(TLSRootSystem):
		return TLSRootSystem, true
	case strings.HasPrefix(value, "/"):
		return TLSRoot(value), true
	default:
		return "", false
	}
}

// Settings bounds every value the adapter may open a pool with.
type Settings struct {
	TLSMode         TLSMode
	TLSRoot         TLSRoot
	MaxConns        int32
	MinConns        int32
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
	ConnectTimeout  time.Duration
	CheckTimeout    time.Duration
}

const (
	MinPoolSize = 1
	MaxPoolSize = 1000
	MinLifetime = time.Minute
	MaxLifetime = 24 * time.Hour
	MinIdleTime = time.Second
	MaxIdleTime = 24 * time.Hour
	MinTimeout  = 100 * time.Millisecond
	MaxTimeout  = time.Minute
)

// Validate accumulates every problem so an operator sees the whole set at once.
func (s Settings) Validate() error {
	var problems []string

	mode, known := ParseTLSMode(string(s.TLSMode))
	switch {
	case !known:
		problems = append(problems, "TLS mode is missing or not one of disable, verify-ca, verify-full")
	case !mode.AuthenticatesServer() && s.TLSRoot != "":
		problems = append(problems, "a trust source is meaningless when the mode does not authenticate the server")
	case mode.AuthenticatesServer():
		root, ok := ParseTLSRoot(string(s.TLSRoot))
		switch {
		case !ok:
			problems = append(problems, "a trust source is required: either system or an absolute path to a certificate file")
		case root == TLSRootSystem && mode == TLSVerifyCA:
			problems = append(problems, "the system pool cannot be paired with verify-ca: the driver rewrites the mode to verify-full")
		}
	}
	if s.MaxConns < MinPoolSize || s.MaxConns > MaxPoolSize {
		problems = append(problems, fmt.Sprintf("maximum connections must be between %d and %d", MinPoolSize, MaxPoolSize))
	}
	if s.MinConns < 0 {
		problems = append(problems, "minimum connections must not be negative")
	}
	if s.MaxConns >= MinPoolSize && s.MinConns > s.MaxConns {
		problems = append(problems, "minimum connections must not exceed maximum connections")
	}
	if s.MaxConnLifetime < MinLifetime || s.MaxConnLifetime > MaxLifetime {
		problems = append(problems, fmt.Sprintf("connection lifetime must be between %s and %s", MinLifetime, MaxLifetime))
	}
	if s.MaxConnIdleTime < MinIdleTime || s.MaxConnIdleTime > MaxIdleTime {
		problems = append(problems, fmt.Sprintf("connection idle time must be between %s and %s", MinIdleTime, MaxIdleTime))
	}
	if s.ConnectTimeout < MinTimeout || s.ConnectTimeout > MaxTimeout {
		problems = append(problems, fmt.Sprintf("connect timeout must be between %s and %s", MinTimeout, MaxTimeout))
	}
	if s.CheckTimeout < MinTimeout || s.CheckTimeout > MaxTimeout {
		problems = append(problems, fmt.Sprintf("health check timeout must be between %s and %s", MinTimeout, MaxTimeout))
	}

	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrConfiguration, strings.Join(problems, "; "))
	}
	return nil
}
