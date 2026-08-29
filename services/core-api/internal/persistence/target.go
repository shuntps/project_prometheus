package persistence

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

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
