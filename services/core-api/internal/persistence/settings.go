package persistence

import (
	"fmt"
	"strings"
	"time"
)

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
