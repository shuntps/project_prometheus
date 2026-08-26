// Package postgres adapts the durable store boundary to PostgreSQL over a
// connection pool that is safe for concurrent use.
package postgres

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence"
)

// allowedConnStringKeys is exactly the set the adapter writes. It bounds the
// string alone; the environment and the account defaults are closed elsewhere.
var allowedConnStringKeys = []string{
	"host", "port", "user", "password", "database",
	"sslmode", "sslrootcert", "sslcert", "sslkey", "passfile", "servicefile",
}

// libpqEnvironment is the set the pinned driver reads, verified against it by
// test. Revisit on every driver upgrade: the driver's table is not exported.
var libpqEnvironment = []string{
	"PGAPPNAME", "PGCHANNELBINDING", "PGCONNECT_TIMEOUT", "PGDATABASE", "PGHOST",
	"PGMAXPROTOCOLVERSION", "PGMINPROTOCOLVERSION", "PGOPTIONS", "PGPASSFILE",
	"PGPASSWORD", "PGPORT", "PGREQUIREAUTH", "PGSERVICE", "PGSERVICEFILE",
	"PGSSLCERT", "PGSSLKEY", "PGSSLMODE", "PGSSLNEGOTIATION", "PGSSLPASSWORD",
	"PGSSLROOTCERT", "PGSSLSNI", "PGTARGETSESSIONATTRS", "PGTZ", "PGUSER",
}

// x509Environment lists the variables the standard library resolves the host
// certificate pool from. They belong to Go, not to the driver, and stay apart.
var x509Environment = []string{"SSL_CERT_FILE", "SSL_CERT_DIR"}

// Pool holds the connections the service reaches PostgreSQL through. It is safe
// for concurrent use by multiple goroutines.
type Pool struct {
	pool *pgxpool.Pool
}

var _ persistence.Checker = (*Pool)(nil)

// Open resolves the destination, proves nothing ambient can move it, then connects.
// Building a pool establishes none, so an unreachable store must fail here.
func Open(ctx context.Context, dsn persistence.DSN, settings persistence.Settings) (*Pool, error) {
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	target, err := persistence.ParseTarget(dsn)
	if err != nil {
		return nil, err
	}
	if err := refuseAmbientSettings(os.LookupEnv); err != nil {
		return nil, err
	}
	if err := refuseAmbientTrustRoots(os.LookupEnv, settings.TLSRoot); err != nil {
		return nil, err
	}

	built := connString(target, settings)

	// The allow-list bounds the string only. It runs first because it rejects a
	// disallowed key before any file is read; the other two channels close below.
	connConfig, err := pgx.ParseConfigWithOptions(built, pgx.ParseConfigOptions{
		ParseConfigOptions: pgconn.ParseConfigOptions{ConnStringAllowedKeys: allowedConnStringKeys},
	})
	if err != nil {
		// The driver's message reproduces host, user and database name; only the
		// class of failure is allowed to survive.
		return nil, fmt.Errorf("%w: the connection string was rejected by the driver", persistence.ErrConfiguration)
	}
	if err := verifyResolved(connConfig, target, settings); err != nil {
		return nil, err
	}

	// NewWithConfig accepts only a config built by pgxpool.ParseConfig, so the
	// verified connection config is carried across onto it.
	cfg, err := pgxpool.ParseConfig(built)
	if err != nil {
		return nil, fmt.Errorf("%w: the pool settings were rejected by the driver", persistence.ErrConfiguration)
	}
	cfg.ConnConfig = connConfig
	cfg.MaxConns = settings.MaxConns
	cfg.MinConns = settings.MinConns
	cfg.MaxConnLifetime = settings.MaxConnLifetime
	cfg.MaxConnIdleTime = settings.MaxConnIdleTime
	cfg.ConnConfig.ConnectTimeout = settings.ConnectTimeout

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("%w: the pool could not be built from the resolved settings", persistence.ErrConfiguration)
	}

	probeCtx, cancel := context.WithTimeout(ctx, settings.ConnectTimeout)
	defer cancel()
	if err := pool.Ping(probeCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("%w: no connection was established within %s", persistence.ErrUnavailable, settings.ConnectTimeout)
	}

	return &Pool{pool: pool}, nil
}

// Check acquires a connection and round-trips to the server, so a pool holding
// only dead connections cannot report the store as available.
func (p *Pool) Check(ctx context.Context) error {
	if err := p.pool.Ping(ctx); err != nil {
		return fmt.Errorf("%w: the health check did not complete", persistence.ErrUnavailable)
	}
	return nil
}

// Close blocks until every connection has been returned to the pool and closed.
func (p *Pool) Close() { p.pool.Close() }

// connString rebuilds the string from the resolved destination and overrides every
// key the driver would otherwise take from the account's home directory.
func connString(t persistence.Target, settings persistence.Settings) string {
	// Four keys default to files under the home directory; writing them empty at
	// the highest precedence stops those reads. The root is replaced, not emptied.
	query := url.Values{
		"sslmode":     []string{string(settings.TLSMode)},
		"sslrootcert": []string{string(settings.TLSRoot)},
		"sslcert":     []string{""},
		"sslkey":      []string{""},
		"passfile":    []string{""},
		"servicefile": []string{""},
	}
	built := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(t.User.Reveal(), t.Password.Reveal()),
		Host:     net.JoinHostPort(t.Host.Reveal(), strconv.Itoa(int(t.Port))),
		Path:     "/" + t.Database.Reveal(),
		RawQuery: query.Encode(),
	}
	return built.String()
}

// refuseAmbientSettings fails closed rather than letting a variable the typed
// settings do not govern reach the destination, the transport or a local file.
func refuseAmbientSettings(lookup func(string) (string, bool)) error {
	var carrying []string
	for _, name := range libpqEnvironment {
		// The driver reads a variable only when its value is not empty, so an
		// absent or exactly empty one influences nothing. Spaces are a value.
		if value, ok := lookup(name); ok && value != "" {
			carrying = append(carrying, name)
		}
	}
	if len(carrying) > 0 {
		return fmt.Errorf("%w: %s must not carry a value; the typed settings are the only authority over the connection",
			persistence.ErrConfiguration, strings.Join(carrying, ", "))
	}
	return nil
}

// refuseAmbientTrustRoots closes the last channel into the host pool, before the
// pool is resolved. An explicit authority is read directly and is not affected.
func refuseAmbientTrustRoots(lookup func(string) (string, bool), root persistence.TLSRoot) error {
	if root != persistence.TLSRootSystem {
		return nil
	}
	var carrying []string
	for _, name := range x509Environment {
		// The standard library replaces its locations only for a non-empty value,
		// so an absent or exactly empty variable steers nothing. Spaces are a path.
		if value, ok := lookup(name); ok && value != "" {
			carrying = append(carrying, name)
		}
	}
	if len(carrying) > 0 {
		return fmt.Errorf("%w: %s must not carry a value when the trust source is %q; the typed settings are the only authority over the certificate authorities",
			persistence.ErrConfiguration, strings.Join(carrying, ", "), persistence.TLSRootSystem)
	}
	return nil
}

// verifyResolved checks the outcome rather than the channels, so a destination
// or a posture that moved during parsing is caught however it was moved.
func verifyResolved(resolved *pgx.ConnConfig, want persistence.Target, settings persistence.Settings) error {
	var problems []string
	if resolved.Host != want.Host.Reveal() || resolved.Port != want.Port {
		problems = append(problems, "the resolved destination is not the configured one")
	}
	if resolved.User != want.User.Reveal() || resolved.Database != want.Database.Reveal() {
		problems = append(problems, "the resolved identity is not the configured one")
	}
	if resolved.Password != want.Password.Reveal() {
		problems = append(problems, "the resolved password is not the configured one")
	}
	if len(resolved.Fallbacks) > 0 {
		problems = append(problems, "the resolved configuration keeps a fallback that could downgrade the connection")
	}
	problems = append(problems, verifyTLS(resolved.TLSConfig, want, settings)...)

	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", persistence.ErrConfiguration, strings.Join(problems, "; "))
	}
	return nil
}

// verifyTLS checks how the transport verifies, not merely that it is encrypted.
// A non-nil configuration proves neither the authority nor the mode's semantics.
func verifyTLS(resolved *tls.Config, want persistence.Target, settings persistence.Settings) []string {
	if settings.TLSMode == persistence.TLSDisable {
		if resolved != nil {
			return []string{"the transport is encrypted where the configured posture is disable"}
		}
		return nil
	}
	if resolved == nil {
		return []string{"the transport is not encrypted where the configured posture authenticates the server"}
	}

	var problems []string
	if len(resolved.Certificates) > 0 {
		problems = append(problems, "a client certificate was attached but none is configured")
	}
	switch expected, err := trustPool(settings.TLSRoot); {
	case err != nil:
		problems = append(problems, "the configured trust source could not be read back for verification")
	case resolved.RootCAs == nil || !resolved.RootCAs.Equal(expected):
		problems = append(problems, "the trust roots are not the configured authority")
	}

	switch settings.TLSMode {
	case persistence.TLSVerifyCA:
		// The driver emulates verify-ca by skipping the standard check and
		// verifying the chain itself, deliberately without the host name.
		if !resolved.InsecureSkipVerify || resolved.VerifyPeerCertificate == nil {
			problems = append(problems, "verify-ca did not resolve to the driver's chain verification")
		}
		// A name may be carried for SNI; the mode does not verify it, so it may
		// only ever be the configured host.
		if resolved.ServerName != "" && resolved.ServerName != want.Host.Reveal() {
			problems = append(problems, "verify-ca resolved with a server name that is not the configured host")
		}
	case persistence.TLSVerifyFull:
		if resolved.InsecureSkipVerify || resolved.VerifyPeerCertificate != nil {
			problems = append(problems, "verify-full did not resolve to standard chain and name verification")
		}
		if resolved.ServerName != want.Host.Reveal() {
			problems = append(problems, "verify-full did not resolve to the configured server name")
		}
	}
	return problems
}

// trustPool reads the configured authority back independently of the driver, so
// the comparison rests on the configuration rather than on the driver's own work.
func trustPool(root persistence.TLSRoot) (*x509.CertPool, error) {
	if root == persistence.TLSRootSystem {
		return x509.SystemCertPool()
	}
	body, err := os.ReadFile(string(root))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(body) {
		return nil, errors.New("the configured trust source holds no usable certificate")
	}
	return pool, nil
}
