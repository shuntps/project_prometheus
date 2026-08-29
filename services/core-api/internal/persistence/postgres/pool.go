// Package postgres adapts the durable store boundary to PostgreSQL over a
// connection pool that is safe for concurrent use.
package postgres

import (
	"context"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence"
)

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

// Unwrap exposes the pool for the migration runner, which needs a session-scoped
// connection of its own to hold an advisory lock across several statements.
func (p *Pool) Unwrap() *pgxpool.Pool { return p.pool }
