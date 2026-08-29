// Package authstore keeps the authentication domain in PostgreSQL. It is the
// only package that knows the driver on that domain's behalf.
package authstore

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	// ErrNotFound reports that nothing usable matched. It says no more, so a
	// caller cannot tell an absent record from a refused one.
	ErrNotFound = errors.New("no usable record")
	// ErrConflict reports a uniqueness rule the database refused to break.
	ErrConflict = errors.New("record already exists")
	// ErrStore reports a failure whose driver detail must not travel further.
	ErrStore = errors.New("store operation failed")
)

// Store owns the authentication tables.
type Store struct {
	pool *pgxpool.Pool
}

// New refuses a missing pool: a store built on one would fail on its first query,
// far from the wiring that produced it.
func New(pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, errors.New("the authentication store requires a connection pool")
	}
	return &Store{pool: pool}, nil
}

func (s *Store) inTx(ctx context.Context, body func(pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ErrStore
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	if err := body(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return ErrStore
	}
	return nil
}

// uniqueViolation is the SQLSTATE PostgreSQL raises for a broken unique rule.
const uniqueViolation = "23505"

// classify keeps the driver's message, which quotes values and constraint names,
// from travelling further than this package.
func classify(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
		return ErrConflict
	}
	return ErrStore
}
