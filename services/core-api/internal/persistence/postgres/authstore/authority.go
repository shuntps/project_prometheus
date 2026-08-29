package authstore

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
)

// lockedAuthority reads the account state and grants a decision depends on, under
// a row lock so a concurrent suspension either precedes this read or waits for it.
func lockedAuthority(ctx context.Context, tx pgx.Tx, account auth.AccountID) (auth.Principal, error) {
	var rawKind, rawStatus string
	// FOR NO KEY UPDATE, not FOR UPDATE: it must block an authority change, yet stay
	// compatible with the FOR KEY SHARE a revocation's event foreign key takes.
	if err := tx.QueryRow(ctx, `SELECT kind, status FROM accounts WHERE id = $1 FOR NO KEY UPDATE`, uuid.UUID(account)).
		Scan(&rawKind, &rawStatus); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return auth.Principal{}, ErrNotFound
		}
		return auth.Principal{}, ErrStore
	}
	kind, known := auth.ParseKind(rawKind)
	if !known {
		return auth.Principal{}, ErrNotFound
	}
	status := auth.Status(rawStatus)
	switch status {
	case auth.StatusPending, auth.StatusActive, auth.StatusSuspended, auth.StatusClosed:
	default:
		// An unknown stored status is never treated as usable.
		return auth.Principal{}, ErrNotFound
	}

	roles, err := grantsOf(ctx, tx, account)
	if err != nil {
		return auth.Principal{}, err
	}
	return auth.Principal{Account: account, Kind: kind, Status: status, Roles: roles}, nil
}

// grantsOf locks the rows it reads. An unlocked read would let a grant be deleted
// between the decision and the write it authorises.
func grantsOf(ctx context.Context, tx pgx.Tx, account auth.AccountID) ([]auth.Role, error) {
	rows, err := tx.Query(ctx, `SELECT role FROM account_role_grants WHERE account_id = $1 ORDER BY role FOR UPDATE`, uuid.UUID(account))
	if err != nil {
		return nil, ErrStore
	}
	defer rows.Close()

	var roles []auth.Role
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, ErrStore
		}
		if role, known := auth.ParseRole(raw); known {
			roles = append(roles, role)
		}
	}
	if rows.Err() != nil {
		return nil, ErrStore
	}
	return roles, nil
}

func (s *Store) roles(ctx context.Context, account auth.AccountID) ([]auth.Role, error) {
	const query = `SELECT role FROM account_role_grants WHERE account_id = $1 ORDER BY role`
	rows, err := s.pool.Query(ctx, query, uuid.UUID(account))
	if err != nil {
		return nil, ErrStore
	}
	defer rows.Close()

	var roles []auth.Role
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, ErrStore
		}
		// An unknown stored value is dropped rather than trusted as a role.
		if role, known := auth.ParseRole(raw); known {
			roles = append(roles, role)
		}
	}
	if rows.Err() != nil {
		return nil, ErrStore
	}
	return roles, nil
}
