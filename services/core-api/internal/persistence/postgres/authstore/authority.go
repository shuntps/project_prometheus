package authstore

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

// lockedAuthority reads the account state and grants a decision depends on, under
// a row lock so a concurrent suspension either precedes this read or waits for it.
func lockedAuthority(ctx context.Context, tx pgx.Tx, account iam.AccountID) (iam.Principal, error) {
	var rawKind, rawStatus string
	// FOR NO KEY UPDATE, not FOR UPDATE: it must block an authority change, yet stay
	// compatible with the FOR KEY SHARE a revocation's event foreign key takes.
	if err := tx.QueryRow(ctx, `SELECT kind, status FROM accounts WHERE id = $1 FOR NO KEY UPDATE`, uuid.UUID(account)).
		Scan(&rawKind, &rawStatus); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return iam.Principal{}, ErrNotFound
		}
		return iam.Principal{}, ErrStore
	}
	kind, known := iam.ParseKind(rawKind)
	if !known {
		return iam.Principal{}, ErrNotFound
	}
	status := iam.Status(rawStatus)
	switch status {
	case iam.StatusPending, iam.StatusActive, iam.StatusSuspended, iam.StatusClosed:
	default:
		// An unknown stored status is never treated as usable.
		return iam.Principal{}, ErrNotFound
	}

	roles, err := grantsOf(ctx, tx, account)
	if err != nil {
		return iam.Principal{}, err
	}
	return iam.Principal{Account: account, Kind: kind, Status: status, Roles: roles}, nil
}

// grantsOf locks the rows it reads. An unlocked read would let a grant be deleted
// between the decision and the write it authorises.
func grantsOf(ctx context.Context, tx pgx.Tx, account iam.AccountID) ([]iam.Role, error) {
	rows, err := tx.Query(ctx, `SELECT role FROM account_role_grants WHERE account_id = $1 ORDER BY role FOR UPDATE`, uuid.UUID(account))
	if err != nil {
		return nil, ErrStore
	}
	defer rows.Close()

	var roles []iam.Role
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, ErrStore
		}
		if role, known := iam.ParseRole(raw); known {
			roles = append(roles, role)
		}
	}
	if rows.Err() != nil {
		return nil, ErrStore
	}
	return roles, nil
}
