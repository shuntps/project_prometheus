package authstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

// ReplaceSession ends the presented session and creates its replacement in one
// transaction. The predecessor may belong to another account, and may be absent.
func (s *Store) ReplaceSession(ctx context.Context, previous *session.ID, successor session.Session,
	expected password.Revision, now time.Time) (Resolved, error) {
	replaced := now.UTC()
	var resolved Resolved

	err := s.inTx(ctx, func(tx pgx.Tx) error {
		// Read Committed lets two statements of one transaction see different
		// states, so the row lock is what serialises this against a suspension.
		principal, err := lockedAuthority(ctx, tx, successor.Account)
		if err != nil {
			return err
		}
		if !principal.Status.CanAuthenticate() {
			return ErrNotFound
		}
		// The surface is bound to the kind by insertSession below, which validates
		// the record against the kind read inside this same locked transaction.
		principal.Surface = successor.Surface

		// The credential is read under a lock and compared to the one the caller
		// verified. A replacement committed since then refuses this session rather
		// than letting a password already superseded open one.
		const lockCredential = `SELECT revision FROM account_password_credentials
			WHERE account_id = $1 FOR SHARE`
		var stored password.Revision
		switch err := tx.QueryRow(ctx, lockCredential, uuid.UUID(successor.Account)).Scan(&stored); {
		case errors.Is(err, pgx.ErrNoRows):
			return ErrNotFound
		case err != nil:
			return ErrStore
		}
		if stored != expected {
			return ErrNotFound
		}

		if previous != nil {
			const revoke = `UPDATE account_sessions SET revoked_at = $2
				WHERE id = $1 AND revoked_at IS NULL RETURNING account_id`
			var owner uuid.UUID
			switch err := tx.QueryRow(ctx, revoke, uuid.UUID(*previous), replaced).Scan(&owner); {
			case err == nil:
				if err := record(ctx, tx, "session_revoked", owner, sessionRef(*previous), replaced); err != nil {
					return err
				}
			case errors.Is(err, pgx.ErrNoRows):
				// Absent or already revoked: the requested outcome already holds.
			default:
				return ErrStore
			}
		}

		if err := insertSession(ctx, tx, successor); err != nil {
			return err
		}
		if err := record(ctx, tx, "session_created", uuid.UUID(successor.Account), sessionRef(successor.ID), successor.CreatedAt); err != nil {
			return err
		}
		resolved = Resolved{Session: successor, Principal: principal}
		return nil
	})
	if err != nil {
		return Resolved{}, err
	}
	return resolved, nil
}

// RevokeSession ends one session. The same statement decides and performs it, so
// a session already revoked is reported as such rather than revoked twice.
func (s *Store) RevokeSession(ctx context.Context, id session.ID, now time.Time) error {
	revoked := now.UTC()
	// Sessions first, then the account through the event's foreign key: the reverse
	// of the authorising paths, which lockedAuthority's mode is chosen to permit.
	return s.inTx(ctx, func(tx pgx.Tx) error {
		const update = `UPDATE account_sessions SET revoked_at = $2
			WHERE id = $1 AND revoked_at IS NULL RETURNING account_id`
		var account uuid.UUID
		if err := tx.QueryRow(ctx, update, uuid.UUID(id), revoked).Scan(&account); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return ErrStore
		}
		return record(ctx, tx, "session_revoked", account, sessionRef(id), revoked)
	})
}

// RevokeAccountSessions stops every live session of one account immediately.
func (s *Store) RevokeAccountSessions(ctx context.Context, account iam.AccountID, now time.Time) (int64, error) {
	revoked := now.UTC()
	var affected int64
	// Same reversed order as RevokeSession, over every live session of the account.
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		const update = `UPDATE account_sessions SET revoked_at = $2 WHERE account_id = $1 AND revoked_at IS NULL`
		tag, err := tx.Exec(ctx, update, uuid.UUID(account), revoked)
		if err != nil {
			return ErrStore
		}
		affected = tag.RowsAffected()
		return record(ctx, tx, "sessions_revoked_for_account", uuid.UUID(account), nil, revoked)
	})
	if err != nil {
		return 0, err
	}
	return affected, nil
}

// Rotate replaces a session in one transaction, so the previous token stops
// working at the instant the new one starts, on the operation's own clock.
func (s *Store) Rotate(ctx context.Context, previous session.ID, successor session.Session, now time.Time) error {
	// The instant comes from the operation, never from the successor: a record
	// under a caller's control must not decide whether its predecessor is alive.
	at := now.UTC()
	if !successor.CreatedAt.UTC().Equal(at) {
		return fmt.Errorf("%w: the successor was not created by this rotation", iam.ErrInvalid)
	}

	return s.inTx(ctx, func(tx pgx.Tx) error {
		// The account and its grants before the session rows, the order every
		// authorising path uses.
		owner, err := accountOfSession(ctx, tx, previous)
		if err != nil {
			return err
		}
		if _, err := lockedAuthority(ctx, tx, owner); err != nil {
			return err
		}

		// Nothing is written until it is established that both sessions carry the
		// same authority.
		const lock = `SELECT account_id, surface, created_at, revoked_at, rotated_to,
				idle_expires_at, absolute_expires_at
			FROM account_sessions WHERE id = $1 FOR UPDATE`
		var (
			account    uuid.UUID
			surface    string
			createdAt  time.Time
			revokedAt  *time.Time
			rotatedTo  *uuid.UUID
			idleUntil  time.Time
			untilLimit time.Time
		)
		if err := tx.QueryRow(ctx, lock, uuid.UUID(previous)).Scan(
			&account, &surface, &createdAt, &revokedAt, &rotatedTo, &idleUntil, &untilLimit); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return ErrStore
		}

		switch {
		case revokedAt != nil, rotatedTo != nil:
			return ErrNotFound
		case !at.Before(idleUntil), !at.Before(untilLimit):
			return ErrNotFound
		case at.Before(createdAt):
			return fmt.Errorf("%w: the successor predates the session it replaces", iam.ErrInvalid)
		case iam.AccountID(account) != successor.Account:
			return fmt.Errorf("%w: the successor belongs to another account", iam.ErrInvalid)
		case iam.Surface(surface) != successor.Surface:
			return fmt.Errorf("%w: the successor belongs to another surface", iam.ErrInvalid)
		}

		if err := insertSession(ctx, tx, successor); err != nil {
			return err
		}

		const update = `UPDATE account_sessions SET rotated_to = $2
			WHERE id = $1 AND revoked_at IS NULL AND rotated_to IS NULL`
		tag, err := tx.Exec(ctx, update, uuid.UUID(previous), uuid.UUID(successor.ID))
		if err != nil {
			return classify(err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return record(ctx, tx, "session_rotated", uuid.UUID(successor.Account), sessionRef(successor.ID), successor.CreatedAt)
	})
}
