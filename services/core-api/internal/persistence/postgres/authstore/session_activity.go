package authstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
)

// RecordActivity extends the inactivity deadline of a live session and nothing
// else. It reports whether a write happened, which is how a suppressed update is
// told apart from a refused one.
//
// The permission is fixed here rather than chosen by a caller, and the decision
// runs inside this transaction: an authority read before it could be gone since.
func (s *Store) RecordActivity(ctx context.Context, id auth.SessionID, now time.Time, lifetimes session.Lifetimes) (bool, error) {
	at := now.UTC()
	var written bool

	err := s.inTx(ctx, func(tx pgx.Tx) error {
		discovered, err := accountOfSession(ctx, tx, id)
		if err != nil {
			return err
		}
		// Authorising paths take the account and its grants before any session row.
		// Revocation runs the other way; only the lock modes keep the two compatible.
		principal, err := lockedAuthority(ctx, tx, discovered)
		if err != nil {
			return err
		}

		const lock = `SELECT account_id, surface, last_active_at, idle_expires_at,
				absolute_expires_at, revoked_at, rotated_to
			FROM account_sessions WHERE id = $1 FOR UPDATE`
		var (
			current   session.Session
			owner     uuid.UUID
			surface   string
			rotatedTo *uuid.UUID
		)
		if err := tx.QueryRow(ctx, lock, uuid.UUID(id)).Scan(
			&owner, &surface, &current.LastActiveAt, &current.IdleExpiresAt,
			&current.AbsoluteExpiresAt, &current.RevokedAt, &rotatedTo); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return ErrStore
		}
		// The session may have been reassigned between the discovery and the lock.
		// Deciding with the authority of another account is refused, never guessed.
		if auth.AccountID(owner) != discovered {
			return ErrNotFound
		}
		current.ID = id
		current.Account = discovered
		current.Surface = auth.Surface(surface)
		if rotatedTo != nil {
			successor := auth.SessionID(*rotatedTo)
			current.RotatedTo = &successor
		}

		if err := current.UsableAt(at); err != nil {
			return ErrNotFound
		}
		principal.Surface = current.Surface
		// An account that can no longer authenticate on this surface makes the record
		// unusable rather than the action denied, and is answered like an absent one.
		if !principal.Status.CanAuthenticate() {
			return ErrNotFound
		}
		if err := auth.ValidateSurface(principal.Kind, principal.Surface); err != nil {
			return ErrNotFound
		}
		if err := auth.Authorize(principal, auth.PermissionOwnSessionRead); err != nil {
			return fmt.Errorf("%w: the account may not renew this session", auth.ErrDenied)
		}
		if !current.ActivityIsWorthPersisting(at, lifetimes) {
			return nil
		}

		const update = `UPDATE account_sessions SET last_active_at = $2, idle_expires_at = $3
			WHERE id = $1 AND revoked_at IS NULL AND rotated_to IS NULL`
		tag, err := tx.Exec(ctx, update, uuid.UUID(id), at, current.RenewedIdleAt(at, lifetimes))
		if err != nil {
			return classify(err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		written = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return written, nil
}
