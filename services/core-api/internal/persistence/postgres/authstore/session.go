package authstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

// Resolved is a session and the authority its account carries right now. Status
// and roles are read on every resolution, never carried inside the token.
type Resolved struct {
	Session   session.Session
	Principal iam.Principal
}

func insertSession(ctx context.Context, tx pgx.Tx, sess session.Session) error {
	kind, err := accountKind(ctx, tx, sess.Account)
	if err != nil {
		return err
	}
	if err := sess.Validate(kind); err != nil {
		return err
	}

	const insert = `INSERT INTO account_sessions
		(id, account_id, token_fingerprint, csrf_token, surface, created_at, last_active_at, idle_expires_at, absolute_expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	if _, err := tx.Exec(ctx, insert,
		uuid.UUID(sess.ID), uuid.UUID(sess.Account), sess.Fingerprint.Bytes(), sess.CSRF.Reveal(), string(sess.Surface),
		sess.CreatedAt, sess.LastActiveAt, sess.IdleExpiresAt, sess.AbsoluteExpiresAt); err != nil {
		return classify(err)
	}
	return nil
}

// accountOfSession discovers which account row to lock first. It is a hint, not a
// fact: the value is re-read and compared once the session itself is locked.
func accountOfSession(ctx context.Context, tx pgx.Tx, id session.ID) (iam.AccountID, error) {
	var owner uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT account_id FROM account_sessions WHERE id = $1`, uuid.UUID(id)).Scan(&owner); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return iam.AccountID{}, ErrNotFound
		}
		return iam.AccountID{}, ErrStore
	}
	return iam.AccountID(owner), nil
}

// Resolve looks a token up by its fingerprint and rebuilds the caller's authority
// from the current account status and the current grants.
func (s *Store) Resolve(ctx context.Context, token session.Token, now time.Time) (Resolved, error) {
	fingerprint := token.Fingerprint()

	const query = `SELECT s.id, s.account_id, s.csrf_token, s.surface, s.created_at, s.last_active_at,
			s.idle_expires_at, s.absolute_expires_at, s.revoked_at, s.rotated_to, a.status, a.kind
		FROM account_sessions s
		JOIN accounts a ON a.id = s.account_id
		WHERE s.token_fingerprint = $1`

	var (
		sess      session.Session
		id        uuid.UUID
		accountID uuid.UUID
		rawCSRF   string
		surface   string
		status    string
		rawKind   string
		rotatedTo *uuid.UUID
	)
	err := s.pool.QueryRow(ctx, query, fingerprint.Bytes()).Scan(
		&id, &accountID, &rawCSRF, &surface, &sess.CreatedAt, &sess.LastActiveAt,
		&sess.IdleExpiresAt, &sess.AbsoluteExpiresAt, &sess.RevokedAt, &rotatedTo, &status, &rawKind)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Resolved{}, ErrNotFound
		}
		return Resolved{}, ErrStore
	}

	csrf, err := session.ParseCSRFToken(rawCSRF)
	if err != nil {
		return Resolved{}, ErrNotFound
	}

	sess.ID = session.ID(id)
	sess.Account = iam.AccountID(accountID)
	sess.Surface = iam.Surface(surface)
	sess.Fingerprint = fingerprint
	sess.CSRF = csrf
	if rotatedTo != nil {
		successor := session.ID(*rotatedTo)
		sess.RotatedTo = &successor
	}

	if err := sess.UsableAt(now); err != nil {
		return Resolved{}, ErrNotFound
	}
	accountStatus := iam.Status(status)
	if !accountStatus.CanAuthenticate() {
		return Resolved{}, ErrNotFound
	}
	kind, known := iam.ParseKind(rawKind)
	if !known {
		return Resolved{}, ErrNotFound
	}
	// A stored row whose surface the kind may not hold is refused, whatever wrote it.
	if err := iam.ValidateSurface(kind, sess.Surface); err != nil {
		return Resolved{}, ErrNotFound
	}

	roles, err := s.roles(ctx, sess.Account)
	if err != nil {
		return Resolved{}, err
	}
	return Resolved{
		Session: sess,
		Principal: iam.Principal{
			Account: sess.Account, Kind: kind, Status: accountStatus,
			Surface: sess.Surface, Roles: roles,
		},
	}, nil
}

// accountKind reads the kind inside the caller's transaction, so a surface rule
// is decided against the account as it stands at that moment.
func accountKind(ctx context.Context, tx pgx.Tx, account iam.AccountID) (iam.Kind, error) {
	var raw string
	if err := tx.QueryRow(ctx, `SELECT kind FROM accounts WHERE id = $1`, uuid.UUID(account)).Scan(&raw); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", ErrStore
	}
	kind, known := iam.ParseKind(raw)
	if !known {
		return "", fmt.Errorf("%w: the stored account kind is unknown", iam.ErrInvalid)
	}
	return kind, nil
}
