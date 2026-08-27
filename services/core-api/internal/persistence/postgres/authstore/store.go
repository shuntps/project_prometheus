// Package authstore keeps the authentication domain in PostgreSQL. It is the
// only package that knows the driver on that domain's behalf.
package authstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
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

func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// NewAccount is everything needed to create one account atomically.
type NewAccount struct {
	Kind        auth.Kind
	Status      auth.Status
	DisplayName string
	Email       auth.EmailAddress
	Password    password.Encoded
	Roles       []auth.Role
}

// Resolved is a session and the authority its account carries right now. Status
// and roles are read on every resolution, never carried inside the token.
type Resolved struct {
	Session   session.Session
	Principal auth.Principal
}

// Event is one recorded security occurrence. It names what happened and to whom,
// and carries none of the material involved.
type Event struct {
	Kind       string
	Account    auth.AccountID
	OccurredAt time.Time
}

// CreateAccount writes the account, its login identity, its credential and its
// grants in one transaction, so a half-created account can never be left behind.
func (s *Store) CreateAccount(ctx context.Context, in NewAccount, now time.Time) (auth.Account, error) {
	if _, known := auth.ParseKind(string(in.Kind)); !known {
		return auth.Account{}, fmt.Errorf("%w: the account kind is unknown", auth.ErrInvalid)
	}
	for _, role := range in.Roles {
		if err := auth.ValidateGrant(in.Kind, role); err != nil {
			return auth.Account{}, err
		}
	}

	id, err := auth.NewAccountID()
	if err != nil {
		return auth.Account{}, err
	}
	identityID, err := uuid.NewRandom()
	if err != nil {
		return auth.Account{}, fmt.Errorf("%w: no identity identifier could be drawn", auth.ErrInvalid)
	}

	created := now.UTC()
	account := auth.Account{
		ID: id, Kind: in.Kind, Status: in.Status, DisplayName: in.DisplayName,
		CreatedAt: created, UpdatedAt: created,
	}

	err = s.inTx(ctx, func(tx pgx.Tx) error {
		const insertAccount = `INSERT INTO accounts (id, kind, status, display_name, created_at, updated_at)
			VALUES ($1, $2, $3, NULLIF($4, ''), $5, $5)`
		if _, err := tx.Exec(ctx, insertAccount, uuid.UUID(id), string(in.Kind), string(in.Status), in.DisplayName, created); err != nil {
			return classify(err)
		}

		const insertIdentity = `INSERT INTO account_email_identities (id, account_id, address, created_at)
			VALUES ($1, $2, $3, $4)`
		if _, err := tx.Exec(ctx, insertIdentity, identityID, uuid.UUID(id), in.Email.Reveal(), created); err != nil {
			return classify(err)
		}

		if !in.Password.IsZero() {
			const insertCredential = `INSERT INTO account_password_credentials (account_id, encoded_hash, created_at, updated_at)
				VALUES ($1, $2, $3, $3)`
			if _, err := tx.Exec(ctx, insertCredential, uuid.UUID(id), in.Password.Reveal(), created); err != nil {
				return classify(err)
			}
			if err := record(ctx, tx, "credential_created", uuid.UUID(id), nil, created); err != nil {
				return err
			}
		}

		for _, role := range in.Roles {
			const insertGrant = `INSERT INTO account_role_grants (account_id, role, granted_at) VALUES ($1, $2, $3)`
			if _, err := tx.Exec(ctx, insertGrant, uuid.UUID(id), string(role), created); err != nil {
				return classify(err)
			}
		}
		return nil
	})
	if err != nil {
		return auth.Account{}, err
	}
	return account, nil
}

// SetPassword replaces the stored representation and records the change.
func (s *Store) SetPassword(ctx context.Context, account auth.AccountID, encoded password.Encoded, now time.Time) error {
	changed := now.UTC()
	return s.inTx(ctx, func(tx pgx.Tx) error {
		const upsert = `INSERT INTO account_password_credentials (account_id, encoded_hash, created_at, updated_at)
			VALUES ($1, $2, $3, $3)
			ON CONFLICT (account_id) DO UPDATE SET encoded_hash = EXCLUDED.encoded_hash, updated_at = EXCLUDED.updated_at`
		tag, err := tx.Exec(ctx, upsert, uuid.UUID(account), encoded.Reveal(), changed)
		if err != nil {
			return classify(err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return record(ctx, tx, "credential_changed", uuid.UUID(account), nil, changed)
	})
}

// EncodedPassword returns the stored representation for verification.
func (s *Store) EncodedPassword(ctx context.Context, account auth.AccountID) (password.Encoded, error) {
	const query = `SELECT encoded_hash FROM account_password_credentials WHERE account_id = $1`
	var raw string
	if err := s.pool.QueryRow(ctx, query, uuid.UUID(account)).Scan(&raw); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return password.Encoded{}, ErrNotFound
		}
		return password.Encoded{}, ErrStore
	}
	return password.NewEncoded(raw), nil
}

// Suspend stops every session of the account taking effect, without rewriting
// the session rows: resolution reads the status again on each request.
func (s *Store) Suspend(ctx context.Context, account auth.AccountID, now time.Time) error {
	suspended := now.UTC()
	return s.inTx(ctx, func(tx pgx.Tx) error {
		const update = `UPDATE accounts SET status = 'suspended', updated_at = $2 WHERE id = $1`
		tag, err := tx.Exec(ctx, update, uuid.UUID(account), suspended)
		if err != nil {
			return classify(err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return record(ctx, tx, "account_suspended", uuid.UUID(account), nil, suspended)
	})
}

// CreateSession stores a session. Only the fingerprint is written.
func (s *Store) CreateSession(ctx context.Context, sess session.Session) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if err := insertSession(ctx, tx, sess); err != nil {
			return err
		}
		return record(ctx, tx, "session_created", uuid.UUID(sess.Account), sessionRef(sess.ID), sess.CreatedAt)
	})
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
		(id, account_id, token_fingerprint, surface, created_at, last_active_at, idle_expires_at, absolute_expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	if _, err := tx.Exec(ctx, insert,
		uuid.UUID(sess.ID), uuid.UUID(sess.Account), sess.Fingerprint.Bytes(), string(sess.Surface),
		sess.CreatedAt, sess.LastActiveAt, sess.IdleExpiresAt, sess.AbsoluteExpiresAt); err != nil {
		return classify(err)
	}
	return nil
}

// Resolve looks a token up by its fingerprint and rebuilds the caller's authority
// from the current account status and the current grants.
func (s *Store) Resolve(ctx context.Context, token session.Token, now time.Time) (Resolved, error) {
	fingerprint := token.Fingerprint()

	const query = `SELECT s.id, s.account_id, s.surface, s.created_at, s.last_active_at,
			s.idle_expires_at, s.absolute_expires_at, s.revoked_at, s.rotated_to, a.status, a.kind
		FROM account_sessions s
		JOIN accounts a ON a.id = s.account_id
		WHERE s.token_fingerprint = $1`

	var (
		sess      session.Session
		id        uuid.UUID
		accountID uuid.UUID
		surface   string
		status    string
		rawKind   string
		rotatedTo *uuid.UUID
	)
	err := s.pool.QueryRow(ctx, query, fingerprint.Bytes()).Scan(
		&id, &accountID, &surface, &sess.CreatedAt, &sess.LastActiveAt,
		&sess.IdleExpiresAt, &sess.AbsoluteExpiresAt, &sess.RevokedAt, &rotatedTo, &status, &rawKind)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Resolved{}, ErrNotFound
		}
		return Resolved{}, ErrStore
	}

	sess.ID = auth.SessionID(id)
	sess.Account = auth.AccountID(accountID)
	sess.Surface = auth.Surface(surface)
	sess.Fingerprint = fingerprint
	if rotatedTo != nil {
		successor := auth.SessionID(*rotatedTo)
		sess.RotatedTo = &successor
	}

	if err := sess.UsableAt(now); err != nil {
		return Resolved{}, ErrNotFound
	}
	accountStatus := auth.Status(status)
	if !accountStatus.CanAuthenticate() {
		return Resolved{}, ErrNotFound
	}
	kind, known := auth.ParseKind(rawKind)
	if !known {
		return Resolved{}, ErrNotFound
	}
	// A stored row whose surface the kind may not hold is refused, whatever wrote it.
	if err := auth.ValidateSurface(kind, sess.Surface); err != nil {
		return Resolved{}, ErrNotFound
	}

	roles, err := s.roles(ctx, sess.Account)
	if err != nil {
		return Resolved{}, err
	}
	return Resolved{
		Session: sess,
		Principal: auth.Principal{
			Account: sess.Account, Kind: kind, Status: accountStatus,
			Surface: sess.Surface, Roles: roles,
		},
	}, nil
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

// Touch extends the idle window of a session still usable at that instant. The
// refusal is decided by the same statement that would update, so nothing revives.
func (s *Store) Touch(ctx context.Context, id auth.SessionID, now time.Time, idle time.Duration) error {
	if idle < session.MinIdle || idle > session.MaxAbsolute {
		return fmt.Errorf("%w: the idle lifetime is not usable", auth.ErrInvalid)
	}
	at := now.UTC()

	const update = `UPDATE account_sessions
		SET last_active_at = $2,
		    idle_expires_at = LEAST($2::timestamptz + $3::interval, absolute_expires_at)
		WHERE id = $1
		  AND revoked_at IS NULL
		  AND rotated_to IS NULL
		  AND idle_expires_at > $2
		  AND absolute_expires_at > $2
		  AND last_active_at <= $2`
	tag, err := s.pool.Exec(ctx, update, uuid.UUID(id), at, idle)
	if err != nil {
		return ErrStore
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RevokeSession stops one session immediately.
func (s *Store) RevokeSession(ctx context.Context, id auth.SessionID, now time.Time) error {
	revoked := now.UTC()
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
func (s *Store) RevokeAccountSessions(ctx context.Context, account auth.AccountID, now time.Time) (int64, error) {
	revoked := now.UTC()
	var affected int64
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

// Rotate replaces a session with a successor in one transaction, so the previous
// token stops working at the same instant the new one starts. The instant is the
// operation's own, and the successor must have been created for it.
func (s *Store) Rotate(ctx context.Context, previous auth.SessionID, successor session.Session, now time.Time) error {
	// The instant comes from the operation, never from the successor: a record
	// under a caller's control must not decide whether its predecessor is alive.
	at := now.UTC()
	if !successor.CreatedAt.UTC().Equal(at) {
		return fmt.Errorf("%w: the successor was not created by this rotation", auth.ErrInvalid)
	}

	return s.inTx(ctx, func(tx pgx.Tx) error {
		// The predecessor is locked and read first. Nothing is written until it is
		// established that both sessions carry the same authority.
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
		err := tx.QueryRow(ctx, lock, uuid.UUID(previous)).Scan(
			&account, &surface, &createdAt, &revokedAt, &rotatedTo, &idleUntil, &untilLimit)
		if err != nil {
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
			return fmt.Errorf("%w: the successor predates the session it replaces", auth.ErrInvalid)
		case auth.AccountID(account) != successor.Account:
			return fmt.Errorf("%w: the successor belongs to another account", auth.ErrInvalid)
		case auth.Surface(surface) != successor.Surface:
			return fmt.Errorf("%w: the successor belongs to another surface", auth.ErrInvalid)
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

// accountKind reads the kind inside the caller's transaction, so a surface rule
// is decided against the account as it stands at that moment.
func accountKind(ctx context.Context, tx pgx.Tx, account auth.AccountID) (auth.Kind, error) {
	var raw string
	if err := tx.QueryRow(ctx, `SELECT kind FROM accounts WHERE id = $1`, uuid.UUID(account)).Scan(&raw); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", ErrStore
	}
	kind, known := auth.ParseKind(raw)
	if !known {
		return "", fmt.Errorf("%w: the stored account kind is unknown", auth.ErrInvalid)
	}
	return kind, nil
}

// Events returns the recorded occurrences for one account, oldest first.
func (s *Store) Events(ctx context.Context, account auth.AccountID) ([]Event, error) {
	const query = `SELECT kind, occurred_at FROM account_security_events
		WHERE account_id = $1 ORDER BY occurred_at, id`
	rows, err := s.pool.Query(ctx, query, uuid.UUID(account))
	if err != nil {
		return nil, ErrStore
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		event := Event{Account: account}
		if err := rows.Scan(&event.Kind, &event.OccurredAt); err != nil {
			return nil, ErrStore
		}
		events = append(events, event)
	}
	if rows.Err() != nil {
		return nil, ErrStore
	}
	return events, nil
}

func sessionRef(id auth.SessionID) *uuid.UUID {
	value := uuid.UUID(id)
	return &value
}

func record(ctx context.Context, tx pgx.Tx, kind string, account uuid.UUID, sessionID *uuid.UUID, at time.Time) error {
	const insert = `INSERT INTO account_security_events (account_id, session_id, kind, occurred_at)
		VALUES ($1, $2, $3, $4)`
	if _, err := tx.Exec(ctx, insert, account, sessionID, kind, at); err != nil {
		return classify(err)
	}
	return nil
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
