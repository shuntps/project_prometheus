package authstore

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

// SetPassword replaces the stored representation and records the change.
func (s *Store) SetPassword(ctx context.Context, account iam.AccountID, encoded password.Encoded, now time.Time) error {
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
func (s *Store) EncodedPassword(ctx context.Context, account iam.AccountID) (password.Encoded, error) {
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

// Credential is what a login attempt needs in order to decide, and nothing more.
type Credential struct {
	Account  iam.AccountID
	Kind     iam.Kind
	Status   iam.Status
	Password password.Encoded
}

// CredentialByEmail reads the credential registered for a login address. Keeping
// the outward answer uniform is the caller's responsibility, in one place.
func (s *Store) CredentialByEmail(ctx context.Context, email iam.EmailAddress) (Credential, error) {
	if email.IsZero() {
		return Credential{}, ErrNotFound
	}
	const query = `SELECT a.id, a.kind, a.status, c.encoded_hash
		FROM account_email_identities e
		JOIN accounts a ON a.id = e.account_id
		JOIN account_password_credentials c ON c.account_id = a.id
		WHERE e.address = $1`

	var (
		id      uuid.UUID
		rawKind string
		status  string
		encoded string
	)
	if err := s.pool.QueryRow(ctx, query, email.Reveal()).Scan(&id, &rawKind, &status, &encoded); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Credential{}, ErrNotFound
		}
		return Credential{}, ErrStore
	}
	kind, known := iam.ParseKind(rawKind)
	if !known {
		return Credential{}, ErrNotFound
	}
	return Credential{
		Account:  iam.AccountID(id),
		Kind:     kind,
		Status:   iam.Status(status),
		Password: password.NewEncoded(encoded),
	}, nil
}
