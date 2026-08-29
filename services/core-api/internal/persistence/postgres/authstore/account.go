package authstore

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
)

// NewAccount is everything needed to create one account atomically.
type NewAccount struct {
	Kind        auth.Kind
	Status      auth.Status
	DisplayName string
	Email       auth.EmailAddress
	Password    password.Encoded
	Roles       []auth.Role
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
