package authstore

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

// NewAccount is everything needed to create one account atomically.
type NewAccount struct {
	Kind        iam.Kind
	Status      iam.Status
	DisplayName string
	Email       iam.EmailAddress
	Password    password.Encoded
	Roles       []iam.Role
}

// CreateAccount writes the account, its login identity, its credential and its
// grants in one transaction, so a half-created account can never be left behind.
func (s *Store) CreateAccount(ctx context.Context, in NewAccount, now time.Time) (iam.Account, error) {
	if _, known := iam.ParseKind(string(in.Kind)); !known {
		return iam.Account{}, fmt.Errorf("%w: the account kind is unknown", iam.ErrInvalid)
	}
	for _, role := range in.Roles {
		if err := iam.ValidateGrant(in.Kind, role); err != nil {
			return iam.Account{}, err
		}
	}

	id, err := iam.NewAccountID()
	if err != nil {
		return iam.Account{}, err
	}
	identityID, err := iam.NewIdentityID()
	if err != nil {
		return iam.Account{}, err
	}

	created := now.UTC()
	account := iam.Account{
		ID: id, Kind: in.Kind, Status: in.Status, DisplayName: in.DisplayName,
		CreatedAt: created, UpdatedAt: created,
	}

	err = s.inTx(ctx, func(tx pgx.Tx) error {
		return insertAccount(ctx, tx, account, identityID, in.Email, in.Password, in.Roles)
	})
	if err != nil {
		return iam.Account{}, err
	}
	return account, nil
}

// insertAccount writes the account, its login identity, its credential and its
// grants. It takes the transaction so that a registration can add its own writes
// to the same commit rather than repeat these.
func insertAccount(ctx context.Context, tx pgx.Tx, account iam.Account, identity iam.IdentityID,
	email iam.EmailAddress, encoded password.Encoded, roles []iam.Role) error {
	const insertAccountRow = `INSERT INTO accounts (id, kind, status, display_name, created_at, updated_at)
		VALUES ($1, $2, $3, NULLIF($4, ''), $5, $5)`
	if _, err := tx.Exec(ctx, insertAccountRow, uuid.UUID(account.ID), string(account.Kind), string(account.Status),
		account.DisplayName, account.CreatedAt); err != nil {
		return classify(err)
	}

	const insertIdentity = `INSERT INTO account_email_identities (id, account_id, address, created_at)
		VALUES ($1, $2, $3, $4)`
	if _, err := tx.Exec(ctx, insertIdentity, uuid.UUID(identity), uuid.UUID(account.ID),
		email.Reveal(), account.CreatedAt); err != nil {
		// Only the address rule may be raced on by a registration; every other
		// uniqueness rule stays an ordinary conflict.
		return classifyIdentity(err)
	}

	if !encoded.IsZero() {
		const insertCredential = `INSERT INTO account_password_credentials
				(account_id, encoded_hash, revision, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $4)`
		if _, err := tx.Exec(ctx, insertCredential, uuid.UUID(account.ID), encoded.Reveal(),
			password.FirstRevision, account.CreatedAt); err != nil {
			return classify(err)
		}
		if err := record(ctx, tx, "credential_created", uuid.UUID(account.ID), nil, account.CreatedAt); err != nil {
			return err
		}
	}

	for _, role := range roles {
		const insertGrant = `INSERT INTO account_role_grants (account_id, role, granted_at) VALUES ($1, $2, $3)`
		if _, err := tx.Exec(ctx, insertGrant, uuid.UUID(account.ID), string(role), account.CreatedAt); err != nil {
			return classify(err)
		}
	}
	return nil
}

// Suspend stops every session of the account taking effect, without rewriting
// the session rows: resolution reads the status again on each request.
func (s *Store) Suspend(ctx context.Context, account iam.AccountID, now time.Time) error {
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
