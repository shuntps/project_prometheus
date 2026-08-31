package authstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/emailverification"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

// ErrAddressTaken reports the one uniqueness rule two registrations may race on.
// It names no constraint, and wraps the ordinary conflict so a caller that only
// asks whether a record exists still gets its answer.
var ErrAddressTaken = fmt.Errorf("%w: the login address is already registered", ErrConflict)

// addressUnique is the index that decides that race. Every other unique rule
// stays an ordinary conflict, so a fingerprint or delivery collision can never
// be mistaken for a registration to retry.
const addressUnique = "account_email_identities_address_unique"

func classifyIdentity(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation && pgErr.ConstraintName == addressUnique {
		return ErrAddressTaken
	}
	return classify(err)
}

// Register creates a public viewer registration, or applies one to an address
// already present, in a single transaction. A collision on the address rule is
// reported as a value so the caller may take the existing-identity path once.
func (s *Store) Register(ctx context.Context, email iam.EmailAddress, encoded password.Encoded,
	lifetimes emailverification.Lifetimes, now time.Time) (bool, error) {
	if email.IsZero() {
		return false, iam.ErrInvalid
	}
	at := now.UTC()
	collided := false

	err := s.inTx(ctx, func(tx pgx.Tx) error {
		identity, account, found, err := identityByAddress(ctx, tx, email)
		if err != nil {
			return err
		}
		if !found {
			if err := createRegistration(ctx, tx, email, encoded, lifetimes, at); err != nil {
				// The flag is set before the error aborts the transaction, which is
				// the only way out: nothing may continue inside a failed one.
				collided = errors.Is(err, ErrAddressTaken)
				return err
			}
			return nil
		}
		return refreshRegistration(ctx, tx, identity, account, encoded, lifetimes, at)
	})
	if collided {
		return true, nil
	}
	return false, err
}

// Reissue emits a fresh challenge for an address already registered. It never
// creates an account: an address nobody registered leaves no trace of the call.
func (s *Store) Reissue(ctx context.Context, email iam.EmailAddress,
	lifetimes emailverification.Lifetimes, now time.Time) error {
	if email.IsZero() {
		return iam.ErrInvalid
	}
	at := now.UTC()
	return s.inTx(ctx, func(tx pgx.Tx) error {
		identity, account, found, err := identityByAddress(ctx, tx, email)
		if err != nil {
			return err
		}
		if !found {
			return nil
		}
		return refreshRegistration(ctx, tx, identity, account, password.Encoded{}, lifetimes, at)
	})
}

// identityByAddress discovers which rows a registration is about, without
// locking: the locks are taken afterwards in one order, account first.
func identityByAddress(ctx context.Context, tx pgx.Tx, email iam.EmailAddress) (iam.IdentityID, iam.AccountID, bool, error) {
	const query = `SELECT id, account_id FROM account_email_identities WHERE address = $1`
	var identity, account uuid.UUID
	if err := tx.QueryRow(ctx, query, email.Reveal()).Scan(&identity, &account); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return iam.IdentityID{}, iam.AccountID{}, false, nil
		}
		return iam.IdentityID{}, iam.AccountID{}, false, ErrStore
	}
	return iam.IdentityID(identity), iam.AccountID(account), true, nil
}

func createRegistration(ctx context.Context, tx pgx.Tx, email iam.EmailAddress, encoded password.Encoded,
	lifetimes emailverification.Lifetimes, at time.Time) error {
	id, err := iam.NewAccountID()
	if err != nil {
		return err
	}
	identity, err := iam.NewIdentityID()
	if err != nil {
		return err
	}
	// The public surface fixes the kind and the status. Neither is taken from a
	// request, so no caller can register a creator or an operator.
	account := iam.Account{
		ID: id, Kind: iam.KindViewer, Status: iam.StatusPending,
		CreatedAt: at, UpdatedAt: at,
	}
	if err := insertAccount(ctx, tx, account, identity, email, encoded, []iam.Role{iam.RoleViewer}); err != nil {
		return err
	}
	if err := record(ctx, tx, "account_registered", uuid.UUID(id), nil, at); err != nil {
		return err
	}
	return issueChallenge(ctx, tx, identity, id, lifetimes, at)
}

// refreshRegistration applies a registration to an address already present. It
// writes nothing unless the account is a pending viewer past its resend interval,
// so no public request touches a creator, an operator or a usable account.
func refreshRegistration(ctx context.Context, tx pgx.Tx, identity iam.IdentityID, account iam.AccountID,
	encoded password.Encoded, lifetimes emailverification.Lifetimes, at time.Time) error {
	var rawKind, rawStatus string
	if err := tx.QueryRow(ctx, `SELECT kind, status FROM accounts WHERE id = $1 FOR NO KEY UPDATE`,
		uuid.UUID(account)).Scan(&rawKind, &rawStatus); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return ErrStore
	}

	var (
		owner      uuid.UUID
		verifiedAt *time.Time
	)
	if err := tx.QueryRow(ctx, `SELECT account_id, verified_at FROM account_email_identities WHERE id = $1 FOR UPDATE`,
		uuid.UUID(identity)).Scan(&owner, &verifiedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return ErrStore
	}
	// The identity may have been reassigned between the discovery and the lock.
	// Deciding with the authority of another account is refused, never guessed.
	if iam.AccountID(owner) != account {
		return nil
	}
	if rawKind != string(iam.KindViewer) || rawStatus != string(iam.StatusPending) || verifiedAt != nil {
		return nil
	}

	current, held, err := currentChallenge(ctx, tx, identity)
	if err != nil {
		return err
	}
	if held && !current.MayReissueAt(at, lifetimes) {
		// Inside the interval nothing is written at all, so the password this call
		// presented is deliberately ignored and the answer discloses no timing.
		return nil
	}
	if err := supersedeCurrentChallenge(ctx, tx, identity, at); err != nil {
		return err
	}

	if !encoded.IsZero() {
		const upsert = `INSERT INTO account_password_credentials (account_id, encoded_hash, created_at, updated_at)
			VALUES ($1, $2, $3, $3)
			ON CONFLICT (account_id) DO UPDATE SET encoded_hash = EXCLUDED.encoded_hash, updated_at = EXCLUDED.updated_at`
		if _, err := tx.Exec(ctx, upsert, uuid.UUID(account), encoded.Reveal(), at); err != nil {
			return classify(err)
		}
		if err := record(ctx, tx, "credential_changed", uuid.UUID(account), nil, at); err != nil {
			return err
		}
	}
	return issueChallenge(ctx, tx, identity, account, lifetimes, at)
}

// currentChallenge locks the identity's current challenge. Current means neither
// consumed nor superseded; an expired one is still current and still holds the
// resend interval against the caller.
func currentChallenge(ctx context.Context, tx pgx.Tx, identity iam.IdentityID) (emailverification.Challenge, bool, error) {
	const query = `SELECT id, issued_at, expires_at FROM account_email_verifications
		WHERE identity_id = $1 AND consumed_at IS NULL AND superseded_at IS NULL FOR UPDATE`
	var id uuid.UUID
	challenge := emailverification.Challenge{Identity: identity}
	if err := tx.QueryRow(ctx, query, uuid.UUID(identity)).Scan(&id, &challenge.IssuedAt, &challenge.ExpiresAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return emailverification.Challenge{}, false, nil
		}
		return emailverification.Challenge{}, false, ErrStore
	}
	challenge.ID = emailverification.ID(id)
	return challenge, true, nil
}

// supersedeCurrentChallenge is what actually invalidates the previous token. The
// partial unique index only forbids a second current challenge; it supersedes
// nothing, so this statement must run before the next one is inserted.
func supersedeCurrentChallenge(ctx context.Context, tx pgx.Tx, identity iam.IdentityID, at time.Time) error {
	const update = `UPDATE account_email_verifications SET superseded_at = $2
		WHERE identity_id = $1 AND consumed_at IS NULL AND superseded_at IS NULL
		RETURNING id`
	rows, err := tx.Query(ctx, update, uuid.UUID(identity), at)
	if err != nil {
		return classify(err)
	}
	var superseded []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return ErrStore
		}
		superseded = append(superseded, id)
	}
	rows.Close()
	if rows.Err() != nil {
		return ErrStore
	}
	if len(superseded) == 0 {
		return nil
	}
	// A superseded challenge can never be consumed, so its pending delivery is
	// work that must not be done.
	if _, err := tx.Exec(ctx, `DELETE FROM account_email_deliveries WHERE challenge_id = ANY($1)`, superseded); err != nil {
		return classify(err)
	}
	return nil
}

// issueChallenge writes the challenge and the outbox row in the caller's
// transaction. The token reaches the outbox and nothing else: the challenge row
// holds only its fingerprint.
func issueChallenge(ctx context.Context, tx pgx.Tx, identity iam.IdentityID, account iam.AccountID,
	lifetimes emailverification.Lifetimes, at time.Time) error {
	challenge, token, err := emailverification.Issue(identity, lifetimes, at)
	if err != nil {
		return err
	}
	delivery, err := emailverification.NewDeliveryID()
	if err != nil {
		return err
	}

	const insertChallenge = `INSERT INTO account_email_verifications
		(id, identity_id, token_fingerprint, issued_at, expires_at) VALUES ($1, $2, $3, $4, $5)`
	if _, err := tx.Exec(ctx, insertChallenge, uuid.UUID(challenge.ID), uuid.UUID(identity),
		challenge.Fingerprint.Bytes(), challenge.IssuedAt, challenge.ExpiresAt); err != nil {
		return classify(err)
	}

	const insertDelivery = `INSERT INTO account_email_deliveries
		(id, challenge_id, token, created_at, available_at, expires_at) VALUES ($1, $2, $3, $4, $4, $5)`
	if _, err := tx.Exec(ctx, insertDelivery, uuid.UUID(delivery), uuid.UUID(challenge.ID),
		token.Reveal(), at, challenge.ExpiresAt); err != nil {
		return classify(err)
	}
	return record(ctx, tx, "email_verification_issued", uuid.UUID(account), nil, at)
}
