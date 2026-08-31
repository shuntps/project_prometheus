package authstore

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/emailverification"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

// ConsumeVerification decides and applies one verification in one transaction.
// It reports whether an activation happened; a coherent second presentation
// writes nothing, and everything else is an absence.
func (s *Store) ConsumeVerification(ctx context.Context, fingerprint emailverification.Fingerprint,
	now time.Time) (bool, error) {
	if fingerprint.IsZero() {
		return false, ErrNotFound
	}
	at := now.UTC()
	activated := false

	err := s.inTx(ctx, func(tx pgx.Tx) error {
		challengeID, identity, account, err := challengeByFingerprint(ctx, tx, fingerprint)
		if err != nil {
			return err
		}

		var rawKind, rawStatus string
		if err := tx.QueryRow(ctx, `SELECT kind, status FROM accounts WHERE id = $1 FOR NO KEY UPDATE`,
			uuid.UUID(account)).Scan(&rawKind, &rawStatus); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
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
				return ErrNotFound
			}
			return ErrStore
		}
		if iam.AccountID(owner) != account {
			return ErrNotFound
		}

		const lock = `SELECT identity_id, token_fingerprint, issued_at, expires_at, consumed_at, superseded_at
			FROM account_email_verifications WHERE id = $1 FOR UPDATE`
		var (
			lockedIdentity uuid.UUID
			storedPrint    []byte
			challenge      emailverification.Challenge
		)
		if err := tx.QueryRow(ctx, lock, uuid.UUID(challengeID)).Scan(&lockedIdentity, &storedPrint,
			&challenge.IssuedAt, &challenge.ExpiresAt, &challenge.ConsumedAt, &challenge.SupersededAt); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return ErrStore
		}
		// The whole chain is established again under the locks: the row still
		// answers to this token, still belongs to this identity, and the identity
		// still belongs to this account.
		if iam.IdentityID(lockedIdentity) != identity {
			return ErrNotFound
		}
		if subtle.ConstantTimeCompare(storedPrint, fingerprint.Bytes()) != 1 {
			return ErrNotFound
		}

		// Decided before the account's current standing: this reports what happened
		// to the address, and a later suspension does not rewrite it. Such an
		// account still cannot authenticate, which sign-in decides on its own.
		if challenge.ConsumedAt != nil {
			if verifiedAt != nil && challenge.ConsumedAt.Before(challenge.ExpiresAt) {
				return nil
			}
			return ErrNotFound
		}
		if challenge.SupersededAt != nil || !at.Before(challenge.ExpiresAt) {
			return ErrNotFound
		}
		if rawKind != string(iam.KindViewer) || rawStatus != string(iam.StatusPending) {
			return ErrNotFound
		}

		const markVerified = `UPDATE account_email_identities SET verified_at = $2 WHERE id = $1 AND verified_at IS NULL`
		tag, err := tx.Exec(ctx, markVerified, uuid.UUID(identity), at)
		if err != nil {
			return classify(err)
		}
		if tag.RowsAffected() != 1 {
			return ErrNotFound
		}

		const activate = `UPDATE accounts SET status = 'active', updated_at = $2 WHERE id = $1 AND status = 'pending'`
		if tag, err = tx.Exec(ctx, activate, uuid.UUID(account), at); err != nil {
			return classify(err)
		}
		if tag.RowsAffected() != 1 {
			return ErrNotFound
		}

		const consume = `UPDATE account_email_verifications SET consumed_at = $2 WHERE id = $1 AND consumed_at IS NULL`
		if tag, err = tx.Exec(ctx, consume, uuid.UUID(challengeID), at); err != nil {
			return classify(err)
		}
		if tag.RowsAffected() != 1 {
			return ErrNotFound
		}

		// The token is now spent, so its pending delivery is work that must not be
		// done. A message already in flight cannot be recalled.
		if _, err := tx.Exec(ctx, `DELETE FROM account_email_deliveries WHERE challenge_id = $1`,
			uuid.UUID(challengeID)); err != nil {
			return classify(err)
		}

		activated = true
		return record(ctx, tx, "email_verification_completed", uuid.UUID(account), nil, at)
	})
	if err != nil {
		return false, err
	}
	return activated, nil
}

// challengeByFingerprint discovers which rows a verification is about, without
// locking: the locks are taken afterwards in one order, account first.
func challengeByFingerprint(ctx context.Context, tx pgx.Tx, fingerprint emailverification.Fingerprint) (
	emailverification.ID, iam.IdentityID, iam.AccountID, error) {
	const query = `SELECT v.id, v.identity_id, e.account_id
		FROM account_email_verifications v
		JOIN account_email_identities e ON e.id = v.identity_id
		WHERE v.token_fingerprint = $1`
	var challenge, identity, account uuid.UUID
	if err := tx.QueryRow(ctx, query, fingerprint.Bytes()).Scan(&challenge, &identity, &account); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return emailverification.ID{}, iam.IdentityID{}, iam.AccountID{}, ErrNotFound
		}
		return emailverification.ID{}, iam.IdentityID{}, iam.AccountID{}, ErrStore
	}
	return emailverification.ID(challenge), iam.IdentityID(identity), iam.AccountID(account), nil
}
