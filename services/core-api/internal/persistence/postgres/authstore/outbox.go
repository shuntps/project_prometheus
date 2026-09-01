package authstore

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/emailverification"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

// ClaimedDelivery is one outbox row a dispatcher holds a lease on, with
// everything the transport needs and nothing else.
type ClaimedDelivery struct {
	ID        emailverification.DeliveryID
	Address   iam.EmailAddress
	Token     emailverification.Token
	ExpiresAt time.Time
	Attempts  int
}

// ClaimDeliveries takes a bounded batch under a lease and commits before any
// message leaves the process. SKIP LOCKED only keeps two concurrent claims off
// one row; recovering a dead process's work is what the lease is for.
func (s *Store) ClaimDeliveries(ctx context.Context, claim uuid.UUID, batch, maxAttempts int,
	lease time.Duration, now time.Time) ([]ClaimedDelivery, error) {
	at := now.UTC()
	// The candidates come from the outbox alone, so the two partial indexes decide
	// them, and the challenge is reached by its key. That table is never emptied,
	// so a plan scanning it would degrade with every registration ever made.
	const query = `WITH claimable AS (
			SELECT d.id, d.challenge_id
			FROM account_email_deliveries d
			WHERE d.token IS NOT NULL
			  AND d.attempts < $2
			  AND d.available_at <= $1
			  AND (d.claim_expires_at IS NULL OR d.claim_expires_at <= $1)
			  AND EXISTS (
				  SELECT 1 FROM account_email_verifications v
				  WHERE v.id = d.challenge_id
				    AND v.consumed_at IS NULL
				    AND v.superseded_at IS NULL
				    AND v.expires_at > $1
			  )
			ORDER BY d.available_at, d.id
			FOR UPDATE OF d SKIP LOCKED
			LIMIT $3
		)
		UPDATE account_email_deliveries d
		SET claimed_at = $1, claim_expires_at = $4, claim_id = $5, attempts = d.attempts + 1
		FROM claimable c
		JOIN account_email_verifications v ON v.id = c.challenge_id
		JOIN account_email_identities e ON e.id = v.identity_id
		WHERE d.id = c.id
		RETURNING d.id, d.token, d.attempts, e.address, v.expires_at`

	rows, err := s.pool.Query(ctx, query, at, maxAttempts, batch, at.Add(lease), claim)
	if err != nil {
		return nil, ErrStore
	}
	defer rows.Close()

	var claimed []ClaimedDelivery
	for rows.Next() {
		var (
			id      uuid.UUID
			raw     string
			address string
			one     ClaimedDelivery
		)
		if err := rows.Scan(&id, &raw, &one.Attempts, &address, &one.ExpiresAt); err != nil {
			return nil, ErrStore
		}
		token, err := emailverification.ParseToken(raw)
		if err != nil {
			return nil, ErrStore
		}
		// The stored address was normalised before it was written, so the domain
		// constructor is the only way it is read back.
		parsed, err := iam.NormaliseEmail(address)
		if err != nil {
			return nil, ErrStore
		}
		one.ID = emailverification.DeliveryID(id)
		one.Token = token
		one.Address = parsed
		claimed = append(claimed, one)
	}
	if rows.Err() != nil {
		return nil, ErrStore
	}
	return claimed, nil
}

// SettleDelivery removes work that must not be attempted again: the transport
// accepted the message, or no further attempt is permitted. The lease owner is
// required, so a dispatcher whose lease lapsed cannot undo a newer claim.
func (s *Store) SettleDelivery(ctx context.Context, id emailverification.DeliveryID, claim uuid.UUID) (bool, error) {
	const remove = `DELETE FROM account_email_deliveries WHERE id = $1 AND claim_id = $2`
	tag, err := s.pool.Exec(ctx, remove, uuid.UUID(id), claim)
	if err != nil {
		return false, ErrStore
	}
	return tag.RowsAffected() == 1, nil
}

// RescheduleDelivery releases the lease and moves the work to its next attempt.
func (s *Store) RescheduleDelivery(ctx context.Context, id emailverification.DeliveryID, claim uuid.UUID,
	at time.Time) (bool, error) {
	const update = `UPDATE account_email_deliveries
		SET available_at = $3, claimed_at = NULL, claim_expires_at = NULL, claim_id = NULL
		WHERE id = $1 AND claim_id = $2`
	tag, err := s.pool.Exec(ctx, update, uuid.UUID(id), claim, at.UTC())
	if err != nil {
		return false, ErrStore
	}
	return tag.RowsAffected() == 1, nil
}

// SweepDeliveries removes work no attempt can complete, at most batch rows per
// call across both causes. Each cause is a range on one column here — the copied
// expiry, or the counter — so no scan is proportional to any other table.
func (s *Store) SweepDeliveries(ctx context.Context, batch, maxAttempts int, now time.Time) (int64, error) {
	if batch < 1 {
		return 0, nil
	}
	at := now.UTC()

	const expired = `WITH lapsed AS (
			SELECT d.id FROM account_email_deliveries d
			WHERE d.expires_at <= $1
			  AND (d.claim_expires_at IS NULL OR d.claim_expires_at <= $1)
			ORDER BY d.expires_at
			LIMIT $2
			FOR UPDATE SKIP LOCKED
		)
		DELETE FROM account_email_deliveries d USING lapsed l WHERE d.id = l.id`
	first, err := s.pool.Exec(ctx, expired, at, batch)
	if err != nil {
		return 0, ErrStore
	}
	removed := first.RowsAffected()

	// The batch is shared: what the first cause took is what the second may not.
	remaining := int64(batch) - removed
	if remaining < 1 {
		return removed, nil
	}
	const exhausted = `WITH spent AS (
			SELECT d.id FROM account_email_deliveries d
			WHERE d.attempts >= $2
			  AND (d.claim_expires_at IS NULL OR d.claim_expires_at <= $1)
			ORDER BY d.attempts
			LIMIT $3
			FOR UPDATE SKIP LOCKED
		)
		DELETE FROM account_email_deliveries d USING spent s WHERE d.id = s.id`
	second, err := s.pool.Exec(ctx, exhausted, at, maxAttempts, remaining)
	if err != nil {
		return removed, ErrStore
	}
	return removed + second.RowsAffected(), nil
}
