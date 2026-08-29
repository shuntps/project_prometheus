package authstore

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
)

// Event is one recorded security occurrence. It names what happened and to whom,
// and carries none of the material involved.
type Event struct {
	Kind       string
	Account    auth.AccountID
	OccurredAt time.Time
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
