package integration_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/emailverification"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

func challengeLifetimes() emailverification.Lifetimes {
	return emailverification.Lifetimes{Lifetime: 8 * time.Hour, ResendInterval: time.Minute}
}

func freshAddress(t *testing.T) iam.EmailAddress {
	t.Helper()
	address, err := iam.NormaliseEmail(fmt.Sprintf("registrant%d@example.com", addressCounter.next()))
	if err != nil {
		t.Fatalf("normalising failed: %v", err)
	}
	return address
}

// registration is what one address looks like in the database, read straight
// from the tables rather than from any value the code handed back.
type registration struct {
	account     string
	identity    string
	kind        string
	status      string
	verifiedAt  *time.Time
	encoded     string
	roles       []string
	challenges  int
	current     *storedChallenge
	deliveries  int
	deliveryTok string
	deliveryID  string
}

type storedChallenge struct {
	id           string
	issuedAt     time.Time
	expiresAt    time.Time
	consumedAt   *time.Time
	supersededAt *time.Time
}

func readRegistration(t *testing.T, pool *pgxpool.Pool, address iam.EmailAddress) (registration, bool) {
	t.Helper()
	var out registration
	const identityQuery = `SELECT e.id, e.account_id, e.verified_at, a.kind, a.status,
			coalesce((SELECT c.encoded_hash FROM account_password_credentials c WHERE c.account_id = a.id), '')
		FROM account_email_identities e JOIN accounts a ON a.id = e.account_id WHERE e.address = $1`
	err := pool.QueryRow(context.Background(), identityQuery, address.Reveal()).
		Scan(&out.identity, &out.account, &out.verifiedAt, &out.kind, &out.status, &out.encoded)
	if err != nil {
		if err == pgx.ErrNoRows {
			return registration{}, false
		}
		t.Fatalf("reading the identity failed: %v", err)
	}

	rows, err := pool.Query(context.Background(),
		`SELECT role FROM account_role_grants WHERE account_id = $1 ORDER BY role`, out.account)
	if err != nil {
		t.Fatalf("reading the grants failed: %v", err)
	}
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			t.Fatalf("scanning a grant failed: %v", err)
		}
		out.roles = append(out.roles, role)
	}
	rows.Close()

	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM account_email_verifications WHERE identity_id = $1`, out.identity).
		Scan(&out.challenges); err != nil {
		t.Fatalf("counting the challenges failed: %v", err)
	}

	var current storedChallenge
	err = pool.QueryRow(context.Background(),
		`SELECT id, issued_at, expires_at, consumed_at, superseded_at FROM account_email_verifications
		 WHERE identity_id = $1 AND consumed_at IS NULL AND superseded_at IS NULL`, out.identity).
		Scan(&current.id, &current.issuedAt, &current.expiresAt, &current.consumedAt, &current.supersededAt)
	switch {
	case err == nil:
		out.current = &current
	case err != pgx.ErrNoRows:
		t.Fatalf("reading the current challenge failed: %v", err)
	}

	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM account_email_deliveries d
		 JOIN account_email_verifications v ON v.id = d.challenge_id WHERE v.identity_id = $1`, out.identity).
		Scan(&out.deliveries); err != nil {
		t.Fatalf("counting the deliveries failed: %v", err)
	}
	if out.current != nil {
		err = pool.QueryRow(context.Background(),
			`SELECT id, token FROM account_email_deliveries WHERE challenge_id = $1`, current.id).
			Scan(&out.deliveryID, &out.deliveryTok)
		if err != nil && err != pgx.ErrNoRows {
			t.Fatalf("reading the delivery failed: %v", err)
		}
	}
	return out, true
}

// tokenFor takes the token the way the dispatcher would: out of the outbox row,
// which is the only place it exists after the transaction that issued it.
func tokenFor(t *testing.T, pool *pgxpool.Pool, address iam.EmailAddress) emailverification.Token {
	t.Helper()
	stored, found := readRegistration(t, pool, address)
	if !found || stored.deliveryTok == "" {
		t.Fatal("no pending delivery carries a token for this address")
	}
	token, err := emailverification.ParseToken(stored.deliveryTok)
	if err != nil {
		t.Fatalf("the stored token is not of the issued shape: %v", err)
	}
	return token
}

func eventCount(t *testing.T, pool *pgxpool.Pool, account, kind string) int {
	t.Helper()
	var recorded int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM account_security_events WHERE account_id = $1 AND kind = $2`,
		account, kind).Scan(&recorded); err != nil {
		t.Fatalf("counting %q events failed: %v", kind, err)
	}
	return recorded
}

// expireChallenge moves a challenge past its expiry without touching either
// terminal column, so it stays current while being unusable.
func expireChallenge(t *testing.T, pool *pgxpool.Pool, id string, at time.Time) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`UPDATE account_email_verifications SET issued_at = $2, expires_at = $3 WHERE id = $1`,
		id, at.Add(-2*time.Hour), at.Add(-time.Hour)); err != nil {
		t.Fatalf("ageing the challenge failed: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`UPDATE account_email_deliveries SET created_at = $2, available_at = $2, expires_at = $3
		 WHERE challenge_id = $1`, id, at.Add(-3*time.Hour), at.Add(-time.Hour)); err != nil {
		t.Fatalf("ageing the delivery failed: %v", err)
	}
}
