package migration

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

/*
The credential revision arrives on a table that already holds rows. These drive
the real migration set: once against a schema stopped at 0003 that carries
credentials, and once against an empty one.
*/

// prefixThrough selects the real set as far as one version. A test that judges
// what a single version does must never be handed versions added after it.
func prefixThrough(t *testing.T, version int64) []Migration {
	t.Helper()
	all, err := Load()
	if err != nil {
		t.Fatalf("loading migrations failed: %v", err)
	}
	var wanted []Migration
	for _, one := range all {
		if one.Version <= version {
			wanted = append(wanted, one)
		}
	}
	if int64(len(wanted)) != version {
		t.Fatalf("%d migration(s) reach version %d, want %d", len(wanted), version, version)
	}
	return wanted
}

// upTo stands a schema exactly where a deployment stood before the change here.
func upTo(t *testing.T, pool *pgxpool.Pool, version int64) {
	t.Helper()
	if _, err := Apply(context.Background(), pool, prefixThrough(t, version)); err != nil {
		t.Fatalf("applying migrations up to %d failed: %v", version, err)
	}
}

func columnDefault(t *testing.T, pool *pgxpool.Pool, table, column string) *string {
	t.Helper()
	const query = `SELECT column_default FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2`
	var value *string
	if err := pool.QueryRow(context.Background(), query, table, column).Scan(&value); err != nil {
		t.Fatalf("inspecting %s.%s failed: %v", table, column, err)
	}
	return value
}

// seedCredential writes an account and a credential the way 0001 shaped them,
// so the backfill is measured on a row that predates the new column.
func seedCredential(t *testing.T, pool *pgxpool.Pool, id string) {
	t.Helper()
	ctx := context.Background()
	const account = `INSERT INTO accounts (id, kind, status, created_at, updated_at)
		VALUES ($1, 'viewer', 'active', now(), now())`
	if _, err := pool.Exec(ctx, account, id); err != nil {
		t.Fatalf("seeding the account failed: %v", err)
	}
	const credential = `INSERT INTO account_password_credentials (account_id, encoded_hash, created_at, updated_at)
		VALUES ($1, '$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', now(), now())`
	if _, err := pool.Exec(ctx, credential, id); err != nil {
		t.Fatalf("seeding the credential failed: %v", err)
	}
}

func TestCredentialRevisionBackfillsExistingRows(t *testing.T) {
	pool := freshPool(t)
	upTo(t, pool, 3)
	const id = "3f1c2a4d-5e6b-4a7c-8d9e-0f1a2b3c4d5e"
	seedCredential(t, pool, id)

	// Through 4 alone: a later version added to the set must not change what this
	// case measures, nor be applied by it.
	result, err := Apply(context.Background(), pool, prefixThrough(t, 4))
	if err != nil {
		t.Fatalf("applying the credential revision failed: %v", err)
	}
	if len(result.Applied) != 1 || result.Applied[0] != 4 {
		t.Fatalf("applied %v, want version 4 alone", result.Applied)
	}

	var revision int64
	if err := pool.QueryRow(context.Background(),
		`SELECT revision FROM account_password_credentials WHERE account_id = $1`, id).Scan(&revision); err != nil {
		t.Fatalf("reading the backfilled revision failed: %v", err)
	}
	if revision != 1 {
		t.Fatalf("the backfilled revision is %d, want 1", revision)
	}
}

func TestCredentialRevisionLeavesNoDefaultBehind(t *testing.T) {
	pool := freshPool(t)
	if _, err := Apply(context.Background(), pool, prefixThrough(t, 4)); err != nil {
		t.Fatalf("applying migrations on an empty schema failed: %v", err)
	}

	if value := columnDefault(t, pool, "account_password_credentials", "revision"); value != nil {
		t.Fatalf("the revision still carries the default %q, so a writer could omit it", *value)
	}

	// A write that omits the revision must fail rather than start over at 1.
	const id = "5c2b1a90-3d4e-4f5a-8b6c-7d8e9f0a1b2c"
	seedAccount := `INSERT INTO accounts (id, kind, status, created_at, updated_at)
		VALUES ($1, 'viewer', 'active', now(), now())`
	if _, err := pool.Exec(context.Background(), seedAccount, id); err != nil {
		t.Fatalf("seeding the account failed: %v", err)
	}
	const omitted = `INSERT INTO account_password_credentials (account_id, encoded_hash, created_at, updated_at)
		VALUES ($1, '$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', now(), now())`
	if _, err := pool.Exec(context.Background(), omitted, id); err == nil {
		t.Fatal("a credential was written without stating its revision")
	}
}

func TestCredentialRevisionRunnerIsIdempotent(t *testing.T) {
	pool := freshPool(t)
	all, err := Load()
	if err != nil {
		t.Fatalf("loading migrations failed: %v", err)
	}
	first, err := Apply(context.Background(), pool, all)
	if err != nil {
		t.Fatalf("the first run failed: %v", err)
	}
	if len(first.Applied) != len(all) {
		t.Fatalf("the first run applied %d of %d migrations", len(first.Applied), len(all))
	}
	second, err := Apply(context.Background(), pool, all)
	if err != nil {
		t.Fatalf("the second run failed: %v", err)
	}
	if len(second.Applied) != 0 {
		t.Fatalf("the second run applied %v, want nothing", second.Applied)
	}
	if versions := recorded(t, pool); len(versions) != len(all) {
		t.Fatalf("the ledger holds %d rows, want %d", len(versions), len(all))
	}
}
