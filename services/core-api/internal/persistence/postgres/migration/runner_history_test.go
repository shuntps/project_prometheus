package migration

import (
	"context"
	"errors"
	"testing"
)

func TestTheEmbeddedSetAppliesAndIsRecorded(t *testing.T) {
	pool := freshPool(t)
	migrations, err := Load()
	if err != nil {
		t.Fatalf("loading the embedded set failed: %v", err)
	}

	result, err := Apply(context.Background(), pool, migrations)
	if err != nil {
		t.Fatalf("applying failed: %v", err)
	}
	if len(result.Applied) != len(migrations) {
		t.Fatalf("%d of %d migrations were applied", len(result.Applied), len(migrations))
	}
	for _, table := range []string{
		"accounts", "account_email_identities", "account_password_credentials",
		"account_role_grants", "account_sessions", "account_security_events",
	} {
		if !tableExists(t, pool, table) {
			t.Errorf("table %q was not created", table)
		}
	}
}

// TestRunningAgainOnACurrentSchemaChangesNothing is what makes the operation safe
// to repeat during a deployment.
func TestRunningAgainOnACurrentSchemaChangesNothing(t *testing.T) {
	pool := freshPool(t)
	migrations, err := Load()
	if err != nil {
		t.Fatalf("loading failed: %v", err)
	}

	if _, err := Apply(context.Background(), pool, migrations); err != nil {
		t.Fatalf("the first run failed: %v", err)
	}
	before := recorded(t, pool)

	second, err := Apply(context.Background(), pool, migrations)
	if err != nil {
		t.Fatalf("the second run failed: %v", err)
	}
	if len(second.Applied) != 0 {
		t.Fatalf("the second run applied %v", second.Applied)
	}
	if got := recorded(t, pool); len(got) != len(before) {
		t.Fatalf("the ledger moved from %v to %v", before, got)
	}
}

// No partial schema and no ledger row. PostgreSQL already wraps one multi-statement
// Exec implicitly, so the test below is what discriminates the explicit transaction.
func TestAFailingMigrationLeavesNothingBehind(t *testing.T) {
	pool := freshPool(t)
	set := []Migration{
		fixture(1, "first", "CREATE TABLE first_table (id int PRIMARY KEY);"),
		fixture(2, "second", "CREATE TABLE second_table (id int PRIMARY KEY); CREATE TABLE second_table (id int PRIMARY KEY);"),
	}

	if _, err := Apply(context.Background(), pool, set); err == nil {
		t.Fatal("a failing migration was reported as applied")
	}
	if !tableExists(t, pool, "first_table") {
		t.Error("the migration that succeeded was rolled back too")
	}
	if tableExists(t, pool, "second_table") {
		t.Error("the failing migration left a table behind")
	}
	if got := recorded(t, pool); len(got) != 1 || got[0] != 1 {
		t.Fatalf("the ledger holds %v, want only version 1", got)
	}

	// The set can be repaired and applied without any manual cleanup.
	set[1] = fixture(2, "second", "CREATE TABLE second_table (id int PRIMARY KEY);")
	if _, err := Apply(context.Background(), pool, set); err != nil {
		t.Fatalf("the repaired set was refused: %v", err)
	}
	if !tableExists(t, pool, "second_table") {
		t.Error("the repaired migration did not apply")
	}
}

// The statements and their ledger row are two separate commands, so only an
// explicit transaction makes the schema change vanish when the second one fails.
func TestAMigrationAndItsLedgerRowCommitTogether(t *testing.T) {
	pool := freshPool(t)
	set := []Migration{
		fixture(1, "first", "CREATE TABLE first_table (id int PRIMARY KEY);"),
		fixture(2, "second", "CREATE TABLE second_table (id int PRIMARY KEY); DROP TABLE schema_migrations;"),
	}

	if _, err := Apply(context.Background(), pool, set); err == nil {
		t.Fatal("a migration that broke its own ledger reported success")
	}
	if !tableExists(t, pool, "schema_migrations") {
		t.Fatal("the ledger was dropped; the statements were not rolled back with the failed record")
	}
	if tableExists(t, pool, "second_table") {
		t.Fatal("the schema change survived although its ledger row was never written")
	}
	if got := recorded(t, pool); len(got) != 1 || got[0] != 1 {
		t.Fatalf("the ledger holds %v, want only version 1", got)
	}
}

// TestAnAppliedMigrationThatChangedIsRefused keeps history from being rewritten:
// forward-only work adds a compensating migration instead.
func TestAnAppliedMigrationThatChangedIsRefused(t *testing.T) {
	pool := freshPool(t)
	original := []Migration{fixture(1, "first", "CREATE TABLE first_table (id int PRIMARY KEY);")}
	if _, err := Apply(context.Background(), pool, original); err != nil {
		t.Fatalf("the first run failed: %v", err)
	}

	edited := []Migration{fixture(1, "first", "CREATE TABLE first_table (id int PRIMARY KEY, extra text);")}
	_, err := Apply(context.Background(), pool, edited)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("got %v, want a history conflict", err)
	}

	// Nothing was applied, and the original set still runs clean.
	if _, err := Apply(context.Background(), pool, original); err != nil {
		t.Fatalf("the unchanged set was refused after the conflict: %v", err)
	}
}

// TestAHistoryThatCannotBeContinuedIsRefused covers a database that has moved
// beyond, or diverged from, the set being applied.
func TestAHistoryThatCannotBeContinuedIsRefused(t *testing.T) {
	pool := freshPool(t)
	applied := []Migration{
		fixture(1, "first", "CREATE TABLE first_table (id int PRIMARY KEY);"),
		fixture(2, "second", "CREATE TABLE second_table (id int PRIMARY KEY);"),
	}
	if _, err := Apply(context.Background(), pool, applied); err != nil {
		t.Fatalf("the first run failed: %v", err)
	}

	shorter := applied[:1]
	if _, err := Apply(context.Background(), pool, shorter); !errors.Is(err, ErrConflict) {
		t.Fatalf("got %v, want a conflict when the database is ahead of the set", err)
	}

	invalid := []Migration{fixture(2, "second", "SELECT 1;")}
	if _, err := Apply(context.Background(), pool, invalid); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want a refusal for a set that does not start at one", err)
	}
}

// TestARenamedMigrationIsRefused keeps the ledger and the set from diverging on
// anything the ledger records.
func TestARenamedMigrationIsRefused(t *testing.T) {
	pool := freshPool(t)
	original := []Migration{fixture(1, "first", "CREATE TABLE first_table (id int PRIMARY KEY);")}
	if _, err := Apply(context.Background(), pool, original); err != nil {
		t.Fatalf("the first run failed: %v", err)
	}

	renamed := []Migration{fixture(1, "renamed", "CREATE TABLE first_table (id int PRIMARY KEY);")}
	if _, err := Apply(context.Background(), pool, renamed); !errors.Is(err, ErrConflict) {
		t.Fatalf("got %v, want a history conflict on the recorded name", err)
	}
	if _, err := Apply(context.Background(), pool, original); err != nil {
		t.Fatalf("the unchanged set was refused after the conflict: %v", err)
	}
}

// TestAnUnreachableDatabaseFailsClosed keeps a run from reporting success when it
// never reached the server.
func TestAnUnreachableDatabaseFailsClosed(t *testing.T) {
	pool := freshPool(t)
	migrations, err := Load()
	if err != nil {
		t.Fatalf("loading failed: %v", err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Apply(cancelled, pool, migrations); err == nil {
		t.Fatal("a cancelled run reported success")
	}
	if tableExists(t, pool, "accounts") {
		t.Error("a cancelled run applied part of the schema")
	}
	if tableExists(t, pool, "schema_migrations") {
		t.Error("a cancelled run created the ledger")
	}
}
