package app_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence"
)

// TestStartingTheServiceAppliesNoMigration keeps schema change a deliberate
// operation: the service reaches a serving state without touching the schema.
func TestStartingTheServiceAppliesNoMigration(t *testing.T) {
	dsn, host := realPostgres(t)
	target := dsnFor(t, dsn, host)

	parsed, err := url.Parse(target.Reveal())
	if err != nil {
		t.Fatalf("the connection string could not be inspected: %v", err)
	}
	values := parsed.Query()
	values.Set("sslmode", string(persistence.TLSDisable))
	parsed.RawQuery = values.Encode()

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, parsed.String())
	if err != nil {
		t.Fatal("connecting to the server failed")
	}
	if _, err := conn.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("resetting the schema failed: %v", err)
	}

	base, _, stop := serve(t, storeConfig(t, freeAddress(t), target))
	waitForHealth(t, base+"/readyz", http.StatusOK, "ready")
	if err := stop(); err != nil {
		t.Fatalf("the run returned an error: %v", err)
	}

	const query = `SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'`
	var tables int
	if err := conn.QueryRow(ctx, query).Scan(&tables); err != nil {
		t.Fatalf("inspecting the schema failed: %v", err)
	}
	if err := conn.Close(ctx); err != nil {
		t.Fatalf("closing the observer failed: %v", err)
	}
	if tables != 0 {
		t.Fatalf("starting the service created %d table(s); migrations must stay a separate operation", tables)
	}
}
