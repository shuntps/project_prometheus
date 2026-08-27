package migration

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrConflict reports a database whose recorded history does not match the set
// being applied. Nothing is applied when it is returned.
var ErrConflict = errors.New("migration history conflict")

// advisoryLockKey serialises runners against one database. The value is
// arbitrary and belongs to this application alone.
const advisoryLockKey int64 = 7_314_902_155_001

// acquireFailure keeps the acquisition cause reachable through errors.Is while
// rendering a fixed message: the driver's own can quote host, user and database.
type acquireFailure struct {
	cause error
}

func (a acquireFailure) Error() string { return "no connection was available for the migration run" }

func (a acquireFailure) Unwrap() error { return a.cause }

// cleanupBudget bounds every statement issued after the run itself has ended.
const cleanupBudget = 5 * time.Second

const ledger = `CREATE TABLE IF NOT EXISTS schema_migrations (
	version    bigint PRIMARY KEY,
	name       text NOT NULL,
	checksum   text NOT NULL,
	applied_at timestamptz NOT NULL DEFAULT now()
)`

// Result reports what an Apply actually changed.
type Result struct {
	Applied []int64
	Current int64
}

type applied struct {
	name     string
	checksum string
}

// Apply brings the database to the end of the set. It holds an advisory lock for
// the whole run, so a concurrent runner waits rather than applying in parallel.
func Apply(ctx context.Context, pool *pgxpool.Pool, migrations []Migration) (Result, error) {
	if err := verifyOrder(migrations); err != nil {
		return Result{}, err
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return Result{}, acquireFailure{cause: err}
	}

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", advisoryLockKey); err != nil {
		// A transport error, a cancellation or a lost reply does not prove the server
		// never took the lock, so the connection is destroyed rather than pooled.
		discardRunner(ctx, conn)
		return Result{}, errors.New("the migration lock could not be taken")
	}
	defer releaseRunner(ctx, conn)

	if _, err := conn.Exec(ctx, ledger); err != nil {
		return Result{}, errors.New("the migration ledger could not be created")
	}

	history, err := readHistory(ctx, conn.Conn())
	if err != nil {
		return Result{}, err
	}
	if err := reconcile(migrations, history); err != nil {
		return Result{}, err
	}

	result := Result{Current: int64(len(history))}
	for _, m := range migrations {
		if _, seen := history[m.Version]; seen {
			continue
		}
		if err := applyOne(ctx, conn.Conn(), m); err != nil {
			return Result{}, err
		}
		result.Applied = append(result.Applied, m.Version)
		result.Current = m.Version
	}
	return result, nil
}

// releaseRunner pools the connection only once the advisory lock is proven released:
// a session lock ends only with its session, so a doubtful connection is closed instead.
func releaseRunner(ctx context.Context, conn *pgxpool.Conn) {
	unlockCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupBudget)
	defer cancel()

	var released bool
	err := conn.QueryRow(unlockCtx, "SELECT pg_advisory_unlock($1)", advisoryLockKey).Scan(&released)
	if err == nil && released {
		conn.Release()
		return
	}
	discardRunner(ctx, conn)
}

// discardRunner takes the connection out of the pool and ends its session, which
// releases any advisory lock the server may still be holding for it.
func discardRunner(ctx context.Context, conn *pgxpool.Conn) {
	hijacked := conn.Hijack()
	closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupBudget)
	defer cancel()
	_ = hijacked.Close(closeCtx)
}

func readHistory(ctx context.Context, conn *pgx.Conn) (map[int64]applied, error) {
	rows, err := conn.Query(ctx, "SELECT version, name, checksum FROM schema_migrations ORDER BY version")
	if err != nil {
		return nil, errors.New("the migration ledger could not be read")
	}
	defer rows.Close()

	history := map[int64]applied{}
	for rows.Next() {
		var version int64
		var record applied
		if err := rows.Scan(&version, &record.name, &record.checksum); err != nil {
			return nil, errors.New("the migration ledger holds an unreadable row")
		}
		history[version] = record
	}
	if rows.Err() != nil {
		return nil, errors.New("the migration ledger could not be read to the end")
	}
	return history, nil
}

// reconcile refuses a database whose history cannot be continued: a changed
// migration, an unknown one, or a gap that would apply changes out of order.
func reconcile(migrations []Migration, history map[int64]applied) error {
	known := map[int64]Migration{}
	for _, m := range migrations {
		known[m.Version] = m
	}

	for version, record := range history {
		m, ok := known[version]
		if !ok {
			return fmt.Errorf("%w: version %d is recorded as applied but is not in the set", ErrConflict, version)
		}
		if m.Checksum != record.checksum {
			return fmt.Errorf("%w: version %d was applied with different statements; forward-only work must add a compensating migration instead of editing history", ErrConflict, version)
		}
		// The recorded name is reconciled too, so a renamed file is a conflict
		// rather than a silent divergence between the ledger and the set.
		if m.Name != record.name {
			return fmt.Errorf("%w: version %d was applied under a different name", ErrConflict, version)
		}
	}

	// The applied versions must form a prefix; otherwise a pending migration
	// would run after one that already depends on a later schema.
	for i, m := range migrations {
		if _, seen := history[m.Version]; seen {
			continue
		}
		for _, later := range migrations[i+1:] {
			if _, seen := history[later.Version]; seen {
				return fmt.Errorf("%w: version %d is applied while the earlier version %d is not", ErrConflict, later.Version, m.Version)
			}
		}
		break
	}
	return nil
}

// applyOne runs the statements and records them in one transaction, so a failure
// leaves neither a partial schema nor a ledger row.
func applyOne(ctx context.Context, conn *pgx.Conn, m Migration) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("migration %d could not be started", m.Version)
	}
	defer func() {
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupBudget)
		defer cancel()
		_ = tx.Rollback(rollbackCtx)
	}()

	if _, err := tx.Exec(ctx, m.SQL); err != nil {
		// The driver's message can quote the statement; only the version survives.
		return fmt.Errorf("migration %d failed and was rolled back", m.Version)
	}
	const record = "INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)"
	if _, err := tx.Exec(ctx, record, m.Version, m.Name, m.Checksum); err != nil {
		return fmt.Errorf("migration %d could not be recorded and was rolled back", m.Version)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("migration %d could not be committed", m.Version)
	}
	return nil
}
